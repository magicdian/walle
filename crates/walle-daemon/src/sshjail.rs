use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::rng;
use russh::keys::{Algorithm, HashAlg, PrivateKey, PublicKey};
use russh::server::{Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelId, Disconnect, MethodKind, MethodSet, Pty, SshId};
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::runtime::Builder;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};
use tracing::{error, info, warn};
use walle_policy::{SshJailHostnameStrategy, SshJailPolicy};

use crate::ssh_overlay::{
    DynamicBlacklistStore, PendingTrapRecord, SshOverlayError, SshOverlayPaths,
    resolve_trap_identity_by_uid,
};

const OPENSSH_SERVER_ID: &str = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5";
const DEFAULT_OS_RELEASE: &str = "5.15.0-113-generic";
const DEFAULT_OS_BANNER: &str = "Ubuntu 22.04.4 LTS";
const DEFAULT_OS_ARCHITECTURE: &str = "x86_64";
const DEFAULT_OS_NAME: &str = "Ubuntu";
const DEFAULT_CPU_COUNT: usize = 4;
const DEFAULT_MEMORY_TOTAL_KB: u64 = 2_048_576;
const DEFAULT_MEMORY_USED_KB: u64 = 642_312;
const DEFAULT_MEMORY_FREE_KB: u64 = 321_144;
const DEFAULT_MEMORY_SHARED_KB: u64 = 22_528;
const DEFAULT_MEMORY_BUFF_CACHE_KB: u64 = 1_085_120;
const DEFAULT_MEMORY_AVAILABLE_KB: u64 = 1_247_820;
const DEFAULT_OS_RELEASE_CONTENTS: &str = concat!(
    "NAME=\"Ubuntu\"\n",
    "VERSION=\"22.04.4 LTS (Jammy Jellyfish)\"\n",
    "ID=ubuntu\n",
    "ID_LIKE=debian\n",
    "PRETTY_NAME=\"Ubuntu 22.04.4 LTS\"\n",
    "VERSION_ID=\"22.04\"\n",
    "HOME_URL=\"https://www.ubuntu.com/\"\n",
);
const FREE_MEMORY_TOTAL_PROBE: &str = "free -k | awk '/^Mem:/{print $2}'";
const OS_RELEASE_NAME_PROBE: &str =
    "cat /etc/os-release 2>/dev/null | grep -E '^(NAME|PRETTY_NAME)=' | head -1";
const SHELL_BUILTINS: [&str; 40] = [
    "cat", "cd", "chattr", "chmod", "clear", "command", "crontab", "df", "echo", "env", "exit",
    "free", "history", "hostname", "id", "ifconfig", "ip", "last", "lockr", "ls", "mkdir",
    "netstat", "nproc", "ping", "ps", "pwd", "rm", "ss", "ssh", "sshd", "sudo", "su", "test",
    "tree", "uname", "uptime", "w", "which", "who", "whoami",
];
const SYSTEM_HOST_KEY_PATHS: [&str; 3] = [
    "/etc/ssh/ssh_host_ed25519_key",
    "/etc/ssh/ssh_host_ecdsa_key",
    "/etc/ssh/ssh_host_rsa_key",
];

pub struct SshJailService {
    bound_port: u16,
    shared: Arc<SshJailShared>,
    shutdown: Option<oneshot::Sender<()>>,
    join_handle: Option<JoinHandle<()>>,
}

impl SshJailService {
    pub fn start(policy: &SshJailPolicy) -> Result<Self, SshJailError> {
        let storage_paths = SshOverlayPaths::from_policy(policy);
        storage_paths.ensure_dirs()?;
        let hostname = resolve_hostname(policy)?;
        let dynamic_blacklist =
            DynamicBlacklistStore::load(storage_paths.dynamic_blacklist_keys_path.clone());
        let shared = Arc::new(SshJailShared::new(
            policy,
            hostname,
            storage_paths,
            dynamic_blacklist,
        ));
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let policy = policy.clone();
        let shared_for_thread = Arc::clone(&shared);
        let join_handle = thread::Builder::new()
            .name("walle-sshjail".to_string())
            .spawn(move || {
                if let Err(error) = run_server(policy, shared_for_thread, ready_tx, shutdown_rx) {
                    error!(
                        component = "sshjail",
                        event = "server_exit",
                        error = %error,
                        "sshjail server thread exited"
                    );
                }
            })
            .map_err(|source| SshJailError::SpawnThread { source })?;

        let bound_port = ready_rx
            .recv()
            .map_err(|_| SshJailError::StartupSignalLost)??;

        info!(
            component = "sshjail",
            event = "started",
            bind = "0.0.0.0",
            bound_port,
            hostname = shared.hostname.as_str(),
            max_sessions = shared.max_sessions,
            root_dir = %shared.storage_paths.root_dir.display(),
            session_audit_dir = %shared.storage_paths.session_audit_dir.display(),
            state_dir = %shared.storage_paths.state_dir.display(),
            "sshjail listener is ready"
        );

        Ok(Self {
            bound_port,
            shared,
            shutdown: Some(shutdown_tx),
            join_handle: Some(join_handle),
        })
    }

    #[must_use]
    pub const fn bound_port(&self) -> u16 {
        self.bound_port
    }

    #[must_use]
    pub fn can_accept_new_session(&self) -> bool {
        self.shared.can_accept_new_session()
    }
}

impl Drop for SshJailService {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }

        if let Some(join_handle) = self.join_handle.take() {
            let _ = join_handle.join();
        }
    }
}

#[derive(Debug, Error)]
pub enum SshJailError {
    #[error(transparent)]
    Overlay(#[from] SshOverlayError),
    #[error("failed to build sshjail runtime: {source}")]
    BuildRuntime { source: std::io::Error },
    #[error("failed to spawn sshjail server thread: {source}")]
    SpawnThread { source: std::io::Error },
    #[error("failed to bind sshjail listener on 0.0.0.0:{port}: {source}")]
    BindListener { port: u16, source: std::io::Error },
    #[error("failed to read sshjail local listener address: {source}")]
    ReadLocalAddress { source: std::io::Error },
    #[error("sshjail startup signal was lost before the listener became ready")]
    StartupSignalLost,
    #[error("failed to run sshjail server loop: {source}")]
    RunServerLoop { source: std::io::Error },
    #[error("failed to generate sshjail host key: {message}")]
    GenerateHostKey { message: String },
    #[error("configured sshjail hostname is missing")]
    MissingConfiguredHostname,
}

#[derive(Debug, Error)]
pub enum SshJailSessionError {
    #[error(transparent)]
    Russh(#[from] russh::Error),
}

#[derive(Debug, Error)]
pub enum LocalTrapError {
    #[error(transparent)]
    Overlay(#[from] SshOverlayError),
    #[error(transparent)]
    SshJail(#[from] SshJailError),
    #[error("missing pending SSH trap token '{token}'")]
    MissingPendingTrap { token: String },
    #[error("failed to read or write local trap session stdio: {source}")]
    Io { source: std::io::Error },
}

pub fn run_local_trap_command(policy: &SshJailPolicy, token: &str) -> Result<i32, LocalTrapError> {
    let paths = SshOverlayPaths::from_policy(policy);
    let pending_trap = PendingTrapRecord::consume(&paths, token)?.ok_or_else(|| {
        LocalTrapError::MissingPendingTrap {
            token: token.to_string(),
        }
    })?;
    let peer_addr = peer_addr_from_ssh_connection();
    let session_id = next_local_trap_session_id();
    let hostname = resolve_hostname(policy)?;
    let audit = SessionAudit::new(paths.session_audit_dir.as_path(), session_id, peer_addr);
    let mut shell = ShellState::new(
        pending_trap.username.as_str(),
        hostname.as_str(),
        peer_addr,
        Duration::from_secs(policy.max_session_duration_secs),
        session_id,
    );
    shell.ensure_identity_home();

    audit.record(
        "connection_open",
        format!(
            "peer_addr={} entrypoint=sshd_overlay trigger={} token={}",
            peer_addr
                .map(|addr| addr.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            pending_trap.trigger.as_str(),
            pending_trap.token
        ),
    );
    audit.record(
        "auth_publickey",
        format!(
            "user={} algorithm={} fingerprint={} public_key={}",
            pending_trap.username,
            pending_trap.key.key_type,
            pending_trap.key.fingerprint,
            pending_trap.key.openssh_key
        ),
    );
    audit.record("auth_succeeded", "session authenticated");
    audit.record("channel_open_session", "channel=stdio");

    let original_command = std::env::var("SSH_ORIGINAL_COMMAND")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    let exit_status = if let Some(command) = original_command {
        audit.record("exec_request", format!("channel=stdio command={command}"));
        audit.record("command", format!("channel=stdio command={command}"));
        execute_local_trap_command_line(&mut shell, &audit, command.as_str())?
    } else {
        if std::env::var("SSH_TTY").is_ok() {
            audit.record(
                "pty_request",
                format!(
                    "channel=stdio term={} cols=0 rows=0",
                    std::env::var("TERM").unwrap_or_else(|_| "unknown".to_string())
                ),
            );
        }
        audit.record("shell_request", "channel=stdio");
        run_local_trap_interactive_loop(&mut shell, &audit)?
    };

    audit.record("channel_close", "channel=stdio");
    audit.record("connection_close", "local trap session finished");
    Ok(exit_status)
}

pub fn run_local_trap_login(policy: &SshJailPolicy) -> Result<i32, LocalTrapError> {
    let uid = unsafe { libc::getuid() };
    let identity = resolve_trap_identity_by_uid(policy, uid)?.ok_or_else(|| {
        LocalTrapError::MissingPendingTrap {
            token: format!("uid:{uid}"),
        }
    })?;
    let peer_addr = peer_addr_from_ssh_connection();
    let session_id = next_local_trap_session_id();
    let hostname = resolve_hostname(policy)?;
    let audit = SessionAudit::new(
        SshOverlayPaths::from_policy(policy)
            .session_audit_dir
            .as_path(),
        session_id,
        peer_addr,
    );
    let mut shell = ShellState::new(
        identity.username.as_str(),
        hostname.as_str(),
        peer_addr,
        Duration::from_secs(policy.max_session_duration_secs),
        session_id,
    );
    shell.ensure_identity_home();

    audit.record(
        "connection_open",
        format!(
            "peer_addr={} entrypoint=sshd_identity_overlay trigger=trap_username uid={uid}",
            peer_addr
                .map(|addr| addr.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        ),
    );
    record_exposed_auth_info(&audit);
    audit.record("auth_succeeded", "session authenticated");
    audit.record("channel_open_session", "channel=stdio");

    let original_command = std::env::var("SSH_ORIGINAL_COMMAND")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    let exit_status = if let Some(command) = original_command {
        audit.record("exec_request", format!("channel=stdio command={command}"));
        audit.record("command", format!("channel=stdio command={command}"));
        execute_local_trap_command_line(&mut shell, &audit, command.as_str())?
    } else {
        if std::env::var("SSH_TTY").is_ok() {
            audit.record(
                "pty_request",
                format!(
                    "channel=stdio term={} cols=0 rows=0",
                    std::env::var("TERM").unwrap_or_else(|_| "unknown".to_string())
                ),
            );
        }
        audit.record("shell_request", "channel=stdio");
        run_local_trap_interactive_loop(&mut shell, &audit)?
    };

    audit.record("channel_close", "channel=stdio");
    audit.record("connection_close", "local trap login finished");
    Ok(exit_status)
}

fn execute_local_trap_command_line(
    shell: &mut ShellState,
    audit: &SessionAudit,
    command: &str,
) -> Result<i32, LocalTrapError> {
    let result = shell.execute_line(command);
    if result.record_history {
        shell.record_history_entry(command);
    }
    for event in &result.audit_events {
        audit.record(event.event, event.details.as_str());
    }
    if !result.output.is_empty() {
        let mut stdout = std::io::stdout().lock();
        stdout
            .write_all(result.output.as_bytes())
            .map_err(|source| LocalTrapError::Io { source })?;
        stdout
            .flush()
            .map_err(|source| LocalTrapError::Io { source })?;
    }
    Ok(result.exit_status as i32)
}

fn run_local_trap_interactive_loop(
    shell: &mut ShellState,
    audit: &SessionAudit,
) -> Result<i32, LocalTrapError> {
    let stdin = std::io::stdin();
    let mut stdin = stdin.lock();
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(shell.banner().as_bytes())
        .and_then(|_| stdout.write_all(shell.prompt().as_bytes()))
        .and_then(|_| stdout.flush())
        .map_err(|source| LocalTrapError::Io { source })?;

    let mut exit_status = 0i32;
    let mut line = String::new();
    loop {
        line.clear();
        let bytes_read = stdin
            .read_line(&mut line)
            .map_err(|source| LocalTrapError::Io { source })?;
        if bytes_read == 0 {
            break;
        }

        let command = line.trim_end_matches(['\r', '\n']).trim().to_string();
        if !command.is_empty() {
            audit.record("command", format!("channel=stdio command={command}"));
        }
        let result = shell.execute_line(command.as_str());
        if result.record_history {
            shell.record_history_entry(command.as_str());
        }
        for event in &result.audit_events {
            audit.record(event.event, event.details.as_str());
        }
        if !result.output.is_empty() {
            stdout
                .write_all(result.output.as_bytes())
                .map_err(|source| LocalTrapError::Io { source })?;
        }
        exit_status = result.exit_status as i32;

        if result.close_channel {
            stdout
                .flush()
                .map_err(|source| LocalTrapError::Io { source })?;
            break;
        }

        stdout
            .write_all(shell.prompt().as_bytes())
            .and_then(|_| stdout.flush())
            .map_err(|source| LocalTrapError::Io { source })?;
    }

    Ok(exit_status)
}

fn peer_addr_from_ssh_connection() -> Option<SocketAddr> {
    let connection = std::env::var("SSH_CONNECTION").ok()?;
    let mut parts = connection.split_whitespace();
    let ip = parts.next()?;
    let port = parts.next()?.parse::<u16>().ok()?;
    format!("{ip}:{port}").parse().ok()
}

fn next_local_trap_session_id() -> u64 {
    let pid = u64::from(std::process::id());
    unix_timestamp_secs() ^ (pid << 16)
}

fn record_exposed_auth_info(audit: &SessionAudit) {
    let Some(path) = std::env::var("SSH_USER_AUTH")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    else {
        return;
    };

    match std::fs::read_to_string(path.as_str()) {
        Ok(contents) => {
            let normalized = contents
                .lines()
                .map(str::trim)
                .collect::<Vec<_>>()
                .join("; ");
            if !normalized.is_empty() {
                audit.record(
                    "auth_info",
                    format!("source=SSH_USER_AUTH path={path} contents={normalized}"),
                );
            }
        }
        Err(error) => {
            audit.record(
                "auth_info",
                format!("source=SSH_USER_AUTH path={path} error={error}"),
            );
        }
    }
    let _ = std::fs::remove_file(path);
}

fn run_server(
    policy: SshJailPolicy,
    shared: Arc<SshJailShared>,
    ready_tx: mpsc::SyncSender<Result<u16, SshJailError>>,
    shutdown_rx: oneshot::Receiver<()>,
) -> Result<(), SshJailError> {
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|source| SshJailError::BuildRuntime { source })?;

    runtime.block_on(async move {
        let listener = TcpListener::bind(("0.0.0.0", policy.listen_port))
            .await
            .map_err(|source| SshJailError::BindListener {
                port: policy.listen_port,
                source,
            })?;
        let bound_port = listener
            .local_addr()
            .map_err(|source| SshJailError::ReadLocalAddress { source })?
            .port();
        let config = Arc::new(build_server_config(&policy)?);

        if ready_tx.send(Ok(bound_port)).is_err() {
            return Ok(());
        }

        let mut server = SshJailServer {
            shared: Arc::clone(&shared),
        };
        let mut running = server.run_on_socket(config, &listener);
        let handle = running.handle();

        tokio::select! {
            result = &mut running => {
                result.map_err(|source| SshJailError::RunServerLoop { source })?;
            }
            _ = shutdown_rx => {
                handle.shutdown("walle sshjail shutdown".to_string());
                running.await.map_err(|source| SshJailError::RunServerLoop { source })?;
            }
        }

        Ok(())
    })
}

fn build_server_config(policy: &SshJailPolicy) -> Result<russh::server::Config, SshJailError> {
    let mut methods = MethodSet::empty();
    methods.push(MethodKind::Password);
    methods.push(MethodKind::PublicKey);
    let host_key = load_server_host_key();

    Ok(russh::server::Config {
        server_id: SshId::Standard(Cow::Borrowed(OPENSSH_SERVER_ID)),
        methods,
        auth_rejection_time: Duration::from_millis(300),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        inactivity_timeout: Some(Duration::from_secs(policy.idle_timeout_secs)),
        max_auth_attempts: 6,
        keys: vec![host_key?],
        ..Default::default()
    })
}

fn load_server_host_key() -> Result<PrivateKey, SshJailError> {
    load_server_host_key_from_paths(SYSTEM_HOST_KEY_PATHS.map(PathBuf::from).as_slice())
}

fn load_server_host_key_from_paths(paths: &[PathBuf]) -> Result<PrivateKey, SshJailError> {
    for path in paths {
        if !path.exists() {
            continue;
        }

        match PrivateKey::read_openssh_file(path.as_path()) {
            Ok(key) => {
                info!(
                    component = "sshjail",
                    event = "host_key_reused",
                    path = %path.display(),
                    "sshjail is reusing the system sshd host key"
                );
                return Ok(key);
            }
            Err(source) => {
                warn!(
                    component = "sshjail",
                    event = "host_key_reuse_failed",
                    path = %path.display(),
                    error = %source,
                    "failed to read a system sshd host key; trying the next candidate"
                );
            }
        }
    }

    warn!(
        component = "sshjail",
        event = "host_key_random_fallback",
        "no readable system sshd host key was found; sshjail is falling back to a generated host key"
    );

    PrivateKey::random(&mut rng(), Algorithm::Ed25519).map_err(|source| {
        SshJailError::GenerateHostKey {
            message: source.to_string(),
        }
    })
}

fn resolve_hostname(policy: &SshJailPolicy) -> Result<String, SshJailError> {
    match policy.hostname_strategy {
        SshJailHostnameStrategy::Configured => policy
            .fake_hostname
            .as_ref()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .ok_or(SshJailError::MissingConfiguredHostname),
        SshJailHostnameStrategy::Real => Ok(resolve_real_hostname()),
        SshJailHostnameStrategy::Generated => Ok(generate_fake_hostname()),
    }
}

fn resolve_real_hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(|| {
            fs::read_to_string("/etc/hostname")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        })
        .unwrap_or_else(generate_fake_hostname)
}

fn generate_fake_hostname() -> String {
    let stamp = unix_timestamp_secs() ^ u64::from(std::process::id());
    format!("web-{:04x}", stamp & 0xffff)
}

struct SshJailShared {
    hostname: String,
    storage_paths: SshOverlayPaths,
    dynamic_blacklist: DynamicBlacklistStore,
    max_sessions: usize,
    max_session_duration: Duration,
    permits: Arc<Semaphore>,
    session_ids: AtomicU64,
    auth_methods: MethodSet,
}

impl SshJailShared {
    fn new(
        policy: &SshJailPolicy,
        hostname: String,
        storage_paths: SshOverlayPaths,
        dynamic_blacklist: DynamicBlacklistStore,
    ) -> Self {
        let mut auth_methods = MethodSet::empty();
        auth_methods.push(MethodKind::Password);
        auth_methods.push(MethodKind::PublicKey);

        Self {
            hostname,
            storage_paths,
            dynamic_blacklist,
            max_sessions: policy.max_sessions,
            max_session_duration: Duration::from_secs(policy.max_session_duration_secs),
            permits: Arc::new(Semaphore::new(policy.max_sessions)),
            session_ids: AtomicU64::new(1),
            auth_methods,
        }
    }

    fn next_session_id(&self) -> u64 {
        self.session_ids.fetch_add(1, Ordering::Relaxed)
    }

    fn try_acquire_session(&self) -> Option<OwnedSemaphorePermit> {
        self.permits.clone().try_acquire_owned().ok()
    }

    fn can_accept_new_session(&self) -> bool {
        self.permits.available_permits() > 0
    }
}

#[derive(Clone)]
struct SshJailServer {
    shared: Arc<SshJailShared>,
}

impl russh::server::Server for SshJailServer {
    type Handler = SshJailHandler;

    fn new_client(&mut self, peer_addr: Option<SocketAddr>) -> Self::Handler {
        let session_id = self.shared.next_session_id();
        let permit = self.shared.try_acquire_session();
        let rejected_for_capacity = permit.is_none();
        let audit = SessionAudit::new(
            self.shared.storage_paths.session_audit_dir.as_path(),
            session_id,
            peer_addr,
        );
        audit.record(
            "connection_open",
            format!(
                "peer_addr={} capacity={}",
                peer_addr
                    .map(|addr| addr.to_string())
                    .unwrap_or_else(|| "unknown".to_string()),
                if rejected_for_capacity {
                    "full"
                } else {
                    "reserved"
                }
            ),
        );

        if rejected_for_capacity {
            warn!(
                component = "sshjail",
                event = "session_rejected_capacity",
                session_id,
                peer_addr = peer_addr
                    .map(|addr| addr.to_string())
                    .unwrap_or_else(|| "unknown".to_string()),
                max_sessions = self.shared.max_sessions,
                "sshjail rejected a new session because capacity is exhausted"
            );
        }

        SshJailHandler {
            shared: Arc::clone(&self.shared),
            _permit: permit,
            audit,
            session_id,
            peer_addr,
            shell: None,
            active_stream: None,
            rejected_for_capacity,
        }
    }

    fn handle_session_error(&mut self, error: <Self::Handler as russh::server::Handler>::Error) {
        warn!(
            component = "sshjail",
            event = "session_error",
            error = %error,
            "sshjail session finished with an error"
        );
    }
}

struct SshJailHandler {
    shared: Arc<SshJailShared>,
    _permit: Option<OwnedSemaphorePermit>,
    audit: SessionAudit,
    session_id: u64,
    peer_addr: Option<SocketAddr>,
    shell: Option<ShellState>,
    active_stream: Option<ActiveInteractiveStream>,
    rejected_for_capacity: bool,
}

impl Drop for SshJailHandler {
    fn drop(&mut self) {
        if let Some(stream) = self.active_stream.as_mut() {
            stream.cancel();
        }
        self.audit.record("connection_close", "handler dropped");
    }
}

struct ActiveInteractiveStream {
    cancel: Option<oneshot::Sender<()>>,
    finished: Arc<AtomicBool>,
}

impl ActiveInteractiveStream {
    fn cancel(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(());
        }
    }

    fn is_finished(&self) -> bool {
        self.finished.load(Ordering::Relaxed)
    }
}

impl SshJailHandler {
    fn start_exec_ping_stream(
        &self,
        handle: russh::server::Handle,
        channel: ChannelId,
        request: PingRequest,
    ) {
        let session_id = self.session_id;
        let hostname = self.shared.hostname.clone();

        tokio::spawn(async move {
            let resolved_ip =
                resolve_ping_target(session_id, hostname.as_str(), request.target.as_str());
            let mut transmitted = 0u32;
            let mut samples = Vec::new();

            if handle
                .data(channel, render_ping_header(&request, resolved_ip.as_str()))
                .await
                .is_ok()
            {
                let mut sequence = 1u32;
                loop {
                    let latency =
                        synthetic_ping_latency(session_id, request.target.as_str(), sequence);
                    samples.push(latency);
                    transmitted += 1;

                    if handle
                        .data(
                            channel,
                            render_ping_reply(resolved_ip.as_str(), sequence, latency),
                        )
                        .await
                        .is_err()
                    {
                        return;
                    }

                    if request.count.is_some_and(|count| sequence >= count) {
                        break;
                    }

                    sequence += 1;
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }

                if transmitted > 0 {
                    let _ = handle
                        .data(
                            channel,
                            render_ping_summary(&request, transmitted, samples.as_slice()),
                        )
                        .await;
                }
            }

            let _ = handle.exit_status_request(channel, 0).await;
            let _ = handle.eof(channel).await;
            let _ = handle.close(channel).await;
        });
    }

    fn start_ping_stream(
        &mut self,
        handle: russh::server::Handle,
        channel: ChannelId,
        prompt: String,
        request: PingRequest,
    ) {
        let (cancel_tx, mut cancel_rx) = oneshot::channel();
        let finished = Arc::new(AtomicBool::new(false));
        let finished_marker = Arc::clone(&finished);
        let session_id = self.session_id;
        let hostname = self.shared.hostname.clone();

        tokio::spawn(async move {
            let resolved_ip =
                resolve_ping_target(session_id, hostname.as_str(), request.target.as_str());
            let mut transmitted = 0u32;
            let mut samples = Vec::new();
            let mut interrupted = false;

            if handle
                .data(channel, render_ping_header(&request, resolved_ip.as_str()))
                .await
                .is_ok()
            {
                let mut sequence = 1u32;
                loop {
                    let latency =
                        synthetic_ping_latency(session_id, request.target.as_str(), sequence);
                    samples.push(latency);
                    transmitted += 1;

                    if handle
                        .data(
                            channel,
                            render_ping_reply(resolved_ip.as_str(), sequence, latency),
                        )
                        .await
                        .is_err()
                    {
                        break;
                    }

                    if request.count.is_some_and(|count| sequence >= count) {
                        break;
                    }

                    sequence += 1;
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                        _ = &mut cancel_rx => {
                            interrupted = true;
                            break;
                        }
                    }
                }

                if interrupted {
                    let _ = handle.data(channel, b"^C\r\n".to_vec()).await;
                }

                if transmitted > 0 {
                    let _ = handle
                        .data(
                            channel,
                            render_ping_summary(&request, transmitted, samples.as_slice()),
                        )
                        .await;
                    let _ = handle.data(channel, prompt.into_bytes()).await;
                }
            }

            finished_marker.store(true, Ordering::Relaxed);
        });

        self.active_stream = Some(ActiveInteractiveStream {
            cancel: Some(cancel_tx),
            finished,
        });
    }

    fn reject_for_capacity(&self) -> Auth {
        Auth::Reject {
            proceed_with_methods: None,
            partial_success: false,
        }
    }

    fn ensure_shell(&mut self, username: &str) -> &mut ShellState {
        self.shell.get_or_insert_with(|| {
            let mut shell = ShellState::new(
                username,
                self.shared.hostname.as_str(),
                self.peer_addr,
                self.shared.max_session_duration,
                self.session_id,
            );
            shell.ensure_identity_home();
            shell
        })
    }

    fn disconnect_if_expired(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<bool, russh::Error> {
        let Some(shell) = self.shell.as_ref() else {
            return Ok(false);
        };

        if !shell.is_expired() {
            return Ok(false);
        }

        session.data(channel, "Session timed out.\r\n".as_bytes())?;
        session.exit_status_request(channel, 0)?;
        session.eof(channel)?;
        session.close(channel)?;
        self.audit
            .record("session_timeout", "max session duration reached");
        Ok(true)
    }

    fn capture_inbound_public_key(&self, event: &'static str, user: &str, public_key: &PublicKey) {
        let openssh_key = public_key
            .to_openssh()
            .unwrap_or_else(|_| format!("{} <encoding_failed>", public_key.algorithm().as_str()));
        let fingerprint = public_key.fingerprint(HashAlg::Sha256).to_string();
        let persisted = match self.shared.dynamic_blacklist.record(openssh_key.as_str()) {
            Ok(persisted) => persisted,
            Err(error) => {
                warn!(
                    component = "sshjail",
                    event = "dynamic_blacklist_persist_failed",
                    path = %self.shared.storage_paths.dynamic_blacklist_keys_path.display(),
                    error = %error,
                    "failed to persist dynamic SSH blacklist update"
                );
                false
            }
        };
        self.audit.record(
            event,
            format!(
                "user={user} algorithm={} fingerprint={} persisted={} public_key={}",
                public_key.algorithm().as_str(),
                fingerprint,
                persisted,
                openssh_key
            ),
        );
    }
}

impl russh::server::Handler for SshJailHandler {
    type Error = SshJailSessionError;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        self.audit.record("auth_none", format!("user={user}"));
        if self.rejected_for_capacity {
            return Ok(self.reject_for_capacity());
        }

        Ok(Auth::Reject {
            proceed_with_methods: Some(self.shared.auth_methods.clone()),
            partial_success: false,
        })
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        self.audit
            .record("auth_password", format!("user={user} password={password}"));

        if self.rejected_for_capacity {
            return Ok(self.reject_for_capacity());
        }

        self.ensure_shell(user);
        Ok(Auth::Accept)
    }

    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        self.capture_inbound_public_key("auth_publickey_offered", user, public_key);

        if self.rejected_for_capacity {
            return Ok(self.reject_for_capacity());
        }

        self.ensure_shell(user);
        Ok(Auth::Accept)
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        self.capture_inbound_public_key("auth_publickey", user, public_key);

        if self.rejected_for_capacity {
            return Ok(self.reject_for_capacity());
        }

        self.ensure_shell(user);
        Ok(Auth::Accept)
    }

    async fn auth_succeeded(&mut self, session: &mut Session) -> Result<(), Self::Error> {
        self.audit.record("auth_succeeded", "session authenticated");

        let handle = session.handle();
        let session_id = self.session_id;
        let duration = self.shared.max_session_duration;
        tokio::spawn(async move {
            tokio::time::sleep(duration).await;
            let _ = handle
                .disconnect(
                    Disconnect::ByApplication,
                    format!("sshjail session {session_id} expired"),
                    String::new(),
                )
                .await;
        });

        Ok(())
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        self.audit
            .record("channel_open_session", format!("channel={}", channel.id()));
        if self.rejected_for_capacity {
            return Ok(false);
        }

        if let Some(shell) = &mut self.shell {
            shell.active_channel = Some(channel.id());
        }

        Ok(true)
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.audit.record(
            "pty_request",
            format!("channel={channel} term={term} cols={col_width} rows={row_height}"),
        );

        if self.rejected_for_capacity {
            session.channel_failure(channel)?;
            return Ok(());
        }

        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.audit
            .record("shell_request", format!("channel={channel}"));

        if self.rejected_for_capacity {
            session.channel_failure(channel)?;
            session.close(channel)?;
            return Ok(());
        }

        session.channel_success(channel)?;
        let Some(shell) = &mut self.shell else {
            session.close(channel)?;
            return Ok(());
        };

        session.data(channel, shell.banner().into_bytes())?;
        session.data(channel, shell.prompt().into_bytes())?;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data).trim().to_string();
        self.audit.record(
            "exec_request",
            format!("channel={channel} command={command}"),
        );

        if self.rejected_for_capacity {
            session.channel_failure(channel)?;
            session.close(channel)?;
            return Ok(());
        }

        session.channel_success(channel)?;

        if self.disconnect_if_expired(channel, session)? {
            return Ok(());
        }

        let exec_ping_request = self
            .shell
            .as_ref()
            .and_then(|shell| shell.prepare_interactive_ping(command.as_str()));

        if let Some(request) = exec_ping_request {
            self.audit
                .record("command", format!("channel={channel} command={command}"));
            self.start_exec_ping_stream(session.handle(), channel, request);
            return Ok(());
        }

        if let Some(shell) = &mut self.shell {
            let mut result = shell.execute_line(command.as_str());
            self.audit
                .record("command", format!("channel={channel} command={command}"));
            let audit_events = std::mem::take(&mut result.audit_events);
            for event in &audit_events {
                self.audit.record(event.event, event.details.as_str());
            }
            if !result.output.is_empty() {
                session.data(channel, result.output.into_bytes())?;
            }
            session.exit_status_request(channel, result.exit_status)?;
            session.eof(channel)?;
            session.close(channel)?;
        } else {
            session.close(channel)?;
        }

        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self
            .active_stream
            .as_ref()
            .is_some_and(ActiveInteractiveStream::is_finished)
        {
            self.active_stream = None;
        }

        if self.rejected_for_capacity {
            session.close(channel)?;
            return Ok(());
        }

        if self.disconnect_if_expired(channel, session)? {
            return Ok(());
        }

        if let Some(stream) = self.active_stream.as_mut() {
            if data.contains(&0x03) {
                stream.cancel();
            }
            return Ok(());
        }

        if self.shell.is_none() {
            session.close(channel)?;
            return Ok(());
        }

        let events = self
            .shell
            .as_mut()
            .expect("shell should exist while channel is open")
            .ingest_input(data);
        for event in events {
            match event {
                ShellEvent::Echo(bytes) => {
                    session.data(channel, bytes)?;
                }
                ShellEvent::CompletionMenu(menu) => {
                    let redraw = self
                        .shell
                        .as_ref()
                        .expect("shell should exist while channel is open")
                        .redraw_input_line();
                    session.data(channel, format!("\r\n{menu}\r\n{redraw}").into_bytes())?;
                }
                ShellEvent::Command(input) => {
                    if input.audit {
                        self.audit.record(
                            "command",
                            format!("channel={channel} command={}", input.line),
                        );
                    }

                    let interactive_ping = {
                        let shell = self
                            .shell
                            .as_mut()
                            .expect("shell should exist while channel is open");
                        if let Some(request) = shell.prepare_interactive_ping(input.line.as_str()) {
                            if input.history {
                                shell.record_history_entry(input.line.as_str());
                            }
                            Some((request, shell.prompt()))
                        } else {
                            None
                        }
                    };

                    if let Some((request, prompt)) = interactive_ping {
                        self.start_ping_stream(session.handle(), channel, prompt, request);
                        continue;
                    }

                    let (mut result, prompt) = {
                        let shell = self
                            .shell
                            .as_mut()
                            .expect("shell should exist while channel is open");
                        let result = shell.execute_line(input.line.as_str());
                        let prompt = if result.close_channel {
                            None
                        } else {
                            Some(shell.prompt())
                        };
                        (result, prompt)
                    };
                    let audit_events = std::mem::take(&mut result.audit_events);
                    if input.history && result.record_history {
                        self.shell
                            .as_mut()
                            .expect("shell should exist while channel is open")
                            .record_history_entry(input.line.as_str());
                    }
                    if !result.output.is_empty() {
                        session.data(channel, result.output.into_bytes())?;
                    }
                    for event in &audit_events {
                        self.audit.record(event.event, event.details.as_str());
                    }
                    if result.close_channel {
                        session.exit_status_request(channel, result.exit_status)?;
                        session.eof(channel)?;
                        session.close(channel)?;
                        return Ok(());
                    }
                    if let Some(prompt) = prompt {
                        session.data(channel, prompt.into_bytes())?;
                    }
                }
            }
        }

        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.audit
            .record("channel_close", format!("channel={channel}"));
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct SessionAudit {
    file: Option<Arc<Mutex<File>>>,
}

impl SessionAudit {
    fn new(audit_dir: &Path, session_id: u64, peer_addr: Option<SocketAddr>) -> Self {
        let filename = format!(
            "session-{}-{}-{}.log",
            unix_timestamp_secs(),
            session_id,
            sanitize_filename(
                peer_addr
                    .map(|addr| addr.ip().to_string())
                    .unwrap_or_else(|| "unknown".to_string())
                    .as_str()
            )
        );
        let path = audit_dir.join(filename);
        let file = match OpenOptions::new().create(true).append(true).open(&path) {
            Ok(file) => Some(Arc::new(Mutex::new(file))),
            Err(source) => {
                warn!(
                    component = "sshjail",
                    event = "audit_open_failed",
                    path = %path.display(),
                    error = %source,
                    "failed to open sshjail audit log file"
                );
                None
            }
        };

        Self { file }
    }

    fn record(&self, event: &str, details: impl AsRef<str>) {
        let Some(file) = &self.file else {
            return;
        };

        let details = details.as_ref().replace('\n', "\\n");
        let line = format!("[{}] {} {}\n", unix_timestamp_secs(), event, details);
        if let Ok(mut file) = file.lock() {
            let _ = file.write_all(line.as_bytes());
            let _ = file.flush();
        }
    }
}

fn sanitize_filename(value: &str) -> String {
    value
        .chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' => ch,
            _ => '_',
        })
        .collect()
}

struct ShellState {
    hostname: String,
    peer_addr: Option<SocketAddr>,
    active_channel: Option<ChannelId>,
    session_id: u64,
    host: VirtualHostFacts,
    filesystem: VirtualFilesystem,
    identities: Vec<ShellIdentity>,
    input_mode: InputMode,
    session_history: Vec<String>,
    line_buffer: String,
    pending_cr: bool,
    started_at: SystemTime,
    max_session_duration: Duration,
}

enum InputMode {
    Normal,
    HiddenInput(HiddenInputMode),
    PythonRepl,
}

enum HiddenInputMode {
    SshPassword(PendingSshAuth),
}

struct PendingSshAuth {
    invocation: SshInvocation,
    attempts: u8,
}

impl ShellState {
    fn new(
        username: &str,
        hostname: &str,
        peer_addr: Option<SocketAddr>,
        max_session_duration: Duration,
        session_id: u64,
    ) -> Self {
        let login_identity = ShellIdentity::for_user(username);
        let host = VirtualHostFacts::ubuntu_default();
        let mut filesystem = VirtualFilesystem::for_login_user(username);
        host.populate_filesystem(&mut filesystem);
        filesystem.add_file("/etc/hostname", format!("{hostname}\n"));
        Self {
            hostname: hostname.to_string(),
            peer_addr,
            active_channel: None,
            session_id,
            host,
            filesystem,
            identities: vec![login_identity],
            input_mode: InputMode::Normal,
            session_history: Vec::new(),
            line_buffer: String::new(),
            pending_cr: false,
            started_at: SystemTime::now(),
            max_session_duration,
        }
    }

    fn ensure_identity_home(&mut self) {
        let Some(identity) = self.identities.last() else {
            return;
        };
        self.filesystem.ensure_identity(identity);
    }

    fn current_identity(&self) -> &ShellIdentity {
        self.identities
            .last()
            .expect("shell identity stack should never be empty")
    }

    fn is_expired(&self) -> bool {
        self.started_at.elapsed().unwrap_or_default() >= self.max_session_duration
    }

    fn banner(&self) -> String {
        let peer = self
            .peer_addr
            .map(|addr| addr.ip().to_string())
            .unwrap_or_else(|| "127.0.0.1".to_string());
        format!(
            "Welcome to {} (GNU/Linux {} {})\r\nLast login: {} from {}\r\n",
            DEFAULT_OS_BANNER,
            DEFAULT_OS_RELEASE,
            self.host.architecture(),
            fake_last_login_timestamp(),
            peer
        )
    }

    fn prompt(&self) -> String {
        match &self.input_mode {
            InputMode::Normal => {
                let identity = self.current_identity();
                format!(
                    "{}@{}:{}{} ",
                    identity.username,
                    self.hostname,
                    identity.display_path(),
                    identity.prompt_symbol
                )
            }
            InputMode::HiddenInput(HiddenInputMode::SshPassword(state)) => {
                let display = state
                    .invocation
                    .display_target()
                    .replace('\r', "")
                    .replace('\n', "");
                format!("{display}'s password: ")
            }
            InputMode::PythonRepl => ">>> ".to_string(),
        }
    }

    fn redraw_input_line(&self) -> String {
        format!("{}{}", self.prompt(), self.line_buffer)
    }

    fn ingest_input(&mut self, data: &[u8]) -> Vec<ShellEvent> {
        let mut events = Vec::new();

        for byte in data {
            match *byte {
                0x03 => {
                    self.pending_cr = false;
                    self.line_buffer.clear();
                    if matches!(
                        self.input_mode,
                        InputMode::HiddenInput(_) | InputMode::PythonRepl
                    ) {
                        self.input_mode = InputMode::Normal;
                    }
                    events.push(ShellEvent::Echo(b"^C\r\n".to_vec()));
                    events.push(ShellEvent::Echo(self.prompt().into_bytes()));
                }
                b'\n' if self.pending_cr => {
                    self.pending_cr = false;
                }
                b'\r' | b'\n' => {
                    self.pending_cr = *byte == b'\r';
                    events.push(ShellEvent::Echo(b"\r\n".to_vec()));
                    let line = self.line_buffer.trim().to_string();
                    self.line_buffer.clear();
                    events.push(ShellEvent::Command(ShellInputLine {
                        line,
                        audit: self.should_audit_current_input(),
                        history: self.should_record_current_input_in_history(),
                    }));
                }
                8 | 127 => {
                    self.pending_cr = false;
                    if !self.line_buffer.is_empty() {
                        self.line_buffer.pop();
                        if !matches!(self.input_mode, InputMode::HiddenInput(_)) {
                            events.push(ShellEvent::Echo(b"\x08 \x08".to_vec()));
                        }
                    }
                }
                b'\t' => {
                    self.pending_cr = false;
                    match self.handle_tab_completion() {
                        TabCompletion::Bell => events.push(ShellEvent::Echo(b"\x07".to_vec())),
                        TabCompletion::Echo(bytes) => events.push(ShellEvent::Echo(bytes)),
                        TabCompletion::Suggestions(menu) => {
                            events.push(ShellEvent::CompletionMenu(menu))
                        }
                    }
                }
                0x20..=0x7e => {
                    self.pending_cr = false;
                    let ch = char::from(*byte);
                    self.line_buffer.push(ch);
                    if !matches!(self.input_mode, InputMode::HiddenInput(_)) {
                        events.push(ShellEvent::Echo(vec![*byte]));
                    }
                }
                _ => {}
            }
        }

        events
    }

    fn should_audit_current_input(&self) -> bool {
        !matches!(
            self.input_mode,
            InputMode::HiddenInput(_) | InputMode::PythonRepl
        )
    }

    fn should_record_current_input_in_history(&self) -> bool {
        !matches!(
            self.input_mode,
            InputMode::HiddenInput(_) | InputMode::PythonRepl
        )
    }

    fn handle_tab_completion(&mut self) -> TabCompletion {
        if !matches!(self.input_mode, InputMode::Normal) {
            return TabCompletion::Bell;
        }

        if self.line_buffer.trim().is_empty() {
            let mut candidates = self.host.command_names();
            candidates.extend(SHELL_BUILTINS.iter().map(|entry| (*entry).to_string()));
            candidates.sort();
            candidates.dedup();
            return self.apply_completion_candidates(0, "", &candidates, false);
        }

        let token_start = self
            .line_buffer
            .rfind(char::is_whitespace)
            .map_or(0, |index| index + 1);
        let fragment = self.line_buffer[token_start..].to_string();
        let completing_command = token_start == 0;

        if completing_command {
            let mut candidates = self
                .host
                .command_names()
                .into_iter()
                .chain(SHELL_BUILTINS.iter().map(|entry| (*entry).to_string()))
                .filter(|entry| entry.starts_with(fragment.as_str()))
                .collect::<Vec<_>>();
            candidates.sort();
            candidates.dedup();
            return self.apply_completion_candidates(
                token_start,
                fragment.as_str(),
                &candidates,
                false,
            );
        }

        let (raw_dir_prefix, basename) = split_completion_fragment(fragment.as_str());
        let search_dir = if raw_dir_prefix.is_empty() {
            self.current_identity().cwd.clone()
        } else {
            resolve_user_path(
                self.current_identity().cwd.as_str(),
                self.current_identity().home.as_str(),
                raw_dir_prefix.as_str(),
            )
        };
        let show_hidden = basename.starts_with('.');
        let Some(entries) = self.filesystem.list(search_dir.as_str(), show_hidden) else {
            return TabCompletion::Bell;
        };

        let mut candidates = entries
            .into_iter()
            .filter(|entry| entry.starts_with(basename.as_str()))
            .map(|entry| {
                let full_path = if search_dir == "/" {
                    format!("/{entry}")
                } else {
                    format!("{search_dir}/{entry}")
                };
                let suffix = if self.filesystem.is_dir(full_path.as_str()) {
                    "/"
                } else {
                    ""
                };
                format!("{raw_dir_prefix}{entry}{suffix}")
            })
            .collect::<Vec<_>>();
        candidates.sort();
        self.apply_completion_candidates(token_start, fragment.as_str(), &candidates, true)
    }

    fn apply_completion_candidates(
        &mut self,
        token_start: usize,
        fragment: &str,
        candidates: &[String],
        path_mode: bool,
    ) -> TabCompletion {
        if candidates.is_empty() {
            return TabCompletion::Bell;
        }

        if candidates.len() == 1 {
            let mut completed = candidates[0].clone();
            if !path_mode || !completed.ends_with('/') {
                completed.push(' ');
            }
            self.line_buffer
                .replace_range(token_start.., completed.as_str());
            let suffix = self.line_buffer[token_start + fragment.len()..].to_string();
            return TabCompletion::Echo(suffix.into_bytes());
        }

        let common = longest_common_prefix(candidates);
        if common.len() > fragment.len() {
            self.line_buffer
                .replace_range(token_start.., common.as_str());
            let suffix = self.line_buffer[token_start + fragment.len()..].to_string();
            return TabCompletion::Echo(suffix.into_bytes());
        }

        TabCompletion::Suggestions(candidates.join("  "))
    }

    fn execute_line(&mut self, line: &str) -> CommandResult {
        match self.input_mode {
            InputMode::Normal => {}
            InputMode::HiddenInput(_) => return self.handle_hidden_input_line(line),
            InputMode::PythonRepl => return self.handle_python_repl_line(line),
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            return CommandResult::default();
        }

        self.execute_script(trimmed)
    }

    fn prepare_interactive_ping(&self, line: &str) -> Option<PingRequest> {
        if !matches!(self.input_mode, InputMode::Normal) {
            return None;
        }

        let tokens = split_shell_words(line.trim());
        if path_basename(tokens.first()?.as_str()) != "ping" {
            return None;
        }

        let request = parse_ping_request(&tokens[1..])?;
        Some(request)
    }

    fn record_history_entry(&mut self, line: &str) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return;
        }
        self.session_history.push(trimmed.to_string());
    }

    fn handle_hidden_input_line(&mut self, _line: &str) -> CommandResult {
        let InputMode::HiddenInput(hidden_mode) = &mut self.input_mode else {
            return CommandResult::default();
        };

        match hidden_mode {
            HiddenInputMode::SshPassword(state) => {
                state.attempts = state.attempts.saturating_add(1);
                if state.attempts < 3 {
                    CommandResult {
                        output: "Permission denied, please try again.\r\n".to_string(),
                        close_channel: false,
                        exit_status: 1,
                        audit_events: Vec::new(),
                        record_history: false,
                    }
                } else {
                    self.input_mode = InputMode::Normal;
                    CommandResult {
                        output: "Permission denied (publickey,password).\r\n".to_string(),
                        close_channel: false,
                        exit_status: 255,
                        audit_events: Vec::new(),
                        record_history: false,
                    }
                }
            }
        }
    }

    fn handle_python_repl_line(&mut self, line: &str) -> CommandResult {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return CommandResult {
                output: String::new(),
                close_channel: false,
                exit_status: 0,
                audit_events: Vec::new(),
                record_history: false,
            };
        }

        if matches!(trimmed, "exit()" | "quit()") {
            self.input_mode = InputMode::Normal;
            return CommandResult {
                output: String::new(),
                close_channel: false,
                exit_status: 0,
                audit_events: Vec::new(),
                record_history: false,
            };
        }

        if let Some(argument) = parse_python_print_argument(trimmed) {
            return CommandResult {
                output: format!("{argument}\r\n"),
                close_channel: false,
                exit_status: 0,
                audit_events: Vec::new(),
                record_history: false,
            };
        }

        if trimmed == "help()" {
            return CommandResult {
                output: "Type help(object) for help about object.\r\n".to_string(),
                close_channel: false,
                exit_status: 0,
                audit_events: Vec::new(),
                record_history: false,
            };
        }

        CommandResult {
            output: format!(
                "Traceback (most recent call last):\r\n  File \"<stdin>\", line 1, in <module>\r\nNameError: name '{}' is not defined\r\n",
                trimmed.split_whitespace().next().unwrap_or(trimmed)
            ),
            close_channel: false,
            exit_status: 1,
            audit_events: Vec::new(),
            record_history: false,
        }
    }

    fn execute_tokens(&mut self, tokens: &[String]) -> CommandResult {
        if let Some(script) = parse_shell_c_invocation(tokens) {
            return self.execute_script(script);
        }

        let raw_command = tokens[0].as_str();
        let command = path_basename(raw_command);
        let args = &tokens[1..];

        match command {
            "exit" => self.handle_exit(),
            "pwd" => CommandResult::output(format!("{}\r\n", self.current_identity().cwd)),
            "uname" => CommandResult::output(self.handle_uname(args)),
            "ls" => self.handle_ls(args),
            "tree" => self.handle_tree(args),
            "cd" => self.handle_cd(args),
            "sudo" => self.handle_sudo(args),
            "su" => self.handle_su(args),
            "whoami" => CommandResult::output(format!("{}\r\n", self.current_identity().username)),
            "id" => {
                let identity = self.current_identity();
                CommandResult::output(format!(
                    "uid={}({}) gid={}({}) groups={}({})\r\n",
                    identity.uid,
                    identity.username,
                    identity.gid,
                    identity.group_name,
                    identity.gid,
                    identity.group_name
                ))
            }
            "hostname" => CommandResult::output(format!("{}\r\n", self.hostname)),
            "echo" => CommandResult::output(format!("{}\r\n", args.join(" "))),
            "nproc" => self.handle_nproc(),
            "free" => self.handle_free(args),
            "df" => self.handle_df(args),
            "uptime" => self.handle_uptime(),
            "env" => self.handle_env(),
            "ps" => self.handle_ps(args),
            "ping" => self.handle_ping(args),
            "cat" => self.handle_cat(args),
            "ifconfig" => self.handle_ifconfig(args),
            "ip" => self.handle_ip(args),
            "ss" => self.handle_ss(args),
            "netstat" => self.handle_netstat(args),
            "which" => self.handle_which(args),
            "command" => self.handle_command_builtin(args),
            "test" => self.handle_test(args),
            "history" => self.handle_history(),
            "last" => self.handle_last(),
            "w" => self.handle_w(),
            "who" => self.handle_who(),
            "crontab" => self.handle_crontab(args),
            "mkdir" => self.handle_mkdir(args),
            "rm" => self.handle_rm(args),
            "chmod" => self.handle_chmod(args),
            "chattr" | "lockr" => CommandResult::default(),
            "ssh" => self.handle_ssh(args),
            "sshd" => self.handle_sshd(args),
            "java" | "javac" | "python3" | "python" | "php" | "nginx" | "apache2" | "mysql" => {
                self.handle_runtime_command(command, args)
            }
            "clear" => CommandResult::output("\x1b[2J\x1b[H".to_string()),
            _ => CommandResult::command_not_found(raw_command),
        }
    }

    fn execute_script(&mut self, script: &str) -> CommandResult {
        if let Some(result) = self.try_execute_probe_script(script) {
            return result;
        }

        let commands = split_shell_commands(script);
        if commands.is_empty() {
            let tokens = split_shell_words(script);
            return if tokens.is_empty() {
                CommandResult::default()
            } else {
                self.execute_tokens(&tokens)
            };
        }

        let mut last_result = CommandResult::default();
        for (index, (command, connector)) in commands.iter().enumerate() {
            if index > 0
                && matches!(connector, ScriptConnector::OnSuccess)
                && last_result.exit_status != 0
            {
                continue;
            }

            last_result = self.execute_single_script_command(command.as_str());
        }

        last_result
    }

    fn execute_single_script_command(&mut self, command: &str) -> CommandResult {
        if let Some(result) = self.try_execute_echo_redirection(command) {
            return result;
        }

        let tokens = split_shell_words(command);
        if tokens.is_empty() {
            return CommandResult::default();
        }

        self.execute_tokens(&tokens)
    }

    fn try_execute_probe_script(&self, script: &str) -> Option<CommandResult> {
        let normalized = script.trim();

        if normalized == FREE_MEMORY_TOTAL_PROBE {
            return Some(CommandResult::output(format!(
                "{}\r\n",
                self.host.total_memory_kb()
            )));
        }

        if normalized == OS_RELEASE_NAME_PROBE {
            return Some(CommandResult::output(format!(
                "NAME=\"{}\"\r\n",
                DEFAULT_OS_NAME
            )));
        }

        if let Some(tool) = parse_which_fallback_script(normalized) {
            return Some(self.command_lookup_result(tool));
        }

        if let Some(paths) = parse_test_file_probe_script(normalized) {
            let found = paths
                .iter()
                .any(|path| self.filesystem.is_file(path.as_str()));
            return Some(if found {
                CommandResult::output("found\r\n".to_string())
            } else {
                CommandResult::status(1)
            });
        }

        if let Some(tool) = parse_version_probe_script(normalized) {
            return Some(self.version_probe_result(tool));
        }

        if let Some(tool) = parse_stderr_version_head_probe_script(normalized) {
            return self.host.probe_output(tool).map(|output| {
                let first_line = output.lines().next().unwrap_or_default();
                CommandResult::output(format!("{first_line}\r\n"))
            });
        }

        None
    }

    fn command_lookup_result(&self, tool: &str) -> CommandResult {
        match self.host.command_path(tool) {
            Some(path) => CommandResult::output(format!("{path}\r\n")),
            None => CommandResult::status(1),
        }
    }

    fn version_probe_result(&self, tool: &str) -> CommandResult {
        match self.host.probe_output(tool) {
            Some(output) => CommandResult::output(format!("{output}\r\n")),
            None => CommandResult::status(127),
        }
    }

    fn resolve_virtual_path(&self, raw: &str) -> String {
        let raw = raw.trim();
        let expanded = if raw == "~" {
            self.current_identity().home.clone()
        } else if let Some(rest) = raw.strip_prefix("~/") {
            format!("{}/{}", self.current_identity().home, rest)
        } else {
            raw.to_string()
        };
        self.filesystem
            .resolve_path(self.current_identity().cwd.as_str(), expanded.as_str())
    }

    fn try_execute_echo_redirection(&mut self, command: &str) -> Option<CommandResult> {
        let (left, append, path) = split_shell_redirection(command)?;
        let tokens = split_shell_words(left.trim());
        if tokens.first().map(String::as_str) != Some("echo") {
            return None;
        }

        let resolved_path = self.resolve_virtual_path(path.trim());
        let contents = format!("{}\n", tokens[1..].join(" "));
        let result = if append {
            self.filesystem
                .append_file(resolved_path.as_str(), contents.as_str())
        } else {
            self.filesystem
                .write_file(resolved_path.as_str(), contents.as_str())
        };

        Some(match result {
            Ok(()) => CommandResult::default(),
            Err(VirtualFilesystemWriteError::MissingParent) => CommandResult {
                output: format!("bash: {}: No such file or directory\r\n", path.trim()),
                close_channel: false,
                exit_status: 1,
                audit_events: Vec::new(),
                record_history: true,
            },
            Err(VirtualFilesystemWriteError::PathIsDirectory) => CommandResult {
                output: format!("bash: {}: Is a directory\r\n", path.trim()),
                close_channel: false,
                exit_status: 1,
                audit_events: Vec::new(),
                record_history: true,
            },
        })
    }

    fn handle_uname(&self, args: &[String]) -> String {
        if args.iter().any(|arg| arg == "-a") {
            format!(
                "Linux {} {} #86-Ubuntu SMP x86_64 GNU/Linux\r\n",
                self.hostname, DEFAULT_OS_RELEASE
            )
        } else if args.iter().any(|arg| arg == "-m") {
            format!("{}\r\n", self.host.architecture())
        } else if args.iter().any(|arg| arg == "-r") {
            format!("{DEFAULT_OS_RELEASE}\r\n")
        } else {
            "Linux\r\n".to_string()
        }
    }

    fn handle_ls(&self, args: &[String]) -> CommandResult {
        let show_hidden = args
            .iter()
            .any(|arg| arg.starts_with('-') && arg.contains('a'));
        let long_format = args
            .iter()
            .any(|arg| arg.starts_with('-') && arg.contains('l'));
        let path_arg = args
            .iter()
            .find(|arg| !arg.starts_with('-'))
            .map(String::as_str);
        let target = match path_arg {
            Some(path) => self.resolve_virtual_path(path),
            None => self.current_identity().cwd.clone(),
        };

        match self
            .filesystem
            .render_ls(target.as_str(), show_hidden, long_format)
        {
            Some(output) => CommandResult::output(output),
            None => CommandResult::output(format!(
                "ls: cannot access '{}': No such file or directory\r\n",
                path_arg.unwrap_or(target.as_str())
            )),
        }
    }

    fn handle_tree(&self, args: &[String]) -> CommandResult {
        let path_arg = args
            .iter()
            .find(|arg| !arg.starts_with('-'))
            .map(String::as_str)
            .unwrap_or(".");
        let target = self.resolve_virtual_path(path_arg);
        match self.filesystem.render_tree(target.as_str()) {
            Some(output) => CommandResult::output(output),
            None => CommandResult::output(format!(
                "{}  [error opening dir]\r\n\r\n0 directories, 0 files\r\n",
                path_arg
            )),
        }
    }

    fn handle_cd(&mut self, args: &[String]) -> CommandResult {
        let target = args.first().map(String::as_str).unwrap_or("~");
        let resolved = self.resolve_virtual_path(target);
        if !self.filesystem.is_dir(resolved.as_str()) {
            return CommandResult::output(format!(
                "bash: cd: {}: No such file or directory\r\n",
                target
            ));
        }

        let current = self
            .identities
            .last_mut()
            .expect("shell identity should exist");
        current.cwd = resolved;
        CommandResult::default()
    }

    fn handle_sudo(&mut self, args: &[String]) -> CommandResult {
        let mut index = 0;
        let mut target_user = "root";

        while index < args.len() {
            match args[index].as_str() {
                "-u" if index + 1 < args.len() => {
                    target_user = args[index + 1].as_str();
                    index += 2;
                }
                "-i" | "-s" => {
                    index += 1;
                }
                _ => break,
            }
        }

        let remainder = &args[index..];
        if remainder.is_empty() {
            self.push_identity(target_user);
            return CommandResult::default();
        }

        if remainder.len() == 1
            && matches!(
                remainder[0].as_str(),
                "su" | "bash" | "sh" | "/bin/bash" | "/bin/sh"
            )
        {
            self.push_identity(target_user);
            return CommandResult::default();
        }

        let saved = self.identities.clone();
        self.push_identity(target_user);
        let output = self.execute_tokens(remainder);
        self.identities = saved;
        output
    }

    fn handle_su(&mut self, args: &[String]) -> CommandResult {
        let target_user = args
            .iter()
            .find(|arg| !arg.starts_with('-'))
            .map(String::as_str)
            .unwrap_or("root");
        self.push_identity(target_user);
        CommandResult::default()
    }

    fn handle_nproc(&self) -> CommandResult {
        CommandResult::output(format!("{}\r\n", self.host.cpu_count()))
    }

    fn handle_free(&self, _args: &[String]) -> CommandResult {
        CommandResult::output(self.host.free_kb_output())
    }

    fn handle_df(&self, _args: &[String]) -> CommandResult {
        CommandResult::output(self.host.df_output())
    }

    fn handle_uptime(&self) -> CommandResult {
        CommandResult::output(self.host.uptime_output())
    }

    fn handle_env(&self) -> CommandResult {
        CommandResult::output(self.host.env_output(self.current_identity()))
    }

    fn handle_ps(&self, args: &[String]) -> CommandResult {
        CommandResult::output(
            self.host
                .ps_output(self.current_identity(), self.session_id, args),
        )
    }

    fn handle_ping(&self, args: &[String]) -> CommandResult {
        let Some(request) = parse_ping_request(args) else {
            return CommandResult::output(
                "usage: ping [-c count] [-W timeout] destination\r\n".to_string(),
            );
        };

        CommandResult::output(render_synthetic_ping(
            self.session_id,
            self.hostname.as_str(),
            &request,
        ))
    }

    fn handle_cat(&self, args: &[String]) -> CommandResult {
        let path = args
            .iter()
            .find(|arg| !arg.starts_with("2>") && !arg.starts_with('>') && !arg.starts_with('<'))
            .map(String::as_str);
        let Some(path) = path else {
            return CommandResult::status(1);
        };

        let resolved = self.resolve_virtual_path(path);

        if let Some(contents) = self.filesystem.read_file(resolved.as_str()) {
            return CommandResult::output(to_crlf(contents));
        }

        if self.filesystem.is_dir(resolved.as_str()) {
            return CommandResult {
                output: format!("cat: {}: Is a directory\r\n", path),
                close_channel: false,
                exit_status: 1,
                audit_events: Vec::new(),
                record_history: true,
            };
        }

        if self.filesystem.is_file(resolved.as_str()) {
            return CommandResult::default();
        }

        CommandResult {
            output: format!("cat: {}: No such file or directory\r\n", path),
            close_channel: false,
            exit_status: 1,
            audit_events: Vec::new(),
            record_history: true,
        }
    }

    fn handle_which(&self, args: &[String]) -> CommandResult {
        let Some(tool) = args
            .iter()
            .find(|arg| !arg.starts_with("2>") && !arg.starts_with('-'))
            .map(String::as_str)
        else {
            return CommandResult::status(1);
        };

        self.command_lookup_result(tool)
    }

    fn handle_command_builtin(&self, args: &[String]) -> CommandResult {
        if args.first().map(String::as_str) != Some("-v") {
            return CommandResult::status(1);
        }

        let Some(tool) = args.get(1).map(String::as_str) else {
            return CommandResult::status(1);
        };

        self.command_lookup_result(tool)
    }

    fn handle_test(&self, args: &[String]) -> CommandResult {
        if args.len() < 2 || args[0] != "-f" {
            return CommandResult::status(1);
        }

        let resolved = self.resolve_virtual_path(args[1].as_str());
        if self.filesystem.is_file(resolved.as_str()) {
            CommandResult::default()
        } else {
            CommandResult::status(1)
        }
    }

    fn handle_ifconfig(&self, args: &[String]) -> CommandResult {
        let requested_interface = args
            .iter()
            .find(|arg| !arg.starts_with('-'))
            .map(String::as_str);

        match self.host.ifconfig_output(requested_interface) {
            Some(output) => CommandResult::output(output),
            None => CommandResult {
                output: format!(
                    "ifconfig: {}: error fetching interface information: Device not found\r\n",
                    requested_interface.unwrap_or("unknown")
                ),
                close_channel: false,
                exit_status: 1,
                audit_events: Vec::new(),
                record_history: true,
            },
        }
    }

    fn handle_ip(&self, args: &[String]) -> CommandResult {
        if args.is_empty() {
            return CommandResult {
                output: "Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }\r\n".to_string(),
                close_channel: false,
                exit_status: 1,
                audit_events: Vec::new(),
                record_history: true,
            };
        }

        let mut index = 0;
        if matches!(args.first().map(String::as_str), Some("-4" | "-6")) {
            index += 1;
        }

        let object = args.get(index).map(String::as_str);
        let action = args.get(index + 1).map(String::as_str);

        match (object, action) {
            (Some("a" | "addr"), None) => match self.host.ip_addr_output(None) {
                Some(output) => CommandResult::output(output),
                None => CommandResult::status(1),
            },
            (Some("addr"), Some("show")) => {
                let requested_interface = args.get(index + 2).map(String::as_str);
                match self.host.ip_addr_output(requested_interface) {
                    Some(output) => CommandResult::output(output),
                    None => CommandResult {
                        output: format!(
                            "Device \"{}\" does not exist.\r\n",
                            requested_interface.unwrap_or("unknown")
                        ),
                        close_channel: false,
                        exit_status: 1,
                        audit_events: Vec::new(),
                        record_history: true,
                    },
                }
            }
            _ => CommandResult {
                output: "Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }\r\n".to_string(),
                close_channel: false,
                exit_status: 1,
                audit_events: Vec::new(),
                record_history: true,
            },
        }
    }

    fn handle_ss(&self, _args: &[String]) -> CommandResult {
        CommandResult::output(self.host.ss_output())
    }

    fn handle_netstat(&self, _args: &[String]) -> CommandResult {
        CommandResult::output(self.host.netstat_output())
    }

    fn handle_history(&self) -> CommandResult {
        let path = format!("{}/.bash_history", self.current_identity().home);
        let output = self
            .filesystem
            .history_output(path.as_str(), &self.session_history);
        CommandResult::output(output)
    }

    fn handle_last(&self) -> CommandResult {
        CommandResult::output(self.host.last_output(
            self.current_identity(),
            self.peer_addr,
            self.hostname.as_str(),
        ))
    }

    fn handle_w(&self) -> CommandResult {
        CommandResult::output(self.host.w_output(
            self.current_identity(),
            self.peer_addr,
            self.hostname.as_str(),
        ))
    }

    fn handle_who(&self) -> CommandResult {
        CommandResult::output(self.host.who_output(
            self.current_identity(),
            self.peer_addr,
            self.hostname.as_str(),
        ))
    }

    fn handle_crontab(&self, args: &[String]) -> CommandResult {
        let target_user =
            parse_crontab_target_user(args).unwrap_or(self.current_identity().username.as_str());
        match self.host.crontab_output(target_user) {
            Some(output) => CommandResult::output(output),
            None => CommandResult {
                output: format!("no crontab for {target_user}\r\n"),
                close_channel: false,
                exit_status: 1,
                audit_events: Vec::new(),
                record_history: true,
            },
        }
    }

    fn handle_mkdir(&mut self, args: &[String]) -> CommandResult {
        let create_parents = args.iter().any(|arg| arg == "-p");
        let paths = args
            .iter()
            .filter(|arg| !arg.starts_with('-'))
            .map(String::as_str)
            .collect::<Vec<_>>();
        if paths.is_empty() {
            return CommandResult {
                output: "mkdir: missing operand\r\n".to_string(),
                close_channel: false,
                exit_status: 1,
                audit_events: Vec::new(),
                record_history: true,
            };
        }

        for path in paths {
            let resolved = self.resolve_virtual_path(path);
            if self.filesystem.is_dir(resolved.as_str()) {
                if create_parents {
                    continue;
                }
                return CommandResult {
                    output: format!("mkdir: cannot create directory '{}': File exists\r\n", path),
                    close_channel: false,
                    exit_status: 1,
                    audit_events: Vec::new(),
                    record_history: true,
                };
            }
            if self.filesystem.is_file(resolved.as_str()) {
                return CommandResult {
                    output: format!("mkdir: cannot create directory '{}': File exists\r\n", path),
                    close_channel: false,
                    exit_status: 1,
                    audit_events: Vec::new(),
                    record_history: true,
                };
            }

            self.filesystem.ensure_dir(resolved.as_str());
        }

        CommandResult::default()
    }

    fn handle_rm(&mut self, args: &[String]) -> CommandResult {
        let force = args.iter().any(|arg| arg.contains('f'));
        let paths = args
            .iter()
            .filter(|arg| !arg.starts_with('-'))
            .map(String::as_str)
            .collect::<Vec<_>>();
        if paths.is_empty() {
            return CommandResult {
                output: "rm: missing operand\r\n".to_string(),
                close_channel: false,
                exit_status: 1,
                audit_events: Vec::new(),
                record_history: true,
            };
        }

        for path in paths {
            let resolved = self.resolve_virtual_path(path);
            if resolved == "/" {
                return CommandResult {
                    output: "rm: refusing to remove '/'\r\n".to_string(),
                    close_channel: false,
                    exit_status: 1,
                    audit_events: Vec::new(),
                    record_history: true,
                };
            }

            if !self.filesystem.remove_path(resolved.as_str()) && !force {
                return CommandResult {
                    output: format!(
                        "rm: cannot remove '{}': No such file or directory\r\n",
                        path
                    ),
                    close_channel: false,
                    exit_status: 1,
                    audit_events: Vec::new(),
                    record_history: true,
                };
            }
        }

        CommandResult::default()
    }

    fn handle_chmod(&mut self, args: &[String]) -> CommandResult {
        let target = args
            .iter()
            .rev()
            .find(|arg| !arg.starts_with('-') && !arg.contains('='))
            .map(String::as_str);
        let Some(target) = target else {
            return CommandResult::status(1);
        };
        let resolved = self.resolve_virtual_path(target);
        if self.filesystem.is_dir(resolved.as_str()) || self.filesystem.is_file(resolved.as_str()) {
            CommandResult::default()
        } else {
            CommandResult {
                output: format!(
                    "chmod: cannot access '{}': No such file or directory\r\n",
                    target
                ),
                close_channel: false,
                exit_status: 1,
                audit_events: Vec::new(),
                record_history: true,
            }
        }
    }

    fn handle_ssh(&mut self, args: &[String]) -> CommandResult {
        if args.iter().any(|arg| arg == "-V") {
            return self
                .host
                .runtime_output("ssh", args)
                .map(|runtime| match runtime {
                    RuntimeCommandResult::Output(output) => CommandResult::output(output),
                    RuntimeCommandResult::EnterPythonRepl { .. } => CommandResult::status(1),
                })
                .unwrap_or_else(|| CommandResult::status(1));
        }

        let Some(invocation) = parse_ssh_invocation(args) else {
            return CommandResult::output("usage: ssh [-46AaCfGgKkMNnqsTtVvXxYy] [-B bind_interface] [-b bind_address] [-c cipher_spec] destination [command]\r\n".to_string());
        };

        self.input_mode = InputMode::HiddenInput(HiddenInputMode::SshPassword(PendingSshAuth {
            invocation: invocation.clone(),
            attempts: 0,
        }));

        CommandResult::default().with_audit_event(
            "ssh_outbound",
            invocation.audit_details(self.current_identity().username.as_str()),
        )
    }

    fn handle_sshd(&self, args: &[String]) -> CommandResult {
        self.host
            .runtime_output("sshd", args)
            .map(|runtime| match runtime {
                RuntimeCommandResult::Output(output) => CommandResult::output(output),
                RuntimeCommandResult::EnterPythonRepl { .. } => CommandResult::status(1),
            })
            .unwrap_or_else(|| CommandResult::status(1))
    }

    fn handle_runtime_command(&mut self, command: &str, args: &[String]) -> CommandResult {
        self.host.runtime_output(command, args).map_or_else(
            || CommandResult::status(1),
            |runtime| match runtime {
                RuntimeCommandResult::Output(output) => CommandResult::output(output),
                RuntimeCommandResult::EnterPythonRepl { banner } => {
                    self.input_mode = InputMode::PythonRepl;
                    CommandResult::output(banner)
                }
            },
        )
    }

    fn handle_exit(&mut self) -> CommandResult {
        if self.identities.len() > 1 {
            self.identities.pop();
            return CommandResult::default();
        }

        CommandResult {
            output: "logout\r\n".to_string(),
            close_channel: true,
            exit_status: 0,
            audit_events: Vec::new(),
            record_history: true,
        }
    }

    fn push_identity(&mut self, username: &str) {
        let identity = ShellIdentity::for_user(username);
        self.filesystem.ensure_identity(&identity);
        self.identities.push(identity);
    }
}

#[derive(Clone, Debug)]
struct VirtualHostFacts {
    binaries: BTreeMap<String, VirtualBinary>,
    interfaces: Vec<VirtualNetworkInterface>,
    service_processes: Vec<VirtualProcess>,
    listening_sockets: Vec<VirtualListeningSocket>,
    mounts: Vec<VirtualMount>,
}

enum RuntimeCommandResult {
    Output(String),
    EnterPythonRepl { banner: String },
}

impl VirtualHostFacts {
    fn ubuntu_default() -> Self {
        let binaries = [
            VirtualBinary::new("apt", "/usr/bin/apt", "apt 2.4.11 (amd64)"),
            VirtualBinary::new("apt-get", "/usr/bin/apt-get", "apt 2.4.11 (amd64)"),
            VirtualBinary::new(
                "dpkg",
                "/usr/bin/dpkg",
                "Debian 'dpkg' package management program version 1.21.1 (amd64).",
            ),
            VirtualBinary::new("snap", "/usr/bin/snap", "snap    2.61.3+22.04"),
            VirtualBinary::new(
                "pip",
                "/usr/bin/pip",
                "pip 23.0.1 from /usr/lib/python3/dist-packages/pip (python 3.10)",
            ),
            VirtualBinary::new(
                "pip3",
                "/usr/bin/pip3",
                "pip 23.0.1 from /usr/lib/python3/dist-packages/pip (python 3.10)",
            ),
            VirtualBinary::new("ifconfig", "/usr/sbin/ifconfig", "net-tools 2.10"),
            VirtualBinary::new("ip", "/usr/sbin/ip", "ip utility, iproute2-5.15.0"),
            VirtualBinary::new(
                "ssh",
                "/usr/bin/ssh",
                "OpenSSH_9.6p1 Ubuntu-3ubuntu13.5, OpenSSL 3.0.13 30 Jan 2024",
            ),
            VirtualBinary::new(
                "sshd",
                "/usr/sbin/sshd",
                "OpenSSH_9.6p1 Ubuntu-3ubuntu13.5, OpenSSL 3.0.13 30 Jan 2024",
            ),
            VirtualBinary::new("ps", "/usr/bin/ps", "procps-ng 4.0.2"),
            VirtualBinary::new("ss", "/usr/bin/ss", "ss utility, iproute2-5.15.0"),
            VirtualBinary::new("netstat", "/usr/bin/netstat", "net-tools 2.10"),
            VirtualBinary::new("df", "/usr/bin/df", "df (GNU coreutils) 9.1"),
            VirtualBinary::new("uptime", "/usr/bin/uptime", "procps-ng 4.0.2"),
            VirtualBinary::new("tree", "/usr/bin/tree", "tree v2.1.0"),
            VirtualBinary::new(
                "java",
                "/usr/bin/java",
                concat!(
                    "openjdk version \"17.0.13\" 2024-10-15\n",
                    "OpenJDK Runtime Environment (build 17.0.13+11-Ubuntu-2ubuntu122.04)\n",
                    "OpenJDK 64-Bit Server VM (build 17.0.13+11-Ubuntu-2ubuntu122.04, mixed mode, sharing)"
                ),
            ),
            VirtualBinary::new("javac", "/usr/bin/javac", "javac 17.0.13"),
            VirtualBinary::new("python3", "/usr/bin/python3", "Python 3.10.12"),
            VirtualBinary::new("python", "/usr/bin/python", "Python 3.10.12"),
            VirtualBinary::new(
                "php",
                "/usr/bin/php",
                concat!(
                    "PHP 8.1.2-1ubuntu2.22 (cli) (built: Feb 14 2026 08:00:00) (NTS)\n",
                    "Copyright (c) The PHP Group\n",
                    "Zend Engine v4.1.2, Copyright (c) Zend Technologies"
                ),
            ),
            VirtualBinary::new("nginx", "/usr/sbin/nginx", "nginx version: nginx/1.18.0 (Ubuntu)"),
            VirtualBinary::new(
                "apache2",
                "/usr/sbin/apache2",
                "Server version: Apache/2.4.52 (Ubuntu)\nServer built: 2026-02-14T08:31:00",
            ),
            VirtualBinary::new(
                "mysql",
                "/usr/bin/mysql",
                "mysql  Ver 8.0.41-0ubuntu0.22.04.1 for Linux on x86_64 ((Ubuntu))",
            ),
        ]
        .into_iter()
        .map(|binary| (binary.name.clone(), binary))
        .collect();

        let interfaces = vec![
            VirtualNetworkInterface::new(
                "lo",
                concat!(
                    "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n",
                    "        inet 127.0.0.1  netmask 255.0.0.0\n",
                    "        inet6 ::1  prefixlen 128  scopeid 0x10<host>\n",
                    "        loop  txqueuelen 1000  (Local Loopback)\n",
                    "        RX packets 18432  bytes 1562214 (1.5 MB)\n",
                    "        TX packets 18432  bytes 1562214 (1.5 MB)\n",
                ),
                concat!(
                    "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n",
                    "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n",
                    "    inet 127.0.0.1/8 scope host lo\n",
                    "       valid_lft forever preferred_lft forever\n",
                    "    inet6 ::1/128 scope host\n",
                    "       valid_lft forever preferred_lft forever\n",
                ),
            ),
            VirtualNetworkInterface::new(
                "eth0",
                concat!(
                    "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n",
                    "        inet 10.0.0.24  netmask 255.255.255.0  broadcast 10.0.0.255\n",
                    "        inet6 fe80::42:aff:fe00:18  prefixlen 64  scopeid 0x20<link>\n",
                    "        ether 02:42:0a:00:00:18  txqueuelen 1000  (Ethernet)\n",
                    "        RX packets 948321  bytes 182443902 (182.4 MB)\n",
                    "        TX packets 615004  bytes 90234118 (90.2 MB)\n",
                ),
                concat!(
                    "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\n",
                    "    link/ether 02:42:0a:00:00:18 brd ff:ff:ff:ff:ff:ff\n",
                    "    inet 10.0.0.24/24 brd 10.0.0.255 scope global dynamic eth0\n",
                    "       valid_lft 84532sec preferred_lft 84532sec\n",
                    "    inet6 fe80::42:aff:fe00:18/64 scope link\n",
                    "       valid_lft forever preferred_lft forever\n",
                ),
            ),
        ];

        let service_processes = vec![
            VirtualProcess::new(
                "root",
                1,
                0,
                0.0,
                0.2,
                169_640,
                11_412,
                "?",
                "Ss",
                "Apr13",
                "0:03",
                "/sbin/init",
            ),
            VirtualProcess::new(
                "root",
                623,
                1,
                0.0,
                0.1,
                38_424,
                8_120,
                "?",
                "Ss",
                "Apr13",
                "0:01",
                "/lib/systemd/systemd-journald",
            ),
            VirtualProcess::new(
                "syslog",
                781,
                1,
                0.0,
                0.1,
                222_584,
                6_428,
                "?",
                "Ssl",
                "Apr13",
                "0:00",
                "/usr/sbin/rsyslogd -n -iNONE",
            ),
            VirtualProcess::new(
                "root",
                814,
                1,
                0.0,
                0.0,
                32_740,
                2_932,
                "?",
                "Ss",
                "Apr13",
                "0:00",
                "/usr/sbin/cron -f",
            ),
            VirtualProcess::new(
                "root",
                970,
                1,
                0.0,
                0.1,
                15_428,
                8_948,
                "?",
                "Ss",
                "Apr13",
                "0:00",
                "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups",
            ),
            VirtualProcess::new(
                "mysql",
                1088,
                1,
                0.2,
                3.4,
                1_725_436,
                142_880,
                "?",
                "Ssl",
                "Apr13",
                "0:28",
                "/usr/sbin/mysqld",
            ),
            VirtualProcess::new(
                "root",
                1154,
                1,
                0.0,
                0.1,
                102_540,
                7_924,
                "?",
                "Ss",
                "Apr13",
                "0:00",
                "nginx: master process /usr/sbin/nginx -g daemon on; master_process on;",
            ),
            VirtualProcess::new(
                "www-data",
                1158,
                1154,
                0.0,
                0.2,
                103_240,
                13_084,
                "?",
                "S",
                "Apr13",
                "0:02",
                "nginx: worker process",
            ),
            VirtualProcess::new(
                "tomcat",
                1280,
                1,
                0.8,
                6.1,
                3_586_240,
                254_312,
                "?",
                "Ssl",
                "Apr13",
                "3:14",
                "/usr/bin/java -Dcatalina.base=/opt/tomcat -Dcatalina.home=/opt/tomcat org.apache.catalina.startup.Bootstrap start",
            ),
        ];

        let listening_sockets = vec![
            VirtualListeningSocket::new("tcp", "0.0.0.0:22", "0.0.0.0:*", "LISTEN", 970, "sshd"),
            VirtualListeningSocket::new("tcp", "0.0.0.0:80", "0.0.0.0:*", "LISTEN", 1154, "nginx"),
            VirtualListeningSocket::new(
                "tcp",
                "127.0.0.1:3306",
                "0.0.0.0:*",
                "LISTEN",
                1088,
                "mysqld",
            ),
            VirtualListeningSocket::new("tcp6", "[::]:8080", "[::]:*", "LISTEN", 1280, "java"),
        ];

        let mounts = vec![
            VirtualMount::new("/dev/vda1", "40G", "17G", "21G", "46%", "/"),
            VirtualMount::new("tmpfs", "393M", "1.4M", "392M", "1%", "/run"),
            VirtualMount::new("tmpfs", "2.0G", "0", "2.0G", "0%", "/dev/shm"),
            VirtualMount::new("/dev/vdb1", "100G", "58G", "38G", "61%", "/srv/backups"),
        ];

        Self {
            binaries,
            interfaces,
            service_processes,
            listening_sockets,
            mounts,
        }
    }

    fn architecture(&self) -> &str {
        DEFAULT_OS_ARCHITECTURE
    }

    fn cpu_count(&self) -> usize {
        DEFAULT_CPU_COUNT
    }

    fn total_memory_kb(&self) -> u64 {
        DEFAULT_MEMORY_TOTAL_KB
    }

    fn populate_filesystem(&self, filesystem: &mut VirtualFilesystem) {
        filesystem.ensure_dir("/bin");
        filesystem.ensure_dir("/sbin");
        filesystem.ensure_dir("/usr");
        filesystem.ensure_dir("/usr/bin");
        filesystem.ensure_dir("/usr/sbin");
        filesystem.ensure_dir("/usr/local");
        filesystem.ensure_dir("/usr/local/bin");
        filesystem.populate_system_tree();
        filesystem.add_file("/etc/os-release", DEFAULT_OS_RELEASE_CONTENTS.to_string());

        for binary in self.binaries.values() {
            filesystem.add_file(binary.path.as_str(), String::new());
        }
    }

    fn command_path(&self, name: &str) -> Option<&str> {
        self.binaries.get(name).map(|binary| binary.path.as_str())
    }

    fn probe_output(&self, name: &str) -> Option<&str> {
        self.binaries
            .get(name)
            .map(|binary| binary.probe_output.as_str())
    }

    fn command_names(&self) -> Vec<String> {
        self.binaries.keys().cloned().collect()
    }

    fn free_kb_output(&self) -> String {
        format!(
            "               total        used        free      shared  buff/cache   available\r\nMem:     {total:>10} {used:>10} {free:>10} {shared:>10} {buff_cache:>11} {available:>11}\r\nSwap:             0          0          0\r\n",
            total = DEFAULT_MEMORY_TOTAL_KB,
            used = DEFAULT_MEMORY_USED_KB,
            free = DEFAULT_MEMORY_FREE_KB,
            shared = DEFAULT_MEMORY_SHARED_KB,
            buff_cache = DEFAULT_MEMORY_BUFF_CACHE_KB,
            available = DEFAULT_MEMORY_AVAILABLE_KB,
        )
    }

    fn ifconfig_output(&self, interface: Option<&str>) -> Option<String> {
        self.select_interfaces(interface).map(|interfaces| {
            interfaces
                .iter()
                .map(|interface| to_crlf(interface.ifconfig_block.as_str()))
                .collect::<Vec<_>>()
                .join("\r\n")
        })
    }

    fn ip_addr_output(&self, interface: Option<&str>) -> Option<String> {
        self.select_interfaces(interface).map(|interfaces| {
            interfaces
                .iter()
                .map(|interface| to_crlf(interface.ip_addr_block.as_str()))
                .collect::<Vec<_>>()
                .join("")
        })
    }

    fn select_interfaces(&self, interface: Option<&str>) -> Option<Vec<&VirtualNetworkInterface>> {
        let interfaces = match interface {
            Some(name) => self
                .interfaces
                .iter()
                .filter(|interface| interface.name == name)
                .collect::<Vec<_>>(),
            None => self.interfaces.iter().collect::<Vec<_>>(),
        };

        if interfaces.is_empty() {
            None
        } else {
            Some(interfaces)
        }
    }

    fn runtime_output(&self, command: &str, args: &[String]) -> Option<RuntimeCommandResult> {
        let arg = args
            .iter()
            .find(|arg| !arg.starts_with("2>") && *arg != "|" && *arg != "head")
            .map(String::as_str);

        match command {
            "java" if args.is_empty() || matches!(arg, Some("-h" | "--help")) => {
                Some(RuntimeCommandResult::Output(to_crlf(
                    "Usage: java [options] <mainclass> [args...]\n   or  java [options] -jar <jarfile> [args...]\n\nwhere options include:\n    -version      print product version and exit\n    -help, -h     print this help message",
                )))
            }
            "java" if matches!(arg, Some("-V" | "-version" | "--version")) => self
                .probe_output("java")
                .map(to_crlf)
                .map(RuntimeCommandResult::Output),
            "javac" if args.is_empty() || matches!(arg, Some("-h" | "--help")) => Some(
                RuntimeCommandResult::Output(to_crlf(
                    "Usage: javac <options> <source files>\nwhere possible options include:\n  -classpath <path>\n  -d <directory>\n  -encoding <encoding>",
                )),
            ),
            "javac" if matches!(arg, Some("-version" | "--version")) => self
                .probe_output("javac")
                .map(|output| format!("{output}\r\n"))
                .map(RuntimeCommandResult::Output),
            "python" | "python3" if args.is_empty() => Some(RuntimeCommandResult::EnterPythonRepl {
                banner: "Python 3.10.12 (main, Feb 14 2026, 08:00:00) [GCC 11.4.0] on linux\r\nType \"help\", \"copyright\", \"credits\" or \"license\" for more information.\r\n".to_string(),
            }),
            "python" | "python3" if matches!(arg, Some("-V" | "--version")) => self
                .probe_output(command)
                .map(|output| format!("{output}\r\n"))
                .map(RuntimeCommandResult::Output),
            "python" | "python3" if matches!(arg, Some("-h" | "--help")) => Some(
                RuntimeCommandResult::Output(to_crlf(
                    "usage: python [option] ... [-c cmd | -m mod | file | -] [arg] ...\nOptions and arguments:\n-V     : print the Python version number and exit\n-h     : print this help message and exit",
                )),
            ),
            "php" if matches!(arg, Some("-v" | "--version")) => self
                .probe_output("php")
                .map(to_crlf)
                .map(RuntimeCommandResult::Output),
            "php" if args.is_empty() || matches!(arg, Some("-h" | "--help")) => Some(
                RuntimeCommandResult::Output(to_crlf(
                    "Usage: php [options] [-f] <file> [--] [args...]\n   php [options] -r <code> [--] [args...]\n   php [options] [-B <begin_code>] -R <code> [-E <end_code>] [--] [args...]",
                )),
            ),
            "nginx" if matches!(arg, Some("-v" | "-V")) => self
                .probe_output("nginx")
                .map(|output| format!("{output}\r\n"))
                .map(RuntimeCommandResult::Output),
            "apache2" if matches!(arg, Some("-v" | "-V")) => self
                .probe_output("apache2")
                .map(to_crlf)
                .map(RuntimeCommandResult::Output),
            "mysql" if matches!(arg, Some("-V" | "--version")) => self
                .probe_output("mysql")
                .map(|output| format!("{output}\r\n"))
                .map(RuntimeCommandResult::Output),
            "ssh" if matches!(arg, Some("-V")) => self
                .probe_output("ssh")
                .map(|output| format!("{output}\r\n"))
                .map(RuntimeCommandResult::Output),
            "sshd" if matches!(arg, Some("-V")) => self
                .probe_output("sshd")
                .map(|output| format!("{output}\r\n"))
                .map(RuntimeCommandResult::Output),
            "sshd" if matches!(arg, Some("-T")) => Some(RuntimeCommandResult::Output(to_crlf(
                "port 22\npasswordauthentication yes\npubkeyauthentication yes\npermitrootlogin prohibit-password\nusepam yes\nx11forwarding yes",
            ))),
            _ => None,
        }
    }

    fn ps_output(&self, identity: &ShellIdentity, session_id: u64, args: &[String]) -> String {
        let wide = args.iter().any(|arg| arg == "aux" || arg == "-ef");
        let processes = self.render_processes(identity, session_id);

        if args.iter().any(|arg| arg == "-ef") {
            let mut lines =
                vec!["UID          PID    PPID  C STIME TTY          TIME CMD".to_string()];
            lines.extend(processes.iter().map(VirtualProcess::ps_ef_line));
            return format!("{}\r\n", lines.join("\r\n"));
        }

        if wide {
            let mut lines = vec![
                "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"
                    .to_string(),
            ];
            lines.extend(processes.iter().map(VirtualProcess::ps_aux_line));
            return format!("{}\r\n", lines.join("\r\n"));
        }

        let mut lines = vec!["  PID TTY          TIME CMD".to_string()];
        lines.extend(
            processes
                .iter()
                .filter(|process| process.tty == "pts/0")
                .map(VirtualProcess::ps_default_line),
        );
        format!("{}\r\n", lines.join("\r\n"))
    }

    fn ss_output(&self) -> String {
        let mut lines =
            vec!["State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process".to_string()];
        lines.extend(
            self.listening_sockets
                .iter()
                .map(VirtualListeningSocket::ss_line),
        );
        format!("{}\r\n", lines.join("\r\n"))
    }

    fn netstat_output(&self) -> String {
        let mut lines = vec![
            "Active Internet connections (only servers)".to_string(),
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name".to_string(),
        ];
        lines.extend(
            self.listening_sockets
                .iter()
                .map(VirtualListeningSocket::netstat_line),
        );
        format!("{}\r\n", lines.join("\r\n"))
    }

    fn df_output(&self) -> String {
        let mut lines = vec!["Filesystem      Size  Used Avail Use% Mounted on".to_string()];
        lines.extend(self.mounts.iter().map(VirtualMount::df_line));
        format!("{}\r\n", lines.join("\r\n"))
    }

    fn uptime_output(&self) -> String {
        " 07:14:03 up 12 days,  3:41,  2 users,  load average: 0.08, 0.11, 0.09\r\n".to_string()
    }

    fn env_output(&self, identity: &ShellIdentity) -> String {
        let mut entries = vec![
            format!("HOME={}", identity.home),
            "LANG=en_US.UTF-8".to_string(),
            format!("LOGNAME={}", identity.username),
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
            format!("PWD={}", identity.cwd),
            "SHELL=/bin/bash".to_string(),
            "TERM=xterm-256color".to_string(),
            format!("USER={}", identity.username),
        ];
        entries.sort();
        format!("{}\r\n", entries.join("\r\n"))
    }

    fn last_output(
        &self,
        identity: &ShellIdentity,
        peer_addr: Option<SocketAddr>,
        _hostname: &str,
    ) -> String {
        let peer = peer_addr
            .map(|addr| addr.ip().to_string())
            .unwrap_or_else(|| "127.0.0.1".to_string());
        to_crlf(format!(
            "{user:<8} pts/0        {peer:<15} Tue Apr 14 07:09   still logged in\nadmin    pts/1        10.0.0.12       Tue Apr 14 06:48 - 06:54  (00:06)\nroot     pts/2        198.51.100.24   Mon Apr 13 23:11 - 23:14  (00:03)\nreboot   system boot  5.15.0-113-gene Mon Apr 01 03:28   still running\n\nwtmp begins Tue Apr 02 00:00:00 2026\n",
            user = identity.username,
        ).as_str())
    }

    fn w_output(
        &self,
        identity: &ShellIdentity,
        peer_addr: Option<SocketAddr>,
        _hostname: &str,
    ) -> String {
        let peer = peer_addr
            .map(|addr| addr.ip().to_string())
            .unwrap_or_else(|| "127.0.0.1".to_string());
        format!(
            " 07:14:03 up 12 days,  3:41,  2 users,  load average: 0.08, 0.11, 0.09\r\nUSER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\r\n{user:<8} pts/0    {peer:<15} 07:09    1.00s  0.04s  0.00s -bash\r\nadmin    pts/1    10.0.0.12       06:48    3:21m  0.12s  0.01s sudo -i\r\n",
            user = identity.username,
        )
    }

    fn who_output(
        &self,
        identity: &ShellIdentity,
        peer_addr: Option<SocketAddr>,
        _hostname: &str,
    ) -> String {
        let peer = peer_addr
            .map(|addr| addr.ip().to_string())
            .unwrap_or_else(|| "127.0.0.1".to_string());
        format!(
            "{user:<8} pts/0        2026-04-14 07:09 ({peer})\r\nadmin    pts/1        2026-04-14 06:48 (10.0.0.12)\r\n",
            user = identity.username,
        )
    }

    fn crontab_output(&self, username: &str) -> Option<String> {
        match username {
            "root" => Some(to_crlf(
                "SHELL=/bin/bash\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n*/15 * * * * /usr/local/bin/backup-healthcheck\n30 3 * * * /root/scripts/backup.sh\n",
            )),
            "admin" => Some(to_crlf(
                "MAILTO=\"\"\n0 4 * * 1 /home/admin/ops/rotate-logs.sh\n",
            )),
            _ => None,
        }
    }

    fn render_processes(&self, identity: &ShellIdentity, session_id: u64) -> Vec<VirtualProcess> {
        let mut processes = self.service_processes.clone();
        let base = 24_000 + ((session_id as u32) % 500) * 10;
        processes.push(VirtualProcess::new(
            "root",
            base,
            970,
            0.0,
            0.1,
            15_620,
            8_512,
            "?",
            "Ss",
            "07:09",
            "0:00",
            format!("sshd: {} [priv]", identity.username).as_str(),
        ));
        processes.push(VirtualProcess::new(
            identity.username.as_str(),
            base + 1,
            base,
            0.0,
            0.1,
            17_220,
            7_236,
            "pts/0",
            "Ss",
            "07:09",
            "0:00",
            format!("sshd: {}@pts/0", identity.username).as_str(),
        ));
        processes.push(VirtualProcess::new(
            identity.username.as_str(),
            base + 2,
            base + 1,
            0.0,
            0.1,
            21_348,
            8_128,
            "pts/0",
            "S+",
            "07:09",
            "0:00",
            "-bash",
        ));
        processes.sort_by_key(|process| process.pid);
        processes
    }
}

#[derive(Clone, Debug)]
struct VirtualBinary {
    name: String,
    path: String,
    probe_output: String,
}

#[derive(Clone, Debug)]
struct VirtualProcess {
    user: String,
    pid: u32,
    ppid: u32,
    cpu: f32,
    mem: f32,
    vsz: u64,
    rss: u64,
    tty: String,
    stat: String,
    start: String,
    time: String,
    command: String,
}

#[derive(Clone, Debug)]
struct VirtualNetworkInterface {
    name: String,
    ifconfig_block: String,
    ip_addr_block: String,
}

#[derive(Clone, Debug)]
struct VirtualListeningSocket {
    proto: String,
    local_address: String,
    peer_address: String,
    state: String,
    pid: u32,
    program: String,
}

#[derive(Clone, Debug)]
struct VirtualMount {
    filesystem: String,
    size: String,
    used: String,
    available: String,
    use_percent: String,
    mounted_on: String,
}

impl VirtualNetworkInterface {
    fn new(name: &str, ifconfig_block: &str, ip_addr_block: &str) -> Self {
        Self {
            name: name.to_string(),
            ifconfig_block: ifconfig_block.to_string(),
            ip_addr_block: ip_addr_block.to_string(),
        }
    }
}

impl VirtualBinary {
    fn new(name: &str, path: &str, probe_output: &str) -> Self {
        Self {
            name: name.to_string(),
            path: path.to_string(),
            probe_output: probe_output.to_string(),
        }
    }
}

impl VirtualProcess {
    #[allow(clippy::too_many_arguments)]
    fn new(
        user: &str,
        pid: u32,
        ppid: u32,
        cpu: f32,
        mem: f32,
        vsz: u64,
        rss: u64,
        tty: &str,
        stat: &str,
        start: &str,
        time: &str,
        command: &str,
    ) -> Self {
        Self {
            user: user.to_string(),
            pid,
            ppid,
            cpu,
            mem,
            vsz,
            rss,
            tty: tty.to_string(),
            stat: stat.to_string(),
            start: start.to_string(),
            time: time.to_string(),
            command: command.to_string(),
        }
    }

    fn ps_aux_line(&self) -> String {
        format!(
            "{:<10} {:>5} {:>4.1} {:>4.1} {:>7} {:>6} {:<8} {:<4} {:<7} {:<5} {}",
            self.user,
            self.pid,
            self.cpu,
            self.mem,
            self.vsz,
            self.rss,
            self.tty,
            self.stat,
            self.start,
            self.time,
            self.command
        )
    }

    fn ps_ef_line(&self) -> String {
        format!(
            "{:<8} {:>5} {:>7}  0 {:<5} {:<8} {:<8} {}",
            self.user, self.pid, self.ppid, self.start, self.tty, self.time, self.command
        )
    }

    fn ps_default_line(&self) -> String {
        format!(
            "{:>5} {:<12} {:<8} {}",
            self.pid, self.tty, self.time, self.command
        )
    }
}

impl VirtualListeningSocket {
    fn new(
        proto: &str,
        local_address: &str,
        peer_address: &str,
        state: &str,
        pid: u32,
        program: &str,
    ) -> Self {
        Self {
            proto: proto.to_string(),
            local_address: local_address.to_string(),
            peer_address: peer_address.to_string(),
            state: state.to_string(),
            pid,
            program: program.to_string(),
        }
    }

    fn ss_line(&self) -> String {
        format!(
            "{:<6} {:>5} {:>6} {:<21} {:<18} users:((\"{}\",pid={},fd=3))",
            self.state, 0, 128, self.local_address, self.peer_address, self.program, self.pid
        )
    }

    fn netstat_line(&self) -> String {
        format!(
            "{:<5} {:>6} {:>6} {:<23} {:<23} {:<11} {}/{}",
            self.proto,
            0,
            0,
            self.local_address,
            self.peer_address,
            self.state,
            self.pid,
            self.program
        )
    }
}

impl VirtualMount {
    fn new(
        filesystem: &str,
        size: &str,
        used: &str,
        available: &str,
        use_percent: &str,
        mounted_on: &str,
    ) -> Self {
        Self {
            filesystem: filesystem.to_string(),
            size: size.to_string(),
            used: used.to_string(),
            available: available.to_string(),
            use_percent: use_percent.to_string(),
            mounted_on: mounted_on.to_string(),
        }
    }

    fn df_line(&self) -> String {
        format!(
            "{:<15} {:>4} {:>5} {:>5} {:>4} {}",
            self.filesystem,
            self.size,
            self.used,
            self.available,
            self.use_percent,
            self.mounted_on
        )
    }
}

#[derive(Clone, Debug)]
struct ShellIdentity {
    username: String,
    cwd: String,
    home: String,
    uid: u32,
    gid: u32,
    group_name: String,
    prompt_symbol: char,
}

impl ShellIdentity {
    fn for_user(username: &str) -> Self {
        match username {
            "root" => Self {
                username: "root".to_string(),
                cwd: "/root".to_string(),
                home: "/root".to_string(),
                uid: 0,
                gid: 0,
                group_name: "root".to_string(),
                prompt_symbol: '#',
            },
            "admin" => Self {
                username: "admin".to_string(),
                cwd: "/home/admin".to_string(),
                home: "/home/admin".to_string(),
                uid: 1001,
                gid: 1001,
                group_name: "admin".to_string(),
                prompt_symbol: '$',
            },
            "ubuntu" => Self {
                username: "ubuntu".to_string(),
                cwd: "/home/ubuntu".to_string(),
                home: "/home/ubuntu".to_string(),
                uid: 1000,
                gid: 1000,
                group_name: "ubuntu".to_string(),
                prompt_symbol: '$',
            },
            "tomcat" => Self {
                username: "tomcat".to_string(),
                cwd: "/opt/tomcat".to_string(),
                home: "/opt/tomcat".to_string(),
                uid: 996,
                gid: 996,
                group_name: "tomcat".to_string(),
                prompt_symbol: '$',
            },
            "www-data" => Self {
                username: "www-data".to_string(),
                cwd: "/var/www".to_string(),
                home: "/var/www".to_string(),
                uid: 33,
                gid: 33,
                group_name: "www-data".to_string(),
                prompt_symbol: '$',
            },
            other => Self {
                username: other.to_string(),
                cwd: format!("/home/{other}"),
                home: format!("/home/{other}"),
                uid: 1002,
                gid: 1002,
                group_name: other.to_string(),
                prompt_symbol: '$',
            },
        }
    }

    fn display_path(&self) -> String {
        if self.cwd == self.home {
            "~".to_string()
        } else if self.cwd.starts_with(format!("{}/", self.home).as_str()) {
            self.cwd.replacen(self.home.as_str(), "~", 1)
        } else {
            self.cwd.clone()
        }
    }
}

#[derive(Clone, Debug)]
struct VirtualFilesystem {
    entries: BTreeMap<String, Vec<String>>,
    file_contents: BTreeMap<String, String>,
}

enum VirtualFilesystemWriteError {
    MissingParent,
    PathIsDirectory,
}

impl VirtualFilesystem {
    fn for_login_user(username: &str) -> Self {
        let mut entries = BTreeMap::new();
        entries.insert(
            "/".to_string(),
            vec![
                "bin", "boot", "dev", "etc", "home", "lib", "lib64", "media", "mnt", "opt", "proc",
                "root", "run", "sbin", "srv", "sys", "tmp", "usr", "var",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
        );
        entries.insert(
            "/root".to_string(),
            vec![".bash_history", ".ssh", "loot", "scripts"]
                .into_iter()
                .map(str::to_string)
                .collect(),
        );
        entries.insert(
            "/var".to_string(),
            vec!["cache", "lib", "log", "tmp", "www"]
                .into_iter()
                .map(str::to_string)
                .collect(),
        );
        entries.insert(
            "/var/log".to_string(),
            vec!["auth.log", "kern.log", "syslog", "nginx", "tomcat"]
                .into_iter()
                .map(str::to_string)
                .collect(),
        );
        entries.insert(
            "/opt".to_string(),
            vec!["tomcat", "backup", "deploy"]
                .into_iter()
                .map(str::to_string)
                .collect(),
        );
        entries.insert(
            "/opt/tomcat".to_string(),
            vec!["bin", "conf", "logs", "temp", "webapps", "work"]
                .into_iter()
                .map(str::to_string)
                .collect(),
        );
        entries.insert(
            "/opt/tomcat/webapps".to_string(),
            vec!["ROOT", "manager", "host-manager", "docs"]
                .into_iter()
                .map(str::to_string)
                .collect(),
        );
        entries.insert(
            "/var/www".to_string(),
            vec!["html", "releases", "shared"]
                .into_iter()
                .map(str::to_string)
                .collect(),
        );
        entries.insert(
            "/var/www/html".to_string(),
            vec!["index.html", "assets", "uploads"]
                .into_iter()
                .map(str::to_string)
                .collect(),
        );
        entries.insert(
            "/etc".to_string(),
            vec![
                "apache2", "cron.d", "hostname", "hosts", "mysql", "nginx", "passwd", "shadow",
                "ssh", "sudoers", "systemd", "tomcat",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
        );
        entries.insert(
            "/home".to_string(),
            vec![
                username.to_string(),
                "ubuntu".to_string(),
                "admin".to_string(),
            ],
        );

        let mut filesystem = Self {
            entries,
            file_contents: BTreeMap::new(),
        };
        filesystem.ensure_identity(&ShellIdentity::for_user(username));
        filesystem.ensure_identity(&ShellIdentity::for_user("root"));
        filesystem
    }

    fn populate_system_tree(&mut self) {
        for dir in [
            "/boot",
            "/dev",
            "/lib",
            "/lib64",
            "/media",
            "/mnt",
            "/proc",
            "/run",
            "/srv",
            "/srv/backups",
            "/srv/backups/www",
            "/sys",
            "/tmp",
            "/var/cache",
            "/var/lib",
            "/var/log/nginx",
            "/var/log/apache2",
            "/var/log/mysql",
            "/var/log/tomcat",
            "/etc/ssh",
            "/etc/nginx",
            "/etc/nginx/sites-available",
            "/etc/apache2",
            "/etc/apache2/sites-enabled",
            "/etc/mysql",
            "/etc/mysql/mysql.conf.d",
        ] {
            self.ensure_dir(dir);
        }

        self.add_file(
            "/etc/ssh/sshd_config",
            "Port 22\nPermitRootLogin prohibit-password\nPasswordAuthentication yes\nPubkeyAuthentication yes\nUsePAM yes\nAllowTcpForwarding yes\nX11Forwarding yes\n".to_string(),
        );
        self.add_file(
            "/etc/ssh/ssh_config",
            "Host *\n    ServerAliveInterval 60\n    HashKnownHosts yes\n    GSSAPIAuthentication no\n".to_string(),
        );
        self.add_file(
            "/etc/nginx/nginx.conf",
            "user www-data;\nworker_processes auto;\npid /run/nginx.pid;\nhttp {\n    include /etc/nginx/sites-available/default;\n}\n".to_string(),
        );
        self.add_file(
            "/etc/nginx/sites-available/default",
            "server {\n    listen 80 default_server;\n    server_name _;\n    location / {\n        proxy_pass http://127.0.0.1:8080;\n    }\n}\n".to_string(),
        );
        self.add_file(
            "/etc/apache2/apache2.conf",
            "ServerRoot \"/etc/apache2\"\nTimeout 300\nKeepAlive On\nMaxKeepAliveRequests 100\n"
                .to_string(),
        );
        self.add_file(
            "/etc/apache2/sites-enabled/000-default.conf",
            "<VirtualHost *:8081>\n    DocumentRoot /var/www/html\n</VirtualHost>\n".to_string(),
        );
        self.add_file(
            "/etc/mysql/mysql.conf.d/mysqld.cnf",
            "[mysqld]\nbind-address = 127.0.0.1\nmysqlx-bind-address = 127.0.0.1\nmax_connections = 200\n".to_string(),
        );
        self.add_file(
            "/etc/passwd",
            "root:x:0:0:root:/root:/bin/bash\nubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\nadmin:x:1001:1001:Admin:/home/admin:/bin/bash\ntomcat:x:996:996:Apache Tomcat:/opt/tomcat:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nmysql:x:112:120:MySQL Server:/nonexistent:/bin/false\n".to_string(),
        );
        self.add_file(
            "/etc/hosts",
            "127.0.0.1 localhost\n127.0.1.1 web-a9c0\n10.0.0.24 web-a9c0.internal web-a9c0\n"
                .to_string(),
        );
        self.add_file(
            "/etc/crontab",
            "SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly\n".to_string(),
        );
        self.add_file(
            "/var/log/auth.log",
            "Apr 14 06:48:13 web-a9c0 sshd[24100]: Accepted password for admin from 10.0.0.12 port 54822 ssh2\nApr 14 07:09:44 web-a9c0 sshd[24120]: Accepted password for tomcat from 8.134.102.17 port 53212 ssh2\n".to_string(),
        );
        self.add_file(
            "/var/log/syslog",
            "Apr 14 06:50:00 web-a9c0 systemd[1]: Started Daily apt download activities.\nApr 14 07:00:17 web-a9c0 CRON[22014]: (root) CMD (/root/scripts/cleanup.sh)\n".to_string(),
        );
        self.add_file(
            "/var/log/kern.log",
            "Apr 14 06:44:22 web-a9c0 kernel: [91234.124] eth0: renamed from veth0c1a\n"
                .to_string(),
        );
        self.add_file(
            "/var/log/nginx/access.log",
            "10.0.0.12 - - [14/Apr/2026:06:55:31 +0800] \"GET /health HTTP/1.1\" 200 2 \"-\" \"curl/8.5.0\"\n198.51.100.44 - - [14/Apr/2026:07:02:13 +0800] \"GET /manager/html HTTP/1.1\" 302 154 \"-\" \"Mozilla/5.0\"\n".to_string(),
        );
        self.add_file(
            "/var/log/nginx/error.log",
            "2026/04/14 06:57:42 [warn] 1158#1158: *81 upstream response is buffered to a temporary file /var/cache/nginx/proxy_temp/1/00/0000000001 while reading upstream\n".to_string(),
        );
        self.add_file(
            "/var/log/apache2/access.log",
            "127.0.0.1 - - [14/Apr/2026:05:11:20 +0800] \"GET /server-status HTTP/1.1\" 403 274\n"
                .to_string(),
        );
        self.add_file(
            "/var/log/mysql/error.log",
            "2026-04-14T06:30:04.019854Z 0 [System] [MY-010116] [Server] /usr/sbin/mysqld: ready for connections.\n".to_string(),
        );
        self.add_file(
            "/var/log/tomcat/catalina.out",
            "14-Apr-2026 03:11:49.123 INFO [main] Server startup in 1234 ms\n".to_string(),
        );
    }

    fn ensure_identity(&mut self, identity: &ShellIdentity) {
        let parent = parent_dir(identity.home.as_str())
            .unwrap_or("/")
            .to_string();
        self.entries
            .entry(parent.clone())
            .or_default()
            .push(path_basename(identity.home.as_str()).to_string());
        self.entries
            .entry(identity.home.clone())
            .or_insert_with(|| match identity.username.as_str() {
                "root" => vec![
                    ".bash_history".to_string(),
                    ".cache".to_string(),
                    ".ssh".to_string(),
                    "payloads".to_string(),
                    "scripts".to_string(),
                ],
                "admin" => vec![
                    ".bash_history".to_string(),
                    ".config".to_string(),
                    "backups".to_string(),
                    "notes.txt".to_string(),
                    "ops".to_string(),
                ],
                "ubuntu" => vec![
                    ".ssh".to_string(),
                    "deploy".to_string(),
                    "logs".to_string(),
                    "snap".to_string(),
                    "tmp".to_string(),
                ],
                "tomcat" => vec![
                    "bin".to_string(),
                    "conf".to_string(),
                    "logs".to_string(),
                    "temp".to_string(),
                    "webapps".to_string(),
                ],
                "www-data" => vec![
                    "html".to_string(),
                    "releases".to_string(),
                    "shared".to_string(),
                    "uploads".to_string(),
                ],
                _ => vec![
                    ".bash_history".to_string(),
                    ".ssh".to_string(),
                    "downloads".to_string(),
                    "logs".to_string(),
                    "tmp".to_string(),
                ],
            });
        dedupe_entries(
            self.entries
                .get_mut(parent.as_str())
                .expect("parent entry should exist"),
        );
        self.populate_identity_tree(identity);
    }

    fn populate_identity_tree(&mut self, identity: &ShellIdentity) {
        match identity.username.as_str() {
            "root" => {
                self.add_file(
                    "/root/.bash_history",
                    "cd /var/www\nls -la\ncat /etc/nginx/nginx.conf\nmysql -uroot -p\n".to_string(),
                );
                self.ensure_dir("/root/.ssh");
                self.add_file(
                    "/root/.ssh/authorized_keys",
                    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBrootlabkey root@web-d249\n".to_string(),
                );
                self.ensure_dir("/root/loot");
                self.add_file(
                    "/root/loot/credentials.txt",
                    "mysql_root_password=Str0ng-Local-Only!\nbackup_token=wk-2026-04-14\n"
                        .to_string(),
                );
                self.add_file(
                    "/root/loot/db01-notes.txt",
                    "staging db dump rotated every night at 03:30\n".to_string(),
                );
                self.ensure_dir("/root/scripts");
                self.add_file(
                    "/root/scripts/backup.sh",
                    "#!/bin/bash\nrsync -a /var/www/ /srv/backups/www/\n".to_string(),
                );
                self.add_file(
                    "/root/scripts/cleanup.sh",
                    "#!/bin/bash\nfind /tmp -type f -mtime +7 -delete\n".to_string(),
                );
            }
            "admin" => {
                self.add_file(
                    "/home/admin/.bash_history",
                    "sudo -i\njournalctl -u nginx --since today\n/home/admin/ops/rotate-logs.sh\n"
                        .to_string(),
                );
                self.ensure_dir("/home/admin/.config");
                self.ensure_dir("/home/admin/backups");
                self.ensure_dir("/home/admin/ops");
                self.add_file(
                    "/home/admin/notes.txt",
                    "Remember to rotate TLS certificates before Friday.\n".to_string(),
                );
                self.add_file(
                    "/home/admin/ops/rotate-logs.sh",
                    "#!/bin/bash\njournalctl --vacuum-time=14d\n".to_string(),
                );
            }
            "ubuntu" => {
                self.add_file(
                    "/home/ubuntu/.bash_history",
                    "cd ~/deploy\ncat release.txt\nsystemctl status walle\n".to_string(),
                );
                self.ensure_dir("/home/ubuntu/.ssh");
                self.ensure_dir("/home/ubuntu/deploy");
                self.ensure_dir("/home/ubuntu/logs");
                self.ensure_dir("/home/ubuntu/tmp");
                self.add_file(
                    "/home/ubuntu/.ssh/authorized_keys",
                    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBuilder ubuntu@instance\n".to_string(),
                );
                self.add_file(
                    "/home/ubuntu/deploy/release.txt",
                    "release=2026.04.14-1\n".to_string(),
                );
                self.add_file(
                    "/home/ubuntu/logs/bootstrap.log",
                    "cloud-init finished successfully\n".to_string(),
                );
            }
            "tomcat" => {
                self.add_file(
                    "/opt/tomcat/.bash_history",
                    "pwd\nls\ncd bin\ncat catalina.sh\n".to_string(),
                );
                self.ensure_dir("/opt/tomcat/bin");
                self.ensure_dir("/opt/tomcat/conf");
                self.ensure_dir("/opt/tomcat/logs");
                self.ensure_dir("/opt/tomcat/temp");
                self.ensure_dir("/opt/tomcat/webapps/ROOT");
                self.add_file(
                    "/opt/tomcat/bin/catalina.sh",
                    "#!/bin/sh\nCATALINA_BASE=/opt/tomcat\n".to_string(),
                );
                self.add_file(
                    "/opt/tomcat/conf/server.xml",
                    "<Server port=\"8005\" shutdown=\"SHUTDOWN\"></Server>\n".to_string(),
                );
                self.add_file(
                    "/opt/tomcat/logs/catalina.out",
                    "14-Apr-2026 03:11:49.123 INFO [main] Server startup in 1234 ms\n".to_string(),
                );
            }
            "www-data" => {
                self.ensure_dir("/var/www/html");
                self.ensure_dir("/var/www/releases");
                self.ensure_dir("/var/www/shared");
                self.ensure_dir("/var/www/uploads");
                self.add_file(
                    "/var/www/html/index.html",
                    "<html><body><h1>It works</h1></body></html>\n".to_string(),
                );
                self.add_file(
                    "/var/www/shared/.env",
                    "APP_ENV=production\nCACHE_DRIVER=file\n".to_string(),
                );
            }
            other => {
                let home = format!("/home/{other}");
                self.add_file(
                    format!("{home}/.bash_history").as_str(),
                    "pwd\nls -la\n".to_string(),
                );
                self.ensure_dir(format!("{home}/.ssh").as_str());
                self.ensure_dir(format!("{home}/downloads").as_str());
                self.ensure_dir(format!("{home}/logs").as_str());
                self.ensure_dir(format!("{home}/tmp").as_str());
                self.add_file(
                    format!("{home}/logs/session.log").as_str(),
                    "session initialized\n".to_string(),
                );
            }
        }
    }

    fn ensure_dir(&mut self, path: &str) {
        let normalized = normalize_path(path);
        if normalized == "/" {
            self.entries.entry(normalized).or_default();
            return;
        }

        if self.entries.contains_key(normalized.as_str()) {
            return;
        }

        if let Some(parent) = parent_dir(normalized.as_str()) {
            self.ensure_dir(parent);
            self.entries
                .entry(parent.to_string())
                .or_default()
                .push(path_basename(normalized.as_str()).to_string());
            dedupe_entries(
                self.entries
                    .get_mut(parent)
                    .expect("parent directory should exist"),
            );
        }

        self.entries.entry(normalized).or_default();
    }

    fn add_file(&mut self, path: &str, contents: String) {
        let normalized = normalize_path(path);
        if let Some(parent) = parent_dir(normalized.as_str()) {
            self.ensure_dir(parent);
            self.entries
                .entry(parent.to_string())
                .or_default()
                .push(path_basename(normalized.as_str()).to_string());
            dedupe_entries(
                self.entries
                    .get_mut(parent)
                    .expect("parent directory should exist"),
            );
        }
        self.file_contents.insert(normalized, contents);
    }

    fn write_file(
        &mut self,
        path: &str,
        contents: &str,
    ) -> Result<(), VirtualFilesystemWriteError> {
        let normalized = normalize_path(path);
        if self.is_dir(normalized.as_str()) {
            return Err(VirtualFilesystemWriteError::PathIsDirectory);
        }

        let Some(parent) = parent_dir(normalized.as_str()) else {
            return Err(VirtualFilesystemWriteError::MissingParent);
        };
        if !self.is_dir(parent) {
            return Err(VirtualFilesystemWriteError::MissingParent);
        }

        self.add_file(normalized.as_str(), contents.to_string());
        Ok(())
    }

    fn append_file(
        &mut self,
        path: &str,
        contents: &str,
    ) -> Result<(), VirtualFilesystemWriteError> {
        let normalized = normalize_path(path);
        if self.is_dir(normalized.as_str()) {
            return Err(VirtualFilesystemWriteError::PathIsDirectory);
        }

        let Some(parent) = parent_dir(normalized.as_str()) else {
            return Err(VirtualFilesystemWriteError::MissingParent);
        };
        if !self.is_dir(parent) {
            return Err(VirtualFilesystemWriteError::MissingParent);
        }

        self.entries
            .entry(parent.to_string())
            .or_default()
            .push(path_basename(normalized.as_str()).to_string());
        dedupe_entries(
            self.entries
                .get_mut(parent)
                .expect("parent directory should exist"),
        );
        self.file_contents
            .entry(normalized)
            .and_modify(|existing| existing.push_str(contents))
            .or_insert_with(|| contents.to_string());
        Ok(())
    }

    fn remove_path(&mut self, path: &str) -> bool {
        let normalized = normalize_path(path);
        if normalized == "/" {
            return false;
        }

        let existed = self.is_dir(normalized.as_str()) || self.is_file(normalized.as_str());
        if !existed {
            return false;
        }

        if let Some(parent) = parent_dir(normalized.as_str())
            && let Some(entries) = self.entries.get_mut(parent)
        {
            entries.retain(|entry| entry != path_basename(normalized.as_str()));
        }

        let prefix = format!("{}/", normalized);
        self.file_contents
            .retain(|key, _| key != &normalized && !key.starts_with(prefix.as_str()));
        self.entries
            .retain(|key, _| key != &normalized && !key.starts_with(prefix.as_str()));
        true
    }

    fn render_ls(&self, path: &str, show_hidden: bool, long_format: bool) -> Option<String> {
        let mut entries = self.list(path, show_hidden)?;
        entries.sort();
        if show_hidden {
            let mut with_hidden = vec![".".to_string(), "..".to_string()];
            with_hidden.extend(entries);
            entries = with_hidden;
        }

        if !long_format {
            return Some(format!("{}\r\n", entries.join("  ")));
        }

        let lines = entries
            .iter()
            .map(|entry| self.render_ls_long_entry(path, entry.as_str()))
            .collect::<Vec<_>>();
        Some(format!("{}\r\n", lines.join("\r\n")))
    }

    fn render_tree(&self, path: &str) -> Option<String> {
        let normalized = normalize_path(path);
        if self.is_file(normalized.as_str()) {
            return Some(format!(
                "{}\r\n\r\n0 directories, 1 file\r\n",
                path_basename(normalized.as_str())
            ));
        }
        if !self.is_dir(normalized.as_str()) {
            return None;
        }

        let mut lines = vec![if normalized == "/" {
            ".".to_string()
        } else {
            path_basename(normalized.as_str()).to_string()
        }];
        let mut stats = TreeStats::default();
        self.render_tree_inner(normalized.as_str(), "", &mut lines, &mut stats);
        lines.push(String::new());
        lines.push(format!(
            "{} directories, {} files",
            stats.directories, stats.files
        ));
        Some(format!("{}\r\n", lines.join("\r\n")))
    }

    fn history_output(&self, path: &str, session_history: &[String]) -> String {
        let mut history_lines = self
            .read_file(path)
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect::<Vec<_>>();
        history_lines.extend(session_history.iter().cloned());
        let lines = history_lines
            .iter()
            .enumerate()
            .map(|(index, line)| format!("{:>5}  {}", index + 1, line))
            .collect::<Vec<_>>();
        format!("{}\r\n", lines.join("\r\n"))
    }

    fn resolve_path(&self, cwd: &str, raw: &str) -> String {
        let raw = raw.trim();
        let raw = if raw.is_empty() || raw == "~" {
            cwd.to_string()
        } else if raw.starts_with('/') {
            raw.to_string()
        } else {
            format!("{cwd}/{raw}")
        };

        normalize_path(raw.as_str())
    }

    fn list(&self, path: &str, show_hidden: bool) -> Option<Vec<String>> {
        self.entries.get(path).map(|entries| {
            entries
                .iter()
                .filter(|entry| show_hidden || !entry.starts_with('.'))
                .cloned()
                .collect::<Vec<_>>()
        })
    }

    fn is_dir(&self, path: &str) -> bool {
        self.entries.contains_key(path)
    }

    fn is_file(&self, path: &str) -> bool {
        let normalized = normalize_path(path);
        if self.is_dir(normalized.as_str()) {
            return false;
        }

        if self.file_contents.contains_key(normalized.as_str()) {
            return true;
        }

        let Some(parent) = parent_dir(normalized.as_str()) else {
            return false;
        };

        self.entries.get(parent).is_some_and(|entries| {
            entries
                .iter()
                .any(|entry| entry == path_basename(normalized.as_str()))
        })
    }

    fn read_file(&self, path: &str) -> Option<&str> {
        let normalized = normalize_path(path);
        self.file_contents
            .get(normalized.as_str())
            .map(String::as_str)
    }

    fn render_ls_long_entry(&self, parent: &str, entry: &str) -> String {
        let full_path = if entry == "." {
            parent.to_string()
        } else if entry == ".." {
            parent_dir(parent).unwrap_or("/").to_string()
        } else if parent == "/" {
            format!("/{entry}")
        } else {
            format!("{parent}/{entry}")
        };
        let normalized = normalize_path(full_path.as_str());
        let is_dir = self.is_dir(normalized.as_str());
        let (owner, group) = ownership_for_path(normalized.as_str());
        let mode = permissions_for_path(normalized.as_str(), is_dir);
        let size = if is_dir {
            4096
        } else {
            self.file_contents
                .get(normalized.as_str())
                .map_or(0, String::len)
        };
        format!(
            "{} 1 {:<8} {:<8} {:>6} Apr 14 03:11 {}",
            mode, owner, group, size, entry
        )
    }

    fn render_tree_inner(
        &self,
        path: &str,
        prefix: &str,
        lines: &mut Vec<String>,
        stats: &mut TreeStats,
    ) {
        let mut entries = self.list(path, false).unwrap_or_default();
        entries.sort();

        for (index, entry) in entries.iter().enumerate() {
            let last = index + 1 == entries.len();
            let connector = if last { "`-- " } else { "|-- " };
            lines.push(format!("{prefix}{connector}{entry}"));
            let child_path = if path == "/" {
                format!("/{entry}")
            } else {
                format!("{path}/{entry}")
            };
            let child_path = normalize_path(child_path.as_str());
            if self.is_dir(child_path.as_str()) {
                stats.directories += 1;
                let next_prefix = if last {
                    format!("{prefix}    ")
                } else {
                    format!("{prefix}|   ")
                };
                self.render_tree_inner(child_path.as_str(), next_prefix.as_str(), lines, stats);
            } else {
                stats.files += 1;
            }
        }
    }
}

#[derive(Default)]
struct TreeStats {
    directories: usize,
    files: usize,
}

fn dedupe_entries(entries: &mut Vec<String>) {
    entries.sort();
    entries.dedup();
}

fn parent_dir(path: &str) -> Option<&str> {
    if path == "/" {
        return None;
    }

    path.rsplit_once('/')
        .map(|(parent, _)| if parent.is_empty() { "/" } else { parent })
}

fn path_basename(path: &str) -> &str {
    path.rsplit('/')
        .find(|part| !part.is_empty())
        .unwrap_or(path)
}

fn normalize_path(path: &str) -> String {
    let mut parts = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }

    if parts.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", parts.join("/"))
    }
}

fn resolve_user_path(cwd: &str, home: &str, raw: &str) -> String {
    let raw = raw.trim();
    let raw = if raw.is_empty() {
        cwd.to_string()
    } else if raw == "~" {
        home.to_string()
    } else if let Some(rest) = raw.strip_prefix("~/") {
        format!("{home}/{rest}")
    } else if raw.starts_with('/') {
        raw.to_string()
    } else {
        format!("{cwd}/{raw}")
    };

    normalize_path(raw.as_str())
}

fn ownership_for_path(path: &str) -> (&'static str, &'static str) {
    if path.starts_with("/opt/tomcat") {
        ("tomcat", "tomcat")
    } else if path.starts_with("/var/www") {
        ("www-data", "www-data")
    } else if path.starts_with("/home/admin") {
        ("admin", "admin")
    } else if path.starts_with("/home/ubuntu") {
        ("ubuntu", "ubuntu")
    } else if path.starts_with("/var/log/nginx") {
        ("www-data", "adm")
    } else if path.starts_with("/var/log/mysql") {
        ("mysql", "adm")
    } else if path.starts_with("/var/log") {
        ("root", "adm")
    } else {
        ("root", "root")
    }
}

fn permissions_for_path(path: &str, is_dir: bool) -> &'static str {
    if is_dir {
        "drwxr-xr-x"
    } else if path.ends_with("authorized_keys") || path.ends_with(".bash_history") {
        "-rw-------"
    } else if path.ends_with(".sh")
        || path.starts_with("/usr/bin/")
        || path.starts_with("/usr/sbin/")
    {
        "-rwxr-xr-x"
    } else if path.ends_with(".log") || path.contains("/var/log/") || path.ends_with(".env") {
        "-rw-r-----"
    } else {
        "-rw-r--r--"
    }
}

fn stable_hash(input: &str) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

struct CommandResult {
    output: String,
    close_channel: bool,
    exit_status: u32,
    audit_events: Vec<CommandAuditEvent>,
    record_history: bool,
}

impl Default for CommandResult {
    fn default() -> Self {
        Self {
            output: String::new(),
            close_channel: false,
            exit_status: 0,
            audit_events: Vec::new(),
            record_history: true,
        }
    }
}

impl CommandResult {
    fn output(output: String) -> Self {
        Self {
            output,
            close_channel: false,
            exit_status: 0,
            audit_events: Vec::new(),
            record_history: true,
        }
    }

    fn status(exit_status: u32) -> Self {
        Self {
            output: String::new(),
            close_channel: false,
            exit_status,
            audit_events: Vec::new(),
            record_history: true,
        }
    }

    fn command_not_found(command: &str) -> Self {
        Self {
            output: format!("bash: {}: command not found\r\n", command),
            close_channel: false,
            exit_status: 127,
            audit_events: Vec::new(),
            record_history: true,
        }
    }

    fn with_audit_event(mut self, event: &'static str, details: String) -> Self {
        self.audit_events.push(CommandAuditEvent { event, details });
        self
    }
}

struct CommandAuditEvent {
    event: &'static str,
    details: String,
}

enum ShellEvent {
    Echo(Vec<u8>),
    CompletionMenu(String),
    Command(ShellInputLine),
}

enum TabCompletion {
    Bell,
    Echo(Vec<u8>),
    Suggestions(String),
}

struct ShellInputLine {
    line: String,
    audit: bool,
    history: bool,
}

fn parse_shell_c_invocation(tokens: &[String]) -> Option<&str> {
    if tokens.len() < 3 {
        return None;
    }

    match tokens[0].as_str() {
        "bash" | "sh" | "/bin/bash" | "/bin/sh" if tokens[1] == "-c" => Some(tokens[2].as_str()),
        _ => None,
    }
}

fn parse_which_fallback_script(script: &str) -> Option<&str> {
    let rest = script.strip_prefix("which ")?;
    let (tool, remainder) = rest.split_once(" 2>/dev/null || command -v ")?;
    let tool = tool.trim();
    if remainder.trim() == format!("{tool} 2>/dev/null") {
        Some(tool)
    } else {
        None
    }
}

fn parse_test_file_probe_script(script: &str) -> Option<Vec<String>> {
    let mut paths = Vec::new();
    for clause in script.split(" || ") {
        let rest = clause.trim().strip_prefix("test -f ")?;
        let (path, _) = rest.split_once(" && echo ")?;
        let path = path.trim();
        if path.is_empty() {
            return None;
        }
        paths.push(path.to_string());
    }

    if paths.is_empty() { None } else { Some(paths) }
}

fn parse_version_probe_script(script: &str) -> Option<&str> {
    let (tool, remainder) = script.split_once(" --version 2>/dev/null || ")?;
    let tool = tool.trim();
    if remainder.trim() == format!("{tool} --help 2>/dev/null | head -1") {
        Some(tool)
    } else {
        None
    }
}

fn parse_stderr_version_head_probe_script(script: &str) -> Option<&'static str> {
    for (tool, flag) in [
        ("java", "-version"),
        ("python3", "--version"),
        ("python", "--version"),
        ("ssh", "-V"),
        ("php", "-v"),
        ("nginx", "-v"),
        ("apache2", "-v"),
        ("mysql", "--version"),
    ] {
        if script == format!("{tool} {flag} 2>&1 | head -1")
            || script == format!("{tool} {flag} 2>&1 | head -n 1")
        {
            return Some(tool);
        }
    }
    None
}

fn parse_python_print_argument(line: &str) -> Option<String> {
    let inner = line.strip_prefix("print(")?.strip_suffix(')')?.trim();
    if inner.is_empty() {
        return Some(String::new());
    }

    if (inner.starts_with('"') && inner.ends_with('"'))
        || (inner.starts_with('\'') && inner.ends_with('\''))
    {
        let literal = &inner[1..inner.len() - 1];
        return Some(
            literal
                .replace("\\n", "\n")
                .replace("\\t", "\t")
                .replace("\\\"", "\"")
                .replace("\\'", "'"),
        );
    }

    Some(inner.to_string())
}

#[derive(Clone, Debug)]
struct PingRequest {
    target: String,
    count: Option<u32>,
}

fn parse_ping_request(args: &[String]) -> Option<PingRequest> {
    let mut index = 0;
    let mut count = None;
    let mut target = None;

    while index < args.len() {
        match args[index].as_str() {
            "-c" if index + 1 < args.len() => {
                let parsed = args[index + 1].parse::<u32>().ok()?;
                count = Some(parsed.clamp(1, 120));
                index += 2;
            }
            "-W" | "-w" | "-i" | "-s" | "-t" if index + 1 < args.len() => {
                index += 2;
            }
            value if value.starts_with('-') => {
                index += 1;
            }
            value => {
                target = Some(value.to_string());
                break;
            }
        }
    }

    Some(PingRequest {
        target: target?,
        count,
    })
}

fn render_synthetic_ping(session_id: u64, hostname: &str, request: &PingRequest) -> String {
    let resolved_ip = resolve_ping_target(session_id, hostname, request.target.as_str());
    let count = request.count.unwrap_or(4).clamp(1, 120);
    let mut lines = vec![
        render_ping_header(request, resolved_ip.as_str())
            .trim_end()
            .to_string(),
    ];

    let mut samples = Vec::new();
    for sequence in 1..=count {
        let latency = synthetic_ping_latency(session_id, request.target.as_str(), sequence);
        samples.push(latency);
        lines.push(
            render_ping_reply(resolved_ip.as_str(), sequence, latency)
                .trim_end()
                .to_string(),
        );
    }

    lines.push(
        render_ping_summary(request, count, samples.as_slice())
            .trim_end()
            .to_string(),
    );
    format!("{}\r\n", lines.join("\r\n"))
}

fn resolve_ping_target(session_id: u64, hostname: &str, target: &str) -> String {
    target
        .parse::<std::net::IpAddr>()
        .map(|ip| ip.to_string())
        .unwrap_or_else(|_| synthetic_public_ipv4(session_id, hostname, target))
}

fn render_ping_header(request: &PingRequest, resolved_ip: &str) -> String {
    format!(
        "PING {} ({}) 56(84) bytes of data.\r\n",
        request.target, resolved_ip
    )
}

fn render_ping_reply(resolved_ip: &str, sequence: u32, latency: f32) -> String {
    format!(
        "64 bytes from {}: icmp_seq={} ttl=53 time={:.1} ms\r\n",
        resolved_ip, sequence, latency
    )
}

fn render_ping_summary(request: &PingRequest, transmitted: u32, samples: &[f32]) -> String {
    if samples.is_empty() {
        return format!(
            "--- {} ping statistics ---\r\n0 packets transmitted, 0 received, 100% packet loss, time 0ms\r\n",
            request.target
        );
    }

    let min = samples.iter().copied().fold(f32::INFINITY, f32::min);
    let max = samples.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let avg = samples.iter().sum::<f32>() / samples.len() as f32;
    let variance = samples
        .iter()
        .map(|sample| {
            let delta = sample - avg;
            delta * delta
        })
        .sum::<f32>()
        / samples.len() as f32;
    let mdev = variance.sqrt();
    let elapsed_ms = transmitted.saturating_sub(1) * 1000;

    format!(
        "--- {} ping statistics ---\r\n{} packets transmitted, {} received, 0% packet loss, time {}ms\r\nrtt min/avg/max/mdev = {:.3}/{:.3}/{:.3}/{:.3} ms\r\n",
        request.target, transmitted, transmitted, elapsed_ms, min, avg, max, mdev
    )
}

fn synthetic_public_ipv4(session_id: u64, hostname: &str, target: &str) -> String {
    let hash = stable_hash(format!("ping:{}:{}:{}", session_id, hostname, target).as_str());
    let first_octets = [
        23u8, 31, 45, 47, 52, 54, 61, 64, 69, 81, 103, 121, 139, 150, 170, 182,
    ];
    let first = first_octets[(hash as usize) % first_octets.len()];
    let second = ((hash >> 8) & 0xff) as u8;
    let third = ((hash >> 16) & 0xff) as u8;
    let fourth = (((hash >> 24) & 0xfe) as u8).saturating_add(1);
    format!("{first}.{second}.{third}.{fourth}")
}

fn synthetic_ping_latency(session_id: u64, target: &str, sequence: u32) -> f32 {
    let hash = stable_hash(format!("latency:{}:{}:{}", session_id, target, sequence).as_str());
    30.0 + ((hash % 200) as f32 / 10.0)
}

#[derive(Clone, Debug)]
struct SshInvocation {
    target_user: Option<String>,
    target_host: String,
    port: u16,
    identity_file: Option<String>,
    proxy_jump: Option<String>,
    forwardings: usize,
    remote_command: Option<String>,
}

impl SshInvocation {
    fn display_target(&self) -> String {
        self.target_user
            .as_ref()
            .map(|user| format!("{user}@{}", self.target_host))
            .unwrap_or_else(|| self.target_host.clone())
    }

    fn audit_details(&self, actor: &str) -> String {
        format!(
            "actor={} target_user={} target_host={} port={} identity_file={} proxy_jump={} forwardings={} remote_command={}",
            actor,
            self.target_user.as_deref().unwrap_or("none"),
            self.target_host,
            self.port,
            self.identity_file.as_deref().unwrap_or("none"),
            self.proxy_jump.as_deref().unwrap_or("none"),
            self.forwardings,
            self.remote_command.as_deref().unwrap_or("none"),
        )
    }
}

fn parse_ssh_invocation(args: &[String]) -> Option<SshInvocation> {
    let mut index = 0;
    let mut port = 22;
    let mut identity_file = None;
    let mut proxy_jump = None;
    let mut forwardings = 0usize;
    let mut target = None;
    let mut remote_command = None;

    while index < args.len() {
        match args[index].as_str() {
            "-p" if index + 1 < args.len() => {
                port = args[index + 1].parse().ok()?;
                index += 2;
            }
            "-i" if index + 1 < args.len() => {
                identity_file = Some(args[index + 1].clone());
                index += 2;
            }
            "-J" if index + 1 < args.len() => {
                proxy_jump = Some(args[index + 1].clone());
                index += 2;
            }
            "-L" | "-R" | "-D" if index + 1 < args.len() => {
                forwardings += 1;
                index += 2;
            }
            value if value.starts_with('-') => {
                index += 1;
            }
            value => {
                target = Some(value.to_string());
                if index + 1 < args.len() {
                    remote_command = Some(args[index + 1..].join(" "));
                }
                break;
            }
        }
    }

    let target = target?;
    let (target_user, target_host) = if let Some((user, host)) = target.split_once('@') {
        (Some(user.to_string()), host.to_string())
    } else {
        (None, target)
    };

    Some(SshInvocation {
        target_user,
        target_host,
        port,
        identity_file,
        proxy_jump,
        forwardings,
        remote_command,
    })
}

fn parse_crontab_target_user(args: &[String]) -> Option<&str> {
    args.windows(2)
        .find(|window| window[0] == "-u")
        .map(|window| window[1].as_str())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScriptConnector {
    Always,
    OnSuccess,
}

fn split_shell_commands(script: &str) -> Vec<(String, ScriptConnector)> {
    let mut commands = Vec::new();
    let mut start = 0usize;
    let mut in_single = false;
    let mut in_double = false;
    let chars = script.char_indices().collect::<Vec<_>>();
    let mut next_connector = ScriptConnector::Always;
    let mut index = 0usize;

    while index < chars.len() {
        let (offset, ch) = chars[index];
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            ';' if !in_single && !in_double => {
                let segment = script[start..offset].trim();
                if !segment.is_empty() {
                    commands.push((segment.to_string(), next_connector));
                }
                next_connector = ScriptConnector::Always;
                start = offset + ch.len_utf8();
            }
            '&' if !in_single && !in_double => {
                let next = chars.get(index + 1).map(|(_, next)| *next);
                if next == Some('&') {
                    let segment = script[start..offset].trim();
                    if !segment.is_empty() {
                        commands.push((segment.to_string(), next_connector));
                    }
                    next_connector = ScriptConnector::OnSuccess;
                    let next_offset = chars[index + 1].0 + '&'.len_utf8();
                    start = next_offset;
                    index += 1;
                }
            }
            _ => {}
        }
        index += 1;
    }

    let segment = script[start..].trim();
    if !segment.is_empty() {
        commands.push((segment.to_string(), next_connector));
    }

    commands
}

fn split_shell_redirection(command: &str) -> Option<(&str, bool, &str)> {
    let mut in_single = false;
    let mut in_double = false;
    let chars = command.char_indices().collect::<Vec<_>>();
    let mut index = 0usize;

    while index < chars.len() {
        let (offset, ch) = chars[index];
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '>' if !in_single && !in_double => {
                let append = chars.get(index + 1).is_some_and(|(_, next)| *next == '>');
                let rhs_start = if append {
                    chars
                        .get(index + 1)
                        .map(|(next_offset, _)| next_offset + '>'.len_utf8())
                        .unwrap_or(offset + ch.len_utf8())
                } else {
                    offset + ch.len_utf8()
                };
                return Some((&command[..offset], append, &command[rhs_start..]));
            }
            _ => {}
        }
        index += 1;
    }

    None
}

fn split_shell_words(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut chars = line.chars().peekable();
    let mut in_single = false;
    let mut in_double = false;

    while let Some(ch) = chars.next() {
        match ch {
            '\'' if !in_double => {
                in_single = !in_single;
            }
            '"' if !in_single => {
                in_double = !in_double;
            }
            '\\' if !in_single => {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            _ if ch.is_whitespace() && !in_single && !in_double => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(ch),
        }
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    tokens
}

fn split_completion_fragment(fragment: &str) -> (String, String) {
    if let Some((dir, basename)) = fragment.rsplit_once('/') {
        let dir_prefix = if fragment.starts_with('/') {
            format!("{dir}/")
        } else if dir.is_empty() {
            "/".to_string()
        } else {
            format!("{dir}/")
        };
        (dir_prefix, basename.to_string())
    } else {
        (String::new(), fragment.to_string())
    }
}

fn longest_common_prefix(candidates: &[String]) -> String {
    let Some(first) = candidates.first() else {
        return String::new();
    };

    let mut prefix = first.clone();
    for candidate in candidates.iter().skip(1) {
        let common_len = prefix
            .chars()
            .zip(candidate.chars())
            .take_while(|(left, right)| left == right)
            .count();
        prefix = prefix.chars().take(common_len).collect();
        if prefix.is_empty() {
            break;
        }
    }
    prefix
}

fn to_crlf(contents: &str) -> String {
    let mut output = String::new();
    for line in contents.lines() {
        output.push_str(line);
        output.push_str("\r\n");
    }
    output
}

fn fake_last_login_timestamp() -> String {
    "Tue Apr 14 03:12:18 2026".to_string()
}

fn unix_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::{
        InputMode, OPENSSH_SERVER_ID, ShellEvent, ShellIdentity, ShellState, SshJailService,
        VirtualFilesystem, load_server_host_key_from_paths, normalize_path, run_local_trap_command,
        run_local_trap_login,
    };
    use crate::ssh_overlay::{
        DynamicBlacklistStore, PendingTrapRecord, SshOverlayPaths, TRAP_LOGIN_SHELL_PATH,
        TrapTriggerKind,
    };
    use rand::rng;
    use russh::keys::{Algorithm, PrivateKey, ssh_key::LineEnding};
    use walle_policy::{SshJailHostnameStrategy, SshJailPolicy};

    fn drive_interactive_command(shell: &mut ShellState, line: &str) {
        let input = format!("{line}\r");
        for event in shell.ingest_input(input.as_bytes()) {
            if let ShellEvent::Command(input) = event {
                let result = shell.execute_line(input.line.as_str());
                if input.history && result.record_history {
                    shell.record_history_entry(input.line.as_str());
                }
            }
        }
    }

    #[test]
    fn normalize_path_collapses_relative_components() {
        assert_eq!(normalize_path("/var/www/../log/./nginx"), "/var/log/nginx");
    }

    #[test]
    fn tomcat_persona_exposes_webapps_directory() {
        let filesystem = VirtualFilesystem::for_login_user("tomcat");
        let entries = filesystem.list("/opt/tomcat", false).unwrap();
        assert!(entries.contains(&"webapps".to_string()));
        assert!(entries.contains(&"conf".to_string()));
    }

    #[test]
    fn fallback_persona_preserves_requested_username() {
        let identity = ShellIdentity::for_user("test1");
        assert_eq!(identity.username, "test1");
        assert_eq!(identity.home, "/home/test1");
    }

    #[test]
    fn shell_supports_sudo_then_exit_back_to_login_user() {
        let mut shell = ShellState::new("ubuntu", "web-01", None, Duration::from_secs(600), 1);
        let _ = shell.execute_line("sudo -i");
        assert_eq!(shell.current_identity().username, "root");
        let _ = shell.execute_line("exit");
        assert_eq!(shell.current_identity().username, "ubuntu");
    }

    #[test]
    fn shell_emulates_real_attacker_exec_recon_commands() {
        let mut shell = ShellState::new("root", "web-01", None, Duration::from_secs(600), 2);

        let uname_machine = shell.execute_line(r#"bash -c 'uname -m'"#);
        assert_eq!(uname_machine.output, "x86_64\r\n");
        assert_eq!(uname_machine.exit_status, 0);

        let nproc = shell.execute_line(r#"bash -c 'nproc'"#);
        assert_eq!(nproc.output, "4\r\n");

        let apt_lookup =
            shell.execute_line(r#"bash -c 'which apt 2>/dev/null || command -v apt 2>/dev/null'"#);
        assert_eq!(apt_lookup.output, "/usr/bin/apt\r\n");
        assert_eq!(apt_lookup.exit_status, 0);

        let yum_lookup =
            shell.execute_line(r#"bash -c 'which yum 2>/dev/null || command -v yum 2>/dev/null'"#);
        assert!(yum_lookup.output.is_empty());
        assert_eq!(yum_lookup.exit_status, 1);

        let apt_file_probe = shell.execute_line(
            r#"bash -c 'test -f /usr/bin/apt && echo '\''found'\'' || test -f /bin/apt && echo '\''found'\'' || test -f /usr/local/bin/apt && echo '\''found'\''' "#,
        );
        assert_eq!(apt_file_probe.output, "found\r\n");
        assert_eq!(apt_file_probe.exit_status, 0);

        let apt_version = shell.execute_line(
            r#"bash -c 'apt --version 2>/dev/null || apt --help 2>/dev/null | head -1'"#,
        );
        assert!(apt_version.output.contains("apt 2.4.11"));
        assert_eq!(apt_version.exit_status, 0);

        let os_release = shell.execute_line(
            r#"bash -c 'cat /etc/os-release 2>/dev/null | grep -E '\''^(NAME|PRETTY_NAME)='\'' | head -1'"#,
        );
        assert_eq!(os_release.output, "NAME=\"Ubuntu\"\r\n");
        assert_eq!(os_release.exit_status, 0);

        let free_total =
            shell.execute_line(r#"bash -c 'free -k | awk '\''/^Mem:/{print $2}'\''' "#);
        assert_eq!(free_total.output, "2048576\r\n");
        assert_eq!(free_total.exit_status, 0);

        let java_version = shell.execute_line(r#"bash -c 'java -version 2>&1 | head -1'"#);
        assert!(java_version.output.contains("openjdk version"));
    }

    #[test]
    fn non_root_personas_share_exec_probe_support() {
        let mut shell = ShellState::new("tomcat", "web-01", None, Duration::from_secs(600), 3);

        assert_eq!(shell.execute_line("pwd").output, "/opt/tomcat\r\n");

        let apt_lookup =
            shell.execute_line(r#"bash -c 'which apt 2>/dev/null || command -v apt 2>/dev/null'"#);
        assert_eq!(apt_lookup.output, "/usr/bin/apt\r\n");
        assert_eq!(apt_lookup.exit_status, 0);

        let os_release = shell.execute_line(
            r#"bash -c 'cat /etc/os-release 2>/dev/null | grep -E '\''^(NAME|PRETTY_NAME)='\'' | head -1'"#,
        );
        assert_eq!(os_release.output, "NAME=\"Ubuntu\"\r\n");
    }

    #[test]
    fn interactive_root_directories_are_traversable_and_cat_respects_types() {
        let mut shell = ShellState::new("root", "web-d249", None, Duration::from_secs(600), 4);

        assert_eq!(shell.execute_line("ls").output, "loot  scripts\r\n");

        let cd_root = shell.execute_line("cd /");
        assert_eq!(cd_root.exit_status, 0);
        let cd_boot = shell.execute_line("cd boot");
        assert_eq!(cd_boot.exit_status, 0);
        assert_eq!(shell.execute_line("pwd").output, "/boot\r\n");
        assert_eq!(shell.execute_line("cd").exit_status, 0);
        assert_eq!(shell.execute_line("pwd").output, "/root\r\n");

        let cd_loot = shell.execute_line("cd loot");
        assert_eq!(cd_loot.exit_status, 0);
        assert_eq!(shell.execute_line("pwd").output, "/root/loot\r\n");

        let loot_listing = shell.execute_line("ls");
        assert!(loot_listing.output.contains("credentials.txt"));
        assert!(loot_listing.output.contains("db01-notes.txt"));

        let cat_loot_file = shell.execute_line("cat credentials.txt");
        assert!(cat_loot_file.output.contains("mysql_root_password"));
        assert_eq!(cat_loot_file.exit_status, 0);

        let cat_directory = shell.execute_line("cat .");
        assert_eq!(cat_directory.output, "cat: .: Is a directory\r\n");
        assert_eq!(cat_directory.exit_status, 1);

        let cd_scripts = shell.execute_line("cd ../scripts");
        assert_eq!(cd_scripts.exit_status, 0);
        assert_eq!(shell.execute_line("pwd").output, "/root/scripts\r\n");

        let cat_script = shell.execute_line("cat backup.sh");
        assert!(cat_script.output.contains("rsync -a /var/www/"));
    }

    #[test]
    fn ssh_persistence_commands_update_virtual_filesystem() {
        let mut shell = ShellState::new("root", "web-d249", None, Duration::from_secs(600), 41);
        let key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCtrapkey material mdrfckr";

        let unlock = shell.execute_line("cd ~; chattr -ia .ssh; lockr -ia .ssh");
        assert_eq!(unlock.exit_status, 0);

        let persist = shell.execute_line(
            format!(
                "cd ~ && rm -rf .ssh && mkdir .ssh && echo \"{key}\">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~"
            )
            .as_str(),
        );
        assert_eq!(persist.exit_status, 0);

        let listing = shell.execute_line("ls -la ~/.ssh");
        assert!(listing.output.contains("authorized_keys"));

        let authorized_keys = shell.execute_line("cat ~/.ssh/authorized_keys");
        assert_eq!(authorized_keys.output, format!("{key}\r\n"));
        assert_eq!(authorized_keys.exit_status, 0);
    }

    #[test]
    fn interactive_network_commands_return_plausible_output() {
        let mut shell = ShellState::new("root", "web-d249", None, Duration::from_secs(600), 5);

        let ifconfig = shell.execute_line("ifconfig");
        assert!(ifconfig.output.contains("eth0: flags=4163"));
        assert!(ifconfig.output.contains("inet 10.0.0.24"));
        assert!(ifconfig.output.contains("lo: flags=73"));
        assert_eq!(ifconfig.exit_status, 0);

        let ifconfig_lo = shell.execute_line("ifconfig lo");
        assert!(ifconfig_lo.output.contains("lo: flags=73"));
        assert!(!ifconfig_lo.output.contains("eth0:"));
        assert_eq!(ifconfig_lo.exit_status, 0);

        let ip_addr = shell.execute_line("ip addr show eth0");
        assert!(ip_addr.output.contains("2: eth0:"));
        assert!(ip_addr.output.contains("inet 10.0.0.24/24"));
        assert_eq!(ip_addr.exit_status, 0);

        let ss = shell.execute_line("ss -lntp");
        assert!(ss.output.contains("0.0.0.0:22"));
        assert!(ss.output.contains("sshd"));

        let ping = shell.execute_line("ping -c 2 example.com");
        assert!(ping.output.contains("PING example.com"));
        assert!(ping.output.contains("icmp_seq=1"));
        assert!(ping.output.contains("packets transmitted, 2 received"));
    }

    #[test]
    fn shell_exposes_process_runtime_and_disk_views() {
        let mut shell = ShellState::new("tomcat", "web-01", None, Duration::from_secs(600), 6);

        let ps = shell.execute_line("ps aux");
        assert!(ps.output.contains("sshd: /usr/sbin/sshd -D"));
        assert!(
            ps.output
                .contains("org.apache.catalina.startup.Bootstrap start")
        );

        let df = shell.execute_line("df -h");
        assert!(df.output.contains("/dev/vda1"));
        assert!(df.output.contains("/srv/backups"));

        let uptime = shell.execute_line("uptime");
        assert!(uptime.output.contains("load average"));

        let env = shell.execute_line("env");
        assert!(env.output.contains("HOME=/opt/tomcat"));
        assert!(env.output.contains("USER=tomcat"));

        let java = shell.execute_line("java -version");
        assert!(java.output.contains("openjdk version"));
        let python = shell.execute_line("python3 --version");
        assert!(python.output.contains("Python 3.10.12"));
    }

    #[test]
    fn runtime_commands_expose_help_and_python_repl() {
        let mut shell = ShellState::new("tomcat", "web-01", None, Duration::from_secs(600), 61);

        let java_help = shell.execute_line("java");
        assert!(java_help.output.contains("Usage: java"));

        let java_short_help = shell.execute_line("java -h");
        assert!(java_short_help.output.contains("Usage: java"));

        let java_version = shell.execute_line("java -V");
        assert!(java_version.output.contains("openjdk version"));

        let javac_help = shell.execute_line("javac");
        assert!(javac_help.output.contains("Usage: javac"));

        let python = shell.execute_line("python");
        assert!(python.output.contains("Python 3.10.12"));
        assert!(matches!(shell.input_mode, InputMode::PythonRepl));

        let print = shell.execute_line(r#"print("hello")"#);
        assert_eq!(print.output, "hello\r\n");

        let help = shell.execute_line("help()");
        assert!(help.output.contains("Type help(object)"));

        let exit = shell.execute_line("exit()");
        assert!(exit.output.is_empty());
        assert!(matches!(shell.input_mode, InputMode::Normal));
    }

    #[test]
    fn shell_exposes_web_configs_and_login_traces() {
        let mut shell = ShellState::new("root", "web-01", None, Duration::from_secs(600), 7);

        let ls_long = shell.execute_line("ls -la /etc/ssh");
        assert!(ls_long.output.contains("sshd_config"));

        let tree = shell.execute_line("tree /etc");
        assert!(tree.output.contains("ssh"));
        assert!(tree.output.contains("nginx"));

        let auth_log = shell.execute_line("cat /var/log/auth.log");
        assert!(auth_log.output.contains("Accepted password for tomcat"));

        let last = shell.execute_line("last");
        assert!(last.output.contains("still logged in"));

        let who = shell.execute_line("who");
        assert!(who.output.contains("pts/0"));

        let history = shell.execute_line("history");
        assert!(history.output.contains("mysql -uroot -p"));

        let crontab = shell.execute_line("crontab -l");
        assert!(crontab.output.contains("/root/scripts/backup.sh"));
    }

    #[test]
    fn interactive_history_tracks_attacker_commands() {
        let mut shell = ShellState::new("root", "web-01", None, Duration::from_secs(600), 71);

        drive_interactive_command(&mut shell, "ls");
        drive_interactive_command(&mut shell, "uptime");
        drive_interactive_command(&mut shell, "python");
        let _ = shell.execute_line("exit()");

        let history = shell.execute_line("history");
        assert!(history.output.contains("ls"));
        assert!(history.output.contains("uptime"));
        assert!(history.output.contains("python"));
    }

    #[test]
    fn silent_success_commands_still_enter_history() {
        let mut shell = ShellState::new("tomcat", "web-01", None, Duration::from_secs(600), 72);

        drive_interactive_command(&mut shell, "cd /");
        drive_interactive_command(&mut shell, "ssh root@172.20.1.40");

        assert!(shell.session_history.iter().any(|line| line == "cd /"));
        assert!(
            shell
                .session_history
                .iter()
                .any(|line| line == "ssh root@172.20.1.40")
        );
    }

    #[test]
    fn ssh_command_prompts_for_password_and_records_metadata_without_secret_capture() {
        let mut shell = ShellState::new("root", "web-01", None, Duration::from_secs(600), 8);
        let result = shell.execute_line("ssh -p 2222 -i ~/.ssh/id_ed25519 deploy@example.net");
        assert_eq!(result.exit_status, 0);
        assert!(result.output.is_empty());
        assert_eq!(shell.prompt(), "deploy@example.net's password: ");
        assert!(matches!(shell.input_mode, InputMode::HiddenInput(_)));
        assert_eq!(result.audit_events.len(), 1);
        assert_eq!(result.audit_events[0].event, "ssh_outbound");
        assert!(
            result.audit_events[0]
                .details
                .contains("target_host=example.net")
        );
        assert!(
            result.audit_events[0]
                .details
                .contains("identity_file=~/.ssh/id_ed25519")
        );

        let first_try = shell.execute_line("hunter2");
        assert_eq!(first_try.output, "Permission denied, please try again.\r\n");
        assert!(!first_try.record_history);
        assert!(matches!(shell.input_mode, InputMode::HiddenInput(_)));

        let second_try = shell.execute_line("hunter2");
        assert_eq!(
            second_try.output,
            "Permission denied, please try again.\r\n"
        );
        assert!(!second_try.record_history);
        assert!(matches!(shell.input_mode, InputMode::HiddenInput(_)));

        let third_try = shell.execute_line("hunter2");
        assert_eq!(
            third_try.output,
            "Permission denied (publickey,password).\r\n"
        );
        assert!(!third_try.record_history);
        assert!(matches!(shell.input_mode, InputMode::Normal));

        let verbose = shell.execute_line("ssh -v root@172.20.1.40");
        assert!(verbose.output.is_empty());
        assert_eq!(shell.prompt(), "root@172.20.1.40's password: ");
        assert!(matches!(shell.input_mode, InputMode::HiddenInput(_)));
    }

    #[test]
    fn interactive_ping_defaults_to_continuous_mode() {
        let shell = ShellState::new("root", "web-01", None, Duration::from_secs(600), 81);

        let default_ping = shell
            .prepare_interactive_ping("ping 223.5.5.5")
            .expect("plain ping should prepare an interactive stream");
        assert_eq!(default_ping.count, None);

        let counted_ping = shell
            .prepare_interactive_ping("ping -c 3 example.com")
            .expect("counted ping should prepare an interactive stream");
        assert_eq!(counted_ping.count, Some(3));
    }

    #[test]
    fn tab_completion_supports_commands_and_paths() {
        let mut shell = ShellState::new("root", "web-01", None, Duration::from_secs(600), 9);

        shell.line_buffer = "his".to_string();
        let events = shell.ingest_input(b"\t");
        assert_eq!(shell.line_buffer, "history ");
        assert!(matches!(events.last(), Some(super::ShellEvent::Echo(_))));

        shell.line_buffer = "p".to_string();
        let events = shell.ingest_input(b"\t");
        assert!(matches!(
            events.last(),
            Some(super::ShellEvent::CompletionMenu(menu)) if menu.contains("ps") && menu.contains("ping")
        ));

        shell.line_buffer = "cd /et".to_string();
        let events = shell.ingest_input(b"\t");
        assert_eq!(shell.line_buffer, "cd /etc/");
        assert!(matches!(events.last(), Some(super::ShellEvent::Echo(_))));
    }

    #[test]
    fn dynamic_port_listener_binds_successfully() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root_dir = std::env::temp_dir().join(format!("walle-sshjail-{nanos}"));
        let service = SshJailService::start(&SshJailPolicy {
            listen_port: 0,
            root_dir: root_dir.to_string_lossy().to_string(),
            hostname_strategy: SshJailHostnameStrategy::Generated,
            ..SshJailPolicy::default()
        })
        .expect("sshjail service should start");

        assert_ne!(service.bound_port(), 0);
        assert!(service.can_accept_new_session());
    }

    #[test]
    fn openssh_server_id_has_valid_ssh_prefix() {
        assert!(OPENSSH_SERVER_ID.starts_with("SSH-2.0-"));
    }

    #[test]
    fn host_key_loader_reuses_existing_system_key() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("walle-sshjail-hostkey-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ssh_host_ed25519_key");
        let key = PrivateKey::random(&mut rng(), Algorithm::Ed25519).unwrap();
        key.write_openssh_file(&path, LineEnding::LF).unwrap();

        let loaded = load_server_host_key_from_paths(&[path]);

        assert_eq!(
            loaded.unwrap().public_key().to_openssh().unwrap(),
            key.public_key().to_openssh().unwrap()
        );
    }

    #[test]
    fn host_key_loader_falls_back_when_no_system_key_exists() {
        let path = PathBuf::from("/tmp/walle-sshjail-missing-host-key");
        let loaded = load_server_host_key_from_paths(&[path]).unwrap();
        assert!(!loaded.public_key().to_openssh().unwrap().is_empty());
    }

    #[test]
    fn dynamic_blacklist_store_persists_and_deduplicates_keys() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root_dir = std::env::temp_dir().join(format!("walle-sshjail-store-{nanos}"));
        let paths = SshOverlayPaths::from_policy(&SshJailPolicy {
            root_dir: root_dir.to_string_lossy().to_string(),
            ..SshJailPolicy::default()
        });
        paths.ensure_dirs().unwrap();

        let store = DynamicBlacklistStore::load(paths.dynamic_blacklist_keys_path.clone());
        let key = PrivateKey::random(&mut rng(), Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .to_openssh()
            .unwrap();

        assert!(store.record(key.as_str()).unwrap());
        assert!(!store.record(key.as_str()).unwrap());
        assert_eq!(store.entries(), vec![key.clone()]);

        let persisted = std::fs::read_to_string(paths.dynamic_blacklist_keys_path).unwrap();
        assert_eq!(persisted, format!("{key}\n"));
    }

    #[test]
    fn local_trap_command_executes_pending_command_and_consumes_token() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root_dir = std::env::temp_dir().join(format!("walle-local-trap-{nanos}"));
        let policy = SshJailPolicy {
            root_dir: root_dir.to_string_lossy().to_string(),
            hostname_strategy: SshJailHostnameStrategy::Generated,
            ..SshJailPolicy::default()
        };
        let paths = SshOverlayPaths::from_policy(&policy);
        let key = PrivateKey::random(&mut rng(), Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .to_openssh()
            .unwrap();
        let record = PendingTrapRecord::create(
            &paths,
            "root",
            Some(0),
            Some("/root"),
            TrapTriggerKind::BlacklistedKey,
            crate::ssh_overlay::PresentedPublicKey::from_authorized_keys_command(
                key.split_whitespace().next().unwrap(),
                key.split_whitespace().nth(1).unwrap(),
                "",
            )
            .unwrap(),
        )
        .unwrap();

        unsafe {
            std::env::set_var("SSH_ORIGINAL_COMMAND", "cd /root");
        }
        let exit_status = run_local_trap_command(&policy, record.token.as_str()).unwrap();
        unsafe {
            std::env::remove_var("SSH_ORIGINAL_COMMAND");
        }

        assert_eq!(exit_status, 0);
        assert!(
            PendingTrapRecord::consume(&paths, record.token.as_str())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn local_trap_login_executes_overlay_identity_command() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root_dir = std::env::temp_dir().join(format!("walle-local-trap-login-{nanos}"));
        let policy = SshJailPolicy {
            root_dir: root_dir.to_string_lossy().to_string(),
            hostname_strategy: SshJailHostnameStrategy::Generated,
            ..SshJailPolicy::default()
        };
        let paths = SshOverlayPaths::from_policy(&policy);
        paths.ensure_dirs().unwrap();

        let uid = unsafe { libc::getuid() };
        let identity_home = paths.trap_home_dir.join("tomcat");
        std::fs::create_dir_all(&identity_home).unwrap();
        std::fs::write(
            &paths.trap_identities_path,
            format!(
                "tomcat\t{uid}\t{uid}\t{}\t{}\tWalle SSH trap identity\n",
                identity_home.display(),
                TRAP_LOGIN_SHELL_PATH
            ),
        )
        .unwrap();

        let exit_status = run_local_trap_login(&policy).unwrap();

        assert_eq!(exit_status, 0);

        let session_logs = std::fs::read_dir(&paths.session_audit_dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        assert_eq!(session_logs.len(), 1);
        let audit = std::fs::read_to_string(&session_logs[0]).unwrap();
        assert!(audit.contains("entrypoint=sshd_identity_overlay"));
        assert!(audit.contains("trigger=trap_username"));
        assert!(audit.contains("auth_succeeded session authenticated"));
        assert!(audit.contains("channel_open_session channel=stdio"));
        assert!(audit.contains("connection_close local trap login finished"));
    }
}
