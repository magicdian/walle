use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::rng;
use russh::keys::{Algorithm, PrivateKey, PublicKey};
use russh::server::{Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelId, Disconnect, MethodKind, MethodSet, Pty, SshId};
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::runtime::Builder;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};
use tracing::{error, info, warn};
use walle_policy::{SshJailHostnameStrategy, SshJailPolicy};

const OPENSSH_SERVER_ID: &str = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5";
const DEFAULT_OS_RELEASE: &str = "5.15.0-113-generic";
const DEFAULT_OS_BANNER: &str = "Ubuntu 22.04.4 LTS";
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
        let audit_dir = PathBuf::from(policy.audit_dir.trim());
        fs::create_dir_all(&audit_dir).map_err(|source| SshJailError::CreateAuditDir {
            path: audit_dir.clone(),
            source,
        })?;

        let hostname = resolve_hostname(policy)?;
        let shared = Arc::new(SshJailShared::new(policy, hostname, audit_dir));
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
            audit_dir = %shared.audit_dir.display(),
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
    #[error("failed to create sshjail audit directory '{}': {source}", .path.display())]
    CreateAuditDir {
        path: PathBuf,
        source: std::io::Error,
    },
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
    audit_dir: PathBuf,
    max_sessions: usize,
    max_session_duration: Duration,
    permits: Arc<Semaphore>,
    session_ids: AtomicU64,
    auth_methods: MethodSet,
}

impl SshJailShared {
    fn new(policy: &SshJailPolicy, hostname: String, audit_dir: PathBuf) -> Self {
        let mut auth_methods = MethodSet::empty();
        auth_methods.push(MethodKind::Password);
        auth_methods.push(MethodKind::PublicKey);

        Self {
            hostname,
            audit_dir,
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
        let audit = SessionAudit::new(self.shared.audit_dir.as_path(), session_id, peer_addr);
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
    rejected_for_capacity: bool,
}

impl Drop for SshJailHandler {
    fn drop(&mut self) {
        self.audit.record("connection_close", "handler dropped");
    }
}

impl SshJailHandler {
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
        self.audit.record("session_timeout", "max session duration reached");
        Ok(true)
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
        self.audit.record(
            "auth_password",
            format!("user={user} password={password}"),
        );

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
        self.audit.record(
            "auth_publickey_offered",
            format!("user={user} algorithm={:?}", public_key.algorithm()),
        );

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
        self.audit.record(
            "auth_publickey",
            format!("user={user} algorithm={:?}", public_key.algorithm()),
        );

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

        if let Some(shell) = &mut self.shell {
            let result = shell.execute_line(command.as_str());
            self.audit
                .record("command", format!("channel={channel} command={command}"));
            if !result.output.is_empty() {
                session.data(channel, result.output.into_bytes())?;
            }
            session.exit_status_request(channel, 0)?;
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
        if self.rejected_for_capacity {
            session.close(channel)?;
            return Ok(());
        }

        if self.disconnect_if_expired(channel, session)? {
            return Ok(());
        }

        let Some(shell) = &mut self.shell else {
            session.close(channel)?;
            return Ok(());
        };

        let events = shell.ingest_input(data);
        for event in events {
            match event {
                ShellEvent::Echo(bytes) => {
                    session.data(channel, bytes)?;
                }
                ShellEvent::Command(line) => {
                    self.audit
                        .record("command", format!("channel={channel} command={line}"));
                    let result = shell.execute_line(line.as_str());
                    if !result.output.is_empty() {
                        session.data(channel, result.output.into_bytes())?;
                    }
                    if result.close_channel {
                        session.exit_status_request(channel, 0)?;
                        session.eof(channel)?;
                        session.close(channel)?;
                        return Ok(());
                    }
                    session.data(channel, shell.prompt().into_bytes())?;
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
    filesystem: VirtualFilesystem,
    identities: Vec<ShellIdentity>,
    line_buffer: String,
    pending_cr: bool,
    started_at: SystemTime,
    max_session_duration: Duration,
}

impl ShellState {
    fn new(
        username: &str,
        hostname: &str,
        peer_addr: Option<SocketAddr>,
        max_session_duration: Duration,
    ) -> Self {
        let login_identity = ShellIdentity::for_user(username);
        let filesystem = VirtualFilesystem::for_login_user(username);
        Self {
            hostname: hostname.to_string(),
            peer_addr,
            active_channel: None,
            filesystem,
            identities: vec![login_identity],
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
            "Welcome to {} (GNU/Linux {} x86_64)\r\nLast login: {} from {}\r\n",
            DEFAULT_OS_BANNER,
            DEFAULT_OS_RELEASE,
            fake_last_login_timestamp(),
            peer
        )
    }

    fn prompt(&self) -> String {
        let identity = self.current_identity();
        format!(
            "{}@{}:{}{} ",
            identity.username,
            self.hostname,
            identity.display_path(),
            identity.prompt_symbol
        )
    }

    fn ingest_input(&mut self, data: &[u8]) -> Vec<ShellEvent> {
        let mut events = Vec::new();

        for byte in data {
            match *byte {
                b'\n' if self.pending_cr => {
                    self.pending_cr = false;
                }
                b'\r' | b'\n' => {
                    self.pending_cr = *byte == b'\r';
                    events.push(ShellEvent::Echo(b"\r\n".to_vec()));
                    let line = self.line_buffer.trim().to_string();
                    self.line_buffer.clear();
                    events.push(ShellEvent::Command(line));
                }
                8 | 127 => {
                    self.pending_cr = false;
                    if !self.line_buffer.is_empty() {
                        self.line_buffer.pop();
                        events.push(ShellEvent::Echo(b"\x08 \x08".to_vec()));
                    }
                }
                b'\t' => {
                    self.pending_cr = false;
                    events.push(ShellEvent::Echo(b"\x07".to_vec()));
                }
                0x20..=0x7e => {
                    self.pending_cr = false;
                    let ch = char::from(*byte);
                    self.line_buffer.push(ch);
                    events.push(ShellEvent::Echo(vec![*byte]));
                }
                _ => {}
            }
        }

        events
    }

    fn execute_line(&mut self, line: &str) -> CommandResult {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return CommandResult::default();
        }

        let tokens = trimmed.split_whitespace().collect::<Vec<_>>();
        let command = tokens[0];

        match command {
            "exit" => self.handle_exit(),
            "pwd" => CommandResult::output(format!("{}\r\n", self.current_identity().cwd)),
            "uname" => CommandResult::output(self.handle_uname(&tokens[1..])),
            "ls" => self.handle_ls(&tokens[1..]),
            "cd" => self.handle_cd(&tokens[1..]),
            "sudo" => self.handle_sudo(&tokens[1..]),
            "su" => self.handle_su(&tokens[1..]),
            "whoami" => CommandResult::output(format!(
                "{}\r\n",
                self.current_identity().username
            )),
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
            "echo" => CommandResult::output(format!("{}\r\n", tokens[1..].join(" "))),
            "clear" => CommandResult::output("\x1b[2J\x1b[H".to_string()),
            _ => CommandResult::output(format!("bash: {}: command not found\r\n", command)),
        }
    }

    fn handle_uname(&self, args: &[&str]) -> String {
        if args.iter().any(|arg| *arg == "-a") {
            format!(
                "Linux {} {} #86-Ubuntu SMP x86_64 GNU/Linux\r\n",
                self.hostname, DEFAULT_OS_RELEASE
            )
        } else {
            "Linux\r\n".to_string()
        }
    }

    fn handle_ls(&self, args: &[&str]) -> CommandResult {
        let show_hidden = args.iter().any(|arg| arg.starts_with('-') && arg.contains('a'));
        let path_arg = args.iter().find(|arg| !arg.starts_with('-')).copied();
        let target = match path_arg {
            Some(path) => self
                .filesystem
                .resolve_path(self.current_identity().cwd.as_str(), path),
            None => self.current_identity().cwd.clone(),
        };

        match self.filesystem.list(target.as_str(), show_hidden) {
            Some(entries) => CommandResult::output(format!("{}\r\n", entries.join("  "))),
            None => CommandResult::output(format!(
                "ls: cannot access '{}': No such file or directory\r\n",
                path_arg.unwrap_or(target.as_str())
            )),
        }
    }

    fn handle_cd(&mut self, args: &[&str]) -> CommandResult {
        let target = args.first().copied().unwrap_or("~");
        let resolved = self
            .filesystem
            .resolve_path(self.current_identity().cwd.as_str(), target);
        if !self.filesystem.is_dir(resolved.as_str()) {
            return CommandResult::output(format!(
                "bash: cd: {}: No such file or directory\r\n",
                target
            ));
        }

        let current = self.identities.last_mut().expect("shell identity should exist");
        current.cwd = resolved;
        CommandResult::default()
    }

    fn handle_sudo(&mut self, args: &[&str]) -> CommandResult {
        let mut index = 0;
        let mut target_user = "root";

        while index < args.len() {
            match args[index] {
                "-u" if index + 1 < args.len() => {
                    target_user = args[index + 1];
                    index += 2;
                }
                "-i" | "-s" => {
                    index += 1;
                }
                _ => break,
            }
        }

        let remainder = &args[index..];
        if remainder.is_empty()
            || matches!(remainder, ["su"] | ["bash"] | ["sh"])
        {
            self.push_identity(target_user);
            return CommandResult::default();
        }

        let saved = self.identities.clone();
        self.push_identity(target_user);
        let output = self.execute_line(&remainder.join(" "));
        self.identities = saved;
        output
    }

    fn handle_su(&mut self, args: &[&str]) -> CommandResult {
        let target_user = args
            .iter()
            .find(|arg| !arg.starts_with('-'))
            .copied()
            .unwrap_or("root");
        self.push_identity(target_user);
        CommandResult::default()
    }

    fn handle_exit(&mut self) -> CommandResult {
        if self.identities.len() > 1 {
            self.identities.pop();
            return CommandResult::default();
        }

        CommandResult {
            output: "logout\r\n".to_string(),
            close_channel: true,
        }
    }

    fn push_identity(&mut self, username: &str) {
        let identity = ShellIdentity::for_user(username);
        self.filesystem.ensure_identity(&identity);
        self.identities.push(identity);
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
            self.cwd
                .replacen(self.home.as_str(), "~", 1)
        } else {
            self.cwd.clone()
        }
    }
}

#[derive(Clone, Debug)]
struct VirtualFilesystem {
    entries: BTreeMap<String, Vec<String>>,
}

impl VirtualFilesystem {
    fn for_login_user(username: &str) -> Self {
        let mut entries = BTreeMap::new();
        entries.insert(
            "/".to_string(),
            vec![
                "bin", "boot", "dev", "etc", "home", "lib", "lib64", "media", "mnt", "opt",
                "proc", "root", "run", "sbin", "srv", "sys", "tmp", "usr", "var",
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
                "apache2", "cron.d", "hostname", "hosts", "mysql", "nginx", "passwd",
                "shadow", "ssh", "sudoers", "systemd", "tomcat",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
        );
        entries.insert(
            "/home".to_string(),
            vec![username.to_string(), "ubuntu".to_string(), "admin".to_string()],
        );

        let mut filesystem = Self { entries };
        filesystem.ensure_identity(&ShellIdentity::for_user(username));
        filesystem.ensure_identity(&ShellIdentity::for_user("root"));
        filesystem
    }

    fn ensure_identity(&mut self, identity: &ShellIdentity) {
        let parent = parent_dir(identity.home.as_str()).unwrap_or("/").to_string();
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
        dedupe_entries(self.entries.get_mut(parent.as_str()).expect("parent entry should exist"));
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
    path.rsplit('/').find(|part| !part.is_empty()).unwrap_or(path)
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

#[derive(Default)]
struct CommandResult {
    output: String,
    close_channel: bool,
}

impl CommandResult {
    fn output(output: String) -> Self {
        Self {
            output,
            close_channel: false,
        }
    }
}

enum ShellEvent {
    Echo(Vec<u8>),
    Command(String),
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

    use rand::rng;
    use russh::keys::{Algorithm, PrivateKey, ssh_key::LineEnding};
    use super::{
        OPENSSH_SERVER_ID, ShellIdentity, ShellState, SshJailService, VirtualFilesystem,
        load_server_host_key_from_paths, normalize_path,
    };
    use walle_policy::{SshJailHostnameStrategy, SshJailPolicy};

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
        let mut shell =
            ShellState::new("ubuntu", "web-01", None, Duration::from_secs(600));
        let _ = shell.execute_line("sudo -i");
        assert_eq!(shell.current_identity().username, "root");
        let _ = shell.execute_line("exit");
        assert_eq!(shell.current_identity().username, "ubuntu");
    }

    #[test]
    fn dynamic_port_listener_binds_successfully() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let audit_dir = std::env::temp_dir().join(format!("walle-sshjail-{nanos}"));
        let service = SshJailService::start(&SshJailPolicy {
            listen_port: 0,
            audit_dir: audit_dir.to_string_lossy().to_string(),
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
}
