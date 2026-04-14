use std::collections::{BTreeMap, BTreeSet, hash_map::DefaultHasher};
use std::fs;
use std::hash::{Hash, Hasher};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::random;
use russh::keys::{HashAlg, PublicKey, PublicKeyBase64};
use thiserror::Error;
use walle_policy::{GpStrategyKind, SshJailPolicy};

pub const NSS_SERVICE_NAME: &str = "walle";
pub const TRAP_LOGIN_SHELL_PATH: &str = "/usr/local/lib/walle/walle-ssh-overlay-shell";
const TRAP_UID_MIN: u32 = 62000;
const TRAP_UID_MAX: u32 = 64999;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrapTriggerKind {
    BlacklistedKey,
    TrapUsername,
}

impl TrapTriggerKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BlacklistedKey => "blacklisted_key",
            Self::TrapUsername => "trap_username",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "blacklisted_key" => Some(Self::BlacklistedKey),
            "trap_username" => Some(Self::TrapUsername),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SshOverlayPaths {
    pub root_dir: PathBuf,
    pub session_audit_dir: PathBuf,
    pub state_dir: PathBuf,
    pub dynamic_blacklist_keys_path: PathBuf,
    pub trap_usernames_path: PathBuf,
    pub trap_identities_path: PathBuf,
    pub auth_info_dir: PathBuf,
    pub pending_trap_dir: PathBuf,
    pub trap_home_dir: PathBuf,
}

impl SshOverlayPaths {
    #[must_use]
    pub fn from_policy(policy: &SshJailPolicy) -> Self {
        let root_dir = PathBuf::from(policy.root_dir.trim());
        let gp_ssh_dir = root_dir.join("gp/ssh");
        let session_audit_dir = gp_ssh_dir.join("sessions");
        let state_dir = gp_ssh_dir.join("state");
        let dynamic_blacklist_keys_path = state_dir.join("blacklist_keys.dynamic");
        let trap_usernames_path = state_dir.join("trap_usernames.runtime");
        let trap_identities_path = state_dir.join("trap_identities.runtime");
        let auth_info_dir = state_dir.join("auth-info");
        let pending_trap_dir = state_dir.join("pending_traps");
        let trap_home_dir = gp_ssh_dir.join("trap-home");
        Self {
            root_dir,
            session_audit_dir,
            state_dir,
            dynamic_blacklist_keys_path,
            trap_usernames_path,
            trap_identities_path,
            auth_info_dir,
            pending_trap_dir,
            trap_home_dir,
        }
    }

    pub fn ensure_dirs(&self) -> Result<(), SshOverlayError> {
        for path in [
            &self.session_audit_dir,
            &self.state_dir,
            &self.auth_info_dir,
            &self.pending_trap_dir,
            &self.trap_home_dir,
        ] {
            fs::create_dir_all(path).map_err(|source| SshOverlayError::CreateDir {
                path: path.clone(),
                source,
            })?;
        }
        Ok(())
    }

    pub fn reset_runtime_state(&self) -> Result<(), SshOverlayError> {
        self.ensure_dirs()?;
        remove_path_if_exists(&self.trap_usernames_path)?;
        remove_path_if_exists(&self.trap_identities_path)?;
        clear_directory(&self.auth_info_dir)?;
        clear_directory(&self.pending_trap_dir)?;
        clear_directory(&self.trap_home_dir)?;
        Ok(())
    }

    #[must_use]
    pub fn pending_trap_path(&self, token: &str) -> PathBuf {
        self.pending_trap_dir.join(format!("{token}.pending"))
    }

    #[must_use]
    pub fn next_auth_info_path(&self) -> PathBuf {
        let stamp = unix_timestamp_nanos();
        let suffix = random::<u64>();
        self.auth_info_dir.join(format!("{stamp}-{suffix}.auth"))
    }
}

#[derive(Debug, Error)]
pub enum SshOverlayError {
    #[error("failed to create SSH overlay directory '{path}': {source}")]
    CreateDir {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to read SSH overlay file '{path}': {source}")]
    ReadFile {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to write SSH overlay file '{path}': {source}")]
    WriteFile {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to remove SSH overlay path '{path}': {source}")]
    RemovePath {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid SSH public key '{value}': {message}")]
    InvalidPublicKey { value: String, message: String },
    #[error("invalid pending SSH trap token '{token}'")]
    InvalidPendingTrapToken { token: String },
    #[error("failed to parse pending SSH trap record '{path}': {message}")]
    InvalidPendingTrapRecord { path: PathBuf, message: String },
    #[error("failed to parse runtime trap identity record '{path}': {message}")]
    InvalidTrapIdentityRecord { path: PathBuf, message: String },
}

#[derive(Clone, Debug)]
pub struct DynamicBlacklistStore {
    path: PathBuf,
    keys: Arc<Mutex<BTreeSet<String>>>,
}

impl DynamicBlacklistStore {
    #[must_use]
    pub fn load(path: PathBuf) -> Self {
        Self {
            path: path.clone(),
            keys: Arc::new(Mutex::new(
                load_line_set(path.as_path()).unwrap_or_default(),
            )),
        }
    }

    pub fn record(&self, openssh_key: &str) -> Result<bool, SshOverlayError> {
        let mut keys = lock_set(&self.keys);
        if !keys.insert(openssh_key.to_string()) {
            return Ok(false);
        }
        persist_line_set(self.path.as_path(), &keys).map_err(|source| {
            SshOverlayError::WriteFile {
                path: self.path.clone(),
                source,
            }
        })?;
        Ok(true)
    }

    #[cfg(test)]
    pub fn entries(&self) -> Vec<String> {
        lock_set(&self.keys).iter().cloned().collect()
    }
}

#[derive(Clone, Debug)]
pub struct TrapUsernameStore {
    path: PathBuf,
    usernames: Arc<Mutex<BTreeSet<String>>>,
}

impl TrapUsernameStore {
    #[must_use]
    pub fn load(path: PathBuf) -> Self {
        Self {
            path: path.clone(),
            usernames: Arc::new(Mutex::new(
                load_line_set(path.as_path()).unwrap_or_default(),
            )),
        }
    }

    pub fn record(&self, username: &str) -> Result<bool, SshOverlayError> {
        let username = username.trim();
        if username.is_empty() {
            return Ok(false);
        }

        let mut usernames = lock_set(&self.usernames);
        if !usernames.insert(username.to_string()) {
            return Ok(false);
        }

        persist_line_set(self.path.as_path(), &usernames).map_err(|source| {
            SshOverlayError::WriteFile {
                path: self.path.clone(),
                source,
            }
        })?;
        Ok(true)
    }

    #[must_use]
    pub fn contains(&self, username: &str) -> bool {
        lock_set(&self.usernames).contains(username.trim())
    }

    #[cfg(test)]
    pub fn entries(&self) -> Vec<String> {
        lock_set(&self.usernames).iter().cloned().collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrapIdentityRecord {
    pub username: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
    pub gecos: String,
}

impl TrapIdentityRecord {
    fn for_username(
        username: &str,
        paths: &SshOverlayPaths,
        existing: &BTreeMap<String, TrapIdentityRecord>,
    ) -> Self {
        let uid = allocate_trap_uid(username, existing);
        let home = paths.trap_home_dir.join(username).display().to_string();
        Self {
            username: username.to_string(),
            uid,
            gid: uid,
            home,
            shell: TRAP_LOGIN_SHELL_PATH.to_string(),
            gecos: "Walle SSH trap identity".to_string(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct TrapIdentityStore {
    path: PathBuf,
    paths: SshOverlayPaths,
    identities: Arc<Mutex<BTreeMap<String, TrapIdentityRecord>>>,
}

impl TrapIdentityStore {
    #[must_use]
    pub fn load(paths: &SshOverlayPaths) -> Self {
        Self {
            path: paths.trap_identities_path.clone(),
            paths: paths.clone(),
            identities: Arc::new(Mutex::new(
                load_trap_identity_map(paths.trap_identities_path.as_path()).unwrap_or_default(),
            )),
        }
    }

    pub fn record(&self, username: &str) -> Result<bool, SshOverlayError> {
        let username = username.trim();
        if username.is_empty() {
            return Ok(false);
        }

        let mut identities = lock_set(&self.identities);
        if identities.contains_key(username) {
            return Ok(false);
        }

        let identity = TrapIdentityRecord::for_username(username, &self.paths, &identities);
        fs::create_dir_all(identity.home.as_str()).map_err(|source| {
            SshOverlayError::CreateDir {
                path: PathBuf::from(identity.home.as_str()),
                source,
            }
        })?;
        identities.insert(username.to_string(), identity);
        persist_trap_identity_map(self.path.as_path(), &identities)?;
        Ok(true)
    }

    #[must_use]
    pub fn contains(&self, username: &str) -> bool {
        lock_set(&self.identities).contains_key(username.trim())
    }

    #[must_use]
    pub fn get_by_username(&self, username: &str) -> Option<TrapIdentityRecord> {
        lock_set(&self.identities).get(username.trim()).cloned()
    }

    #[must_use]
    pub fn get_by_uid(&self, uid: u32) -> Option<TrapIdentityRecord> {
        lock_set(&self.identities)
            .values()
            .find(|identity| identity.uid == uid)
            .cloned()
    }

    #[cfg(test)]
    pub fn entries(&self) -> Vec<TrapIdentityRecord> {
        lock_set(&self.identities).values().cloned().collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresentedPublicKey {
    pub key_type: String,
    pub key_base64: String,
    pub fingerprint: String,
    pub openssh_key: String,
}

impl PresentedPublicKey {
    pub fn from_authorized_keys_command(
        key_type: &str,
        key_base64: &str,
        fingerprint: &str,
    ) -> Result<Self, SshOverlayError> {
        let raw = format!("{} {}", key_type.trim(), key_base64.trim());
        match PublicKey::from_openssh(raw.as_str()) {
            Ok(public_key) => Ok(Self {
                key_type: public_key.algorithm().as_str().to_string(),
                key_base64: public_key.public_key_base64(),
                fingerprint: public_key.fingerprint(HashAlg::Sha256).to_string(),
                openssh_key: public_key
                    .to_openssh()
                    .unwrap_or_else(|_| raw.clone())
                    .trim()
                    .to_string(),
            }),
            Err(source) => {
                let key_type = key_type.trim();
                let key_base64 = key_base64.trim();
                if key_type.is_empty() || key_base64.is_empty() {
                    return Err(SshOverlayError::InvalidPublicKey {
                        value: raw,
                        message: source.to_string(),
                    });
                }

                Ok(Self {
                    key_type: key_type.to_string(),
                    key_base64: key_base64.to_string(),
                    fingerprint: fingerprint.trim().to_string(),
                    openssh_key: format!("{key_type} {key_base64}"),
                })
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingTrapRecord {
    pub token: String,
    pub username: String,
    pub uid: Option<u32>,
    pub home: Option<String>,
    pub trigger: TrapTriggerKind,
    pub key: PresentedPublicKey,
    pub created_at_secs: u64,
}

impl PendingTrapRecord {
    pub fn create(
        paths: &SshOverlayPaths,
        username: &str,
        uid: Option<u32>,
        home: Option<&str>,
        trigger: TrapTriggerKind,
        key: PresentedPublicKey,
    ) -> Result<Self, SshOverlayError> {
        paths.ensure_dirs()?;
        let created_at_secs = unix_timestamp_secs();
        let token = generate_pending_token();
        let record = Self {
            token: token.clone(),
            username: username.trim().to_string(),
            uid,
            home: home
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string),
            trigger,
            key,
            created_at_secs,
        };
        let path = paths.pending_trap_path(token.as_str());
        persist_pending_trap(path.as_path(), &record)?;
        Ok(record)
    }

    pub fn consume(paths: &SshOverlayPaths, token: &str) -> Result<Option<Self>, SshOverlayError> {
        validate_pending_token(token)?;
        let path = paths.pending_trap_path(token);
        let contents = match fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(source) if source.kind() == ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(SshOverlayError::ReadFile {
                    path: path.clone(),
                    source,
                });
            }
        };
        fs::remove_file(&path).map_err(|source| SshOverlayError::RemovePath {
            path: path.clone(),
            source,
        })?;
        parse_pending_trap(path.as_path(), contents.as_str()).map(Some)
    }
}

#[derive(Clone, Debug)]
pub struct SshOverlayRuntimeState {
    trap_usernames: TrapUsernameStore,
    trap_identities: TrapIdentityStore,
    paths: SshOverlayPaths,
}

impl SshOverlayRuntimeState {
    pub fn new(policy: &SshJailPolicy) -> Self {
        let paths = SshOverlayPaths::from_policy(policy);
        let trap_usernames = TrapUsernameStore::load(paths.trap_usernames_path.clone());
        let trap_identities = TrapIdentityStore::load(&paths);
        Self {
            trap_usernames,
            trap_identities,
            paths,
        }
    }

    pub fn prepare_runtime_state(&self) -> Result<(), SshOverlayError> {
        self.paths.reset_runtime_state()
    }

    pub fn clear_runtime_state(&self) -> Result<(), SshOverlayError> {
        self.paths.reset_runtime_state()
    }

    pub fn record_invalid_username(&self, username: &str) -> Result<bool, SshOverlayError> {
        let promoted_username = self.trap_usernames.record(username)?;
        let promoted_identity = self.trap_identities.record(username)?;
        Ok(promoted_username || promoted_identity)
    }

    #[must_use]
    pub fn paths(&self) -> &SshOverlayPaths {
        &self.paths
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedKeysTrapRequest {
    pub user: String,
    pub uid: Option<u32>,
    pub home: Option<String>,
    pub key_type: String,
    pub key_base64: String,
    pub fingerprint: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedKeysTrapDecision {
    pub trigger: TrapTriggerKind,
    pub pending_trap: PendingTrapRecord,
    pub authorized_key_line: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExposedAuthInfoRecord {
    pub service: String,
    pub username: String,
    pub auth_type: String,
    pub password: Option<String>,
    pub rhost: Option<String>,
}

pub fn evaluate_authorized_keys_trap(
    policy: &SshJailPolicy,
    request: &AuthorizedKeysTrapRequest,
    daemon_active: bool,
    containment_enabled: bool,
    binary_path: &Path,
) -> Result<Option<AuthorizedKeysTrapDecision>, SshOverlayError> {
    if !daemon_active || !containment_enabled {
        return Ok(None);
    }

    let paths = SshOverlayPaths::from_policy(policy);
    paths.ensure_dirs()?;

    let presented = PresentedPublicKey::from_authorized_keys_command(
        request.key_type.as_str(),
        request.key_base64.as_str(),
        request.fingerprint.as_str(),
    )?;
    let trap_identities = TrapIdentityStore::load(&paths);
    let blacklisted = blacklist_contains(policy, &paths, &presented)?;
    let trigger = if blacklisted {
        Some(TrapTriggerKind::BlacklistedKey)
    } else if trap_identities.contains(request.user.as_str()) {
        Some(TrapTriggerKind::TrapUsername)
    } else {
        None
    };

    let Some(trigger) = trigger else {
        return Ok(None);
    };

    let pending_trap = PendingTrapRecord::create(
        &paths,
        request.user.as_str(),
        request.uid,
        request.home.as_deref(),
        trigger,
        presented,
    )?;
    let authorized_key_line = render_trap_authorized_key_line(binary_path, &pending_trap);

    Ok(Some(AuthorizedKeysTrapDecision {
        trigger,
        pending_trap,
        authorized_key_line,
    }))
}

#[must_use]
pub fn render_sshd_config_fragment(binary_path: &Path) -> String {
    let command = format!(
        "{} ssh overlay authorized-keys --user %u --uid %U --home %h --key-type %t --key-base64 %k --fingerprint %f",
        binary_path.display()
    );
    format!(
        concat!(
            "# Walle SSH overlay sample\n",
            "# Merge carefully if this host already uses AuthorizedKeysCommand.\n",
            "# The helper fails open unless the walle daemon is active and SSH GP containment is enabled.\n",
            "AuthorizedKeysCommand {}\n",
            "AuthorizedKeysCommandUser root\n"
        ),
        command
    )
}

#[must_use]
pub fn render_nsswitch_config_fragment() -> String {
    concat!(
        "# Walle identity overlay sample\n",
        "# Keep `files` before `walle` so real system users always win.\n",
        "passwd: files walle systemd\n",
        "group: files walle systemd\n",
        "shadow: files walle\n",
        "initgroups: files walle\n",
    )
    .to_string()
}

#[must_use]
pub fn render_pam_config_fragment(module_path: &Path) -> String {
    format!(
        concat!(
            "# Walle SSH overlay PAM sample for /etc/pam.d/sshd\n",
            "# Place the auth line before `@include common-auth`.\n",
            "# Place the account line after `pam_nologin.so` and before `@include common-account`.\n",
            "# Place the session line after `pam_keyinit.so` and before `@include common-session`.\n",
            "auth    [success=done default=ignore] {}\n",
            "account [success=done default=ignore] {}\n",
            "session [success=done default=ignore] {}\n"
        ),
        module_path.display(),
        module_path.display(),
        module_path.display()
    )
}

#[must_use]
pub fn render_trap_login_shell_wrapper(binary_path: &Path) -> String {
    format!(
        concat!(
            "#!/bin/sh\n",
            "unset SSH_ORIGINAL_COMMAND\n",
            "if [ \"$1\" = \"-c\" ] && [ $# -ge 2 ]; then\n",
            "  export SSH_ORIGINAL_COMMAND=\"$2\"\n",
            "fi\n",
            "exec {} ssh overlay trap-login\n"
        ),
        binary_path.display()
    )
}

#[must_use]
pub fn gp_containment_enabled(gp_strategy: GpStrategyKind, gp_enabled: bool) -> bool {
    gp_enabled && matches!(gp_strategy, GpStrategyKind::Contain)
}

pub fn resolve_trap_identity_by_username(
    policy: &SshJailPolicy,
    username: &str,
) -> Result<Option<TrapIdentityRecord>, SshOverlayError> {
    let paths = SshOverlayPaths::from_policy(policy);
    let identities = TrapIdentityStore::load(&paths);
    Ok(identities.get_by_username(username))
}

pub fn resolve_trap_identity_by_uid(
    policy: &SshJailPolicy,
    uid: u32,
) -> Result<Option<TrapIdentityRecord>, SshOverlayError> {
    let paths = SshOverlayPaths::from_policy(policy);
    let identities = TrapIdentityStore::load(&paths);
    Ok(identities.get_by_uid(uid))
}

pub fn persist_exposed_auth_info(
    policy: &SshJailPolicy,
    record: &ExposedAuthInfoRecord,
) -> Result<PathBuf, SshOverlayError> {
    let paths = SshOverlayPaths::from_policy(policy);
    paths.ensure_dirs()?;
    let path = paths.next_auth_info_path();
    let mut contents = String::new();
    contents.push_str(&format!("service={}\n", record.service.trim()));
    contents.push_str(&format!("user={}\n", record.username.trim()));
    contents.push_str(&format!("auth_type={}\n", record.auth_type.trim()));
    if let Some(password) = record.password.as_deref() {
        contents.push_str(&format!("password={}\n", password.trim()));
    }
    if let Some(rhost) = record.rhost.as_deref() {
        contents.push_str(&format!("rhost={}\n", rhost.trim()));
    }
    contents.push_str(&format!("created_at_secs={}\n", unix_timestamp_secs()));
    persist_contents(path.as_path(), contents.as_str())?;
    Ok(path)
}

fn render_trap_authorized_key_line(binary_path: &Path, pending_trap: &PendingTrapRecord) -> String {
    let command = format!(
        "{} ssh overlay trap-shell --token {}",
        binary_path.display(),
        pending_trap.token
    );
    let escaped = command.replace('\\', "\\\\").replace('"', "\\\"");
    format!(
        "restrict,pty,command=\"{escaped}\" {} walle-{}",
        pending_trap.key.openssh_key,
        pending_trap.trigger.as_str()
    )
}

fn blacklist_contains(
    policy: &SshJailPolicy,
    paths: &SshOverlayPaths,
    presented: &PresentedPublicKey,
) -> Result<bool, SshOverlayError> {
    file_contains_blacklist(
        Path::new(policy.static_blacklist_keys_path.as_str()),
        presented,
    )
    .or_else(|error| match error {
        SshOverlayError::ReadFile { path, source } if source.kind() == ErrorKind::NotFound => {
            let _ = path;
            Ok(false)
        }
        other => Err(other),
    })
    .and_then(|static_match| {
        if static_match {
            Ok(true)
        } else {
            file_contains_blacklist(paths.dynamic_blacklist_keys_path.as_path(), presented).or_else(
                |error| match error {
                    SshOverlayError::ReadFile { path, source }
                        if source.kind() == ErrorKind::NotFound =>
                    {
                        let _ = path;
                        Ok(false)
                    }
                    other => Err(other),
                },
            )
        }
    })
}

fn file_contains_blacklist(
    path: &Path,
    presented: &PresentedPublicKey,
) -> Result<bool, SshOverlayError> {
    let contents = fs::read_to_string(path).map_err(|source| SshOverlayError::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;

    for line in contents.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line == presented.fingerprint {
            return Ok(true);
        }

        if let Ok(public_key) = PublicKey::from_openssh(line) {
            if public_key.fingerprint(HashAlg::Sha256).to_string() == presented.fingerprint {
                return Ok(true);
            }
            if public_key.public_key_base64() == presented.key_base64 {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

fn persist_pending_trap(path: &Path, record: &PendingTrapRecord) -> Result<(), SshOverlayError> {
    let mut contents = String::new();
    contents.push_str(&format!("user={}\n", record.username));
    if let Some(uid) = record.uid {
        contents.push_str(&format!("uid={uid}\n"));
    }
    if let Some(home) = &record.home {
        contents.push_str(&format!("home={home}\n"));
    }
    contents.push_str(&format!("trigger={}\n", record.trigger.as_str()));
    contents.push_str(&format!("created_at_secs={}\n", record.created_at_secs));
    contents.push_str(&format!("fingerprint={}\n", record.key.fingerprint));
    contents.push_str(&format!("key_type={}\n", record.key.key_type));
    contents.push_str(&format!("key_base64={}\n", record.key.key_base64));

    persist_contents(path, contents.as_str())
}

fn parse_pending_trap(path: &Path, contents: &str) -> Result<PendingTrapRecord, SshOverlayError> {
    let mut username = None;
    let mut uid = None;
    let mut home = None;
    let mut trigger = None;
    let mut created_at_secs = None;
    let mut fingerprint = None;
    let mut key_type = None;
    let mut key_base64 = None;

    for line in contents.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "user" => username = Some(value.trim().to_string()),
            "uid" => uid = value.trim().parse::<u32>().ok(),
            "home" => home = Some(value.trim().to_string()),
            "trigger" => trigger = TrapTriggerKind::parse(value.trim()),
            "created_at_secs" => created_at_secs = value.trim().parse::<u64>().ok(),
            "fingerprint" => fingerprint = Some(value.trim().to_string()),
            "key_type" => key_type = Some(value.trim().to_string()),
            "key_base64" => key_base64 = Some(value.trim().to_string()),
            _ => {}
        }
    }

    let username = username.filter(|value| !value.is_empty()).ok_or_else(|| {
        SshOverlayError::InvalidPendingTrapRecord {
            path: path.to_path_buf(),
            message: "missing user".to_string(),
        }
    })?;
    let trigger = trigger.ok_or_else(|| SshOverlayError::InvalidPendingTrapRecord {
        path: path.to_path_buf(),
        message: "missing trigger".to_string(),
    })?;
    let created_at_secs =
        created_at_secs.ok_or_else(|| SshOverlayError::InvalidPendingTrapRecord {
            path: path.to_path_buf(),
            message: "missing created_at_secs".to_string(),
        })?;
    let key = PresentedPublicKey::from_authorized_keys_command(
        key_type
            .as_deref()
            .ok_or_else(|| SshOverlayError::InvalidPendingTrapRecord {
                path: path.to_path_buf(),
                message: "missing key_type".to_string(),
            })?,
        key_base64
            .as_deref()
            .ok_or_else(|| SshOverlayError::InvalidPendingTrapRecord {
                path: path.to_path_buf(),
                message: "missing key_base64".to_string(),
            })?,
        fingerprint
            .as_deref()
            .ok_or_else(|| SshOverlayError::InvalidPendingTrapRecord {
                path: path.to_path_buf(),
                message: "missing fingerprint".to_string(),
            })?,
    )?;
    let token = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_string();

    Ok(PendingTrapRecord {
        token,
        username,
        uid,
        home,
        trigger,
        key,
        created_at_secs,
    })
}

fn persist_trap_identity_map(
    path: &Path,
    identities: &BTreeMap<String, TrapIdentityRecord>,
) -> Result<(), SshOverlayError> {
    let mut contents = String::new();
    for identity in identities.values() {
        contents.push_str(identity.username.as_str());
        contents.push('\t');
        contents.push_str(identity.uid.to_string().as_str());
        contents.push('\t');
        contents.push_str(identity.gid.to_string().as_str());
        contents.push('\t');
        contents.push_str(identity.home.as_str());
        contents.push('\t');
        contents.push_str(identity.shell.as_str());
        contents.push('\t');
        contents.push_str(identity.gecos.as_str());
        contents.push('\n');
    }
    persist_contents(path, contents.as_str())
}

fn load_trap_identity_map(
    path: &Path,
) -> Result<BTreeMap<String, TrapIdentityRecord>, SshOverlayError> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(source) if source.kind() == ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(source) => {
            return Err(SshOverlayError::ReadFile {
                path: path.to_path_buf(),
                source,
            });
        }
    };

    let mut identities = BTreeMap::new();
    for line in contents.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let mut fields = line.split('\t');
        let username = fields.next().unwrap_or_default().trim();
        let uid = fields.next().and_then(|value| value.parse::<u32>().ok());
        let gid = fields.next().and_then(|value| value.parse::<u32>().ok());
        let home = fields.next().map(str::trim).unwrap_or_default();
        let shell = fields.next().map(str::trim).unwrap_or_default();
        let gecos = fields.next().map(str::trim).unwrap_or_default();

        if username.is_empty()
            || uid.is_none()
            || gid.is_none()
            || home.is_empty()
            || shell.is_empty()
        {
            return Err(SshOverlayError::InvalidTrapIdentityRecord {
                path: path.to_path_buf(),
                message: format!("invalid identity line '{line}'"),
            });
        }

        identities.insert(
            username.to_string(),
            TrapIdentityRecord {
                username: username.to_string(),
                uid: uid.unwrap_or_default(),
                gid: gid.unwrap_or_default(),
                home: home.to_string(),
                shell: shell.to_string(),
                gecos: gecos.to_string(),
            },
        );
    }

    Ok(identities)
}

fn allocate_trap_uid(username: &str, existing: &BTreeMap<String, TrapIdentityRecord>) -> u32 {
    let mut hasher = DefaultHasher::new();
    username.hash(&mut hasher);
    let span = TRAP_UID_MAX - TRAP_UID_MIN + 1;
    let start = TRAP_UID_MIN + (hasher.finish() as u32 % span);

    for offset in 0..span {
        let candidate = TRAP_UID_MIN + ((start - TRAP_UID_MIN + offset) % span);
        if trap_uid_is_available(candidate, existing) {
            return candidate;
        }
    }

    TRAP_UID_MAX
}

fn trap_uid_is_available(candidate: u32, existing: &BTreeMap<String, TrapIdentityRecord>) -> bool {
    if existing
        .values()
        .any(|identity| identity.uid == candidate || identity.gid == candidate)
    {
        return false;
    }

    !system_uid_or_gid_exists(candidate)
}

#[cfg(target_os = "linux")]
fn system_uid_or_gid_exists(candidate: u32) -> bool {
    system_uid_exists(candidate) || system_gid_exists(candidate)
}

#[cfg(not(target_os = "linux"))]
fn system_uid_or_gid_exists(_candidate: u32) -> bool {
    false
}

#[cfg(target_os = "linux")]
fn system_uid_exists(candidate: u32) -> bool {
    unsafe {
        let mut pwd = std::mem::zeroed::<libc::passwd>();
        let mut result = std::ptr::null_mut();
        let mut buffer = vec![0u8; 4096];
        libc::getpwuid_r(
            candidate,
            &mut pwd,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        ) == 0
            && !result.is_null()
    }
}

#[cfg(target_os = "linux")]
fn system_gid_exists(candidate: u32) -> bool {
    unsafe {
        let mut grp = std::mem::zeroed::<libc::group>();
        let mut result = std::ptr::null_mut();
        let mut buffer = vec![0u8; 4096];
        libc::getgrgid_r(
            candidate,
            &mut grp,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        ) == 0
            && !result.is_null()
    }
}

fn persist_line_set(path: &Path, values: &BTreeSet<String>) -> Result<(), std::io::Error> {
    let mut contents = String::new();
    for value in values {
        contents.push_str(value);
        contents.push('\n');
    }
    persist_contents(path, contents.as_str()).map_err(|error| match error {
        SshOverlayError::WriteFile { source, .. } => source,
        _ => std::io::Error::other("unexpected persist error"),
    })
}

fn persist_contents(path: &Path, contents: &str) -> Result<(), SshOverlayError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| SshOverlayError::CreateDir {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    let temp_path = path.with_extension("tmp");
    fs::write(&temp_path, contents).map_err(|source| SshOverlayError::WriteFile {
        path: temp_path.clone(),
        source,
    })?;
    fs::rename(&temp_path, path).map_err(|source| SshOverlayError::WriteFile {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(())
}

fn load_line_set(path: &Path) -> Result<BTreeSet<String>, SshOverlayError> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(source) if source.kind() == ErrorKind::NotFound => return Ok(BTreeSet::new()),
        Err(source) => {
            return Err(SshOverlayError::ReadFile {
                path: path.to_path_buf(),
                source,
            });
        }
    };

    Ok(contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect())
}

fn lock_set<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn remove_path_if_exists(path: &Path) -> Result<(), SshOverlayError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == ErrorKind::NotFound => Ok(()),
        Err(source) => Err(SshOverlayError::RemovePath {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn clear_directory(path: &Path) -> Result<(), SshOverlayError> {
    match fs::read_dir(path) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry.map_err(|source| SshOverlayError::ReadFile {
                    path: path.to_path_buf(),
                    source,
                })?;
                let entry_path = entry.path();
                if entry.file_type().map(|ty| ty.is_dir()).unwrap_or(false) {
                    fs::remove_dir_all(&entry_path).map_err(|source| {
                        SshOverlayError::RemovePath {
                            path: entry_path,
                            source,
                        }
                    })?;
                } else {
                    fs::remove_file(&entry_path).map_err(|source| SshOverlayError::RemovePath {
                        path: entry_path,
                        source,
                    })?;
                }
            }
            Ok(())
        }
        Err(source) if source.kind() == ErrorKind::NotFound => Ok(()),
        Err(source) => Err(SshOverlayError::ReadFile {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn validate_pending_token(token: &str) -> Result<(), SshOverlayError> {
    if token.is_empty() || !token.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(SshOverlayError::InvalidPendingTrapToken {
            token: token.to_string(),
        });
    }
    Ok(())
}

fn generate_pending_token() -> String {
    format!("{:016x}{:016x}", unix_timestamp_nanos(), random::<u64>())
}

fn unix_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn unix_timestamp_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use rand::rng;
    use russh::keys::{Algorithm, PrivateKey};

    use super::{
        AuthorizedKeysTrapRequest, DynamicBlacklistStore, ExposedAuthInfoRecord, PendingTrapRecord,
        PresentedPublicKey, SshOverlayPaths, SshOverlayRuntimeState, TRAP_LOGIN_SHELL_PATH,
        TrapIdentityStore, TrapTriggerKind, TrapUsernameStore, evaluate_authorized_keys_trap,
        gp_containment_enabled, persist_exposed_auth_info, render_nsswitch_config_fragment,
        render_pam_config_fragment, render_sshd_config_fragment, render_trap_login_shell_wrapper,
    };
    use walle_policy::{GpStrategyKind, SshJailPolicy};

    fn temp_root(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("walle-overlay-{name}-{nanos}"));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn test_policy(root_dir: &PathBuf) -> SshJailPolicy {
        SshJailPolicy {
            root_dir: root_dir.display().to_string(),
            static_blacklist_keys_path: root_dir
                .join("static_blacklist_keys")
                .display()
                .to_string(),
            ..SshJailPolicy::default()
        }
    }

    fn test_request() -> AuthorizedKeysTrapRequest {
        let public_key = PrivateKey::random(&mut rng(), Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .to_openssh()
            .unwrap();
        let mut parts = public_key.split_whitespace();
        AuthorizedKeysTrapRequest {
            user: "ubuntu".to_string(),
            uid: Some(1000),
            home: Some("/home/ubuntu".to_string()),
            key_type: parts.next().unwrap().to_string(),
            key_base64: parts.next().unwrap().to_string(),
            fingerprint: String::new(),
        }
    }

    #[test]
    fn dynamic_blacklist_store_dedupes_and_persists() {
        let root = temp_root("dynamic-store");
        let paths = SshOverlayPaths::from_policy(&test_policy(&root));
        paths.ensure_dirs().unwrap();
        let store = DynamicBlacklistStore::load(paths.dynamic_blacklist_keys_path.clone());
        assert!(store.record("ssh-ed25519 AAAAC3Nza").unwrap());
        assert!(!store.record("ssh-ed25519 AAAAC3Nza").unwrap());
        let persisted = std::fs::read_to_string(paths.dynamic_blacklist_keys_path).unwrap();
        assert_eq!(persisted, "ssh-ed25519 AAAAC3Nza\n");
    }

    #[test]
    fn trap_username_store_persists_runtime_overlay() {
        let root = temp_root("trap-users");
        let paths = SshOverlayPaths::from_policy(&test_policy(&root));
        paths.ensure_dirs().unwrap();
        let store = TrapUsernameStore::load(paths.trap_usernames_path.clone());
        assert!(store.record("tomcat").unwrap());
        assert!(!store.record("tomcat").unwrap());
        assert!(store.contains("tomcat"));
        let reloaded = TrapUsernameStore::load(paths.trap_usernames_path.clone());
        assert!(reloaded.contains("tomcat"));
    }

    #[test]
    fn trap_identity_store_persists_runtime_records() {
        let root = temp_root("trap-identities");
        let paths = SshOverlayPaths::from_policy(&test_policy(&root));
        paths.ensure_dirs().unwrap();
        let store = TrapIdentityStore::load(&paths);

        assert!(store.record("tomcat").unwrap());
        assert!(!store.record("tomcat").unwrap());

        let persisted = std::fs::read_to_string(&paths.trap_identities_path).unwrap();
        assert!(persisted.contains("tomcat\t"));

        let reloaded = TrapIdentityStore::load(&paths);
        let identity = reloaded.get_by_username("tomcat").unwrap();
        assert_eq!(identity.username, "tomcat");
        assert_eq!(identity.gid, identity.uid);
        assert_eq!(
            identity.home,
            paths.trap_home_dir.join("tomcat").display().to_string()
        );
        assert_eq!(identity.shell, TRAP_LOGIN_SHELL_PATH);
        assert_eq!(reloaded.get_by_uid(identity.uid).unwrap(), identity);
    }

    #[test]
    fn runtime_state_reset_clears_runtime_only_files() {
        let root = temp_root("runtime-reset");
        let policy = test_policy(&root);
        let runtime = SshOverlayRuntimeState::new(&policy);
        runtime.prepare_runtime_state().unwrap();
        runtime.record_invalid_username("tomcat").unwrap();
        let paths = runtime.paths();
        std::fs::write(paths.pending_trap_path("abcd"), "user=tomcat\ntrigger=trap_username\ncreated_at_secs=1\nfingerprint=SHA256:test\nkey_type=ssh-rsa\nkey_base64=AAAA\n").unwrap();
        runtime.clear_runtime_state().unwrap();
        assert!(!paths.trap_usernames_path.exists());
        assert!(!paths.trap_identities_path.exists());
        assert_eq!(
            std::fs::read_dir(&paths.pending_trap_dir).unwrap().count(),
            0
        );
    }

    #[test]
    fn pending_trap_round_trip_consumes_the_record() {
        let root = temp_root("pending-trap");
        let policy = test_policy(&root);
        let paths = SshOverlayPaths::from_policy(&policy);
        let key = PresentedPublicKey::from_authorized_keys_command(
            "ssh-ed25519",
            "AAAAC3NzaC1lZDI1NTE5AAAAIMm6d3vHyj2s3T9iY2K0b5bK6cY4+L9F2rI+0O3P5WqY",
            "",
        )
        .unwrap();
        let record = PendingTrapRecord::create(
            &paths,
            "ubuntu",
            Some(1000),
            Some("/home/ubuntu"),
            TrapTriggerKind::BlacklistedKey,
            key,
        )
        .unwrap();
        let consumed = PendingTrapRecord::consume(&paths, record.token.as_str())
            .unwrap()
            .unwrap();
        assert_eq!(consumed.username, "ubuntu");
        assert_eq!(consumed.trigger, TrapTriggerKind::BlacklistedKey);
        assert!(
            PendingTrapRecord::consume(&paths, record.token.as_str())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn authorized_keys_trap_matches_static_blacklist_and_renders_forced_command() {
        let root = temp_root("authz-static");
        let policy = test_policy(&root);
        let mut request = test_request();
        let presented = PresentedPublicKey::from_authorized_keys_command(
            request.key_type.as_str(),
            request.key_base64.as_str(),
            request.fingerprint.as_str(),
        )
        .unwrap();
        request.fingerprint = presented.fingerprint.clone();
        std::fs::write(
            &policy.static_blacklist_keys_path,
            format!("{}\n", presented.openssh_key),
        )
        .unwrap();
        let decision = evaluate_authorized_keys_trap(
            &policy,
            &request,
            true,
            true,
            PathBuf::from("/usr/local/bin/walle").as_path(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(decision.trigger, TrapTriggerKind::BlacklistedKey);
        assert!(
            decision
                .authorized_key_line
                .contains("command=\"/usr/local/bin/walle ssh overlay trap-shell --token")
        );
        assert!(
            decision
                .authorized_key_line
                .contains(request.key_type.as_str())
        );
        assert!(
            decision
                .authorized_key_line
                .contains(request.key_base64.as_str())
        );
    }

    #[test]
    fn authorized_keys_trap_matches_runtime_trap_user_overlay() {
        let root = temp_root("authz-user");
        let policy = test_policy(&root);
        let runtime = SshOverlayRuntimeState::new(&policy);
        runtime.prepare_runtime_state().unwrap();
        runtime.record_invalid_username("ubuntu").unwrap();
        let mut request = test_request();
        let presented = PresentedPublicKey::from_authorized_keys_command(
            request.key_type.as_str(),
            request.key_base64.as_str(),
            request.fingerprint.as_str(),
        )
        .unwrap();
        request.fingerprint = presented.fingerprint.clone();
        let decision = evaluate_authorized_keys_trap(
            &policy,
            &request,
            true,
            true,
            PathBuf::from("/usr/local/bin/walle").as_path(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(decision.trigger, TrapTriggerKind::TrapUsername);
    }

    #[test]
    fn authorized_keys_trap_fails_open_when_runtime_or_containment_is_inactive() {
        let root = temp_root("authz-inactive");
        let policy = test_policy(&root);
        let mut request = test_request();
        let presented = PresentedPublicKey::from_authorized_keys_command(
            request.key_type.as_str(),
            request.key_base64.as_str(),
            request.fingerprint.as_str(),
        )
        .unwrap();
        request.fingerprint = presented.fingerprint.clone();
        std::fs::write(
            &policy.static_blacklist_keys_path,
            format!("{}\n", presented.fingerprint),
        )
        .unwrap();
        assert!(
            evaluate_authorized_keys_trap(
                &policy,
                &request,
                false,
                true,
                PathBuf::from("/usr/local/bin/walle").as_path(),
            )
            .unwrap()
            .is_none()
        );
        assert!(
            evaluate_authorized_keys_trap(
                &policy,
                &request,
                true,
                false,
                PathBuf::from("/usr/local/bin/walle").as_path(),
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn render_sshd_config_fragment_points_at_binary_and_root_helper() {
        let rendered = render_sshd_config_fragment(PathBuf::from("/usr/local/bin/walle").as_path());
        assert!(
            rendered
                .contains("AuthorizedKeysCommand /usr/local/bin/walle ssh overlay authorized-keys")
        );
        assert!(rendered.contains("AuthorizedKeysCommandUser root"));
    }

    #[test]
    fn render_nsswitch_config_fragment_keeps_files_first() {
        let rendered = render_nsswitch_config_fragment();
        assert!(rendered.contains("passwd: files walle systemd"));
        assert!(rendered.contains("group: files walle systemd"));
        assert!(rendered.contains("shadow: files walle"));
        assert!(rendered.contains("initgroups: files walle"));
    }

    #[test]
    fn render_pam_config_fragment_uses_absolute_module_path() {
        let rendered = render_pam_config_fragment(
            PathBuf::from("/usr/local/lib/walle/pam_walle.so").as_path(),
        );
        assert!(
            rendered.contains(
                "auth    [success=done default=ignore] /usr/local/lib/walle/pam_walle.so"
            )
        );
        assert!(
            rendered.contains(
                "account [success=done default=ignore] /usr/local/lib/walle/pam_walle.so"
            )
        );
        assert!(
            rendered.contains(
                "session [success=done default=ignore] /usr/local/lib/walle/pam_walle.so"
            )
        );
    }

    #[test]
    fn render_trap_login_shell_wrapper_translates_shell_c_invocations() {
        let rendered =
            render_trap_login_shell_wrapper(PathBuf::from("/usr/local/bin/walle").as_path());
        assert!(rendered.contains("if [ \"$1\" = \"-c\" ] && [ $# -ge 2 ]; then"));
        assert!(rendered.contains("export SSH_ORIGINAL_COMMAND=\"$2\""));
        assert!(rendered.contains("exec /usr/local/bin/walle ssh overlay trap-login"));
    }

    #[test]
    fn persist_exposed_auth_info_writes_auth_info_file_under_state_dir() {
        let root = temp_root("auth-info");
        let policy = test_policy(&root);
        let path = persist_exposed_auth_info(
            &policy,
            &ExposedAuthInfoRecord {
                service: "sshd".to_string(),
                username: "tomcat".to_string(),
                auth_type: "password".to_string(),
                password: Some("secret123".to_string()),
                rhost: Some("203.0.113.9".to_string()),
            },
        )
        .unwrap();

        assert!(path.starts_with(root.join("gp/ssh/state/auth-info")));
        let contents = std::fs::read_to_string(path).unwrap();
        assert!(contents.contains("service=sshd"));
        assert!(contents.contains("user=tomcat"));
        assert!(contents.contains("auth_type=password"));
        assert!(contents.contains("password=secret123"));
        assert!(contents.contains("rhost=203.0.113.9"));
    }

    #[test]
    fn gp_containment_helper_only_allows_enabled_contain_strategy() {
        assert!(gp_containment_enabled(GpStrategyKind::Contain, true));
        assert!(!gp_containment_enabled(GpStrategyKind::Observe, true));
        assert!(!gp_containment_enabled(GpStrategyKind::Contain, false));
    }
}
