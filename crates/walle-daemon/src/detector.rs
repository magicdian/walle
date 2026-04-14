#[cfg(target_os = "linux")]
use std::collections::HashSet;
use std::collections::{HashMap, VecDeque};
#[cfg(target_os = "linux")]
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
#[cfg(target_os = "linux")]
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::{Child, ChildStdout, Command, Stdio};
use std::time::Duration;

use thiserror::Error;
use tracing::{debug, info, warn};
use walle_common::{BanEntryV4, BanReasonCode, BanSource};
use walle_policy::{SshLogSourceMode, SshProtectionPolicy};

const DEFAULT_SSH_LOG_FILES: &[&str] = &["/var/log/auth.log", "/var/log/secure"];
const JOURNAL_SOCKET_PATH: &str = "/run/systemd/journal/socket";
const NANOS_PER_SEC: u64 = 1_000_000_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SshResolvedLogSource {
    Journald,
    LogFile(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SshLiveSourceMode {
    JournaldFollow,
    LogFileWatch,
    Polling,
}

impl SshLiveSourceMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::JournaldFollow => "journald_follow",
            Self::LogFileWatch => "log_file_watch",
            Self::Polling => "polling",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct SshLiveSourceCapabilities {
    journald_follow: bool,
    file_watch: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshFailureEvent {
    pub ip: IpAddr,
    pub reason: SshFailureReason,
    pub username: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SshFailureReason {
    FailedPassword,
    InvalidUser,
    PamAuthFailure,
    MaxAuthAttemptsExceeded,
    PreauthConnectionClosed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshBanDecision {
    pub ip: IpAddr,
    pub matched_failures: usize,
    pub observed_at_secs: u64,
    pub expires_at_secs: u64,
}

impl SshBanDecision {
    #[must_use]
    pub fn into_ban_entry(self) -> BanEntryV4 {
        BanEntryV4 {
            created_at_ns: self.observed_at_secs.saturating_mul(NANOS_PER_SEC),
            expires_at_ns: self.expires_at_secs.saturating_mul(NANOS_PER_SEC),
            source: BanSource::SshDetector,
            reason: BanReasonCode::SshAuthFailures,
            flags: 0,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SshIngestSummary {
    pub lines_read: usize,
    pub matched_failures: usize,
    pub bans: Vec<SshBanDecision>,
}

#[derive(Debug, Error)]
pub enum SshIngestError {
    #[error("failed to read SSH log file '{path}': {source}")]
    ReadLogFile { path: String, source: io::Error },
    #[error("failed to seek SSH log file '{path}': {source}")]
    SeekLogFile { path: String, source: io::Error },
    #[error("failed to watch SSH log file '{path}': {source}")]
    WatchLogFile { path: String, source: io::Error },
    #[error("journald ingestion is only supported on Linux hosts")]
    UnsupportedJournald,
    #[error("failed to run journalctl: {0}")]
    Journalctl(io::Error),
    #[error("journalctl exited with status {status}: {stderr}")]
    JournalctlFailed { status: i32, stderr: String },
    #[error("journalctl follow did not expose a readable stdout pipe")]
    JournalctlMissingStdout,
    #[error("journalctl follow process exited unexpectedly")]
    JournalctlEnded,
    #[error("failed to wait for SSH live source '{source_name}': {source}")]
    WaitLiveSource {
        source_name: String,
        source: io::Error,
    },
    #[error("failed to read SSH live source '{source_name}': {source}")]
    ReadLiveSource {
        source_name: String,
        source: io::Error,
    },
}

#[derive(Clone, Debug)]
pub struct SshDetectorService {
    policy: SshProtectionPolicy,
    sources: Vec<SshResolvedLogSource>,
    failures_by_ip: HashMap<IpAddr, VecDeque<u64>>,
    active_bans: HashMap<IpAddr, u64>,
}

impl SshDetectorService {
    #[must_use]
    pub fn new(policy: SshProtectionPolicy) -> Self {
        let sources = resolve_sources_for_host(&policy);

        Self {
            policy,
            sources,
            failures_by_ip: HashMap::new(),
            active_bans: HashMap::new(),
        }
    }

    #[must_use]
    pub fn describe(&self) -> String {
        format!(
            "ssh detector: enabled={}, threshold={}, window_secs={}, ban_duration_secs={}, sources={}",
            self.policy.enabled,
            self.policy.failure_threshold,
            self.policy.window_secs,
            self.policy.ban_duration_secs,
            self.sources
                .iter()
                .map(source_label)
                .collect::<Vec<_>>()
                .join(", ")
        )
    }

    pub fn log_startup(&self) {
        info!(
            component = "ssh-detector",
            event = "source_plan",
            sources = %self
                .sources
                .iter()
                .map(source_label)
                .collect::<Vec<_>>()
                .join(", "),
            "prepared SSH detector source plan"
        );

        debug!(
            component = "ssh-detector",
            enabled = self.policy.enabled,
            failure_threshold = self.policy.failure_threshold,
            window_secs = self.policy.window_secs,
            ban_duration_secs = self.policy.ban_duration_secs,
            "prepared SSH detector configuration"
        );
    }

    #[must_use]
    pub fn sources(&self) -> &[SshResolvedLogSource] {
        &self.sources
    }

    #[must_use]
    pub fn create_ingestor(&self) -> SshLogIngestor {
        SshLogIngestor::new(self.sources.clone())
    }

    pub fn create_live_ingestor(&self) -> SshLiveIngestor {
        SshLiveIngestor::new(self.sources.clone())
    }

    #[must_use]
    pub fn inspect_log_line(&self, line: &str) -> Option<SshFailureEvent> {
        parse_failure_event(line)
    }

    pub fn process_log_line(
        &mut self,
        line: &str,
        observed_at_secs: u64,
    ) -> Option<SshBanDecision> {
        if !self.policy.enabled {
            return None;
        }

        let event = parse_failure_event(line)?;
        self.observe_failure(event.ip, observed_at_secs)
    }

    pub fn observe_failure(&mut self, ip: IpAddr, observed_at_secs: u64) -> Option<SshBanDecision> {
        if let Some(expires_at_secs) = self.active_bans.get(&ip) {
            if *expires_at_secs > observed_at_secs {
                return None;
            }
            self.active_bans.remove(&ip);
        }

        let window_start = observed_at_secs.saturating_sub(self.policy.window_secs);
        let failures = self.failures_by_ip.entry(ip).or_default();

        while let Some(oldest) = failures.front() {
            if *oldest < window_start {
                failures.pop_front();
            } else {
                break;
            }
        }

        failures.push_back(observed_at_secs);

        if failures.len() < self.policy.failure_threshold as usize {
            return None;
        }

        let matched_failures = failures.len();
        failures.clear();

        let expires_at_secs = observed_at_secs.saturating_add(self.policy.ban_duration_secs);
        self.active_bans.insert(ip, expires_at_secs);

        Some(SshBanDecision {
            ip,
            matched_failures,
            observed_at_secs,
            expires_at_secs,
        })
    }

    pub fn force_ban(&mut self, ip: IpAddr, observed_at_secs: u64) -> Option<SshBanDecision> {
        if let Some(expires_at_secs) = self.active_bans.get(&ip) {
            if *expires_at_secs > observed_at_secs {
                return None;
            }
            self.active_bans.remove(&ip);
        }

        self.failures_by_ip.remove(&ip);

        let expires_at_secs = observed_at_secs.saturating_add(self.policy.ban_duration_secs);
        self.active_bans.insert(ip, expires_at_secs);

        Some(SshBanDecision {
            ip,
            matched_failures: 1,
            observed_at_secs,
            expires_at_secs,
        })
    }

    pub fn replay_lines<I>(
        &mut self,
        lines: I,
        start_at_secs: u64,
        step_secs: u64,
    ) -> SshIngestSummary
    where
        I: IntoIterator<Item = String>,
    {
        let mut summary = SshIngestSummary::default();

        for (index, line) in lines.into_iter().enumerate() {
            summary.lines_read += 1;
            let observed_at_secs =
                start_at_secs.saturating_add((index as u64).saturating_mul(step_secs));

            if self.inspect_log_line(&line).is_some() {
                summary.matched_failures += 1;
            }

            if let Some(ban) = self.process_log_line(&line, observed_at_secs) {
                summary.bans.push(ban);
            }
        }

        summary
    }
}

#[derive(Clone, Debug)]
pub struct SshLogIngestor {
    inputs: Vec<SshLogInput>,
}

impl SshLogIngestor {
    #[must_use]
    pub fn new(sources: Vec<SshResolvedLogSource>) -> Self {
        Self {
            inputs: build_log_inputs(sources, false),
        }
    }

    #[must_use]
    pub fn new_tailing(sources: Vec<SshResolvedLogSource>) -> Self {
        Self {
            inputs: build_log_inputs(sources, true),
        }
    }

    pub fn poll_lines(&mut self) -> Result<Vec<String>, SshIngestError> {
        let mut lines = Vec::new();

        for input in &mut self.inputs {
            let mut batch = input.read_new_lines()?;
            lines.append(&mut batch);
        }

        Ok(lines)
    }

    pub fn read_all_lines_from_file(
        path: impl Into<PathBuf>,
    ) -> Result<Vec<String>, SshIngestError> {
        let mut cursor = LogFileCursor::new(path.into());
        cursor.read_all_lines()
    }
}

fn build_log_inputs(sources: Vec<SshResolvedLogSource>, tail_from_end: bool) -> Vec<SshLogInput> {
    sources
        .into_iter()
        .map(|source| match source {
            SshResolvedLogSource::Journald => SshLogInput::Journald(JournalctlCursor::default()),
            SshResolvedLogSource::LogFile(path) => {
                let mut cursor = LogFileCursor::new(PathBuf::from(path));
                if tail_from_end && let Err(error) = cursor.seek_to_end() {
                    warn!(
                        component = "ssh-detector",
                        event = "tail_init_failed",
                        path = %cursor.path.display(),
                        error = %error,
                        "failed to move SSH log cursor to the end during live-source initialization"
                    );
                }
                SshLogInput::File(cursor)
            }
        })
        .collect()
}

pub struct SshLiveIngestor {
    mode: SshLiveSourceMode,
    sources: Vec<SshResolvedLogSource>,
    inner: SshLiveIngestorInner,
}

enum SshLiveIngestorInner {
    Polling(SshLogIngestor),
    #[cfg(target_os = "linux")]
    JournaldFollow(JournalctlFollowSource),
    #[cfg(target_os = "linux")]
    LogFileWatch(LogFileWatchSource),
}

impl SshLiveIngestor {
    pub fn new(sources: Vec<SshResolvedLogSource>) -> Self {
        let capabilities = detect_live_source_capabilities();
        let candidates = live_source_candidates(&sources, capabilities);

        #[cfg(target_os = "linux")]
        {
            for mode in candidates {
                match mode {
                    SshLiveSourceMode::JournaldFollow => match JournalctlFollowSource::new() {
                        Ok(source) => {
                            return Self {
                                mode,
                                sources,
                                inner: SshLiveIngestorInner::JournaldFollow(source),
                            };
                        }
                        Err(error) => {
                            warn!(
                                component = "ssh-detector",
                                event = "live_source_fallback",
                                attempted_mode = mode.as_str(),
                                error = %error,
                                "failed to initialize preferred SSH live source; falling back"
                            );
                        }
                    },
                    SshLiveSourceMode::LogFileWatch => match LogFileWatchSource::new(&sources) {
                        Ok(source) => {
                            return Self {
                                mode,
                                sources,
                                inner: SshLiveIngestorInner::LogFileWatch(source),
                            };
                        }
                        Err(error) => {
                            warn!(
                                component = "ssh-detector",
                                event = "live_source_fallback",
                                attempted_mode = mode.as_str(),
                                error = %error,
                                "failed to initialize preferred SSH live source; falling back"
                            );
                        }
                    },
                    SshLiveSourceMode::Polling => {
                        return Self::polling(sources);
                    }
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        let _ = candidates;

        Self::polling(sources)
    }

    #[must_use]
    pub fn mode(&self) -> SshLiveSourceMode {
        self.mode
    }

    #[must_use]
    pub fn sources(&self) -> &[SshResolvedLogSource] {
        &self.sources
    }

    pub fn read_lines(&mut self, max_wait: Duration) -> Result<Vec<String>, SshIngestError> {
        match &mut self.inner {
            SshLiveIngestorInner::Polling(ingestor) => ingestor.poll_lines(),
            #[cfg(target_os = "linux")]
            SshLiveIngestorInner::JournaldFollow(source) => source.read_lines(max_wait),
            #[cfg(target_os = "linux")]
            SshLiveIngestorInner::LogFileWatch(source) => source.read_lines(max_wait),
        }
    }

    pub fn log_startup(&self) {
        info!(
            component = "ssh-detector",
            event = "live_source_selected",
            mode = self.mode.as_str(),
            sources = %self
                .sources()
                .iter()
                .map(source_label)
                .collect::<Vec<_>>()
                .join(", "),
            "selected SSH live ingestion mode"
        );
    }

    fn polling(sources: Vec<SshResolvedLogSource>) -> Self {
        Self {
            mode: SshLiveSourceMode::Polling,
            sources: sources.clone(),
            inner: SshLiveIngestorInner::Polling(SshLogIngestor::new_tailing(sources)),
        }
    }
}

#[derive(Clone, Debug)]
enum SshLogInput {
    File(LogFileCursor),
    Journald(JournalctlCursor),
}

impl SshLogInput {
    fn read_new_lines(&mut self) -> Result<Vec<String>, SshIngestError> {
        match self {
            Self::File(cursor) => cursor.read_new_lines(),
            Self::Journald(cursor) => cursor.read_new_lines(),
        }
    }
}

#[derive(Clone, Debug)]
struct LogFileCursor {
    path: PathBuf,
    offset: u64,
    carryover: String,
}

impl LogFileCursor {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            offset: 0,
            carryover: String::new(),
        }
    }

    fn seek_to_end(&mut self) -> Result<(), SshIngestError> {
        let path_label = self.path.display().to_string();
        let metadata = match File::open(&self.path) {
            Ok(file) => file
                .metadata()
                .map_err(|source| SshIngestError::ReadLogFile {
                    path: path_label.clone(),
                    source,
                })?,
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                self.offset = 0;
                self.carryover.clear();
                return Ok(());
            }
            Err(source) => {
                return Err(SshIngestError::ReadLogFile {
                    path: path_label,
                    source,
                });
            }
        };

        self.offset = metadata.len();
        self.carryover.clear();
        Ok(())
    }

    fn read_new_lines(&mut self) -> Result<Vec<String>, SshIngestError> {
        let path_label = self.path.display().to_string();
        let mut file = File::open(&self.path).map_err(|source| SshIngestError::ReadLogFile {
            path: path_label.clone(),
            source,
        })?;

        let metadata = file
            .metadata()
            .map_err(|source| SshIngestError::ReadLogFile {
                path: path_label.clone(),
                source,
            })?;

        if metadata.len() < self.offset {
            self.offset = 0;
            self.carryover.clear();
            warn!(
                component = "ssh-detector",
                event = "log_rotation_detected",
                path = %path_label,
                "SSH log file appears to have been truncated or rotated; resetting offset"
            );
        }

        file.seek(SeekFrom::Start(self.offset))
            .map_err(|source| SshIngestError::SeekLogFile {
                path: path_label.clone(),
                source,
            })?;

        let mut buffer = String::new();
        file.read_to_string(&mut buffer)
            .map_err(|source| SshIngestError::ReadLogFile {
                path: path_label.clone(),
                source,
            })?;

        self.offset = file
            .stream_position()
            .map_err(|source| SshIngestError::SeekLogFile {
                path: path_label,
                source,
            })?;

        Ok(split_lines_with_carryover(&mut self.carryover, buffer))
    }

    fn read_all_lines(&mut self) -> Result<Vec<String>, SshIngestError> {
        let path_label = self.path.display().to_string();
        let mut file = File::open(&self.path).map_err(|source| SshIngestError::ReadLogFile {
            path: path_label,
            source,
        })?;
        let mut buffer = String::new();
        file.read_to_string(&mut buffer)
            .map_err(|source| SshIngestError::ReadLogFile {
                path: self.path.display().to_string(),
                source,
            })?;

        let mut carryover = String::new();
        let mut lines = split_lines_with_carryover(&mut carryover, buffer);
        if !carryover.is_empty() {
            lines.push(carryover);
        }
        Ok(lines)
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug, Default)]
struct JournalctlCursor {
    cursor: Option<String>,
}

impl JournalctlCursor {
    fn read_new_lines(&mut self) -> Result<Vec<String>, SshIngestError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = self;
            Err(SshIngestError::UnsupportedJournald)
        }

        #[cfg(target_os = "linux")]
        {
            if self.cursor.is_none() {
                self.cursor = initialize_journal_cursor()?;
                return Ok(Vec::new());
            }

            let output = run_journalctl(&[
                "--show-cursor",
                "--no-pager",
                "-o",
                "cat",
                "--after-cursor",
                self.cursor.as_deref().unwrap_or_default(),
                "-u",
                "ssh",
                "-u",
                "sshd",
            ])?;

            let stdout = String::from_utf8_lossy(&output.stdout);
            let (lines, cursor) = parse_journalctl_output(&stdout);
            if let Some(cursor) = cursor {
                self.cursor = Some(cursor);
            }

            Ok(lines)
        }
    }
}

#[cfg(target_os = "linux")]
fn initialize_journal_cursor() -> Result<Option<String>, SshIngestError> {
    let output = run_journalctl(&[
        "--show-cursor",
        "--no-pager",
        "--lines",
        "0",
        "-o",
        "cat",
        "-u",
        "ssh",
        "-u",
        "sshd",
    ])?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let (_, cursor) = parse_journalctl_output(&stdout);

    if cursor.is_some() {
        return Ok(cursor);
    }

    let output = run_journalctl(&[
        "--show-cursor",
        "--no-pager",
        "--lines",
        "1",
        "-o",
        "cat",
        "-u",
        "ssh",
        "-u",
        "sshd",
    ])?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let (_, cursor) = parse_journalctl_output(&stdout);
    Ok(cursor)
}

#[cfg(target_os = "linux")]
fn run_journalctl(args: &[&str]) -> Result<std::process::Output, SshIngestError> {
    let output = Command::new("journalctl")
        .args(args)
        .output()
        .map_err(SshIngestError::Journalctl)?;

    if output.status.success() {
        Ok(output)
    } else {
        Err(SshIngestError::JournalctlFailed {
            status: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}

#[cfg(target_os = "linux")]
struct JournalctlFollowSource {
    _child: Child,
    stdout: BufReader<ChildStdout>,
    carryover: String,
}

#[cfg(target_os = "linux")]
impl JournalctlFollowSource {
    fn new() -> Result<Self, SshIngestError> {
        let cursor = initialize_journal_cursor()?;
        let mut child = Command::new("journalctl")
            .args(journalctl_follow_args(cursor.as_deref()))
            .stdout(Stdio::piped())
            .spawn()
            .map_err(SshIngestError::Journalctl)?;
        let stdout = child
            .stdout
            .take()
            .ok_or(SshIngestError::JournalctlMissingStdout)?;

        Ok(Self {
            _child: child,
            stdout: BufReader::new(stdout),
            carryover: String::new(),
        })
    }

    fn read_lines(&mut self, timeout: Duration) -> Result<Vec<String>, SshIngestError> {
        let fd = self.stdout.get_ref().as_raw_fd();
        if !wait_for_fd(fd, timeout, "journald_follow")? {
            return Ok(Vec::new());
        }

        let mut lines = Vec::new();
        loop {
            let mut line = String::new();
            match self.stdout.read_line(&mut line) {
                Ok(0) => {
                    if lines.is_empty() {
                        return Err(SshIngestError::JournalctlEnded);
                    }
                    break;
                }
                Ok(_) => {
                    let mut batch = split_lines_with_carryover(&mut self.carryover, line);
                    lines.append(&mut batch);
                }
                Err(source) => {
                    return Err(SshIngestError::ReadLiveSource {
                        source_name: "journald_follow".to_string(),
                        source,
                    });
                }
            }

            if !wait_for_fd(fd, Duration::ZERO, "journald_follow")? {
                break;
            }
        }

        Ok(lines)
    }
}

#[cfg(target_os = "linux")]
fn journalctl_follow_args(after_cursor: Option<&str>) -> Vec<String> {
    let mut args = vec![
        "--no-pager".to_string(),
        "--follow".to_string(),
        "-o".to_string(),
        "cat".to_string(),
        "-u".to_string(),
        "ssh".to_string(),
        "-u".to_string(),
        "sshd".to_string(),
    ];

    if let Some(cursor) = after_cursor {
        args.push("--after-cursor".to_string());
        args.push(cursor.to_string());
    } else {
        args.push("--lines".to_string());
        args.push("0".to_string());
        args.push("--since".to_string());
        args.push("now".to_string());
    }

    args
}

#[cfg(target_os = "linux")]
struct LogFileWatchSource {
    fd: OwnedFd,
    directories: HashMap<i32, HashMap<String, String>>,
    cursors: HashMap<String, LogFileCursor>,
}

#[cfg(target_os = "linux")]
impl LogFileWatchSource {
    fn new(sources: &[SshResolvedLogSource]) -> Result<Self, SshIngestError> {
        let raw_fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
        if raw_fd < 0 {
            return Err(SshIngestError::WatchLogFile {
                path: "inotify".to_string(),
                source: io::Error::last_os_error(),
            });
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        let mut directories: HashMap<i32, HashMap<String, String>> = HashMap::new();
        let mut cursors = HashMap::new();

        for path in sources.iter().filter_map(|source| match source {
            SshResolvedLogSource::Journald => None,
            SshResolvedLogSource::LogFile(path) => Some(path.clone()),
        }) {
            let parent = Path::new(&path)
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("/"));
            let file_name = Path::new(&path)
                .file_name()
                .map(|name| name.to_string_lossy().to_string())
                .ok_or_else(|| SshIngestError::WatchLogFile {
                    path: path.clone(),
                    source: io::Error::new(io::ErrorKind::InvalidInput, "missing file name"),
                })?;

            let directory_c = CString::new(parent.as_os_str().as_bytes()).map_err(|_| {
                SshIngestError::WatchLogFile {
                    path: parent.display().to_string(),
                    source: io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "directory path contains an interior null byte",
                    ),
                }
            })?;

            let wd = unsafe {
                libc::inotify_add_watch(
                    raw_fd,
                    directory_c.as_ptr(),
                    libc::IN_CLOSE_WRITE
                        | libc::IN_MODIFY
                        | libc::IN_CREATE
                        | libc::IN_MOVED_TO
                        | libc::IN_ATTRIB,
                )
            };
            if wd < 0 {
                return Err(SshIngestError::WatchLogFile {
                    path: parent.display().to_string(),
                    source: io::Error::last_os_error(),
                });
            }

            directories
                .entry(wd)
                .or_default()
                .insert(file_name, path.clone());
            let mut cursor = LogFileCursor::new(PathBuf::from(&path));
            cursor.seek_to_end()?;
            cursors.insert(path, cursor);
        }

        if cursors.is_empty() {
            return Err(SshIngestError::WatchLogFile {
                path: "log_file_watch".to_string(),
                source: io::Error::new(io::ErrorKind::InvalidInput, "no log files configured"),
            });
        }

        Ok(Self {
            fd,
            directories,
            cursors,
        })
    }

    fn read_lines(&mut self, timeout: Duration) -> Result<Vec<String>, SshIngestError> {
        if !wait_for_fd(self.fd.as_raw_fd(), timeout, "log_file_watch")? {
            return Ok(Vec::new());
        }

        let mut buffer = [0_u8; 4096];
        let bytes_read = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                buffer.as_mut_ptr().cast::<libc::c_void>(),
                buffer.len(),
            )
        };
        if bytes_read < 0 {
            return Err(SshIngestError::ReadLiveSource {
                source_name: "log_file_watch".to_string(),
                source: io::Error::last_os_error(),
            });
        }

        let changed = parse_inotify_paths(&buffer[..bytes_read as usize], &self.directories);

        let mut lines = Vec::new();
        for path in changed {
            let Some(cursor) = self.cursors.get_mut(&path) else {
                continue;
            };

            if !Path::new(&path).exists() {
                continue;
            }

            let mut batch = cursor.read_new_lines()?;
            lines.append(&mut batch);
        }

        Ok(lines)
    }
}

#[cfg(target_os = "linux")]
fn parse_inotify_paths(
    buffer: &[u8],
    directories: &HashMap<i32, HashMap<String, String>>,
) -> Vec<String> {
    let mut changed = HashSet::new();
    let mut offset = 0_usize;

    while offset + std::mem::size_of::<libc::inotify_event>() <= buffer.len() {
        let event = unsafe { &*(buffer[offset..].as_ptr().cast::<libc::inotify_event>()) };
        let event_size = std::mem::size_of::<libc::inotify_event>() + event.len as usize;
        if offset + event_size > buffer.len() {
            break;
        }

        if let Some(files) = directories.get(&event.wd) {
            let name_bytes =
                &buffer[offset + std::mem::size_of::<libc::inotify_event>()..offset + event_size];
            let name = name_bytes
                .split(|byte| *byte == 0)
                .next()
                .map(|value| String::from_utf8_lossy(value).to_string())
                .unwrap_or_default();

            if let Some(path) = files.get(&name) {
                changed.insert(path.clone());
            }
        }

        offset += event_size;
    }

    let mut changed = changed.into_iter().collect::<Vec<_>>();
    changed.sort();
    changed
}

#[cfg(target_os = "linux")]
fn wait_for_fd(fd: RawFd, timeout: Duration, source_name: &str) -> Result<bool, SshIngestError> {
    let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
    let mut poll_fd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let result = unsafe { libc::poll(&mut poll_fd, 1, timeout_ms) };

    if result < 0 {
        return Err(SshIngestError::WaitLiveSource {
            source_name: source_name.to_string(),
            source: io::Error::last_os_error(),
        });
    }

    Ok(result > 0 && (poll_fd.revents & libc::POLLIN) != 0)
}

fn split_lines_with_carryover(carryover: &mut String, buffer: String) -> Vec<String> {
    let mut combined = String::new();
    if !carryover.is_empty() {
        combined.push_str(carryover);
        carryover.clear();
    }
    combined.push_str(&buffer);

    if combined.is_empty() {
        return Vec::new();
    }

    let ends_with_newline = combined.ends_with('\n');
    let mut parts = combined
        .split('\n')
        .map(|line| line.trim_end_matches('\r').to_string())
        .collect::<Vec<_>>();

    if ends_with_newline {
        if matches!(parts.last(), Some(last) if last.is_empty()) {
            parts.pop();
        }
        parts
    } else {
        if let Some(last) = parts.pop() {
            *carryover = last;
        }
        parts
    }
}

#[cfg(target_os = "linux")]
fn parse_journalctl_output(stdout: &str) -> (Vec<String>, Option<String>) {
    let mut lines = Vec::new();
    let mut cursor = None;

    for line in stdout.lines() {
        if let Some(found) = line.strip_prefix("-- cursor: ") {
            cursor = Some(found.trim().to_string());
        } else if !line.trim().is_empty() {
            lines.push(line.to_string());
        }
    }

    (lines, cursor)
}

fn source_label(source: &SshResolvedLogSource) -> String {
    match source {
        SshResolvedLogSource::Journald => "journald".to_string(),
        SshResolvedLogSource::LogFile(path) => path.clone(),
    }
}

fn detect_live_source_capabilities() -> SshLiveSourceCapabilities {
    #[cfg(target_os = "linux")]
    {
        SshLiveSourceCapabilities {
            journald_follow: Path::new(JOURNAL_SOCKET_PATH).exists(),
            file_watch: true,
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        SshLiveSourceCapabilities::default()
    }
}

fn live_source_candidates(
    sources: &[SshResolvedLogSource],
    capabilities: SshLiveSourceCapabilities,
) -> Vec<SshLiveSourceMode> {
    let has_journald = sources
        .iter()
        .any(|source| matches!(source, SshResolvedLogSource::Journald));
    let has_log_files = sources
        .iter()
        .any(|source| matches!(source, SshResolvedLogSource::LogFile(_)));

    let mut modes = Vec::new();
    if has_journald && capabilities.journald_follow {
        modes.push(SshLiveSourceMode::JournaldFollow);
    }
    if has_log_files && capabilities.file_watch {
        modes.push(SshLiveSourceMode::LogFileWatch);
    }
    modes.push(SshLiveSourceMode::Polling);
    modes
}

fn resolve_sources_for_host(policy: &SshProtectionPolicy) -> Vec<SshResolvedLogSource> {
    resolve_sources_with(policy, Path::new(JOURNAL_SOCKET_PATH).exists(), |path| {
        Path::new(path).exists()
    })
}

fn resolve_sources_with<F>(
    policy: &SshProtectionPolicy,
    journald_available: bool,
    path_exists: F,
) -> Vec<SshResolvedLogSource>
where
    F: Fn(&str) -> bool,
{
    match policy.log_source_mode {
        SshLogSourceMode::Journald => vec![SshResolvedLogSource::Journald],
        SshLogSourceMode::LogFiles => configured_log_files(policy),
        SshLogSourceMode::Auto => {
            if journald_available {
                return vec![SshResolvedLogSource::Journald];
            }

            let configured = configured_log_files(policy);
            let existing = configured
                .into_iter()
                .filter(|source| match source {
                    SshResolvedLogSource::Journald => journald_available,
                    SshResolvedLogSource::LogFile(path) => path_exists(path),
                })
                .collect::<Vec<_>>();

            if !existing.is_empty() {
                return existing;
            }

            default_log_files()
        }
    }
}

fn configured_log_files(policy: &SshProtectionPolicy) -> Vec<SshResolvedLogSource> {
    if policy.log_file_paths.is_empty() {
        return default_log_files();
    }

    policy
        .log_file_paths
        .iter()
        .map(|path| SshResolvedLogSource::LogFile(path.clone()))
        .collect()
}

fn default_log_files() -> Vec<SshResolvedLogSource> {
    DEFAULT_SSH_LOG_FILES
        .iter()
        .map(|path| SshResolvedLogSource::LogFile((*path).to_string()))
        .collect()
}

fn parse_failure_event(line: &str) -> Option<SshFailureEvent> {
    if line.contains("Failed password") {
        return extract_ip_after_from(line).map(|ip| SshFailureEvent {
            ip,
            reason: SshFailureReason::FailedPassword,
            username: extract_username_after_failed_password(line),
        });
    }

    if line.contains("Invalid user") {
        return extract_ip_after_from(line).map(|ip| SshFailureEvent {
            ip,
            reason: SshFailureReason::InvalidUser,
            username: extract_username_after_invalid_user(line),
        });
    }

    if line.contains("maximum authentication attempts exceeded") {
        return extract_ip_after_from(line).map(|ip| SshFailureEvent {
            ip,
            reason: SshFailureReason::MaxAuthAttemptsExceeded,
            username: extract_username_after_generic_for(line),
        });
    }

    if line.contains("authentication failure;") {
        return extract_ip_after_key(line, "rhost=").map(|ip| SshFailureEvent {
            ip,
            reason: SshFailureReason::PamAuthFailure,
            username: extract_token_after_key(line, "user="),
        });
    }

    if let Some((username, ip)) = extract_preauth_user_and_ip(line) {
        return Some(SshFailureEvent {
            ip,
            reason: SshFailureReason::PreauthConnectionClosed,
            username: Some(username),
        });
    }

    None
}

fn extract_ip_after_from(line: &str) -> Option<IpAddr> {
    let start = line.find(" from ")? + " from ".len();
    extract_ip_token(&line[start..])
}

fn extract_ip_after_key(line: &str, key: &str) -> Option<IpAddr> {
    let start = line.find(key)? + key.len();
    extract_ip_token(&line[start..])
}

fn extract_username_after_failed_password(line: &str) -> Option<String> {
    extract_token_between(line, " for invalid user ", " from ")
        .or_else(|| extract_token_between(line, " for ", " from "))
}

fn extract_username_after_invalid_user(line: &str) -> Option<String> {
    extract_token_between(line, "Invalid user ", " from ")
}

fn extract_username_after_generic_for(line: &str) -> Option<String> {
    extract_token_between(line, " for ", " from ")
}

fn extract_preauth_user_and_ip(line: &str) -> Option<(String, IpAddr)> {
    const PREAUTH_SUFFIX: &str = " [preauth]";
    let prefix = if line.contains("Connection closed by authenticating user ") {
        "Connection closed by authenticating user "
    } else if line.contains("Connection reset by authenticating user ") {
        "Connection reset by authenticating user "
    } else {
        return None;
    };

    if !line.contains(PREAUTH_SUFFIX) {
        return None;
    }

    let start = line.find(prefix)? + prefix.len();
    let rest = &line[start..];
    let end = rest.find(" port ")?;
    let mut parts = rest[..end].split_whitespace();
    let username = parts.next()?.trim();
    let ip = parts.next()?.parse().ok()?;

    (!username.is_empty()).then(|| (username.to_string(), ip))
}

fn extract_token_after_key(line: &str, key: &str) -> Option<String> {
    line.split_whitespace()
        .find_map(|token| token.strip_prefix(key))
        .filter(|token| !token.is_empty())
        .map(ToString::to_string)
}

fn extract_token_between(line: &str, prefix: &str, suffix: &str) -> Option<String> {
    let start = line.find(prefix)? + prefix.len();
    let rest = &line[start..];
    let end = rest.find(suffix)?;
    let token = rest[..end].trim();
    (!token.is_empty()).then(|| token.to_string())
}

fn extract_ip_token(input: &str) -> Option<IpAddr> {
    let token = input
        .split_whitespace()
        .next()?
        .trim_matches(|ch| ch == '[' || ch == ']');
    token.parse().ok()
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use walle_policy::{SshLogSourceMode, SshProtectionPolicy};

    use super::{
        LogFileCursor, SshDetectorService, SshFailureReason, SshLiveSourceCapabilities,
        SshLiveSourceMode, SshLogIngestor, SshResolvedLogSource, live_source_candidates,
        parse_failure_event, resolve_sources_with, split_lines_with_carryover,
    };
    #[cfg(target_os = "linux")]
    use super::journalctl_follow_args;

    #[test]
    fn parses_failed_password_line_from_auth_log() {
        let line = "Jul 12 12:00:00 host sshd[100]: Failed password for invalid user admin from 203.0.113.10 port 22 ssh2";
        let event = parse_failure_event(line).unwrap();
        assert_eq!(event.ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)));
        assert_eq!(event.reason, SshFailureReason::FailedPassword);
        assert_eq!(event.username.as_deref(), Some("admin"));
    }

    #[test]
    fn parses_pam_auth_failure_line_from_secure_log() {
        let line = "Jul 12 12:00:00 host sshd[200]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=198.51.100.5 user=root";
        let event = parse_failure_event(line).unwrap();
        assert_eq!(event.ip, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5)));
        assert_eq!(event.reason, SshFailureReason::PamAuthFailure);
        assert_eq!(event.username.as_deref(), Some("root"));
    }

    #[test]
    fn parses_preauth_connection_closed_line_from_auth_log() {
        let line = "2026-04-14T02:00:22.462580+08:00 host sshd[465140]: Connection closed by authenticating user root 180.76.76.76 port 53256 [preauth]";
        let event = parse_failure_event(line).unwrap();
        assert_eq!(event.ip, IpAddr::V4(Ipv4Addr::new(180, 76, 76, 76)));
        assert_eq!(event.reason, SshFailureReason::PreauthConnectionClosed);
        assert_eq!(event.username.as_deref(), Some("root"));
    }

    #[test]
    fn parses_preauth_connection_reset_line_from_auth_log() {
        let line = "2026-04-14T02:00:22.462580+08:00 host sshd[465140]: Connection reset by authenticating user root 8.8.8.8 port 53256 [preauth]";
        let event = parse_failure_event(line).unwrap();
        assert_eq!(event.ip, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(event.reason, SshFailureReason::PreauthConnectionClosed);
        assert_eq!(event.username.as_deref(), Some("root"));
    }

    #[test]
    fn auto_mode_prefers_journald_when_available() {
        let policy = SshProtectionPolicy::default();
        let sources = resolve_sources_with(&policy, true, |path| path == "/var/log/auth.log");
        assert_eq!(sources, vec![SshResolvedLogSource::Journald]);
    }

    #[test]
    fn auto_mode_falls_back_to_existing_log_file_when_journald_is_unavailable() {
        let policy = SshProtectionPolicy::default();
        let sources = resolve_sources_with(&policy, false, |path| path == "/var/log/auth.log");
        assert_eq!(
            sources,
            vec![SshResolvedLogSource::LogFile(
                "/var/log/auth.log".to_string()
            )]
        );
    }

    #[test]
    fn explicit_journald_mode_ignores_file_checks() {
        let policy = SshProtectionPolicy {
            log_source_mode: SshLogSourceMode::Journald,
            ..SshProtectionPolicy::default()
        };

        let sources = resolve_sources_with(&policy, false, |_| false);
        assert_eq!(sources, vec![SshResolvedLogSource::Journald]);
    }

    #[test]
    fn live_source_candidates_prefer_event_driven_then_polling_for_journald() {
        let modes = live_source_candidates(
            &[SshResolvedLogSource::Journald],
            SshLiveSourceCapabilities {
                journald_follow: true,
                file_watch: true,
            },
        );

        assert_eq!(
            modes,
            vec![
                SshLiveSourceMode::JournaldFollow,
                SshLiveSourceMode::Polling
            ]
        );
    }

    #[test]
    fn live_source_candidates_prefer_file_watch_then_polling_for_log_files() {
        let modes = live_source_candidates(
            &[SshResolvedLogSource::LogFile(
                "/var/log/auth.log".to_string(),
            )],
            SshLiveSourceCapabilities {
                journald_follow: true,
                file_watch: true,
            },
        );

        assert_eq!(
            modes,
            vec![SshLiveSourceMode::LogFileWatch, SshLiveSourceMode::Polling]
        );
    }

    #[test]
    fn live_source_candidates_fall_back_to_polling_when_watch_support_is_missing() {
        let modes = live_source_candidates(
            &[SshResolvedLogSource::LogFile(
                "/var/log/auth.log".to_string(),
            )],
            SshLiveSourceCapabilities::default(),
        );

        assert_eq!(modes, vec![SshLiveSourceMode::Polling]);
    }

    #[test]
    fn threshold_crossing_emits_ban_decision() {
        let mut detector = SshDetectorService::new(SshProtectionPolicy {
            failure_threshold: 3,
            window_secs: 60,
            ban_duration_secs: 120,
            ..SshProtectionPolicy::default()
        });
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));

        assert!(detector.observe_failure(ip, 1).is_none());
        assert!(detector.observe_failure(ip, 10).is_none());

        let decision = detector.observe_failure(ip, 20).unwrap();
        assert_eq!(decision.ip, ip);
        assert_eq!(decision.matched_failures, 3);
        assert_eq!(decision.expires_at_secs, 140);
    }

    #[test]
    fn old_failures_fall_outside_the_window() {
        let mut detector = SshDetectorService::new(SshProtectionPolicy {
            failure_threshold: 2,
            window_secs: 10,
            ban_duration_secs: 60,
            ..SshProtectionPolicy::default()
        });
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20));

        assert!(detector.observe_failure(ip, 1).is_none());
        assert!(detector.observe_failure(ip, 20).is_none());
    }

    #[test]
    fn split_lines_keeps_partial_line_in_carryover() {
        let mut carryover = String::new();
        let lines = split_lines_with_carryover(&mut carryover, "one\ntwo".to_string());

        assert_eq!(lines, vec!["one".to_string()]);
        assert_eq!(carryover, "two".to_string());
    }

    #[test]
    fn file_cursor_reads_incremental_lines() {
        let path = unique_temp_path("walle-auth.log");
        fs::write(
            &path,
            "Jul 12 sshd[1]: Failed password for root from 203.0.113.1 port 22 ssh2\n",
        )
        .unwrap();

        let mut cursor = LogFileCursor::new(path.clone());
        let first = cursor.read_new_lines().unwrap();
        assert_eq!(first.len(), 1);

        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        writeln!(
            file,
            "Jul 12 sshd[2]: Invalid user admin from 203.0.113.2 port 22"
        )
        .unwrap();

        let second = cursor.read_new_lines().unwrap();
        assert_eq!(second.len(), 1);

        fs::remove_file(path).ok();
    }

    #[test]
    fn replay_file_reads_all_lines() {
        let path = unique_temp_path("walle-secure.log");
        fs::write(
            &path,
            "Jul 12 sshd[1]: Failed password for root from 203.0.113.1 port 22 ssh2\nJul 12 sshd[2]: Failed password for root from 203.0.113.1 port 22 ssh2\n",
        )
        .unwrap();

        let lines = SshLogIngestor::read_all_lines_from_file(path.clone()).unwrap();
        assert_eq!(lines.len(), 2);

        fs::remove_file(path).ok();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn journald_follow_args_with_cursor_resume_precisely() {
        let args = journalctl_follow_args(Some("s=123;i=456"));
        assert!(args.windows(2).any(|window| {
            window[0] == "--after-cursor" && window[1] == "s=123;i=456"
        }));
        assert!(args.iter().any(|value| value == "--follow"));
        assert!(!args.iter().any(|value| value == "--since"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn journald_follow_args_without_cursor_skip_historical_entries() {
        let args = journalctl_follow_args(None);
        assert!(args.windows(2).any(|window| window[0] == "--lines" && window[1] == "0"));
        assert!(args.windows(2).any(|window| window[0] == "--since" && window[1] == "now"));
        assert!(args.iter().any(|value| value == "--follow"));
    }

    fn unique_temp_path(file_name: &str) -> PathBuf {
        let mut path = env::temp_dir();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!("{timestamp}-{file_name}"));
        path
    }
}
