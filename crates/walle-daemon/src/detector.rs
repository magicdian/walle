use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::Command;

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshFailureEvent {
    pub ip: IpAddr,
    pub reason: SshFailureReason,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SshFailureReason {
    FailedPassword,
    InvalidUser,
    PamAuthFailure,
    MaxAuthAttemptsExceeded,
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
    #[error("journald ingestion is only supported on Linux hosts")]
    UnsupportedJournald,
    #[error("failed to run journalctl: {0}")]
    Journalctl(io::Error),
    #[error("journalctl exited with status {status}: {stderr}")]
    JournalctlFailed { status: i32, stderr: String },
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
        let inputs = sources
            .into_iter()
            .map(|source| match source {
                SshResolvedLogSource::Journald => {
                    SshLogInput::Journald(JournalctlCursor::default())
                }
                SshResolvedLogSource::LogFile(path) => {
                    SshLogInput::File(LogFileCursor::new(PathBuf::from(path)))
                }
            })
            .collect();

        Self { inputs }
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

            if journald_available {
                return vec![SshResolvedLogSource::Journald];
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
        });
    }

    if line.contains("Invalid user") {
        return extract_ip_after_from(line).map(|ip| SshFailureEvent {
            ip,
            reason: SshFailureReason::InvalidUser,
        });
    }

    if line.contains("maximum authentication attempts exceeded") {
        return extract_ip_after_from(line).map(|ip| SshFailureEvent {
            ip,
            reason: SshFailureReason::MaxAuthAttemptsExceeded,
        });
    }

    if line.contains("authentication failure;") {
        return extract_ip_after_key(line, "rhost=").map(|ip| SshFailureEvent {
            ip,
            reason: SshFailureReason::PamAuthFailure,
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
        LogFileCursor, SshDetectorService, SshFailureReason, SshLogIngestor, SshResolvedLogSource,
        parse_failure_event, resolve_sources_with, split_lines_with_carryover,
    };

    #[test]
    fn parses_failed_password_line_from_auth_log() {
        let line = "Jul 12 12:00:00 host sshd[100]: Failed password for invalid user admin from 203.0.113.10 port 22 ssh2";
        let event = parse_failure_event(line).unwrap();
        assert_eq!(event.ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)));
        assert_eq!(event.reason, SshFailureReason::FailedPassword);
    }

    #[test]
    fn parses_pam_auth_failure_line_from_secure_log() {
        let line = "Jul 12 12:00:00 host sshd[200]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=198.51.100.5 user=root";
        let event = parse_failure_event(line).unwrap();
        assert_eq!(event.ip, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5)));
        assert_eq!(event.reason, SshFailureReason::PamAuthFailure);
    }

    #[test]
    fn auto_mode_prefers_existing_linux_log_file() {
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
