use std::fs;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use russh::client;
use russh::client::AuthResult;
use russh::keys::PrivateKeyWithHashAlg;
use thiserror::Error;
use tokio::runtime::Builder;
use tokio::time::timeout;
use walle_policy::SshJailPolicy;

use crate::sshjail::{SshJailError, SshJailService};

const MEMINFO_PATH: &str = "/proc/meminfo";
const PROC_LIMITS_PATH: &str = "/proc/self/limits";
const FAILURE_SAMPLE_LIMIT: usize = 10;

#[derive(Clone, Debug)]
pub struct SshJailStressOptions {
    pub target_sessions: usize,
    pub max_sessions: usize,
    pub hold_secs: u64,
    pub launch_interval_ms: u64,
    pub sample_interval_ms: u64,
    pub connect_timeout_ms: u64,
    pub username: String,
}

impl Default for SshJailStressOptions {
    fn default() -> Self {
        Self {
            target_sessions: 1_024,
            max_sessions: 1_024,
            hold_secs: 30,
            launch_interval_ms: 20,
            sample_interval_ms: 500,
            connect_timeout_ms: 5_000,
            username: "root".to_string(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshJailStressReport {
    pub bound_port: u16,
    pub target_sessions: usize,
    pub max_sessions: usize,
    pub attempted_sessions: usize,
    pub established_sessions: usize,
    pub failed_sessions: usize,
    pub failure_samples: Vec<String>,
    pub nofile_soft_limit: Option<u64>,
    pub nofile_hard_limit: Option<u64>,
    pub memory_total_kb: u64,
    pub memory_budget_50pct_kb: u64,
    pub baseline_available_kb: u64,
    pub min_available_kb: u64,
    pub peak_consumed_kb: u64,
    pub per_session_kb: u64,
    pub estimated_fd_per_session: Option<u64>,
    pub recommended_by_nofile_50pct: Option<usize>,
    pub observed_max_interactive_shells: usize,
    pub recommended_max_sessions: usize,
    pub recommended_max_sessions_capped: usize,
    pub recommended_max_sessions_final: usize,
}

#[derive(Debug, Error)]
pub enum SshJailStressError {
    #[error("invalid stress option `{field}`: {reason}")]
    InvalidOption {
        field: &'static str,
        reason: &'static str,
    },
    #[error("failed to start sshjail stress target: {source}")]
    StartSshJail { source: SshJailError },
    #[error("failed to build tokio runtime for stress test: {source}")]
    BuildRuntime { source: io::Error },
    #[error("failed to read {path}: {source}")]
    ReadMemInfo {
        path: &'static str,
        source: io::Error,
    },
    #[error("failed to parse `{field}` from {path}")]
    ParseMemInfo {
        path: &'static str,
        field: &'static str,
    },
    #[error("failed to generate stress-test SSH key: {message}")]
    GenerateClientKey { message: String },
}

#[derive(Clone, Copy, Debug)]
struct SystemMemorySnapshot {
    total_kb: u64,
    available_kb: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct OpenFileLimitSnapshot {
    soft: Option<u64>,
    hard: Option<u64>,
}

struct StressClientSession {
    _handle: client::Handle<StressClientHandler>,
    channel: russh::Channel<client::Msg>,
}

#[derive(Clone)]
struct StressClientHandler;

impl client::Handler for StressClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Recommendation {
    memory_budget_kb: u64,
    per_session_kb: u64,
    recommended_by_memory_uncapped: usize,
    recommended_by_memory_capped: usize,
    estimated_fd_per_session: Option<u64>,
    recommended_by_nofile_50pct: Option<usize>,
    observed_max_interactive_shells: usize,
    recommended_final: usize,
}

pub fn run_sshjail_stress_test(
    base_policy: &SshJailPolicy,
    options: SshJailStressOptions,
) -> Result<SshJailStressReport, SshJailStressError> {
    validate_options(&options)?;

    let mut policy = base_policy.clone();
    policy.max_sessions = options.max_sessions;

    let service = SshJailService::start(&policy)
        .map_err(|source| SshJailStressError::StartSshJail { source })?;
    let bound_port = service.bound_port();

    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|source| SshJailStressError::BuildRuntime { source })?;

    let report = runtime.block_on(async_run_stress(bound_port, options))?;

    drop(service);
    Ok(report)
}

fn validate_options(options: &SshJailStressOptions) -> Result<(), SshJailStressError> {
    if options.max_sessions == 0 {
        return Err(SshJailStressError::InvalidOption {
            field: "max_sessions",
            reason: "must be greater than zero",
        });
    }
    if options.target_sessions == 0 {
        return Err(SshJailStressError::InvalidOption {
            field: "target_sessions",
            reason: "must be greater than zero",
        });
    }
    if options.sample_interval_ms == 0 {
        return Err(SshJailStressError::InvalidOption {
            field: "sample_interval_ms",
            reason: "must be greater than zero",
        });
    }
    if options.connect_timeout_ms == 0 {
        return Err(SshJailStressError::InvalidOption {
            field: "connect_timeout_ms",
            reason: "must be greater than zero",
        });
    }
    if options.username.trim().is_empty() {
        return Err(SshJailStressError::InvalidOption {
            field: "username",
            reason: "cannot be empty",
        });
    }
    Ok(())
}

async fn async_run_stress(
    bound_port: u16,
    options: SshJailStressOptions,
) -> Result<SshJailStressReport, SshJailStressError> {
    let address = format!("127.0.0.1:{bound_port}");
    let connect_timeout = Duration::from_millis(options.connect_timeout_ms);
    let launch_interval = Duration::from_millis(options.launch_interval_ms);
    let sample_interval = Duration::from_millis(options.sample_interval_ms);
    let client_config = Arc::new(client::Config::default());
    let client_key = Arc::new(
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::ssh_key::Algorithm::Ed25519)
            .map_err(|source| SshJailStressError::GenerateClientKey {
                message: source.to_string(),
            })?,
    );

    let nofile_limits = read_open_file_limits();
    let baseline = read_system_memory_snapshot()?;
    let mut min_available_kb = baseline.available_kb;
    let mut sessions = Vec::with_capacity(options.target_sessions);
    let mut attempted_sessions = 0usize;
    let mut failed_sessions = 0usize;
    let mut failure_samples = Vec::new();

    for index in 0..options.target_sessions {
        attempted_sessions += 1;
        match open_one_session(
            address.as_str(),
            client_config.clone(),
            connect_timeout,
            options.username.as_str(),
            client_key.clone(),
        )
        .await
        {
            Ok(session) => sessions.push(session),
            Err(error) => {
                failed_sessions += 1;
                if failure_samples.len() < FAILURE_SAMPLE_LIMIT {
                    failure_samples.push(format!("session[{index}] {error}"));
                }
            }
        }

        let snapshot = read_system_memory_snapshot()?;
        min_available_kb = min_available_kb.min(snapshot.available_kb);

        if !launch_interval.is_zero() {
            tokio::time::sleep(launch_interval).await;
        }
    }

    if options.hold_secs > 0 {
        let hold_deadline = tokio::time::Instant::now() + Duration::from_secs(options.hold_secs);
        while tokio::time::Instant::now() < hold_deadline {
            tokio::time::sleep(sample_interval).await;
            let snapshot = read_system_memory_snapshot()?;
            min_available_kb = min_available_kb.min(snapshot.available_kb);
        }
    }

    for session in sessions {
        let _ = session.channel.close().await;
    }

    let established_sessions = attempted_sessions.saturating_sub(failed_sessions);
    let peak_consumed_kb = baseline.available_kb.saturating_sub(min_available_kb);
    let recommendation = calculate_recommendation(
        baseline.total_kb,
        peak_consumed_kb,
        established_sessions,
        options.target_sessions,
        nofile_limits.soft,
    );

    Ok(SshJailStressReport {
        bound_port,
        target_sessions: options.target_sessions,
        max_sessions: options.max_sessions,
        attempted_sessions,
        established_sessions,
        failed_sessions,
        failure_samples,
        nofile_soft_limit: nofile_limits.soft,
        nofile_hard_limit: nofile_limits.hard,
        memory_total_kb: baseline.total_kb,
        memory_budget_50pct_kb: recommendation.memory_budget_kb,
        baseline_available_kb: baseline.available_kb,
        min_available_kb,
        peak_consumed_kb,
        per_session_kb: recommendation.per_session_kb,
        estimated_fd_per_session: recommendation.estimated_fd_per_session,
        recommended_by_nofile_50pct: recommendation.recommended_by_nofile_50pct,
        observed_max_interactive_shells: recommendation.observed_max_interactive_shells,
        recommended_max_sessions: recommendation.recommended_by_memory_uncapped,
        recommended_max_sessions_capped: recommendation.recommended_by_memory_capped,
        recommended_max_sessions_final: recommendation.recommended_final,
    })
}

async fn open_one_session(
    address: &str,
    client_config: Arc<client::Config>,
    connect_timeout: Duration,
    username: &str,
    client_key: Arc<russh::keys::PrivateKey>,
) -> Result<StressClientSession, String> {
    let mut handle = timeout(
        connect_timeout,
        client::connect(client_config, address, StressClientHandler),
    )
    .await
    .map_err(|_| format!("connect timeout after {} ms", connect_timeout.as_millis()))?
    .map_err(|error| format!("connect failed: {error}"))?;

    let auth = timeout(
        connect_timeout,
        handle.authenticate_publickey(
            username.to_string(),
            PrivateKeyWithHashAlg::new(client_key, None),
        ),
    )
    .await
    .map_err(|_| format!("auth timeout after {} ms", connect_timeout.as_millis()))?
    .map_err(|error| format!("authenticate_publickey failed: {error}"))?;

    if !matches!(auth, AuthResult::Success) {
        return Err("authentication rejected by sshjail".to_string());
    }

    let channel = timeout(connect_timeout, handle.channel_open_session())
        .await
        .map_err(|_| {
            format!(
                "channel_open_session timeout after {} ms",
                connect_timeout.as_millis()
            )
        })?
        .map_err(|error| format!("channel_open_session failed: {error}"))?;

    timeout(
        connect_timeout,
        channel.request_pty(true, "xterm-256color", 120, 30, 0, 0, &[]),
    )
    .await
    .map_err(|_| {
        format!(
            "request_pty timeout after {} ms",
            connect_timeout.as_millis()
        )
    })?
    .map_err(|error| format!("request_pty failed: {error}"))?;

    timeout(connect_timeout, channel.request_shell(true))
        .await
        .map_err(|_| {
            format!(
                "request_shell timeout after {} ms",
                connect_timeout.as_millis()
            )
        })?
        .map_err(|error| format!("request_shell failed: {error}"))?;

    Ok(StressClientSession {
        _handle: handle,
        channel,
    })
}

fn read_system_memory_snapshot() -> Result<SystemMemorySnapshot, SshJailStressError> {
    let content =
        fs::read_to_string(MEMINFO_PATH).map_err(|source| SshJailStressError::ReadMemInfo {
            path: MEMINFO_PATH,
            source,
        })?;
    parse_system_memory_snapshot(content.as_str())
}

fn read_open_file_limits() -> OpenFileLimitSnapshot {
    let content = match fs::read_to_string(PROC_LIMITS_PATH) {
        Ok(value) => value,
        Err(_) => return OpenFileLimitSnapshot::default(),
    };
    parse_open_file_limits(content.as_str())
}

fn parse_open_file_limits(content: &str) -> OpenFileLimitSnapshot {
    let mut snapshot = OpenFileLimitSnapshot::default();

    for line in content.lines() {
        if !line.starts_with("Max open files") {
            continue;
        }

        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() < 5 {
            break;
        }

        snapshot.soft = parse_limit_value(tokens[3]);
        snapshot.hard = parse_limit_value(tokens[4]);
        break;
    }

    snapshot
}

fn parse_limit_value(value: &str) -> Option<u64> {
    if value.eq_ignore_ascii_case("unlimited") {
        None
    } else {
        value.parse::<u64>().ok()
    }
}

fn parse_system_memory_snapshot(content: &str) -> Result<SystemMemorySnapshot, SshJailStressError> {
    let mut total_kb = None;
    let mut available_kb = None;

    for line in content.lines() {
        if line.starts_with("MemTotal:") {
            total_kb = parse_meminfo_value(line);
            continue;
        }
        if line.starts_with("MemAvailable:") {
            available_kb = parse_meminfo_value(line);
        }
    }

    let total_kb = total_kb.ok_or(SshJailStressError::ParseMemInfo {
        path: MEMINFO_PATH,
        field: "MemTotal",
    })?;
    let available_kb = available_kb.ok_or(SshJailStressError::ParseMemInfo {
        path: MEMINFO_PATH,
        field: "MemAvailable",
    })?;

    Ok(SystemMemorySnapshot {
        total_kb,
        available_kb,
    })
}

fn parse_meminfo_value(line: &str) -> Option<u64> {
    line.split_whitespace().nth(1)?.parse::<u64>().ok()
}

fn calculate_recommendation(
    total_kb: u64,
    peak_consumed_kb: u64,
    established_sessions: usize,
    tested_cap: usize,
    nofile_soft_limit: Option<u64>,
) -> Recommendation {
    let memory_budget_kb = total_kb / 2;
    let observed_max_interactive_shells = established_sessions;

    if established_sessions == 0 {
        return Recommendation {
            memory_budget_kb,
            per_session_kb: 0,
            recommended_by_memory_uncapped: 0,
            recommended_by_memory_capped: 0,
            estimated_fd_per_session: None,
            recommended_by_nofile_50pct: None,
            observed_max_interactive_shells,
            recommended_final: 0,
        };
    }

    let per_session_kb = if peak_consumed_kb == 0 {
        0
    } else {
        peak_consumed_kb.div_ceil(established_sessions as u64)
    };

    let recommended_by_memory_uncapped = if per_session_kb == 0 {
        established_sessions
    } else {
        (memory_budget_kb / per_session_kb) as usize
    };

    let recommended_by_memory_capped = recommended_by_memory_uncapped.min(tested_cap);

    let estimated_fd_per_session = nofile_soft_limit.map(|soft_limit| {
        let estimate = soft_limit.div_ceil(established_sessions as u64);
        estimate.max(1)
    });
    let recommended_by_nofile_50pct = match (nofile_soft_limit, estimated_fd_per_session) {
        (Some(soft_limit), Some(estimated_per_session)) => {
            let half_budget = soft_limit / 2;
            Some((half_budget / estimated_per_session) as usize)
        }
        _ => None,
    };

    let recommended_final = recommended_by_nofile_50pct
        .unwrap_or(recommended_by_memory_capped)
        .min(recommended_by_memory_capped);

    Recommendation {
        memory_budget_kb,
        per_session_kb,
        recommended_by_memory_uncapped,
        recommended_by_memory_capped,
        estimated_fd_per_session,
        recommended_by_nofile_50pct,
        observed_max_interactive_shells,
        recommended_final,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SshJailStressError, SshJailStressOptions, calculate_recommendation, parse_open_file_limits,
        parse_system_memory_snapshot, validate_options,
    };

    #[test]
    fn options_validation_rejects_zero_max_sessions() {
        let options = SshJailStressOptions {
            max_sessions: 0,
            ..SshJailStressOptions::default()
        };

        let result = validate_options(&options);
        assert!(matches!(
            result,
            Err(SshJailStressError::InvalidOption {
                field: "max_sessions",
                ..
            })
        ));
    }

    #[test]
    fn meminfo_parser_reads_total_and_available_kb() {
        let snapshot = parse_system_memory_snapshot(
            "MemTotal:       8000000 kB\nMemFree:         1000000 kB\nMemAvailable:    3000000 kB\n",
        )
        .unwrap();

        assert_eq!(snapshot.total_kb, 8_000_000);
        assert_eq!(snapshot.available_kb, 3_000_000);
    }

    #[test]
    fn recommendation_uses_50_percent_memory_budget() {
        let recommendation = calculate_recommendation(
            8_000_000, // total
            2_000_000, // peak consumed
            1_000,     // established sessions
            1_024,     // tested cap
            None,      // nofile soft
        );

        assert_eq!(recommendation.memory_budget_kb, 4_000_000);
        assert_eq!(recommendation.per_session_kb, 2_000);
        assert_eq!(recommendation.recommended_by_memory_uncapped, 2_000);
        assert_eq!(recommendation.recommended_by_memory_capped, 1_024);
        assert_eq!(recommendation.recommended_final, 1_024);
    }

    #[test]
    fn recommendation_uses_nofile_limit_when_available() {
        let recommendation = calculate_recommendation(
            8_000_000, // total
            100_000,   // peak consumed
            300,       // established sessions
            1_024,     // tested cap
            Some(1_024),
        );

        assert_eq!(recommendation.estimated_fd_per_session, Some(4));
        assert_eq!(recommendation.recommended_by_nofile_50pct, Some(128));
        assert_eq!(recommendation.recommended_final, 128);
    }

    #[test]
    fn parser_reads_open_file_limits() {
        let limits = parse_open_file_limits(
            "Limit                     Soft Limit           Hard Limit           Units\nMax open files            1024                 4096                 files\n",
        );

        assert_eq!(limits.soft, Some(1_024));
        assert_eq!(limits.hard, Some(4_096));
    }
}
