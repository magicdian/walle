use std::path::PathBuf;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub mod detector;
pub mod error;
pub mod logging;
pub mod runtime;
pub mod xdp;

use tracing::{debug, info, warn};
use walle_common::{AccessMode, IcmpMode};
use walle_policy::WalleConfig;

use crate::detector::{
    SshBanDecision, SshDetectorService, SshFailureEvent, SshIngestSummary, SshLogIngestor,
    SshResolvedLogSource,
};
pub use crate::error::DaemonError;
use crate::logging::format_unix_timestamp_secs;
use crate::runtime::{
    EnvironmentReport, RuntimeController, RuntimeSnapshot, log_environment_report,
    verify_environment,
};
pub use crate::xdp::XdpError;
use crate::xdp::{XdpAttachment, maybe_attach};

const DEFAULT_SSH_POLL_INTERVAL_MS: u64 = 1_000;

#[derive(Clone, Debug)]
pub struct DaemonOptions {
    pub interface: Option<String>,
    pub foreground: bool,
    pub xdp_object: Option<PathBuf>,
    pub map_pin_path: Option<PathBuf>,
    pub ssh_poll_interval_ms: u64,
    pub ssh_follow_iterations: Option<u64>,
}

impl Default for DaemonOptions {
    fn default() -> Self {
        Self {
            interface: None,
            foreground: false,
            xdp_object: None,
            map_pin_path: None,
            ssh_poll_interval_ms: DEFAULT_SSH_POLL_INTERVAL_MS,
            ssh_follow_iterations: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusSnapshot {
    pub interface: Option<String>,
    pub access_mode: AccessMode,
    pub icmp_mode: IcmpMode,
    pub ssh_protection_enabled: bool,
    pub ssh_failure_threshold: u32,
    pub xdp_attached: bool,
    pub allow_v4_entries: usize,
    pub allow_v6_entries: usize,
    pub deny_v4_entries: usize,
    pub deny_v6_entries: usize,
    pub icmp_rule_entries: usize,
}

pub struct WalleDaemon {
    detector: SshDetectorService,
    ssh_ingestor: SshLogIngestor,
    runtime: RuntimeController,
    xdp: Option<XdpAttachment>,
    config: WalleConfig,
    options: DaemonOptions,
}

impl WalleDaemon {
    pub fn new(config: WalleConfig, options: DaemonOptions) -> Result<Self, DaemonError> {
        config.validate()?;

        let runtime = RuntimeController::new(options.interface.clone());
        let detector = SshDetectorService::new(config.ssh.clone());
        let ssh_ingestor = detector.create_ingestor();

        Ok(Self {
            detector,
            ssh_ingestor,
            runtime,
            xdp: None,
            config,
            options,
        })
    }

    pub fn run(&mut self) -> Result<(), DaemonError> {
        self.startup()?;

        if self.should_run_follow_loop() {
            self.run_ssh_follow_loop()?;
        }

        Ok(())
    }

    pub fn startup(&mut self) -> Result<(), DaemonError> {
        info!(
            component = "daemon",
            event = "startup",
            interface = self.options.interface.as_deref().unwrap_or("unset"),
            foreground = self.options.foreground,
            "starting phase-1 daemon scaffold"
        );

        let environment = self.verify_environment();
        log_environment_report(&environment);

        self.xdp = maybe_attach(
            self.options.interface.as_deref(),
            self.options.xdp_object.as_deref(),
            self.options.map_pin_path.as_deref(),
        )?;

        if let Some(xdp) = &self.xdp {
            self.runtime.connect_map_backend(xdp.map_pin_path())?;

            info!(
                component = "daemon",
                event = "xdp_ready",
                interface = xdp.interface(),
                object_path = %xdp.object_path().display(),
                map_pin_path = %xdp.map_pin_path().display(),
                "XDP runtime attachment is active"
            );
        }

        self.detector.log_startup();
        self.runtime.sync_policy(&self.config)?;
        self.runtime.expire_bans(unix_timestamp_secs())?;

        info!(
            component = "daemon",
            event = "startup_complete",
            compatible = environment.is_compatible(),
            detector = %self.detector.describe(),
            "daemon runtime is ready"
        );

        Ok(())
    }

    pub fn run_ssh_follow_loop(&mut self) -> Result<(), DaemonError> {
        let max_iterations = self.options.ssh_follow_iterations;
        let poll_interval = Duration::from_millis(self.options.ssh_poll_interval_ms);

        info!(
            component = "daemon",
            event = "ssh_follow_loop_start",
            poll_interval_ms = self.options.ssh_poll_interval_ms,
            max_iterations = max_iterations
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unbounded".to_string()),
            "starting SSH follow loop"
        );

        let mut iteration = 0_u64;

        loop {
            if matches!(max_iterations, Some(limit) if iteration >= limit) {
                info!(
                    component = "daemon",
                    event = "ssh_follow_loop_complete",
                    iterations = iteration,
                    "completed bounded SSH follow loop"
                );
                return Ok(());
            }

            iteration = iteration.saturating_add(1);
            let observed_at_secs = unix_timestamp_secs();
            self.runtime.expire_bans(observed_at_secs)?;

            match self.poll_ssh_sources(observed_at_secs) {
                Ok(summary) => {
                    if summary.lines_read > 0 || !summary.bans.is_empty() {
                        info!(
                            component = "ssh-detector",
                            event = "poll_summary",
                            iteration,
                            observed_at = %format_unix_timestamp_secs(observed_at_secs),
                            lines_read = summary.lines_read,
                            matched_failures = summary.matched_failures,
                            bans = summary.bans.len(),
                            "processed SSH source batch"
                        );
                    } else {
                        debug!(
                            component = "ssh-detector",
                            event = "poll_summary",
                            iteration,
                            observed_at = %format_unix_timestamp_secs(observed_at_secs),
                            lines_read = 0,
                            matched_failures = 0,
                            bans = 0,
                            "no new SSH events detected"
                        );
                    }
                }
                Err(error) => {
                    warn!(
                        component = "ssh-detector",
                        event = "poll_failed",
                        iteration,
                        observed_at = %format_unix_timestamp_secs(observed_at_secs),
                        poll_interval_ms = self.options.ssh_poll_interval_ms,
                        error = %error,
                        "SSH source poll failed; retrying after backoff"
                    );
                }
            }

            if matches!(max_iterations, Some(limit) if iteration >= limit) {
                info!(
                    component = "daemon",
                    event = "ssh_follow_loop_complete",
                    iterations = iteration,
                    "completed bounded SSH follow loop"
                );
                return Ok(());
            }

            thread::sleep(poll_interval);
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> StatusSnapshot {
        let runtime: RuntimeSnapshot = self.runtime.snapshot();

        StatusSnapshot {
            interface: runtime.interface,
            access_mode: runtime.access_mode,
            icmp_mode: runtime.icmp_mode,
            ssh_protection_enabled: self.config.ssh.enabled,
            ssh_failure_threshold: self.config.ssh.failure_threshold,
            xdp_attached: self.xdp.is_some(),
            allow_v4_entries: runtime.allow_v4_entries,
            allow_v6_entries: runtime.allow_v6_entries,
            deny_v4_entries: runtime.deny_v4_entries,
            deny_v6_entries: runtime.deny_v6_entries,
            icmp_rule_entries: runtime.icmp_rule_entries,
        }
    }

    #[must_use]
    pub fn verify_environment(&self) -> EnvironmentReport {
        verify_environment(self.options.interface.as_deref())
    }

    #[must_use]
    pub fn ssh_sources(&self) -> &[SshResolvedLogSource] {
        self.detector.sources()
    }

    #[must_use]
    pub fn inspect_ssh_log_line(&self, line: &str) -> Option<SshFailureEvent> {
        self.detector.inspect_log_line(line)
    }

    pub fn process_ssh_log_line(
        &mut self,
        line: &str,
        observed_at_secs: u64,
    ) -> Result<Option<SshBanDecision>, DaemonError> {
        let decision = self.detector.process_log_line(line, observed_at_secs);

        if let Some(ban) = decision.clone() {
            self.runtime.apply_ssh_ban(ban)?;
        }

        Ok(decision)
    }

    pub fn poll_ssh_sources(
        &mut self,
        observed_at_secs: u64,
    ) -> Result<SshIngestSummary, DaemonError> {
        let lines = self.ssh_ingestor.poll_lines()?;
        let summary = self.detector.replay_lines(lines, observed_at_secs, 1);

        for decision in &summary.bans {
            self.runtime.apply_ssh_ban(decision.clone())?;
        }

        Ok(summary)
    }

    pub fn replay_ssh_log_file(
        &mut self,
        path: impl Into<std::path::PathBuf>,
        start_at_secs: u64,
        step_secs: u64,
    ) -> Result<SshIngestSummary, DaemonError> {
        let lines = SshLogIngestor::read_all_lines_from_file(path.into())?;
        let summary = self.detector.replay_lines(lines, start_at_secs, step_secs);

        for decision in &summary.bans {
            self.runtime.apply_ssh_ban(decision.clone())?;
        }

        Ok(summary)
    }

    fn should_run_follow_loop(&self) -> bool {
        self.options.foreground && self.options.ssh_follow_iterations != Some(0)
    }
}

fn unix_timestamp_secs() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_SSH_POLL_INTERVAL_MS, DaemonOptions, WalleDaemon};
    use walle_policy::WalleConfig;

    #[test]
    fn default_daemon_options_use_expected_ssh_poll_interval() {
        let options = DaemonOptions::default();

        assert_eq!(options.ssh_poll_interval_ms, DEFAULT_SSH_POLL_INTERVAL_MS);
        assert_eq!(options.ssh_follow_iterations, None);
        assert!(!options.foreground);
    }

    #[test]
    fn follow_loop_requires_foreground_execution() {
        let daemon = WalleDaemon::new(WalleConfig::default(), DaemonOptions::default())
            .expect("default daemon options should be valid");

        assert!(!daemon.should_run_follow_loop());
    }

    #[test]
    fn zero_iteration_follow_loop_is_treated_as_disabled() {
        let daemon = WalleDaemon::new(
            WalleConfig::default(),
            DaemonOptions {
                foreground: true,
                ssh_follow_iterations: Some(0),
                ..DaemonOptions::default()
            },
        )
        .expect("zero-iteration foreground daemon should still be constructible");

        assert!(!daemon.should_run_follow_loop());
    }

    #[test]
    fn foreground_follow_loop_runs_when_iterations_are_positive() {
        let daemon = WalleDaemon::new(
            WalleConfig::default(),
            DaemonOptions {
                foreground: true,
                ssh_follow_iterations: Some(2),
                ..DaemonOptions::default()
            },
        )
        .expect("bounded foreground daemon should be constructible");

        assert!(daemon.should_run_follow_loop());
    }
}
