pub mod detector;
pub mod error;
pub mod runtime;

use tracing::info;
use walle_common::{AccessMode, IcmpMode};
use walle_policy::WalleConfig;

use crate::detector::{
    SshBanDecision, SshDetectorService, SshFailureEvent, SshIngestSummary, SshLogIngestor,
    SshResolvedLogSource,
};
pub use crate::error::DaemonError;
use crate::runtime::{
    EnvironmentReport, RuntimeController, RuntimeSnapshot, log_environment_report,
    verify_environment,
};

#[derive(Clone, Debug, Default)]
pub struct DaemonOptions {
    pub interface: Option<String>,
    pub foreground: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusSnapshot {
    pub interface: Option<String>,
    pub access_mode: AccessMode,
    pub icmp_mode: IcmpMode,
    pub ssh_protection_enabled: bool,
    pub ssh_failure_threshold: u32,
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
            config,
            options,
        })
    }

    pub fn run(&mut self) -> Result<(), DaemonError> {
        info!(
            component = "daemon",
            event = "startup",
            interface = self.options.interface.as_deref().unwrap_or("unset"),
            foreground = self.options.foreground,
            "starting phase-1 daemon scaffold"
        );

        let environment = self.verify_environment();
        log_environment_report(&environment);

        self.detector.log_startup();
        self.runtime.sync_policy(&self.config)?;

        info!(
            component = "daemon",
            event = "startup_complete",
            compatible = environment.is_compatible(),
            detector = %self.detector.describe(),
            "daemon runtime is ready"
        );

        Ok(())
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
            self.runtime.apply_ssh_ban(ban);
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
            self.runtime.apply_ssh_ban(decision.clone());
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
            self.runtime.apply_ssh_ban(decision.clone());
        }

        Ok(summary)
    }
}
