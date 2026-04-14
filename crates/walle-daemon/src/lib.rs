use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub mod detector;
pub mod error;
pub mod gp;
pub mod install;
pub mod logging;
pub mod runtime;
pub mod sshjail;
pub mod xdp;

use tracing::{debug, info, warn};
use walle_common::{AccessMode, IcmpMode, MAP_NAME_CONFIG, StatsCounters};
use walle_policy::{GpStrategyKind, InterfacePolicy, WalleConfig};

use crate::detector::{
    SshBanDecision, SshDetectorService, SshFailureEvent, SshFailureReason, SshIngestSummary,
    SshLiveIngestor, SshLiveSourceMode, SshLogIngestor, SshResolvedLogSource,
};
pub use crate::error::{DaemonError, RuntimeLockError};
use crate::gp::{
    GpAdapterRequest, GpExecutionOutcome, GpExecutionStatus, GpExecutor, SshGpRequest,
};
use crate::logging::format_unix_timestamp_secs;
use crate::runtime::{
    BanRecord, EnvironmentReport, RuntimeBackendKind, RuntimeController, RuntimeSnapshot,
    log_environment_report, verify_environment,
};
use crate::sshjail::SshJailService;
pub use crate::xdp::XdpError;
use crate::xdp::{XdpAttachment, attach, map_pin_path_for_interface};

const DEFAULT_SSH_POLL_INTERVAL_MS: u64 = 1_000;
const DEFAULT_RUNTIME_LOCK_PATH: &str = "/tmp/walle.lock";
static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DaemonRunOutcome {
    StartupOnly,
    ForegroundLoopCompleted,
    ShutdownRequested,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusSnapshot {
    pub ssh_protection_enabled: bool,
    pub ssh_failure_threshold: u32,
    pub xdp_attached: bool,
    pub xdp_attached_interfaces: usize,
    pub totals: AggregatedStatus,
    pub interfaces: Vec<InterfaceStatusSnapshot>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregatedStatus {
    pub interface_count: usize,
    pub allow_v4_entries: usize,
    pub allow_v6_entries: usize,
    pub deny_v4_entries: usize,
    pub deny_v6_entries: usize,
    pub icmp_rule_entries: usize,
    pub stats: StatsCounters,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceStatusSnapshot {
    pub interface: String,
    pub runtime_backend: RuntimeBackendKind,
    pub xdp_attached: bool,
    pub access_mode: AccessMode,
    pub icmp_mode: IcmpMode,
    pub allow_v4_entries: usize,
    pub allow_v6_entries: usize,
    pub deny_v4_entries: usize,
    pub deny_v6_entries: usize,
    pub icmp_rule_entries: usize,
    pub stats: StatsCounters,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BanStatusSnapshot {
    pub total_bans: usize,
    pub interfaces: Vec<InterfaceBanSnapshot>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceBanSnapshot {
    pub interface: String,
    pub runtime_backend: RuntimeBackendKind,
    pub bans: Vec<BanRecord>,
}

pub struct WalleDaemon {
    detector: SshDetectorService,
    gp_executor: GpExecutor,
    ssh_live_ingestor: SshLiveIngestor,
    ssh_poll_ingestor: SshLogIngestor,
    runtimes: Vec<InterfaceRuntime>,
    ssh_jail: Option<SshJailService>,
    config: WalleConfig,
    options: DaemonOptions,
}

struct InterfaceRuntime {
    interface: InterfacePolicy,
    runtime: RuntimeController,
    xdp: Option<XdpAttachment>,
}

#[derive(Debug)]
pub struct RuntimeInstanceLock {
    path: PathBuf,
    file: File,
}

impl WalleDaemon {
    pub fn new(config: WalleConfig, options: DaemonOptions) -> Result<Self, DaemonError> {
        config.validate()?;

        let detector = SshDetectorService::new(config.ssh_policy().clone());
        let gp_executor = GpExecutor::new(config.ssh_policy().gp.clone());
        let ssh_live_ingestor = detector.create_live_ingestor();
        let ssh_poll_ingestor = detector.create_ingestor();
        let selected_interfaces = select_interfaces(&config, options.interface.as_deref())?;
        let runtimes = selected_interfaces
            .into_iter()
            .map(|interface| InterfaceRuntime {
                runtime: RuntimeController::new(Some(interface.name.clone())),
                interface,
                xdp: None,
            })
            .collect();

        Ok(Self {
            detector,
            gp_executor,
            ssh_live_ingestor,
            ssh_poll_ingestor,
            runtimes,
            ssh_jail: None,
            config,
            options,
        })
    }

    pub fn run(&mut self) -> Result<DaemonRunOutcome, DaemonError> {
        let shutdown = ShutdownSignalHandler::install()?;
        let _instance_lock = RuntimeInstanceLock::acquire_default()?;
        self.startup()?;

        if shutdown.is_requested() {
            self.log_shutdown_requested("startup", None);
            self.shutdown("signal");
            return Ok(DaemonRunOutcome::ShutdownRequested);
        }

        if self.should_run_follow_loop() {
            let outcome = self.run_ssh_follow_loop_until(|| shutdown.is_requested())?;
            let reason = match outcome {
                DaemonRunOutcome::ForegroundLoopCompleted => "follow_loop_complete",
                DaemonRunOutcome::ShutdownRequested => "signal",
                DaemonRunOutcome::StartupOnly => "startup_only",
            };
            self.shutdown(reason);
            return Ok(outcome);
        }

        Ok(DaemonRunOutcome::StartupOnly)
    }

    pub fn startup(&mut self) -> Result<(), DaemonError> {
        info!(
            component = "daemon",
            event = "startup",
            interfaces = self
                .runtimes
                .iter()
                .map(|runtime| runtime.interface.name.as_str())
                .collect::<Vec<_>>()
                .join(","),
            foreground = self.options.foreground,
            "starting phase-1 daemon scaffold"
        );

        let environment = self.verify_environment();
        log_environment_report(&environment);
        if !environment.is_compatible() {
            return Err(DaemonError::EnvironmentIncompatible {
                details: environment.failure_details().join("; "),
            });
        }

        self.start_sshjail_if_needed();

        for runtime in &mut self.runtimes {
            runtime.xdp = Some(attach(
                runtime.interface.name.as_str(),
                self.options.xdp_object.as_deref(),
                self.options.map_pin_path.as_deref(),
            )?);

            if let Some(xdp) = &runtime.xdp {
                runtime.runtime.connect_map_backend(xdp.map_pin_path())?;

                info!(
                    component = "daemon",
                    event = "xdp_ready",
                    interface = xdp.interface(),
                    object_path = %xdp.object_path().display(),
                    map_pin_path = %xdp.map_pin_path().display(),
                    "XDP runtime attachment is active"
                );
            }
        }

        self.detector.log_startup();
        self.gp_executor.log_startup();
        self.ssh_live_ingestor.log_startup();
        let observed_at_secs = unix_timestamp_secs();
        let ssh_jail_port = self
            .ssh_jail
            .as_ref()
            .map(SshJailService::bound_port)
            .unwrap_or(self.config.ssh_policy().gp.sshjail.listen_port);
        for runtime in &mut self.runtimes {
            runtime
                .runtime
                .sync_policy_for_interface_with_ssh_jail_port(
                    &self.config,
                    &runtime.interface,
                    ssh_jail_port,
                )?;
            runtime.runtime.expire_bans(observed_at_secs)?;
            runtime.runtime.expire_ssh_contain(observed_at_secs)?;
        }

        info!(
            component = "daemon",
            event = "startup_complete",
            compatible = environment.is_compatible(),
            detector = %self.detector.describe(),
            gp = %self.gp_executor.describe(),
            interfaces = self.runtimes.len(),
            "daemon runtime is ready"
        );

        Ok(())
    }

    pub fn connect_existing_runtime_backends(&mut self) -> Result<usize, DaemonError> {
        let mut connected = 0;

        for runtime in &mut self.runtimes {
            if matches!(runtime.runtime.backend_kind(), RuntimeBackendKind::BpfMaps) {
                connected += 1;
                continue;
            }

            let map_pin_path = map_pin_path_for_interface(
                runtime.interface.name.as_str(),
                self.options.map_pin_path.as_deref(),
            );

            if !map_pin_path.join(MAP_NAME_CONFIG).exists() {
                continue;
            }

            runtime.runtime.connect_map_backend(&map_pin_path)?;
            connected += 1;
        }

        Ok(connected)
    }

    pub fn run_ssh_follow_loop(&mut self) -> Result<DaemonRunOutcome, DaemonError> {
        self.run_ssh_follow_loop_until(|| false)
    }

    fn run_ssh_follow_loop_until<F>(
        &mut self,
        mut is_shutdown_requested: F,
    ) -> Result<DaemonRunOutcome, DaemonError>
    where
        F: FnMut() -> bool,
    {
        let max_iterations = self.options.ssh_follow_iterations;
        let poll_interval = Duration::from_millis(self.options.ssh_poll_interval_ms);
        let live_mode = self.ssh_live_ingestor.mode();

        info!(
            component = "daemon",
            event = "ssh_follow_loop_start",
            poll_interval_ms = self.options.ssh_poll_interval_ms,
            live_mode = live_mode.as_str(),
            max_iterations = max_iterations
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unbounded".to_string()),
            "starting SSH follow loop"
        );

        let mut iteration = 0_u64;

        loop {
            if is_shutdown_requested() {
                self.log_shutdown_requested("follow_loop", Some(iteration));
                return Ok(DaemonRunOutcome::ShutdownRequested);
            }

            if matches!(max_iterations, Some(limit) if iteration >= limit) {
                info!(
                    component = "daemon",
                    event = "ssh_follow_loop_complete",
                    iterations = iteration,
                    "completed bounded SSH follow loop"
                );
                return Ok(DaemonRunOutcome::ForegroundLoopCompleted);
            }

            iteration = iteration.saturating_add(1);
            let observed_at_secs = unix_timestamp_secs();
            for runtime in &mut self.runtimes {
                runtime.runtime.expire_bans(observed_at_secs)?;
                runtime.runtime.expire_ssh_contain(observed_at_secs)?;
            }

            match self.read_live_ssh_sources(observed_at_secs, poll_interval) {
                Ok(summary) => {
                    if summary.lines_read > 0 {
                        info!(
                            component = "ssh-detector",
                            event = "live_batch_processed",
                            mode = live_mode.as_str(),
                            iteration,
                            observed_at = %format_unix_timestamp_secs(observed_at_secs),
                            lines_read = summary.lines_read,
                            matched_failures = summary.matched_failures,
                            bans = summary.bans.len(),
                            "processed SSH source batch"
                        );
                    } else if matches!(live_mode, SshLiveSourceMode::Polling) {
                        debug!(
                            component = "ssh-detector",
                            event = "live_batch_idle",
                            mode = live_mode.as_str(),
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
                        event = "live_read_failed",
                        mode = live_mode.as_str(),
                        iteration,
                        observed_at = %format_unix_timestamp_secs(observed_at_secs),
                        poll_interval_ms = self.options.ssh_poll_interval_ms,
                        error = %error,
                        "SSH live source read failed; retrying after backoff"
                    );
                }
            }

            if is_shutdown_requested() {
                self.log_shutdown_requested("follow_loop", Some(iteration));
                return Ok(DaemonRunOutcome::ShutdownRequested);
            }

            if matches!(max_iterations, Some(limit) if iteration >= limit) {
                info!(
                    component = "daemon",
                    event = "ssh_follow_loop_complete",
                    iterations = iteration,
                    "completed bounded SSH follow loop"
                );
                return Ok(DaemonRunOutcome::ForegroundLoopCompleted);
            }
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> StatusSnapshot {
        let (configured_allow_v4, configured_allow_v6) =
            count_addresses_by_family(&self.config.access_policy().allowlist);
        let (configured_deny_v4, configured_deny_v6) =
            count_addresses_by_family(&self.config.access_policy().denylist);
        let mut totals = AggregatedStatus {
            interface_count: self.runtimes.len(),
            allow_v4_entries: 0,
            allow_v6_entries: 0,
            deny_v4_entries: 0,
            deny_v6_entries: 0,
            icmp_rule_entries: 0,
            stats: StatsCounters::default(),
        };

        let interfaces: Vec<InterfaceStatusSnapshot> = self
            .runtimes
            .iter()
            .map(|runtime| {
                let live: RuntimeSnapshot = runtime.runtime.snapshot();
                let configured_icmp_rule_entries = runtime
                    .interface
                    .filters
                    .icmp
                    .compile_rules()
                    .map(|rules| rules.len())
                    .unwrap_or(0);

                let snapshot = InterfaceStatusSnapshot {
                    interface: runtime.interface.name.clone(),
                    runtime_backend: live.backend,
                    xdp_attached: runtime.xdp.is_some()
                        || matches!(live.backend, RuntimeBackendKind::BpfMaps),
                    access_mode: self.config.access_policy().mode,
                    icmp_mode: runtime.interface.filters.icmp.mode,
                    allow_v4_entries: live.allow_v4_entries.max(configured_allow_v4),
                    allow_v6_entries: live.allow_v6_entries.max(configured_allow_v6),
                    deny_v4_entries: live.deny_v4_entries.max(configured_deny_v4),
                    deny_v6_entries: live.deny_v6_entries.max(configured_deny_v6),
                    icmp_rule_entries: live.icmp_rule_entries.max(configured_icmp_rule_entries),
                    stats: live.stats,
                };

                totals.allow_v4_entries += snapshot.allow_v4_entries;
                totals.allow_v6_entries += snapshot.allow_v6_entries;
                totals.deny_v4_entries += snapshot.deny_v4_entries;
                totals.deny_v6_entries += snapshot.deny_v6_entries;
                totals.icmp_rule_entries += snapshot.icmp_rule_entries;
                add_stats(&mut totals.stats, snapshot.stats);

                snapshot
            })
            .collect();

        StatusSnapshot {
            ssh_protection_enabled: self.config.ssh_policy().enabled,
            ssh_failure_threshold: self.config.ssh_policy().failure_threshold,
            xdp_attached: interfaces.iter().any(|runtime| runtime.xdp_attached),
            xdp_attached_interfaces: interfaces
                .iter()
                .filter(|runtime| runtime.xdp_attached)
                .count(),
            totals,
            interfaces,
        }
    }

    #[must_use]
    pub fn verify_environment(&self) -> EnvironmentReport {
        verify_environment(
            self.runtimes
                .first()
                .map(|runtime| runtime.interface.name.as_str()),
        )
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
        let (_, decision) = self.process_single_ssh_line(line, observed_at_secs)?;

        Ok(decision)
    }

    pub fn poll_ssh_sources(
        &mut self,
        observed_at_secs: u64,
    ) -> Result<SshIngestSummary, DaemonError> {
        let lines = self.ssh_poll_ingestor.poll_lines()?;
        self.process_ssh_lines(lines, observed_at_secs)
    }

    pub fn replay_ssh_log_file(
        &mut self,
        path: impl Into<std::path::PathBuf>,
        start_at_secs: u64,
        step_secs: u64,
    ) -> Result<SshIngestSummary, DaemonError> {
        let lines = SshLogIngestor::read_all_lines_from_file(path.into())?;
        let mut summary = SshIngestSummary::default();

        for (index, line) in lines.into_iter().enumerate() {
            let observed_at_secs =
                start_at_secs.saturating_add((index as u64).saturating_mul(step_secs));
            summary.lines_read = summary.lines_read.saturating_add(1);
            let (event, decision) = self.process_single_ssh_line(&line, observed_at_secs)?;
            if event.is_some() {
                summary.matched_failures = summary.matched_failures.saturating_add(1);
            }
            if let Some(decision) = decision {
                summary.bans.push(decision);
            }
        }

        Ok(summary)
    }

    pub fn add_manual_ban(
        &mut self,
        ip: std::net::IpAddr,
        duration_secs: Option<u64>,
    ) -> Result<(), DaemonError> {
        self.ensure_live_runtime_backends("walle ban add")?;

        let observed_at_secs = unix_timestamp_secs();
        for runtime in &mut self.runtimes {
            runtime.runtime.expire_bans(observed_at_secs)?;
            runtime.runtime.expire_ssh_contain(observed_at_secs)?;
            runtime
                .runtime
                .add_manual_ban(ip, observed_at_secs, duration_secs)?;
        }

        Ok(())
    }

    pub fn remove_ban(&mut self, ip: std::net::IpAddr) -> Result<usize, DaemonError> {
        self.ensure_live_runtime_backends("walle ban remove")?;

        let observed_at_secs = unix_timestamp_secs();
        let mut removed = 0;
        for runtime in &mut self.runtimes {
            runtime.runtime.expire_bans(observed_at_secs)?;
            runtime.runtime.expire_ssh_contain(observed_at_secs)?;
            let _ = runtime.runtime.remove_ssh_contain(ip)?;
            if runtime.runtime.remove_ban(ip)? {
                removed += 1;
            }
        }

        Ok(removed)
    }

    pub fn list_bans(&mut self) -> Result<BanStatusSnapshot, DaemonError> {
        self.ensure_live_runtime_backends("walle ban list")?;

        let observed_at_secs = unix_timestamp_secs();
        let mut total_bans = 0;
        let mut interfaces = Vec::with_capacity(self.runtimes.len());

        for runtime in &mut self.runtimes {
            runtime.runtime.expire_bans(observed_at_secs)?;
            runtime.runtime.expire_ssh_contain(observed_at_secs)?;
            let bans = runtime.runtime.list_bans()?;
            total_bans += bans.len();
            interfaces.push(InterfaceBanSnapshot {
                interface: runtime.interface.name.clone(),
                runtime_backend: runtime.runtime.backend_kind(),
                bans,
            });
        }

        Ok(BanStatusSnapshot {
            total_bans,
            interfaces,
        })
    }

    fn should_run_follow_loop(&self) -> bool {
        self.options.foreground && self.options.ssh_follow_iterations != Some(0)
    }

    fn read_live_ssh_sources(
        &mut self,
        observed_at_secs: u64,
        max_wait: Duration,
    ) -> Result<SshIngestSummary, DaemonError> {
        let lines = self.ssh_live_ingestor.read_lines(max_wait)?;
        self.process_ssh_lines(lines, observed_at_secs)
    }

    fn process_ssh_lines(
        &mut self,
        lines: Vec<String>,
        observed_at_secs: u64,
    ) -> Result<SshIngestSummary, DaemonError> {
        let mut summary = SshIngestSummary::default();

        for (index, line) in lines.into_iter().enumerate() {
            let line_observed_at_secs =
                observed_at_secs.saturating_add((index as u64).saturating_mul(1));
            summary.lines_read = summary.lines_read.saturating_add(1);
            let (event, decision) = self.process_single_ssh_line(&line, line_observed_at_secs)?;
            if event.is_some() {
                summary.matched_failures = summary.matched_failures.saturating_add(1);
            }
            if let Some(decision) = decision {
                summary.bans.push(decision);
            }
        }

        Ok(summary)
    }

    fn process_single_ssh_line(
        &mut self,
        line: &str,
        observed_at_secs: u64,
    ) -> Result<(Option<SshFailureEvent>, Option<SshBanDecision>), DaemonError> {
        let event = self.detector.inspect_log_line(line);

        if let Some(event) = event.clone() {
            self.execute_ssh_gp_for_failure(&event, observed_at_secs);
            let decision = self
                .apply_invalid_user_force_ban(&event, observed_at_secs)
                .or_else(|| self.detector.observe_failure(event.ip, observed_at_secs));

            if let Some(ban) = decision.clone() {
                self.apply_ssh_ban_to_all(ban.clone())?;
                self.execute_ssh_gp_for_decision(&ban);
            }

            Ok((Some(event), decision))
        } else {
            Ok((None, None))
        }
    }

    fn execute_ssh_gp_for_failure(
        &mut self,
        event: &SshFailureEvent,
        observed_at_secs: u64,
    ) -> GpExecutionOutcome {
        let mut outcome =
            self.gp_executor
                .execute(GpAdapterRequest::Ssh(SshGpRequest::from_failure_event(
                    event,
                    observed_at_secs,
                )));

        if matches!(outcome.status, GpExecutionStatus::Contained) {
            let expires_at_secs =
                observed_at_secs.saturating_add(self.config.ssh_policy().ban_duration_secs);
            if let Err(error) = self.apply_ssh_contain_to_all(
                event.ip,
                observed_at_secs,
                expires_at_secs,
                walle_common::SshContainTrigger::GpSignalObserved,
            ) {
                warn!(
                    component = "gp",
                    event = "contain_apply_failed",
                    ip = %event.ip,
                    observed_at_secs,
                    error = %error,
                    "failed to apply SSH containment after signal observation"
                );
                outcome.status = GpExecutionStatus::FailedOpen;
                outcome.error = Some(crate::gp::GpExecutionError::ContainmentApplyFailed);
            }
        }

        outcome
    }

    fn execute_ssh_gp_for_decision(&mut self, decision: &SshBanDecision) -> GpExecutionOutcome {
        let mut outcome =
            self.gp_executor
                .execute(GpAdapterRequest::Ssh(SshGpRequest::from_ban_decision(
                    decision,
                )));

        if matches!(outcome.status, GpExecutionStatus::Contained)
            && let Err(error) = self.apply_ssh_contain_to_all(
                decision.ip,
                decision.observed_at_secs,
                decision.expires_at_secs,
                walle_common::SshContainTrigger::GpDecisionEmitted,
            )
        {
            warn!(
                component = "gp",
                event = "contain_apply_failed",
                ip = %decision.ip,
                observed_at_secs = decision.observed_at_secs,
                error = %error,
                "failed to apply SSH containment after ban decision"
            );
            outcome.status = GpExecutionStatus::FailedOpen;
            outcome.error = Some(crate::gp::GpExecutionError::ContainmentApplyFailed);
        }

        outcome
    }

    fn apply_ssh_ban_to_all(&mut self, decision: SshBanDecision) -> Result<(), DaemonError> {
        for runtime in &mut self.runtimes {
            runtime.runtime.apply_ssh_ban(decision.clone())?;
        }

        Ok(())
    }

    fn apply_ssh_contain_to_all(
        &mut self,
        ip: std::net::IpAddr,
        observed_at_secs: u64,
        expires_at_secs: u64,
        trigger: walle_common::SshContainTrigger,
    ) -> Result<(), DaemonError> {
        let Some(ssh_jail) = self.ssh_jail.as_ref() else {
            return Err(DaemonError::SshJailUnavailable {
                reason: "sshjail listener is not running".to_string(),
            });
        };

        if !ssh_jail.can_accept_new_session() {
            return Err(DaemonError::SshJailUnavailable {
                reason: "sshjail session capacity is exhausted".to_string(),
            });
        }

        for runtime in &mut self.runtimes {
            runtime
                .runtime
                .apply_ssh_contain(ip, observed_at_secs, expires_at_secs, trigger)?;
        }

        Ok(())
    }

    fn apply_invalid_user_force_ban(
        &mut self,
        event: &SshFailureEvent,
        observed_at_secs: u64,
    ) -> Option<SshBanDecision> {
        if !self.config.ssh_policy().invalid_user_force_ban_enabled
            || !matches!(event.reason, SshFailureReason::InvalidUser)
        {
            return None;
        }

        let decision = self.detector.force_ban(event.ip, observed_at_secs);
        if let Some(decision) = decision.as_ref() {
            debug!(
                component = "ssh-detector",
                event = "invalid_user_force_ban_triggered",
                ip = %event.ip,
                username = event.username.as_deref().unwrap_or("unknown"),
                observed_at_secs,
                expires_at_secs = decision.expires_at_secs,
                "triggered immediate SSH ban for an invalid user attempt"
            );
        }

        decision
    }

    fn ensure_live_runtime_backends(&mut self, action: &'static str) -> Result<(), DaemonError> {
        if self.connect_existing_runtime_backends()? == 0 {
            return Err(DaemonError::NoActiveRuntime { action });
        }

        Ok(())
    }

    fn start_sshjail_if_needed(&mut self) {
        if !self.requires_sshjail() || self.ssh_jail.is_some() {
            return;
        }

        match SshJailService::start(&self.config.ssh_policy().gp.sshjail) {
            Ok(service) => {
                self.ssh_jail = Some(service);
            }
            Err(error) => {
                warn!(
                    component = "sshjail",
                    event = "startup_failed",
                    error = %error,
                    "failed to start sshjail; containment will fail open"
                );
            }
        }
    }

    fn requires_sshjail(&self) -> bool {
        matches!(
            self.config.ssh_policy().gp.strategy,
            GpStrategyKind::Contain
        )
    }

    fn log_shutdown_requested(&self, phase: &'static str, iteration: Option<u64>) {
        info!(
            component = "daemon",
            event = "shutdown_requested",
            reason = "signal",
            phase,
            iteration = iteration.unwrap_or(0),
            iteration_known = iteration.is_some(),
            "received shutdown request; stopping daemon gracefully"
        );
    }

    fn shutdown(&mut self, reason: &'static str) {
        let detached_interfaces = self
            .runtimes
            .iter()
            .filter(|runtime| runtime.xdp.is_some())
            .count();
        let sshjail_was_running = self.ssh_jail.is_some();

        for runtime in &mut self.runtimes {
            let _ = runtime.xdp.take();
        }
        let _ = self.ssh_jail.take();

        info!(
            component = "daemon",
            event = "shutdown_complete",
            reason,
            detached_interfaces,
            sshjail_was_running,
            "daemon resources were released"
        );
    }
}

fn select_interfaces(
    config: &WalleConfig,
    requested_interface: Option<&str>,
) -> Result<Vec<InterfacePolicy>, DaemonError> {
    match requested_interface {
        Some(name) => config
            .interfaces()
            .iter()
            .find(|interface| interface.name == name)
            .cloned()
            .map(|interface| vec![interface])
            .ok_or_else(|| DaemonError::InterfaceNotConfigured {
                interface: name.to_string(),
            }),
        None => Ok(config.interfaces().to_vec()),
    }
}

fn count_addresses_by_family(addresses: &[std::net::IpAddr]) -> (usize, usize) {
    let mut v4 = 0;
    let mut v6 = 0;

    for address in addresses {
        match address {
            std::net::IpAddr::V4(_) => v4 += 1,
            std::net::IpAddr::V6(_) => v6 += 1,
        }
    }

    (v4, v6)
}

fn add_stats(total: &mut StatsCounters, value: StatsCounters) {
    total.packets_allowed = total.packets_allowed.saturating_add(value.packets_allowed);
    total.packets_dropped = total.packets_dropped.saturating_add(value.packets_dropped);
    total.allowlist_hits = total.allowlist_hits.saturating_add(value.allowlist_hits);
    total.denylist_hits = total.denylist_hits.saturating_add(value.denylist_hits);
    total.icmp_rule_hits = total.icmp_rule_hits.saturating_add(value.icmp_rule_hits);
    total.parser_failures = total.parser_failures.saturating_add(value.parser_failures);
}

struct ShutdownSignalHandler {
    #[cfg(target_os = "linux")]
    previous_sigint: libc::sigaction,
    #[cfg(target_os = "linux")]
    previous_sigterm: libc::sigaction,
}

impl ShutdownSignalHandler {
    fn install() -> Result<Self, DaemonError> {
        SHUTDOWN_REQUESTED.store(false, Ordering::SeqCst);

        #[cfg(target_os = "linux")]
        {
            let previous_sigint = install_shutdown_signal(libc::SIGINT)?;
            let previous_sigterm = match install_shutdown_signal(libc::SIGTERM) {
                Ok(action) => action,
                Err(error) => {
                    let _ = restore_shutdown_signal(libc::SIGINT, &previous_sigint);
                    return Err(error);
                }
            };

            return Ok(Self {
                previous_sigint,
                previous_sigterm,
            });
        }

        #[cfg(not(target_os = "linux"))]
        {
            Ok(Self {})
        }
    }

    fn is_requested(&self) -> bool {
        SHUTDOWN_REQUESTED.load(Ordering::SeqCst)
    }
}

impl Drop for ShutdownSignalHandler {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        {
            let _ = restore_shutdown_signal(libc::SIGINT, &self.previous_sigint);
            let _ = restore_shutdown_signal(libc::SIGTERM, &self.previous_sigterm);
        }

        SHUTDOWN_REQUESTED.store(false, Ordering::SeqCst);
    }
}

#[cfg(target_os = "linux")]
extern "C" fn mark_shutdown_requested(_signal: libc::c_int) {
    SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
}

#[cfg(target_os = "linux")]
fn install_shutdown_signal(signal: libc::c_int) -> Result<libc::sigaction, DaemonError> {
    let mut new_action: libc::sigaction = unsafe { std::mem::zeroed() };
    new_action.sa_sigaction = mark_shutdown_requested as *const () as usize;
    new_action.sa_flags = libc::SA_RESTART;

    if unsafe { libc::sigemptyset(&mut new_action.sa_mask) } != 0 {
        return Err(DaemonError::InstallSignalHandler {
            signal: shutdown_signal_name(signal),
            source: std::io::Error::last_os_error(),
        });
    }

    let mut previous_action: libc::sigaction = unsafe { std::mem::zeroed() };
    if unsafe { libc::sigaction(signal, &new_action, &mut previous_action) } != 0 {
        return Err(DaemonError::InstallSignalHandler {
            signal: shutdown_signal_name(signal),
            source: std::io::Error::last_os_error(),
        });
    }

    Ok(previous_action)
}

#[cfg(target_os = "linux")]
fn restore_shutdown_signal(
    signal: libc::c_int,
    action: &libc::sigaction,
) -> Result<(), DaemonError> {
    if unsafe { libc::sigaction(signal, action, std::ptr::null_mut()) } != 0 {
        return Err(DaemonError::InstallSignalHandler {
            signal: shutdown_signal_name(signal),
            source: std::io::Error::last_os_error(),
        });
    }

    Ok(())
}

#[cfg(target_os = "linux")]
const fn shutdown_signal_name(signal: libc::c_int) -> &'static str {
    match signal {
        libc::SIGINT => "SIGINT",
        libc::SIGTERM => "SIGTERM",
        _ => "unknown",
    }
}

impl RuntimeInstanceLock {
    pub fn acquire_default() -> Result<Self, RuntimeLockError> {
        Self::acquire(Path::new(DEFAULT_RUNTIME_LOCK_PATH))
    }

    fn acquire(path: &Path) -> Result<Self, RuntimeLockError> {
        loop {
            match OpenOptions::new().write(true).create_new(true).open(path) {
                Ok(mut file) => {
                    writeln!(file, "{}", process::id()).map_err(|source| {
                        RuntimeLockError::Write {
                            path: path.to_path_buf(),
                            source,
                        }
                    })?;
                    file.sync_all().map_err(|source| RuntimeLockError::Write {
                        path: path.to_path_buf(),
                        source,
                    })?;

                    info!(
                        component = "daemon",
                        event = "runtime_lock_acquired",
                        lock_path = %path.display(),
                        pid = process::id(),
                        "acquired runtime lock"
                    );

                    return Ok(Self {
                        path: path.to_path_buf(),
                        file,
                    });
                }
                Err(source) if source.kind() == ErrorKind::AlreadyExists => {
                    let owner_pid = read_lock_owner_pid(path)?;
                    if owner_pid.is_some_and(|pid| !process_is_alive(pid)) {
                        warn!(
                            component = "daemon",
                            event = "runtime_lock_stale",
                            lock_path = %path.display(),
                            owner_pid = owner_pid
                                .map(|pid| pid.to_string())
                                .unwrap_or_else(|| "unknown".to_string()),
                            "removing stale runtime lock before retrying"
                        );
                        fs::remove_file(path).map_err(|source| RuntimeLockError::RemoveStale {
                            path: path.to_path_buf(),
                            source,
                        })?;
                        continue;
                    }

                    return Err(RuntimeLockError::AlreadyRunning {
                        path: path.to_path_buf(),
                        owner_pid,
                    });
                }
                Err(source) => {
                    return Err(RuntimeLockError::Create {
                        path: path.to_path_buf(),
                        source,
                    });
                }
            }
        }
    }
}

impl Drop for RuntimeInstanceLock {
    fn drop(&mut self) {
        let _ = self.file.sync_all();
        if let Err(error) = fs::remove_file(&self.path)
            && error.kind() != ErrorKind::NotFound
        {
            warn!(
                component = "daemon",
                event = "runtime_lock_release_failed",
                lock_path = %self.path.display(),
                error = %error,
                "failed to release runtime lock"
            );
        }
    }
}

fn read_lock_owner_pid(path: &Path) -> Result<Option<u32>, RuntimeLockError> {
    let mut contents = String::new();
    File::open(path)
        .and_then(|mut file| file.read_to_string(&mut contents))
        .map_err(|source| RuntimeLockError::Read {
            path: path.to_path_buf(),
            source,
        })?;

    let owner_pid = contents.trim().parse::<u32>().ok();
    Ok(owner_pid)
}

#[cfg(target_os = "linux")]
fn process_is_alive(pid: u32) -> bool {
    Path::new("/proc").join(pid.to_string()).exists()
}

#[cfg(not(target_os = "linux"))]
fn process_is_alive(_pid: u32) -> bool {
    true
}

fn unix_timestamp_secs() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::process;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        DEFAULT_SSH_POLL_INTERVAL_MS, DaemonOptions, DaemonRunOutcome, RuntimeInstanceLock,
        WalleDaemon, select_interfaces,
    };
    use crate::detector::{SshBanDecision, SshFailureEvent, SshFailureReason};
    use crate::gp::GpExecutionStatus;
    use walle_common::{IcmpMatchType, IcmpMode};
    use walle_policy::{
        GpPolicy, GpStrategyKind, GpTriggerMode, IcmpAllowRule, IcmpPolicy, InterfaceFilters,
        InterfacePolicy, WalleConfig, XdpMode,
    };

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

    #[test]
    fn follow_loop_exits_cleanly_when_shutdown_is_requested_before_polling() {
        let mut daemon = WalleDaemon::new(
            WalleConfig::default(),
            DaemonOptions {
                foreground: true,
                ..DaemonOptions::default()
            },
        )
        .expect("foreground daemon should be constructible");

        let outcome = daemon
            .run_ssh_follow_loop_until(|| true)
            .expect("shutdown request should stop the follow loop cleanly");

        assert_eq!(outcome, DaemonRunOutcome::ShutdownRequested);
    }

    #[test]
    fn daemon_selects_all_declared_interfaces_by_default() {
        let config = config_with_interfaces();
        let daemon = WalleDaemon::new(config, DaemonOptions::default())
            .expect("declared interfaces should be accepted");

        let snapshot = daemon.snapshot();
        assert_eq!(snapshot.interfaces.len(), 2);
        assert_eq!(snapshot.interfaces[0].interface, "eth0");
        assert_eq!(snapshot.interfaces[1].interface, "eth1");
        assert_eq!(snapshot.interfaces[0].icmp_mode, IcmpMode::AllowRulesActive);
        assert_eq!(snapshot.interfaces[1].icmp_mode, IcmpMode::Disabled);
        assert_eq!(snapshot.interfaces[0].icmp_rule_entries, 1);
        assert_eq!(snapshot.interfaces[1].icmp_rule_entries, 0);
        assert_eq!(snapshot.totals.interface_count, 2);
        assert_eq!(snapshot.totals.icmp_rule_entries, 1);
    }

    #[test]
    fn snapshot_aggregates_stats_across_interfaces() {
        let mut daemon = WalleDaemon::new(config_with_interfaces(), DaemonOptions::default())
            .expect("declared interfaces should be accepted");

        daemon
            .process_ssh_log_line(
                "Apr 13 12:00:00 host sshd[123]: Failed password for root from 198.51.100.42 port 22 ssh2",
                1,
            )
            .expect("processing the first failed line should succeed");
        daemon
            .process_ssh_log_line(
                "Apr 13 12:00:01 host sshd[124]: Failed password for root from 198.51.100.42 port 22 ssh2",
                2,
            )
            .expect("processing the second failed line should succeed");
        daemon
            .process_ssh_log_line(
                "Apr 13 12:00:02 host sshd[125]: Failed password for root from 198.51.100.42 port 22 ssh2",
                3,
            )
            .expect("processing the third failed line should succeed");
        daemon
            .process_ssh_log_line(
                "Apr 13 12:00:03 host sshd[126]: Failed password for root from 198.51.100.42 port 22 ssh2",
                4,
            )
            .expect("processing the fourth failed line should succeed");
        daemon
            .process_ssh_log_line(
                "Apr 13 12:00:04 host sshd[127]: Failed password for root from 198.51.100.42 port 22 ssh2",
                5,
            )
            .expect("processing the fifth failed line should succeed");

        let snapshot = daemon.snapshot();
        assert_eq!(snapshot.totals.deny_v4_entries, 2);
        assert!(
            snapshot
                .interfaces
                .iter()
                .all(|item| item.deny_v4_entries >= 1)
        );
        assert_eq!(snapshot.totals.stats.packets_allowed, 0);
        assert_eq!(snapshot.totals.stats.parser_failures, 0);
    }

    #[test]
    fn invalid_user_force_ban_emits_immediate_ban_decision() {
        let mut config = config_with_interfaces();
        config.detectors.ssh.invalid_user_force_ban_enabled = true;

        let mut daemon = WalleDaemon::new(config, DaemonOptions::default())
            .expect("declared interfaces should be accepted");

        let decision = daemon
            .process_ssh_log_line(
                "Apr 13 12:00:00 host sshd[123]: Invalid user admin from 198.51.100.42 port 22 ssh2",
                10,
            )
            .expect("invalid-user line should be processed")
            .expect("invalid-user fast path should emit a ban decision");

        assert_eq!(
            decision.ip,
            "198.51.100.42"
                .parse::<std::net::IpAddr>()
                .expect("test IP should parse")
        );
        assert_eq!(decision.matched_failures, 1);
        assert_eq!(decision.observed_at_secs, 10);
        assert_eq!(decision.expires_at_secs, 910);

        let snapshot = daemon.snapshot();
        assert_eq!(snapshot.totals.deny_v4_entries, 2);
    }

    #[test]
    fn invalid_user_force_ban_does_not_require_sshjail() {
        let mut config = config_with_interfaces();
        config.detectors.ssh.invalid_user_force_ban_enabled = true;

        let daemon = WalleDaemon::new(config, DaemonOptions::default())
            .expect("declared interfaces should be accepted");

        assert!(!daemon.requires_sshjail());
    }

    #[test]
    fn daemon_rejects_unknown_interface_override() {
        let result = WalleDaemon::new(
            config_with_interfaces(),
            DaemonOptions {
                interface: Some("eth9".to_string()),
                ..DaemonOptions::default()
            },
        );

        match result {
            Ok(_) => panic!("unknown interface override should be rejected"),
            Err(error) => {
                assert!(
                    error
                        .to_string()
                        .contains("requested interface 'eth9' is not declared")
                );
            }
        }
    }

    #[test]
    fn select_interfaces_filters_to_requested_interface() {
        let config = config_with_interfaces();
        let selected = select_interfaces(&config, Some("eth1"))
            .expect("configured interface should be selectable");

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].name, "eth1");
        assert_eq!(selected[0].filters.icmp.mode, IcmpMode::Disabled);
    }

    #[test]
    fn ssh_gp_pre_ban_trigger_uses_signal_observed_boundary() {
        let mut daemon = WalleDaemon::new(
            config_with_gp(GpPolicy {
                enabled: true,
                strategy: GpStrategyKind::Observe,
                trigger_mode: GpTriggerMode::SignalObserved,
                ..GpPolicy::default()
            }),
            DaemonOptions::default(),
        )
        .expect("GP-enabled config should be accepted");

        let outcome = daemon.execute_ssh_gp_for_failure(
            &SshFailureEvent {
                ip: "198.51.100.10".parse().expect("test IP should parse"),
                reason: SshFailureReason::FailedPassword,
                username: Some("root".to_string()),
            },
            10,
        );

        assert_eq!(outcome.status, GpExecutionStatus::Observed);
    }

    #[test]
    fn ssh_gp_post_ban_trigger_is_filtered_when_only_pre_ban_is_enabled() {
        let mut daemon = WalleDaemon::new(
            config_with_gp(GpPolicy {
                enabled: true,
                strategy: GpStrategyKind::Observe,
                trigger_mode: GpTriggerMode::SignalObserved,
                ..GpPolicy::default()
            }),
            DaemonOptions::default(),
        )
        .expect("GP-enabled config should be accepted");

        let outcome = daemon.execute_ssh_gp_for_decision(&SshBanDecision {
            ip: "198.51.100.10".parse().expect("test IP should parse"),
            matched_failures: 5,
            observed_at_secs: 15,
            expires_at_secs: 60,
        });

        assert_eq!(outcome.status, GpExecutionStatus::TriggerFiltered);
    }

    #[test]
    fn ssh_ban_flow_remains_active_when_gp_strategy_is_unavailable() {
        let mut daemon = WalleDaemon::new(
            config_with_gp(GpPolicy {
                enabled: true,
                strategy: GpStrategyKind::Contain,
                trigger_mode: GpTriggerMode::All,
                ..GpPolicy::default()
            }),
            DaemonOptions::default(),
        )
        .expect("GP-enabled config should be accepted");

        for observed_at_secs in 1..=5 {
            daemon
                .process_ssh_log_line(
                    "Apr 13 12:00:00 host sshd[123]: Failed password for root from 198.51.100.42 port 22 ssh2",
                    observed_at_secs,
                )
                .expect("SSH line processing should succeed even when GP fails open");
        }

        let snapshot = daemon.snapshot();
        assert_eq!(snapshot.totals.deny_v4_entries, 2);
        assert!(
            snapshot
                .interfaces
                .iter()
                .all(|interface| interface.deny_v4_entries >= 1)
        );
    }

    #[test]
    fn runtime_lock_rejects_second_live_instance() {
        let path = unique_test_lock_path("active");
        let _guard = RuntimeInstanceLock::acquire(&path).expect("first lock should be acquired");

        let error =
            RuntimeInstanceLock::acquire(&path).expect_err("second lock should be rejected");

        let message = error.to_string();
        assert!(message.contains("another walle instance is already running"));
        assert!(message.contains(path.to_string_lossy().as_ref()));

        let _ = fs::remove_file(path);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn runtime_lock_recovers_stale_pid_file() {
        let path = unique_test_lock_path("stale");
        fs::write(&path, "999999\n").expect("stale pid file should be written");

        let _guard = RuntimeInstanceLock::acquire(&path).expect("stale lock should be recovered");

        let contents = fs::read_to_string(&path).expect("lock file should remain present");
        assert_eq!(contents.trim(), process::id().to_string());

        let _ = fs::remove_file(path);
    }

    fn unique_test_lock_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("walle-{name}-{}-{nanos}.lock", process::id()))
    }

    fn config_with_interfaces() -> WalleConfig {
        let mut config = WalleConfig::default();
        config.interfaces = vec![
            InterfacePolicy {
                name: "eth0".to_string(),
                xdp_mode: XdpMode::Driver,
                filters: InterfaceFilters {
                    icmp: IcmpPolicy {
                        mode: IcmpMode::AllowRulesActive,
                        allow_rules: vec![IcmpAllowRule {
                            match_type: IcmpMatchType::RawBytesExact,
                            payload_hex: "09070108".to_string(),
                            enabled: true,
                        }],
                    },
                },
            },
            InterfacePolicy {
                name: "eth1".to_string(),
                xdp_mode: XdpMode::Driver,
                filters: InterfaceFilters {
                    icmp: IcmpPolicy::default(),
                },
            },
        ];
        config
    }

    fn config_with_gp(gp: GpPolicy) -> WalleConfig {
        let mut config = config_with_interfaces();
        config.detectors.ssh.gp = gp;
        config
    }
}
