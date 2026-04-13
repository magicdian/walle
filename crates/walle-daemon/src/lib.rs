use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub mod detector;
pub mod error;
pub mod logging;
pub mod runtime;
pub mod xdp;

use tracing::{debug, info, warn};
use walle_common::{AccessMode, IcmpMode, MAP_NAME_CONFIG, StatsCounters};
use walle_policy::{InterfacePolicy, WalleConfig};

use crate::detector::{
    SshBanDecision, SshDetectorService, SshFailureEvent, SshIngestSummary, SshLogIngestor,
    SshResolvedLogSource,
};
pub use crate::error::{DaemonError, RuntimeLockError};
use crate::logging::format_unix_timestamp_secs;
use crate::runtime::{
    EnvironmentReport, RuntimeBackendKind, RuntimeController, RuntimeSnapshot,
    log_environment_report, verify_environment,
};
pub use crate::xdp::XdpError;
use crate::xdp::{XdpAttachment, attach, map_pin_path_for_interface};

const DEFAULT_SSH_POLL_INTERVAL_MS: u64 = 1_000;
const DEFAULT_RUNTIME_LOCK_PATH: &str = "/tmp/walle.lock";

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

pub struct WalleDaemon {
    detector: SshDetectorService,
    ssh_ingestor: SshLogIngestor,
    runtimes: Vec<InterfaceRuntime>,
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
        let ssh_ingestor = detector.create_ingestor();
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
            ssh_ingestor,
            runtimes,
            config,
            options,
        })
    }

    pub fn run(&mut self) -> Result<(), DaemonError> {
        let _instance_lock = RuntimeInstanceLock::acquire_default()?;
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
        let observed_at_secs = unix_timestamp_secs();
        for runtime in &mut self.runtimes {
            runtime
                .runtime
                .sync_policy_for_interface(&self.config, &runtime.interface)?;
            runtime.runtime.expire_bans(observed_at_secs)?;
        }

        info!(
            component = "daemon",
            event = "startup_complete",
            compatible = environment.is_compatible(),
            detector = %self.detector.describe(),
            interfaces = self.runtimes.len(),
            "daemon runtime is ready"
        );

        Ok(())
    }

    pub fn connect_existing_runtime_backends(&mut self) -> Result<(), DaemonError> {
        for runtime in &mut self.runtimes {
            let map_pin_path = map_pin_path_for_interface(
                runtime.interface.name.as_str(),
                self.options.map_pin_path.as_deref(),
            );

            if !map_pin_path.join(MAP_NAME_CONFIG).exists() {
                continue;
            }

            runtime.runtime.connect_map_backend(&map_pin_path)?;
        }

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
            for runtime in &mut self.runtimes {
                runtime.runtime.expire_bans(observed_at_secs)?;
            }

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
        let decision = self.detector.process_log_line(line, observed_at_secs);

        if let Some(ban) = decision.clone() {
            self.apply_ssh_ban_to_all(ban)?;
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
            self.apply_ssh_ban_to_all(decision.clone())?;
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
            self.apply_ssh_ban_to_all(decision.clone())?;
        }

        Ok(summary)
    }

    fn should_run_follow_loop(&self) -> bool {
        self.options.foreground && self.options.ssh_follow_iterations != Some(0)
    }

    fn apply_ssh_ban_to_all(&mut self, decision: SshBanDecision) -> Result<(), DaemonError> {
        for runtime in &mut self.runtimes {
            runtime.runtime.apply_ssh_ban(decision.clone())?;
        }

        Ok(())
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
        DEFAULT_SSH_POLL_INTERVAL_MS, DaemonOptions, RuntimeInstanceLock, WalleDaemon,
        select_interfaces,
    };
    use walle_common::{IcmpMatchType, IcmpMode};
    use walle_policy::{
        IcmpAllowRule, IcmpPolicy, InterfaceFilters, InterfacePolicy, WalleConfig, XdpMode,
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
}
