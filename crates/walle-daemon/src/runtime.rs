use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::str::FromStr;

use thiserror::Error;
use tracing::{debug, info};
use walle_common::{
    AccessMode, BanEntryV4, IcmpMode, IcmpRule, MAP_NAME_ALLOW_V4, MAP_NAME_ALLOW_V6,
    MAP_NAME_CONFIG, MAP_NAME_DENY_V4, MAP_NAME_DENY_V6, MAP_NAME_ICMP_RULES, RuntimeConfig,
};
use walle_policy::WalleConfig;

#[derive(Clone, Debug)]
pub struct RuntimeController {
    interface: Option<String>,
    repository: InMemoryMapRepository,
}

impl RuntimeController {
    #[must_use]
    pub fn new(interface: Option<String>) -> Self {
        Self {
            interface,
            repository: InMemoryMapRepository::default(),
        }
    }

    pub fn sync_policy(&mut self, config: &WalleConfig) -> Result<(), RuntimeError> {
        let runtime_config = config.runtime_config();
        let icmp_rules = config.icmp.compile_rules()?;

        self.repository.write_config(runtime_config);
        self.repository.replace_allowlist(&config.access.allowlist);
        self.repository.replace_denylist(&config.access.denylist);
        self.repository.replace_icmp_rules(&icmp_rules);

        debug!(
            component = "runtime",
            event = "config_sync",
            interface = self.interface.as_deref().unwrap_or("unset"),
            access_mode = ?runtime_config.access_mode,
            icmp_mode = ?runtime_config.icmp_mode,
            allow_v4_entries = self.repository.allow_v4.len(),
            allow_v6_entries = self.repository.allow_v6.len(),
            deny_v4_entries = self.repository.deny_v4.len(),
            deny_v6_entries = self.repository.deny_v6.len(),
            icmp_rules = self.repository.icmp_rules.len(),
            "runtime config has been synced into the phase-2 map repository"
        );

        Ok(())
    }

    pub fn apply_ssh_ban(&mut self, decision: crate::detector::SshBanDecision) {
        let ban_entry = decision.clone().into_ban_entry();

        match decision.ip {
            IpAddr::V4(ip) => self.repository.upsert_deny_v4(ip, ban_entry),
            IpAddr::V6(ip) => self.repository.upsert_deny_v6(ip, ban_entry),
        }

        debug!(
            component = "runtime",
            event = "ssh_ban_applied",
            ip = %decision.ip,
            expires_at_secs = decision.expires_at_secs,
            matched_failures = decision.matched_failures,
            "applied SSH detector ban to runtime repository"
        );
    }

    #[must_use]
    pub fn snapshot(&self) -> RuntimeSnapshot {
        let repo = self.repository.snapshot();

        RuntimeSnapshot {
            interface: self.interface.clone(),
            access_mode: repo.config.access_mode,
            icmp_mode: repo.config.icmp_mode,
            allow_v4_entries: repo.allow_v4_entries,
            allow_v6_entries: repo.allow_v6_entries,
            deny_v4_entries: repo.deny_v4_entries,
            deny_v6_entries: repo.deny_v6_entries,
            icmp_rule_entries: repo.icmp_rule_entries,
            map_names: vec![
                MAP_NAME_CONFIG,
                MAP_NAME_ALLOW_V4,
                MAP_NAME_ALLOW_V6,
                MAP_NAME_DENY_V4,
                MAP_NAME_DENY_V6,
                MAP_NAME_ICMP_RULES,
            ],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeSnapshot {
    pub interface: Option<String>,
    pub access_mode: AccessMode,
    pub icmp_mode: IcmpMode,
    pub allow_v4_entries: usize,
    pub allow_v6_entries: usize,
    pub deny_v4_entries: usize,
    pub deny_v6_entries: usize,
    pub icmp_rule_entries: usize,
    pub map_names: Vec<&'static str>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepositorySnapshot {
    pub config: RuntimeConfig,
    pub allow_v4_entries: usize,
    pub allow_v6_entries: usize,
    pub deny_v4_entries: usize,
    pub deny_v6_entries: usize,
    pub icmp_rule_entries: usize,
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryMapRepository {
    config: RuntimeConfig,
    allow_v4: BTreeSet<Ipv4Addr>,
    allow_v6: BTreeSet<Ipv6Addr>,
    deny_v4: HashMap<Ipv4Addr, BanEntryV4>,
    deny_v6: HashMap<Ipv6Addr, BanEntryV4>,
    icmp_rules: Vec<IcmpRule>,
}

impl InMemoryMapRepository {
    pub fn write_config(&mut self, config: RuntimeConfig) {
        self.config = config;
    }

    pub fn replace_allowlist(&mut self, addresses: &[IpAddr]) {
        self.allow_v4.clear();
        self.allow_v6.clear();

        for address in addresses {
            match address {
                IpAddr::V4(ipv4) => {
                    self.allow_v4.insert(*ipv4);
                }
                IpAddr::V6(ipv6) => {
                    self.allow_v6.insert(*ipv6);
                }
            }
        }
    }

    pub fn replace_denylist(&mut self, addresses: &[IpAddr]) {
        self.deny_v4.clear();
        self.deny_v6.clear();

        for address in addresses {
            match address {
                IpAddr::V4(ipv4) => {
                    self.deny_v4.insert(*ipv4, BanEntryV4::manual_indefinite(0));
                }
                IpAddr::V6(ipv6) => {
                    self.deny_v6.insert(*ipv6, BanEntryV4::manual_indefinite(0));
                }
            }
        }
    }

    pub fn upsert_deny_v4(&mut self, ip: Ipv4Addr, entry: BanEntryV4) {
        self.deny_v4.insert(ip, entry);
    }

    pub fn upsert_deny_v6(&mut self, ip: Ipv6Addr, entry: BanEntryV4) {
        self.deny_v6.insert(ip, entry);
    }

    pub fn replace_icmp_rules(&mut self, rules: &[IcmpRule]) {
        self.icmp_rules.clear();
        self.icmp_rules.extend_from_slice(rules);
    }

    #[must_use]
    pub fn snapshot(&self) -> RepositorySnapshot {
        RepositorySnapshot {
            config: self.config,
            allow_v4_entries: self.allow_v4.len(),
            allow_v6_entries: self.allow_v6.len(),
            deny_v4_entries: self.deny_v4.len(),
            deny_v6_entries: self.deny_v6.len(),
            icmp_rule_entries: self.icmp_rules.len(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvironmentCheck {
    pub name: &'static str,
    pub status: CheckStatus,
    pub detail: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvironmentReport {
    pub kernel_release: Option<String>,
    pub checks: Vec<EnvironmentCheck>,
}

impl EnvironmentReport {
    #[must_use]
    pub fn is_compatible(&self) -> bool {
        self.checks
            .iter()
            .all(|check| check.status != CheckStatus::Fail)
    }
}

pub fn verify_environment(interface: Option<&str>) -> EnvironmentReport {
    #[cfg(target_os = "linux")]
    {
        linux_environment_report(interface)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let mut checks = Vec::new();
        checks.push(EnvironmentCheck {
            name: "os",
            status: CheckStatus::Fail,
            detail: format!("current host '{}' is not Linux", std::env::consts::OS),
        });

        if let Some(name) = interface {
            checks.push(EnvironmentCheck {
                name: "interface",
                status: CheckStatus::Warn,
                detail: format!("interface check skipped for non-Linux host: {name}"),
            });
        }

        EnvironmentReport {
            kernel_release: None,
            checks,
        }
    }
}

#[cfg(target_os = "linux")]
fn linux_environment_report(interface: Option<&str>) -> EnvironmentReport {
    let kernel_release = fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|content| content.trim().to_string());

    let mut checks = Vec::new();
    checks.push(EnvironmentCheck {
        name: "os",
        status: CheckStatus::Pass,
        detail: "linux host detected".to_string(),
    });

    let kernel_status = match kernel_release
        .as_deref()
        .and_then(parse_kernel_release)
        .map(|version| version >= KernelVersion::new(5, 15, 0))
    {
        Some(true) => EnvironmentCheck {
            name: "kernel",
            status: CheckStatus::Pass,
            detail: format!(
                "kernel release {} meets the supported baseline >= 5.15",
                kernel_release.as_deref().unwrap_or("unknown")
            ),
        },
        Some(false) => EnvironmentCheck {
            name: "kernel",
            status: CheckStatus::Fail,
            detail: format!(
                "kernel release {} is below the supported baseline >= 5.15",
                kernel_release.as_deref().unwrap_or("unknown")
            ),
        },
        None => EnvironmentCheck {
            name: "kernel",
            status: CheckStatus::Warn,
            detail: "unable to parse kernel release".to_string(),
        },
    };
    checks.push(kernel_status);

    checks.push(path_check(
        "bpffs",
        "/sys/fs/bpf",
        "bpffs mount point is available",
        "bpffs mount point is missing",
    ));
    checks.push(path_check(
        "btf",
        "/sys/kernel/btf/vmlinux",
        "kernel BTF is available",
        "kernel BTF file is missing",
    ));

    if let Some(name) = interface {
        let interface_path = format!("/sys/class/net/{name}");
        checks.push(path_check(
            "interface",
            &interface_path,
            &format!("interface '{name}' exists"),
            &format!("interface '{name}' was not found"),
        ));
    }

    EnvironmentReport {
        kernel_release,
        checks,
    }
}

#[cfg(target_os = "linux")]
fn path_check(name: &'static str, path: &str, pass: &str, fail: &str) -> EnvironmentCheck {
    if Path::new(path).exists() {
        EnvironmentCheck {
            name,
            status: CheckStatus::Pass,
            detail: pass.to_string(),
        }
    } else {
        EnvironmentCheck {
            name,
            status: CheckStatus::Fail,
            detail: fail.to_string(),
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct KernelVersion {
    major: u32,
    minor: u32,
    patch: u32,
}

#[cfg(target_os = "linux")]
impl KernelVersion {
    const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

#[cfg(target_os = "linux")]
fn parse_kernel_release(input: &str) -> Option<KernelVersion> {
    let release = input.split('-').next()?;
    let mut parts = release.split('.');

    let major = u32::from_str(parts.next()?).ok()?;
    let minor = u32::from_str(parts.next()?).ok()?;
    let patch = u32::from_str(parts.next().unwrap_or("0")).ok()?;

    Some(KernelVersion::new(major, minor, patch))
}

pub fn log_environment_report(report: &EnvironmentReport) {
    info!(
        component = "runtime",
        event = "environment_check",
        compatible = report.is_compatible(),
        kernel_release = report.kernel_release.as_deref().unwrap_or("unknown"),
        "environment compatibility report generated"
    );

    for check in &report.checks {
        debug!(
            component = "runtime",
            event = "environment_check_detail",
            check = check.name,
            status = ?check.status,
            detail = %check.detail,
            "environment check detail"
        );
    }
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("policy compilation failed: {0}")]
    Policy(#[from] walle_policy::PolicyError),
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use walle_common::{AccessMode, IcmpMode};
    use walle_policy::{IcmpAllowRule, WalleConfig};

    use super::{InMemoryMapRepository, RuntimeController};

    #[cfg(target_os = "linux")]
    use super::{KernelVersion, parse_kernel_release};

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_kernel_release_ignores_distribution_suffix() {
        let parsed = parse_kernel_release("5.15.0-117-generic");
        assert_eq!(parsed, Some(KernelVersion::new(5, 15, 0)));
    }

    #[test]
    fn repository_separates_ipv4_and_ipv6_entries() {
        let mut repo = InMemoryMapRepository::default();
        repo.replace_allowlist(&[
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ]);

        let snapshot = repo.snapshot();
        assert_eq!(snapshot.allow_v4_entries, 1);
        assert_eq!(snapshot.allow_v6_entries, 1);
    }

    #[test]
    fn runtime_sync_populates_repository_from_policy() {
        let mut controller = RuntimeController::new(Some("eth0".to_string()));
        let mut config = WalleConfig::default();
        config.access.mode = AccessMode::WhitelistOnly;
        config.access.allowlist = vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))];
        config.access.denylist = vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2))];
        config.icmp.mode = IcmpMode::AllowRulesActive;
        config.icmp.allow_rules = vec![IcmpAllowRule {
            match_type: walle_common::IcmpMatchType::RawBytesExact,
            payload: vec![0x61, 0x62],
            enabled: true,
        }];

        controller.sync_policy(&config).unwrap();
        let snapshot = controller.snapshot();

        assert_eq!(snapshot.access_mode, AccessMode::WhitelistOnly);
        assert_eq!(snapshot.allow_v4_entries, 1);
        assert_eq!(snapshot.deny_v4_entries, 1);
        assert_eq!(snapshot.icmp_rule_entries, 1);
    }
}
