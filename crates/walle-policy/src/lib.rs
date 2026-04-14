use core::fmt;
use std::collections::HashSet;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use walle_common::{
    AccessMode, ICMP_RULE_PAYLOAD_CAPACITY, IcmpMatchType, IcmpMode, RuntimeConfig,
};

pub use walle_common::IcmpRule;

pub const DEFAULT_CONFIG_PATH: &str = "/etc/walle/config.toml";
const CONFIG_VERSION_V1: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalleConfig {
    #[serde(default = "default_config_version")]
    pub version: u32,
    #[serde(default)]
    pub detectors: DetectorPolicies,
    #[serde(default)]
    pub policy: GlobalPolicy,
    #[serde(default)]
    pub interfaces: Vec<InterfacePolicy>,
}

impl Default for WalleConfig {
    fn default() -> Self {
        Self {
            version: default_config_version(),
            detectors: DetectorPolicies::default(),
            policy: GlobalPolicy::default(),
            interfaces: Vec::new(),
        }
    }
}

impl WalleConfig {
    pub fn load_default() -> Result<Self, PolicyError> {
        Self::load_from_path(Path::new(DEFAULT_CONFIG_PATH))
    }

    pub fn load_from_path(path: &Path) -> Result<Self, PolicyError> {
        let content = fs::read_to_string(path).map_err(|source| PolicyError::ReadConfigFile {
            path: path.to_path_buf(),
            source,
        })?;
        let config: Self =
            toml::from_str(&content).map_err(|source| PolicyError::ParseConfigFile {
                path: path.to_path_buf(),
                source,
            })?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.version != CONFIG_VERSION_V1 {
            return Err(PolicyError::UnsupportedConfigVersion {
                actual: self.version,
                supported: CONFIG_VERSION_V1,
            });
        }

        self.detectors.ssh.validate()?;

        let mut seen_interfaces = HashSet::new();
        for interface in &self.interfaces {
            interface.validate()?;

            if !seen_interfaces.insert(interface.name.clone()) {
                return Err(PolicyError::DuplicateInterface {
                    name: interface.name.clone(),
                });
            }
        }

        Ok(())
    }

    #[must_use]
    pub fn access_policy(&self) -> &AccessPolicy {
        &self.policy.access
    }

    #[must_use]
    pub fn ssh_policy(&self) -> &SshProtectionPolicy {
        &self.detectors.ssh
    }

    #[must_use]
    pub fn interfaces(&self) -> &[InterfacePolicy] {
        &self.interfaces
    }

    #[must_use]
    pub fn logging_policy(&self) -> &LoggingPolicy {
        &self.policy.logging
    }

    #[must_use]
    pub fn runtime_config_for(&self, interface: &InterfacePolicy) -> RuntimeConfig {
        self.runtime_config_for_ssh_jail_port(interface, self.ssh_policy().gp.sshjail.listen_port)
    }

    #[must_use]
    pub fn runtime_config_for_ssh_jail_port(
        &self,
        interface: &InterfacePolicy,
        ssh_jail_port: u16,
    ) -> RuntimeConfig {
        RuntimeConfig::new(
            self.policy.access.mode,
            interface.filters.icmp.mode,
            self.ssh_policy().gp.sshjail.protected_port,
            ssh_jail_port,
        )
    }

    #[must_use]
    pub fn primary_interface(&self) -> Option<&InterfacePolicy> {
        self.interfaces.first()
    }

    #[must_use]
    pub fn primary_icmp_policy(&self) -> &IcmpPolicy {
        self.primary_interface()
            .map(|interface| &interface.filters.icmp)
            .unwrap_or(&DEFAULT_ICMP_POLICY)
    }

    #[must_use]
    pub fn primary_runtime_config(&self) -> RuntimeConfig {
        self.primary_runtime_config_for_ssh_jail_port(self.ssh_policy().gp.sshjail.listen_port)
    }

    #[must_use]
    pub fn primary_runtime_config_for_ssh_jail_port(&self, ssh_jail_port: u16) -> RuntimeConfig {
        self.primary_interface()
            .map(|interface| self.runtime_config_for_ssh_jail_port(interface, ssh_jail_port))
            .unwrap_or_else(|| {
                RuntimeConfig::new(
                    self.policy.access.mode,
                    IcmpMode::Disabled,
                    self.ssh_policy().gp.sshjail.protected_port,
                    ssh_jail_port,
                )
            })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectorPolicies {
    #[serde(default)]
    pub ssh: SshProtectionPolicy,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlobalPolicy {
    #[serde(default)]
    pub access: AccessPolicy,
    #[serde(default)]
    pub logging: LoggingPolicy,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
}

impl LogLevel {
    #[must_use]
    pub const fn as_filter_directive(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoggingPolicy {
    #[serde(default)]
    pub level: LogLevel,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessPolicy {
    pub mode: AccessMode,
    #[serde(default)]
    pub allowlist: Vec<IpAddr>,
    #[serde(default)]
    pub denylist: Vec<IpAddr>,
}

impl Default for AccessPolicy {
    fn default() -> Self {
        Self {
            mode: AccessMode::BlacklistOnly,
            allowlist: Vec::new(),
            denylist: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GpStrategyKind {
    #[default]
    Observe,
    Degrade,
    Contain,
}

impl GpStrategyKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::Degrade => "degrade",
            Self::Contain => "contain",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GpTriggerMode {
    SignalObserved,
    DecisionEmitted,
    #[default]
    All,
}

impl GpTriggerMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SignalObserved => "signal_observed",
            Self::DecisionEmitted => "decision_emitted",
            Self::All => "all",
        }
    }

    #[must_use]
    pub const fn matches_signal_observed(self) -> bool {
        matches!(self, Self::SignalObserved | Self::All)
    }

    #[must_use]
    pub const fn matches_decision_emitted(self) -> bool {
        matches!(self, Self::DecisionEmitted | Self::All)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpPolicy {
    pub enabled: bool,
    #[serde(default)]
    pub strategy: GpStrategyKind,
    #[serde(default)]
    pub trigger_mode: GpTriggerMode,
    #[serde(default)]
    pub sshjail: SshJailPolicy,
}

impl Default for GpPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            strategy: GpStrategyKind::Observe,
            trigger_mode: GpTriggerMode::DecisionEmitted,
            sshjail: SshJailPolicy::default(),
        }
    }
}

impl GpPolicy {
    fn validate(&self) -> Result<(), PolicyError> {
        self.sshjail.validate()?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SshJailHostnameStrategy {
    Real,
    Configured,
    #[default]
    Generated,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshJailPolicy {
    #[serde(default = "default_protected_ssh_port")]
    pub protected_port: u16,
    #[serde(default = "default_sshjail_listen_port")]
    pub listen_port: u16,
    #[serde(default = "default_sshjail_max_sessions")]
    pub max_sessions: usize,
    #[serde(default = "default_sshjail_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
    #[serde(default = "default_sshjail_max_session_duration_secs")]
    pub max_session_duration_secs: u64,
    #[serde(default = "default_sshjail_root_dir", alias = "audit_dir")]
    pub root_dir: String,
    #[serde(default = "default_sshjail_static_blacklist_keys_path")]
    pub static_blacklist_keys_path: String,
    #[serde(default)]
    pub hostname_strategy: SshJailHostnameStrategy,
    #[serde(default)]
    pub fake_hostname: Option<String>,
}

impl Default for SshJailPolicy {
    fn default() -> Self {
        Self {
            protected_port: default_protected_ssh_port(),
            listen_port: default_sshjail_listen_port(),
            max_sessions: default_sshjail_max_sessions(),
            idle_timeout_secs: default_sshjail_idle_timeout_secs(),
            max_session_duration_secs: default_sshjail_max_session_duration_secs(),
            root_dir: default_sshjail_root_dir(),
            static_blacklist_keys_path: default_sshjail_static_blacklist_keys_path(),
            hostname_strategy: SshJailHostnameStrategy::Generated,
            fake_hostname: None,
        }
    }
}

impl SshJailPolicy {
    fn validate(&self) -> Result<(), PolicyError> {
        if self.protected_port == 0 {
            return Err(PolicyError::InvalidSshProtectedPort);
        }

        if self.listen_port != 0 && self.listen_port == self.protected_port {
            return Err(PolicyError::ConflictingSshJailPort {
                port: self.listen_port,
            });
        }

        if self.max_sessions == 0 {
            return Err(PolicyError::InvalidSshJailMaxSessions);
        }

        if self.idle_timeout_secs == 0 {
            return Err(PolicyError::InvalidSshJailIdleTimeout);
        }

        if self.max_session_duration_secs == 0 {
            return Err(PolicyError::InvalidSshJailSessionDuration);
        }

        if self.root_dir.trim().is_empty() {
            return Err(PolicyError::EmptySshJailRootDir);
        }

        if self.static_blacklist_keys_path.trim().is_empty() {
            return Err(PolicyError::EmptySshJailStaticBlacklistKeysPath);
        }

        if matches!(self.hostname_strategy, SshJailHostnameStrategy::Configured)
            && self
                .fake_hostname
                .as_ref()
                .map(|value| value.trim().is_empty())
                .unwrap_or(true)
        {
            return Err(PolicyError::MissingConfiguredSshJailHostname);
        }

        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshProtectionPolicy {
    pub enabled: bool,
    pub failure_threshold: u32,
    pub window_secs: u64,
    pub ban_duration_secs: u64,
    #[serde(default)]
    pub invalid_user_force_ban_enabled: bool,
    pub log_source_mode: SshLogSourceMode,
    #[serde(default)]
    pub log_file_paths: Vec<String>,
    #[serde(default)]
    pub gp: GpPolicy,
}

impl Default for SshProtectionPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            failure_threshold: 5,
            window_secs: 300,
            ban_duration_secs: 900,
            invalid_user_force_ban_enabled: false,
            log_source_mode: SshLogSourceMode::Auto,
            log_file_paths: Vec::new(),
            gp: GpPolicy::default(),
        }
    }
}

impl SshProtectionPolicy {
    fn validate(&self) -> Result<(), PolicyError> {
        if !self.enabled {
            return Ok(());
        }

        if self.failure_threshold == 0 {
            return Err(PolicyError::InvalidSshThreshold);
        }

        if self.window_secs == 0 {
            return Err(PolicyError::InvalidSshWindow);
        }

        if self.ban_duration_secs == 0 {
            return Err(PolicyError::InvalidBanDuration);
        }

        for path in &self.log_file_paths {
            if path.trim().is_empty() {
                return Err(PolicyError::EmptySshLogPath);
            }
        }

        self.gp.validate()?;

        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SshLogSourceMode {
    Auto,
    Journald,
    LogFiles,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum XdpMode {
    #[default]
    Driver,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfacePolicy {
    pub name: String,
    #[serde(default)]
    pub xdp_mode: XdpMode,
    #[serde(default)]
    pub filters: InterfaceFilters,
}

impl InterfacePolicy {
    fn validate(&self) -> Result<(), PolicyError> {
        if self.name.trim().is_empty() {
            return Err(PolicyError::EmptyInterfaceName);
        }

        self.filters.validate()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceFilters {
    #[serde(default)]
    pub icmp: IcmpPolicy,
}

impl InterfaceFilters {
    fn validate(&self) -> Result<(), PolicyError> {
        self.icmp.validate()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IcmpPolicy {
    pub mode: IcmpMode,
    #[serde(default)]
    pub allow_rules: Vec<IcmpAllowRule>,
}

impl Default for IcmpPolicy {
    fn default() -> Self {
        Self {
            mode: IcmpMode::Disabled,
            allow_rules: Vec::new(),
        }
    }
}

impl IcmpPolicy {
    fn validate(&self) -> Result<(), PolicyError> {
        for rule in &self.allow_rules {
            rule.validate()?;
        }

        Ok(())
    }

    pub fn compile_rules(&self) -> Result<Vec<IcmpRule>, PolicyError> {
        self.allow_rules
            .iter()
            .filter(|rule| rule.enabled)
            .map(IcmpAllowRule::compile)
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IcmpAllowRule {
    pub match_type: IcmpMatchType,
    pub payload_hex: String,
    pub enabled: bool,
}

impl IcmpAllowRule {
    fn validate(&self) -> Result<(), PolicyError> {
        if !self.enabled {
            return Ok(());
        }

        if self.match_type != IcmpMatchType::RawBytesExact {
            return Err(PolicyError::UnsupportedIcmpMatchType(self.match_type));
        }

        let payload = decode_hex_payload(&self.payload_hex)?;

        if payload.is_empty() {
            return Err(PolicyError::EmptyIcmpPayload);
        }

        if payload.len() > ICMP_RULE_PAYLOAD_CAPACITY {
            return Err(PolicyError::IcmpPayloadTooLong {
                actual: payload.len(),
                limit: ICMP_RULE_PAYLOAD_CAPACITY,
            });
        }

        Ok(())
    }

    pub fn compile(&self) -> Result<IcmpRule, PolicyError> {
        self.validate()?;
        let payload = decode_hex_payload(&self.payload_hex)?;

        match IcmpRule::raw_bytes_exact(&payload) {
            Some(rule) => Ok(rule),
            None => Err(PolicyError::EmptyIcmpPayload),
        }
    }
}

fn decode_hex_payload(input: &str) -> Result<Vec<u8>, PolicyError> {
    let trimmed = input.trim();
    if trimmed.len() % 2 != 0 {
        return Err(PolicyError::InvalidIcmpPayloadHex {
            value: input.to_string(),
        });
    }

    let mut payload = Vec::with_capacity(trimmed.len() / 2);
    let mut index = 0;
    while index < trimmed.len() {
        let byte = u8::from_str_radix(&trimmed[index..index + 2], 16).map_err(|_| {
            PolicyError::InvalidIcmpPayloadHex {
                value: input.to_string(),
            }
        })?;
        payload.push(byte);
        index += 2;
    }

    Ok(payload)
}

const fn default_config_version() -> u32 {
    CONFIG_VERSION_V1
}

const fn default_protected_ssh_port() -> u16 {
    22
}

const fn default_sshjail_listen_port() -> u16 {
    0
}

const fn default_sshjail_max_sessions() -> usize {
    32
}

const fn default_sshjail_idle_timeout_secs() -> u64 {
    600
}

const fn default_sshjail_max_session_duration_secs() -> u64 {
    3_600
}

fn default_sshjail_root_dir() -> String {
    "/tmp/walle".to_string()
}

fn default_sshjail_static_blacklist_keys_path() -> String {
    "/etc/walle/blacklist_keys".to_string()
}

static DEFAULT_ICMP_POLICY: IcmpPolicy = IcmpPolicy {
    mode: IcmpMode::Disabled,
    allow_rules: Vec::new(),
};

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("failed to read config file '{}': {source}", .path.display())]
    ReadConfigFile {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse config file '{}': {source}", .path.display())]
    ParseConfigFile {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[error("unsupported config version {actual}; supported version is {supported}")]
    UnsupportedConfigVersion { actual: u32, supported: u32 },
    #[error("SSH failure threshold must be greater than zero")]
    InvalidSshThreshold,
    #[error("SSH failure window must be greater than zero")]
    InvalidSshWindow,
    #[error("SSH ban duration must be greater than zero")]
    InvalidBanDuration,
    #[error("protected SSH port must be greater than zero")]
    InvalidSshProtectedPort,
    #[error("sshjail listen port {port} cannot match the protected SSH port")]
    ConflictingSshJailPort { port: u16 },
    #[error("sshjail max_sessions must be greater than zero")]
    InvalidSshJailMaxSessions,
    #[error("sshjail idle timeout must be greater than zero")]
    InvalidSshJailIdleTimeout,
    #[error("sshjail max session duration must be greater than zero")]
    InvalidSshJailSessionDuration,
    #[error("sshjail root_dir cannot be empty")]
    EmptySshJailRootDir,
    #[error("sshjail static_blacklist_keys_path cannot be empty")]
    EmptySshJailStaticBlacklistKeysPath,
    #[error("sshjail fake_hostname is required when hostname_strategy is configured")]
    MissingConfiguredSshJailHostname,
    #[error("SSH log file paths cannot contain empty values")]
    EmptySshLogPath,
    #[error("interface names cannot be empty")]
    EmptyInterfaceName,
    #[error("duplicate interface declaration '{name}'")]
    DuplicateInterface { name: String },
    #[error("ICMP exact-match payload cannot be empty")]
    EmptyIcmpPayload,
    #[error("ICMP payload hex '{value}' is invalid")]
    InvalidIcmpPayloadHex { value: String },
    #[error("ICMP payload is too long: {actual} bytes exceeds limit {limit}")]
    IcmpPayloadTooLong { actual: usize, limit: usize },
    #[error("ICMP match type {0:?} is not supported in v0")]
    UnsupportedIcmpMatchType(IcmpMatchType),
}

impl fmt::Display for AccessPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "mode={:?}, allowlist_entries={}, denylist_entries={}",
            self.mode,
            self.allowlist.len(),
            self.denylist.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::{
        DEFAULT_CONFIG_PATH, DetectorPolicies, GlobalPolicy, GpPolicy, GpStrategyKind,
        GpTriggerMode, IcmpAllowRule, InterfaceFilters, InterfacePolicy, LogLevel, PolicyError,
        SshJailHostnameStrategy, SshLogSourceMode, SshProtectionPolicy, WalleConfig,
    };
    use walle_common::{AccessMode, IcmpMatchType, IcmpMode};

    #[test]
    fn default_config_is_valid() {
        let config = WalleConfig::default();
        assert!(config.validate().is_ok());
        assert_eq!(config.version, 1);
        assert!(config.interfaces().is_empty());
        assert_eq!(config.logging_policy().level, LogLevel::Info);
        assert!(!config.ssh_policy().gp.enabled);
        assert_eq!(config.ssh_policy().gp.strategy, GpStrategyKind::Observe);
        assert_eq!(
            config.ssh_policy().gp.trigger_mode,
            GpTriggerMode::DecisionEmitted
        );
        assert_eq!(config.ssh_policy().gp.sshjail.listen_port, 0);
        assert_eq!(config.ssh_policy().gp.sshjail.root_dir, "/tmp/walle");
        assert_eq!(
            config.ssh_policy().gp.sshjail.static_blacklist_keys_path,
            "/etc/walle/blacklist_keys"
        );
    }

    #[test]
    fn default_config_path_is_linux_system_location() {
        assert_eq!(DEFAULT_CONFIG_PATH, "/etc/walle/config.toml");
    }

    #[test]
    fn disabled_ssh_policy_skips_threshold_checks() {
        let policy = SshProtectionPolicy {
            enabled: false,
            failure_threshold: 0,
            window_secs: 0,
            ban_duration_secs: 0,
            invalid_user_force_ban_enabled: false,
            log_source_mode: SshLogSourceMode::Auto,
            log_file_paths: Vec::new(),
            gp: GpPolicy::default(),
        };

        assert!(policy.validate().is_ok());
    }

    #[test]
    fn gp_trigger_mode_match_helpers_cover_both_trigger_boundaries() {
        assert!(GpTriggerMode::SignalObserved.matches_signal_observed());
        assert!(!GpTriggerMode::SignalObserved.matches_decision_emitted());
        assert!(GpTriggerMode::DecisionEmitted.matches_decision_emitted());
        assert!(!GpTriggerMode::DecisionEmitted.matches_signal_observed());
        assert!(GpTriggerMode::All.matches_signal_observed());
        assert!(GpTriggerMode::All.matches_decision_emitted());
    }

    #[test]
    fn empty_log_path_is_rejected() {
        let policy = SshProtectionPolicy {
            log_file_paths: vec!["".to_string()],
            ..SshProtectionPolicy::default()
        };

        assert!(matches!(
            policy.validate(),
            Err(PolicyError::EmptySshLogPath)
        ));
    }

    #[test]
    fn configured_hostname_requires_value() {
        let policy = SshProtectionPolicy {
            gp: GpPolicy {
                sshjail: super::SshJailPolicy {
                    hostname_strategy: SshJailHostnameStrategy::Configured,
                    fake_hostname: None,
                    ..super::SshJailPolicy::default()
                },
                ..GpPolicy::default()
            },
            ..SshProtectionPolicy::default()
        };

        assert!(matches!(
            policy.validate(),
            Err(PolicyError::MissingConfiguredSshJailHostname)
        ));
    }

    #[test]
    fn sshjail_listen_port_cannot_match_protected_port() {
        let policy = SshProtectionPolicy {
            gp: GpPolicy {
                sshjail: super::SshJailPolicy {
                    protected_port: 22,
                    listen_port: 22,
                    ..super::SshJailPolicy::default()
                },
                ..GpPolicy::default()
            },
            ..SshProtectionPolicy::default()
        };

        assert!(matches!(
            policy.validate(),
            Err(PolicyError::ConflictingSshJailPort { port: 22 })
        ));
    }

    #[test]
    fn future_match_types_are_rejected_for_now() {
        let rule = IcmpAllowRule {
            match_type: IcmpMatchType::Regex,
            payload_hex: "010203".to_string(),
            enabled: true,
        };

        assert!(matches!(
            rule.validate(),
            Err(PolicyError::UnsupportedIcmpMatchType(IcmpMatchType::Regex))
        ));
    }

    #[test]
    fn runtime_config_tracks_access_and_primary_interface_icmp_modes() {
        let config = WalleConfig {
            policy: GlobalPolicy {
                access: super::AccessPolicy {
                    mode: AccessMode::WhitelistOnly,
                    allowlist: Vec::new(),
                    denylist: Vec::new(),
                },
                ..GlobalPolicy::default()
            },
            interfaces: vec![InterfacePolicy {
                name: "eth0".to_string(),
                xdp_mode: super::XdpMode::Driver,
                filters: InterfaceFilters {
                    icmp: super::IcmpPolicy {
                        mode: IcmpMode::DropAll,
                        allow_rules: Vec::new(),
                    },
                },
            }],
            ..WalleConfig::default()
        };

        let runtime = config.primary_runtime_config();

        assert_eq!(runtime.access_mode, AccessMode::WhitelistOnly);
        assert_eq!(runtime.icmp_mode, IcmpMode::DropAll);
    }

    #[test]
    fn runtime_config_can_override_dynamic_sshjail_port() {
        let config = WalleConfig {
            interfaces: vec![InterfacePolicy {
                name: "eth0".to_string(),
                xdp_mode: super::XdpMode::Driver,
                filters: InterfaceFilters::default(),
            }],
            ..WalleConfig::default()
        };

        let runtime = config.runtime_config_for_ssh_jail_port(&config.interfaces()[0], 40222);

        assert_eq!(runtime.protected_ssh_port, 22);
        assert_eq!(runtime.ssh_jail_port, 40222);
    }

    #[test]
    fn duplicate_interfaces_are_rejected() {
        let config = WalleConfig {
            interfaces: vec![
                InterfacePolicy {
                    name: "eth0".to_string(),
                    xdp_mode: super::XdpMode::Driver,
                    filters: InterfaceFilters::default(),
                },
                InterfacePolicy {
                    name: "eth0".to_string(),
                    xdp_mode: super::XdpMode::Driver,
                    filters: InterfaceFilters::default(),
                },
            ],
            ..WalleConfig::default()
        };

        assert!(matches!(
            config.validate(),
            Err(PolicyError::DuplicateInterface { name }) if name == "eth0"
        ));
    }

    #[test]
    fn empty_interface_name_is_rejected() {
        let config = WalleConfig {
            interfaces: vec![InterfacePolicy {
                name: " ".to_string(),
                xdp_mode: super::XdpMode::Driver,
                filters: InterfaceFilters::default(),
            }],
            ..WalleConfig::default()
        };

        assert!(matches!(
            config.validate(),
            Err(PolicyError::EmptyInterfaceName)
        ));
    }

    #[test]
    fn invalid_payload_hex_is_rejected() {
        let config = WalleConfig {
            interfaces: vec![InterfacePolicy {
                name: "eth0".to_string(),
                xdp_mode: super::XdpMode::Driver,
                filters: InterfaceFilters {
                    icmp: super::IcmpPolicy {
                        mode: IcmpMode::AllowRulesActive,
                        allow_rules: vec![IcmpAllowRule {
                            match_type: IcmpMatchType::RawBytesExact,
                            payload_hex: "zz".to_string(),
                            enabled: true,
                        }],
                    },
                },
            }],
            ..WalleConfig::default()
        };

        assert!(matches!(
            config.validate(),
            Err(PolicyError::InvalidIcmpPayloadHex { value }) if value == "zz"
        ));
    }

    #[test]
    fn load_from_toml_parses_nested_interface_config() {
        let path = unique_test_config_path("load");
        let config_text = r#"
version = 1

[detectors.ssh]
enabled = true
failure_threshold = 5
window_secs = 300
ban_duration_secs = 900
invalid_user_force_ban_enabled = true
log_source_mode = "auto"
log_file_paths = []

[detectors.ssh.gp]
enabled = true
strategy = "contain"
trigger_mode = "decision_emitted"

[detectors.ssh.gp.sshjail]
protected_port = 22
listen_port = 2222
max_sessions = 64
idle_timeout_secs = 600
max_session_duration_secs = 3600
root_dir = "/tmp/walle"
static_blacklist_keys_path = "/etc/walle/blacklist_keys"
hostname_strategy = "configured"
fake_hostname = "web-01"

[policy.access]
mode = "blacklist_only"
allowlist = []
denylist = []

[policy.logging]
level = "debug"

[[interfaces]]
name = "eth0"
xdp_mode = "driver"

[interfaces.filters.icmp]
mode = "allow_rules_active"

[[interfaces.filters.icmp.allow_rules]]
match_type = "raw_bytes_exact"
payload_hex = "09070108"
enabled = true
"#;
        fs::write(&path, config_text).expect("config fixture should be written");

        let config = WalleConfig::load_from_path(&path).expect("config should parse");
        assert_eq!(config.interfaces().len(), 1);
        assert_eq!(config.interfaces()[0].name, "eth0");
        assert_eq!(config.logging_policy().level, LogLevel::Debug);
        assert_eq!(
            config.interfaces()[0].filters.icmp.allow_rules[0].payload_hex,
            "09070108"
        );
        assert!(config.ssh_policy().gp.enabled);
        assert!(config.ssh_policy().invalid_user_force_ban_enabled);
        assert_eq!(config.ssh_policy().gp.strategy, GpStrategyKind::Contain);
        assert_eq!(
            config.ssh_policy().gp.trigger_mode,
            GpTriggerMode::DecisionEmitted
        );
        assert_eq!(config.ssh_policy().gp.sshjail.max_sessions, 64);
        assert_eq!(config.ssh_policy().gp.sshjail.root_dir, "/tmp/walle");
        assert_eq!(
            config.ssh_policy().gp.sshjail.static_blacklist_keys_path,
            "/etc/walle/blacklist_keys"
        );
        assert_eq!(
            config.ssh_policy().gp.sshjail.hostname_strategy,
            SshJailHostnameStrategy::Configured
        );
        assert_eq!(
            config.ssh_policy().gp.sshjail.fake_hostname.as_deref(),
            Some("web-01")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn load_from_toml_accepts_legacy_audit_dir_alias_for_root_dir() {
        let path = unique_test_config_path("legacy-audit-dir");
        let config_text = r#"
version = 1

[detectors.ssh]
enabled = false
failure_threshold = 5
window_secs = 300
ban_duration_secs = 900
log_source_mode = "auto"
log_file_paths = []

[detectors.ssh.gp]
enabled = false

[detectors.ssh.gp.sshjail]
audit_dir = "/var/lib/walle"
"#;
        fs::write(&path, config_text).expect("config fixture should be written");

        let config = WalleConfig::load_from_path(&path).expect("config should parse");
        assert_eq!(config.ssh_policy().gp.sshjail.root_dir, "/var/lib/walle");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn payload_hex_compiles_into_expected_rule() {
        let rule = IcmpAllowRule {
            match_type: IcmpMatchType::RawBytesExact,
            payload_hex: "09070108".to_string(),
            enabled: true,
        };

        let compiled = rule.compile().expect("payload hex should compile");
        let expected = super::IcmpRule::raw_bytes_exact(&[0x09, 0x07, 0x01, 0x08])
            .expect("expected fixture payload should compile");
        assert_eq!(compiled, expected);
    }

    #[test]
    fn detector_and_policy_defaults_are_wired() {
        let config = WalleConfig {
            detectors: DetectorPolicies::default(),
            policy: GlobalPolicy::default(),
            interfaces: vec![InterfacePolicy {
                name: "eth0".to_string(),
                xdp_mode: super::XdpMode::Driver,
                filters: InterfaceFilters::default(),
            }],
            ..WalleConfig::default()
        };

        assert!(config.ssh_policy().enabled);
        assert_eq!(config.access_policy().mode, AccessMode::BlacklistOnly);
    }

    fn unique_test_config_path(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("walle-policy-{name}-{nanos}.toml"))
    }
}
