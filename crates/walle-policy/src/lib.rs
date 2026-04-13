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
        RuntimeConfig::new(self.policy.access.mode, interface.filters.icmp.mode)
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
        self.primary_interface()
            .map(|interface| self.runtime_config_for(interface))
            .unwrap_or_else(|| RuntimeConfig::new(self.policy.access.mode, IcmpMode::Disabled))
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshProtectionPolicy {
    pub enabled: bool,
    pub failure_threshold: u32,
    pub window_secs: u64,
    pub ban_duration_secs: u64,
    pub log_source_mode: SshLogSourceMode,
    #[serde(default)]
    pub log_file_paths: Vec<String>,
}

impl Default for SshProtectionPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            failure_threshold: 5,
            window_secs: 300,
            ban_duration_secs: 900,
            log_source_mode: SshLogSourceMode::Auto,
            log_file_paths: Vec::new(),
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
        DEFAULT_CONFIG_PATH, DetectorPolicies, GlobalPolicy, IcmpAllowRule, InterfaceFilters,
        InterfacePolicy, LogLevel, PolicyError, SshLogSourceMode, SshProtectionPolicy, WalleConfig,
    };
    use walle_common::{AccessMode, IcmpMatchType, IcmpMode};

    #[test]
    fn default_config_is_valid() {
        let config = WalleConfig::default();
        assert!(config.validate().is_ok());
        assert_eq!(config.version, 1);
        assert!(config.interfaces().is_empty());
        assert_eq!(config.logging_policy().level, LogLevel::Info);
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
            log_source_mode: SshLogSourceMode::Auto,
            log_file_paths: Vec::new(),
        };

        assert!(policy.validate().is_ok());
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
log_source_mode = "auto"
log_file_paths = []

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
