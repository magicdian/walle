use core::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use walle_common::{
    AccessMode, ICMP_RULE_PAYLOAD_CAPACITY, IcmpMatchType, IcmpMode, RuntimeConfig,
};

pub use walle_common::IcmpRule;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalleConfig {
    pub access: AccessPolicy,
    pub ssh: SshProtectionPolicy,
    pub icmp: IcmpPolicy,
}

impl Default for WalleConfig {
    fn default() -> Self {
        Self {
            access: AccessPolicy::default(),
            ssh: SshProtectionPolicy::default(),
            icmp: IcmpPolicy::default(),
        }
    }
}

impl WalleConfig {
    pub fn validate(&self) -> Result<(), PolicyError> {
        self.ssh.validate()?;
        self.icmp.validate()?;
        Ok(())
    }

    #[must_use]
    pub fn runtime_config(&self) -> RuntimeConfig {
        RuntimeConfig::new(self.access.mode, self.icmp.mode)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessPolicy {
    pub mode: AccessMode,
    pub allowlist: Vec<IpAddr>,
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
pub enum SshLogSourceMode {
    Auto,
    Journald,
    LogFiles,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IcmpPolicy {
    pub mode: IcmpMode,
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
    pub payload: Vec<u8>,
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

        if self.payload.is_empty() {
            return Err(PolicyError::EmptyIcmpPayload);
        }

        if self.payload.len() > ICMP_RULE_PAYLOAD_CAPACITY {
            return Err(PolicyError::IcmpPayloadTooLong {
                actual: self.payload.len(),
                limit: ICMP_RULE_PAYLOAD_CAPACITY,
            });
        }

        Ok(())
    }

    pub fn compile(&self) -> Result<IcmpRule, PolicyError> {
        self.validate()?;

        match IcmpRule::raw_bytes_exact(&self.payload) {
            Some(rule) => Ok(rule),
            None => Err(PolicyError::EmptyIcmpPayload),
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("SSH failure threshold must be greater than zero")]
    InvalidSshThreshold,
    #[error("SSH failure window must be greater than zero")]
    InvalidSshWindow,
    #[error("SSH ban duration must be greater than zero")]
    InvalidBanDuration,
    #[error("SSH log file paths cannot contain empty values")]
    EmptySshLogPath,
    #[error("ICMP exact-match payload cannot be empty")]
    EmptyIcmpPayload,
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
    use super::{IcmpAllowRule, PolicyError, SshLogSourceMode, SshProtectionPolicy, WalleConfig};
    use walle_common::{IcmpMatchType, IcmpMode};

    #[test]
    fn default_config_is_valid() {
        let config = WalleConfig::default();
        assert_eq!(config.validate(), Ok(()));
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

        assert_eq!(policy.validate(), Ok(()));
    }

    #[test]
    fn empty_log_path_is_rejected() {
        let policy = SshProtectionPolicy {
            log_file_paths: vec!["".to_string()],
            ..SshProtectionPolicy::default()
        };

        assert_eq!(policy.validate(), Err(PolicyError::EmptySshLogPath));
    }

    #[test]
    fn future_match_types_are_rejected_for_now() {
        let rule = IcmpAllowRule {
            match_type: IcmpMatchType::Regex,
            payload: vec![1, 2, 3],
            enabled: true,
        };

        assert_eq!(
            rule.validate(),
            Err(PolicyError::UnsupportedIcmpMatchType(IcmpMatchType::Regex,))
        );
    }

    #[test]
    fn runtime_config_tracks_access_and_icmp_modes() {
        let mut config = WalleConfig::default();
        config.icmp.mode = IcmpMode::DropAll;

        let runtime = config.runtime_config();

        assert_eq!(runtime.icmp_mode, IcmpMode::DropAll);
    }
}
