#![no_std]

use serde::{Deserialize, Serialize};

pub const CONFIG_MAP_KEY: u32 = 0;
pub const STATS_MAP_KEY: u32 = 0;
pub const ICMP_RULE_PAYLOAD_CAPACITY: usize = 64;
pub const CONFIG_MAP_CAPACITY: u32 = 1;
pub const STATS_MAP_CAPACITY: u32 = 1;
pub const ALLOW_MAP_CAPACITY: u32 = 4096;
pub const DENY_MAP_CAPACITY: u32 = 4096;
pub const ICMP_RULE_MAP_CAPACITY: u32 = 256;
pub const XDP_PROGRAM_NAME: &str = "walle_ingress";
pub const DEFAULT_MAP_PIN_PATH: &str = "/sys/fs/bpf/walle";
pub const MAP_NAME_CONFIG: &str = "config";
pub const MAP_NAME_ALLOW_V4: &str = "allow_v4";
pub const MAP_NAME_ALLOW_V6: &str = "allow_v6";
pub const MAP_NAME_DENY_V4: &str = "deny_v4";
pub const MAP_NAME_DENY_V6: &str = "deny_v6";
pub const MAP_NAME_ICMP_RULES: &str = "icmp_rules";
pub const MAP_NAME_STATS: &str = "stats";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PacketAction {
    Allow = 0,
    Drop = 1,
}

impl Default for PacketAction {
    fn default() -> Self {
        Self::Allow
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AccessMode {
    BlacklistOnly = 0,
    WhitelistOnly = 1,
    BlacklistWithWhitelistException = 2,
}

impl AccessMode {
    #[must_use]
    pub const fn decide(self, is_whitelisted: bool, is_blacklisted: bool) -> PacketAction {
        if is_whitelisted {
            return PacketAction::Allow;
        }

        match self {
            Self::WhitelistOnly => PacketAction::Drop,
            Self::BlacklistOnly | Self::BlacklistWithWhitelistException => {
                if is_blacklisted {
                    PacketAction::Drop
                } else {
                    PacketAction::Allow
                }
            }
        }
    }
}

impl Default for AccessMode {
    fn default() -> Self {
        Self::BlacklistOnly
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum IcmpMode {
    Disabled = 0,
    DropAll = 1,
    AllowRulesActive = 2,
}

impl Default for IcmpMode {
    fn default() -> Self {
        Self::Disabled
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum IcmpMatchType {
    RawBytesExact = 0,
    StringExact = 1,
    Regex = 2,
}

impl Default for IcmpMatchType {
    fn default() -> Self {
        Self::RawBytesExact
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum BanSource {
    Manual = 0,
    SshDetector = 1,
    FutureHttpDetector = 2,
}

impl Default for BanSource {
    fn default() -> Self {
        Self::Manual
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum BanReasonCode {
    Manual = 0,
    SshAuthFailures = 1,
    FutureHttpAbuse = 2,
}

impl Default for BanReasonCode {
    fn default() -> Self {
        Self::Manual
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct RuntimeConfig {
    pub version: u16,
    pub access_mode: AccessMode,
    pub icmp_mode: IcmpMode,
    pub default_action: PacketAction,
    pub flags: u32,
}

impl RuntimeConfig {
    #[must_use]
    pub const fn new(access_mode: AccessMode, icmp_mode: IcmpMode) -> Self {
        Self {
            version: 1,
            access_mode,
            icmp_mode,
            default_action: PacketAction::Allow,
            flags: 0,
        }
    }
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self::new(AccessMode::BlacklistOnly, IcmpMode::Disabled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct BanEntryV4 {
    pub expires_at_ns: u64,
    pub created_at_ns: u64,
    pub source: BanSource,
    pub reason: BanReasonCode,
    pub flags: u16,
}

impl Default for BanEntryV4 {
    fn default() -> Self {
        Self {
            expires_at_ns: 0,
            created_at_ns: 0,
            source: BanSource::Manual,
            reason: BanReasonCode::Manual,
            flags: 0,
        }
    }
}

impl BanEntryV4 {
    #[must_use]
    pub const fn manual_indefinite(created_at_ns: u64) -> Self {
        Self {
            expires_at_ns: 0,
            created_at_ns,
            source: BanSource::Manual,
            reason: BanReasonCode::Manual,
            flags: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(C)]
pub struct Ipv4AddrKey {
    pub octets: [u8; 4],
}

impl Ipv4AddrKey {
    #[must_use]
    pub const fn new(octets: [u8; 4]) -> Self {
        Self { octets }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(C)]
pub struct Ipv6AddrKey {
    pub octets: [u8; 16],
}

impl Ipv6AddrKey {
    #[must_use]
    pub const fn new(octets: [u8; 16]) -> Self {
        Self { octets }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct IcmpRule {
    pub match_type: IcmpMatchType,
    pub payload_length: u16,
    pub enabled: u8,
    pub reserved: u8,
    pub payload: [u8; ICMP_RULE_PAYLOAD_CAPACITY],
}

impl IcmpRule {
    #[must_use]
    pub fn raw_bytes_exact(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() || bytes.len() > ICMP_RULE_PAYLOAD_CAPACITY {
            return None;
        }

        let mut payload = [0; ICMP_RULE_PAYLOAD_CAPACITY];
        let mut index = 0;

        while index < bytes.len() {
            payload[index] = bytes[index];
            index += 1;
        }

        Some(Self {
            match_type: IcmpMatchType::RawBytesExact,
            payload_length: bytes.len() as u16,
            enabled: 1,
            reserved: 0,
            payload,
        })
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct StatsCounters {
    pub packets_allowed: u64,
    pub packets_dropped: u64,
    pub allowlist_hits: u64,
    pub denylist_hits: u64,
    pub icmp_rule_hits: u64,
    pub parser_failures: u64,
}

#[cfg(test)]
mod tests {
    use super::{AccessMode, BanEntryV4, IcmpRule, PacketAction};

    #[test]
    fn whitelist_always_wins_even_if_blacklisted() {
        let verdict = AccessMode::BlacklistOnly.decide(true, true);
        assert_eq!(verdict, PacketAction::Allow);
    }

    #[test]
    fn whitelist_only_drops_unknown_sources() {
        let verdict = AccessMode::WhitelistOnly.decide(false, false);
        assert_eq!(verdict, PacketAction::Drop);
    }

    #[test]
    fn icmp_rule_builder_rejects_empty_payloads() {
        assert!(IcmpRule::raw_bytes_exact(&[]).is_none());
    }

    #[test]
    fn manual_ban_helper_creates_indefinite_ban() {
        let entry = BanEntryV4::manual_indefinite(42);
        assert_eq!(entry.created_at_ns, 42);
        assert_eq!(entry.expires_at_ns, 0);
    }
}

#[cfg(target_os = "linux")]
unsafe impl aya::Pod for RuntimeConfig {}
#[cfg(target_os = "linux")]
unsafe impl aya::Pod for BanEntryV4 {}
#[cfg(target_os = "linux")]
unsafe impl aya::Pod for Ipv4AddrKey {}
#[cfg(target_os = "linux")]
unsafe impl aya::Pod for Ipv6AddrKey {}
#[cfg(target_os = "linux")]
unsafe impl aya::Pod for IcmpRule {}
#[cfg(target_os = "linux")]
unsafe impl aya::Pod for StatsCounters {}
