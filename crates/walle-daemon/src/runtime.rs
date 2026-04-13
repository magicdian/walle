use std::collections::{BTreeSet, HashMap, HashSet};
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[cfg(target_os = "linux")]
use std::fs;
use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::str::FromStr;

use thiserror::Error;
use tracing::{debug, info};
use walle_common::{
    AccessMode, BanEntryV4, CONFIG_MAP_KEY, ICMP_RULE_MAP_CAPACITY, IcmpMode, IcmpRule,
    Ipv4AddrKey, Ipv6AddrKey, MAP_NAME_ALLOW_V4, MAP_NAME_ALLOW_V6, MAP_NAME_CONFIG,
    MAP_NAME_DENY_V4, MAP_NAME_DENY_V6, MAP_NAME_ICMP_RULES, MAP_NAME_STATS, RuntimeConfig,
    STATS_MAP_KEY, StatsCounters,
};
use walle_policy::{InterfacePolicy, WalleConfig};

use crate::logging::format_unix_timestamp_secs;

#[cfg(target_os = "linux")]
use aya::{
    Pod,
    maps::{Array, HashMap as BpfHashMap, Map, MapData, MapError},
};

pub struct RuntimeController {
    interface: Option<String>,
    repository: RuntimeRepository,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BanRecord {
    pub ip: IpAddr,
    pub entry: BanEntryV4,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BanExpirySummary {
    pub removed_v4: usize,
    pub removed_v6: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeBackendKind {
    InMemory,
    BpfMaps,
}

impl RuntimeBackendKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InMemory => "in_memory",
            Self::BpfMaps => "bpf_maps",
        }
    }
}

impl BanExpirySummary {
    #[must_use]
    pub const fn total_removed(self) -> usize {
        self.removed_v4 + self.removed_v6
    }
}

impl RuntimeController {
    #[must_use]
    pub fn new(interface: Option<String>) -> Self {
        Self {
            interface,
            repository: RuntimeRepository::InMemory(InMemoryMapRepository::default()),
        }
    }

    pub fn connect_map_backend(&mut self, map_pin_path: &Path) -> Result<(), RuntimeError> {
        #[cfg(target_os = "linux")]
        {
            let repository = LinuxMapRepository::open(map_pin_path)?;
            self.repository = RuntimeRepository::Linux(repository);

            info!(
                component = "runtime",
                event = "repository_backend_selected",
                interface = self.interface.as_deref().unwrap_or("unset"),
                backend = "bpf_maps",
                map_pin_path = %map_pin_path.display(),
                "runtime repository switched to pinned BPF maps"
            );
        }

        #[cfg(not(target_os = "linux"))]
        let _ = map_pin_path;

        Ok(())
    }

    #[must_use]
    pub fn backend_kind(&self) -> RuntimeBackendKind {
        self.repository.kind()
    }

    pub fn sync_policy_for_interface(
        &mut self,
        config: &WalleConfig,
        interface: &InterfacePolicy,
    ) -> Result<(), RuntimeError> {
        let runtime_config = config.runtime_config_for(interface);
        let icmp_rules = interface.filters.icmp.compile_rules()?;
        let access = config.access_policy();

        self.repository.write_config(runtime_config)?;
        self.repository.replace_allowlist(&access.allowlist)?;
        self.repository.replace_denylist(&access.denylist)?;
        self.repository.replace_icmp_rules(&icmp_rules)?;

        let snapshot = self.repository.snapshot()?;

        debug!(
            component = "runtime",
            event = "config_sync",
            interface = self.interface.as_deref().unwrap_or("unset"),
            access_mode = ?runtime_config.access_mode,
            icmp_mode = ?runtime_config.icmp_mode,
            allow_v4_entries = snapshot.allow_v4_entries,
            allow_v6_entries = snapshot.allow_v6_entries,
            deny_v4_entries = snapshot.deny_v4_entries,
            deny_v6_entries = snapshot.deny_v6_entries,
            icmp_rules = snapshot.icmp_rule_entries,
            backend = self.repository.name(),
            "runtime config has been synced into the active runtime repository"
        );

        Ok(())
    }

    pub fn add_manual_ban(
        &mut self,
        ip: IpAddr,
        created_at_secs: u64,
        duration_secs: Option<u64>,
    ) -> Result<(), RuntimeError> {
        let entry = manual_ban_entry(created_at_secs, duration_secs);

        match ip {
            IpAddr::V4(ip) => self.repository.upsert_deny_v4(ip, entry)?,
            IpAddr::V6(ip) => self.repository.upsert_deny_v6(ip, entry)?,
        }

        info!(
            component = "runtime",
            event = "manual_ban_applied",
            ip = %ip,
            created_at = %format_unix_timestamp_secs(created_at_secs),
            expires_at = %format_optional_unix_timestamp_secs(ban_entry_expires_at_secs(entry)),
            backend = self.repository.name(),
            "applied manual ban to runtime repository"
        );

        Ok(())
    }

    pub fn apply_ssh_ban(
        &mut self,
        decision: crate::detector::SshBanDecision,
    ) -> Result<(), RuntimeError> {
        let ban_entry = decision.clone().into_ban_entry();

        match decision.ip {
            IpAddr::V4(ip) => self.repository.upsert_deny_v4(ip, ban_entry)?,
            IpAddr::V6(ip) => self.repository.upsert_deny_v6(ip, ban_entry)?,
        }

        debug!(
            component = "runtime",
            event = "ssh_ban_applied",
            ip = %decision.ip,
            observed_at = %format_unix_timestamp_secs(decision.observed_at_secs),
            expires_at = %format_unix_timestamp_secs(decision.expires_at_secs),
            matched_failures = decision.matched_failures,
            backend = self.repository.name(),
            "applied SSH detector ban to runtime repository"
        );

        Ok(())
    }

    pub fn remove_ban(&mut self, ip: IpAddr) -> Result<bool, RuntimeError> {
        let removed = match ip {
            IpAddr::V4(ip) => self.repository.remove_deny_v4(ip)?,
            IpAddr::V6(ip) => self.repository.remove_deny_v6(ip)?,
        };

        if removed {
            info!(
                component = "runtime",
                event = "ban_removed",
                ip = %ip,
                backend = self.repository.name(),
                "removed runtime ban entry"
            );
        } else {
            debug!(
                component = "runtime",
                event = "ban_remove_noop",
                ip = %ip,
                backend = self.repository.name(),
                "runtime ban entry was already absent"
            );
        }

        Ok(removed)
    }

    pub fn expire_bans(&mut self, observed_at_secs: u64) -> Result<BanExpirySummary, RuntimeError> {
        let summary = self.repository.expire_bans(observed_at_secs)?;

        if summary.total_removed() > 0 {
            info!(
                component = "runtime",
                event = "ban_expiry_cleanup",
                observed_at = %format_unix_timestamp_secs(observed_at_secs),
                removed_v4 = summary.removed_v4,
                removed_v6 = summary.removed_v6,
                backend = self.repository.name(),
                "expired runtime bans were removed"
            );
        }

        Ok(summary)
    }

    pub fn list_bans(&self) -> Result<Vec<BanRecord>, RuntimeError> {
        self.repository.list_bans()
    }

    #[must_use]
    pub fn snapshot(&self) -> RuntimeSnapshot {
        let repo = self.repository.snapshot().unwrap_or_default();

        RuntimeSnapshot {
            interface: self.interface.clone(),
            backend: self.repository.kind(),
            access_mode: repo.config.access_mode,
            icmp_mode: repo.config.icmp_mode,
            allow_v4_entries: repo.allow_v4_entries,
            allow_v6_entries: repo.allow_v6_entries,
            deny_v4_entries: repo.deny_v4_entries,
            deny_v6_entries: repo.deny_v6_entries,
            icmp_rule_entries: repo.icmp_rule_entries,
            stats: repo.stats,
            map_names: vec![
                MAP_NAME_CONFIG,
                MAP_NAME_ALLOW_V4,
                MAP_NAME_ALLOW_V6,
                MAP_NAME_DENY_V4,
                MAP_NAME_DENY_V6,
                MAP_NAME_ICMP_RULES,
                MAP_NAME_STATS,
            ],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeSnapshot {
    pub interface: Option<String>,
    pub backend: RuntimeBackendKind,
    pub access_mode: AccessMode,
    pub icmp_mode: IcmpMode,
    pub allow_v4_entries: usize,
    pub allow_v6_entries: usize,
    pub deny_v4_entries: usize,
    pub deny_v6_entries: usize,
    pub icmp_rule_entries: usize,
    pub stats: StatsCounters,
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
    pub stats: StatsCounters,
}

impl Default for RepositorySnapshot {
    fn default() -> Self {
        Self {
            config: RuntimeConfig::default(),
            allow_v4_entries: 0,
            allow_v6_entries: 0,
            deny_v4_entries: 0,
            deny_v6_entries: 0,
            icmp_rule_entries: 0,
            stats: StatsCounters::default(),
        }
    }
}

enum RuntimeRepository {
    InMemory(InMemoryMapRepository),
    #[cfg(target_os = "linux")]
    Linux(LinuxMapRepository),
}

impl RuntimeRepository {
    fn kind(&self) -> RuntimeBackendKind {
        match self {
            Self::InMemory(_) => RuntimeBackendKind::InMemory,
            #[cfg(target_os = "linux")]
            Self::Linux(_) => RuntimeBackendKind::BpfMaps,
        }
    }

    fn name(&self) -> &'static str {
        self.kind().as_str()
    }

    fn write_config(&mut self, config: RuntimeConfig) -> Result<(), RuntimeError> {
        match self {
            Self::InMemory(repository) => {
                repository.write_config(config);
                Ok(())
            }
            #[cfg(target_os = "linux")]
            Self::Linux(repository) => repository.write_config(config),
        }
    }

    fn replace_allowlist(&mut self, addresses: &[IpAddr]) -> Result<(), RuntimeError> {
        match self {
            Self::InMemory(repository) => {
                repository.replace_allowlist(addresses);
                Ok(())
            }
            #[cfg(target_os = "linux")]
            Self::Linux(repository) => repository.replace_allowlist(addresses),
        }
    }

    fn replace_denylist(&mut self, addresses: &[IpAddr]) -> Result<(), RuntimeError> {
        match self {
            Self::InMemory(repository) => {
                repository.replace_denylist(addresses);
                Ok(())
            }
            #[cfg(target_os = "linux")]
            Self::Linux(repository) => repository.replace_denylist(addresses),
        }
    }

    fn replace_icmp_rules(&mut self, rules: &[IcmpRule]) -> Result<(), RuntimeError> {
        match self {
            Self::InMemory(repository) => {
                repository.replace_icmp_rules(rules);
                Ok(())
            }
            #[cfg(target_os = "linux")]
            Self::Linux(repository) => repository.replace_icmp_rules(rules),
        }
    }

    fn upsert_deny_v4(&mut self, ip: Ipv4Addr, entry: BanEntryV4) -> Result<(), RuntimeError> {
        match self {
            Self::InMemory(repository) => {
                repository.upsert_deny_v4(ip, entry);
                Ok(())
            }
            #[cfg(target_os = "linux")]
            Self::Linux(repository) => repository.upsert_deny_v4(ip, entry),
        }
    }

    fn upsert_deny_v6(&mut self, ip: Ipv6Addr, entry: BanEntryV4) -> Result<(), RuntimeError> {
        match self {
            Self::InMemory(repository) => {
                repository.upsert_deny_v6(ip, entry);
                Ok(())
            }
            #[cfg(target_os = "linux")]
            Self::Linux(repository) => repository.upsert_deny_v6(ip, entry),
        }
    }

    fn snapshot(&self) -> Result<RepositorySnapshot, RuntimeError> {
        match self {
            Self::InMemory(repository) => Ok(repository.snapshot()),
            #[cfg(target_os = "linux")]
            Self::Linux(repository) => repository.snapshot(),
        }
    }

    fn remove_deny_v4(&mut self, ip: Ipv4Addr) -> Result<bool, RuntimeError> {
        match self {
            Self::InMemory(repository) => Ok(repository.remove_deny_v4(ip)),
            #[cfg(target_os = "linux")]
            Self::Linux(repository) => repository.remove_deny_v4(ip),
        }
    }

    fn remove_deny_v6(&mut self, ip: Ipv6Addr) -> Result<bool, RuntimeError> {
        match self {
            Self::InMemory(repository) => Ok(repository.remove_deny_v6(ip)),
            #[cfg(target_os = "linux")]
            Self::Linux(repository) => repository.remove_deny_v6(ip),
        }
    }

    fn expire_bans(&mut self, observed_at_secs: u64) -> Result<BanExpirySummary, RuntimeError> {
        match self {
            Self::InMemory(repository) => Ok(repository.expire_bans(observed_at_secs)),
            #[cfg(target_os = "linux")]
            Self::Linux(repository) => repository.expire_bans(observed_at_secs),
        }
    }

    fn list_bans(&self) -> Result<Vec<BanRecord>, RuntimeError> {
        match self {
            Self::InMemory(repository) => Ok(repository.list_bans()),
            #[cfg(target_os = "linux")]
            Self::Linux(repository) => repository.list_bans(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryMapRepository {
    config: RuntimeConfig,
    allow_v4: BTreeSet<Ipv4Addr>,
    allow_v6: BTreeSet<Ipv6Addr>,
    deny_v4: HashMap<Ipv4Addr, BanEntryV4>,
    deny_v6: HashMap<Ipv6Addr, BanEntryV4>,
    icmp_rules: HashSet<IcmpRule>,
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

    pub fn remove_deny_v4(&mut self, ip: Ipv4Addr) -> bool {
        self.deny_v4.remove(&ip).is_some()
    }

    pub fn remove_deny_v6(&mut self, ip: Ipv6Addr) -> bool {
        self.deny_v6.remove(&ip).is_some()
    }

    pub fn replace_icmp_rules(&mut self, rules: &[IcmpRule]) {
        self.icmp_rules.clear();
        self.icmp_rules.extend(rules.iter().copied());
    }

    #[must_use]
    pub fn expire_bans(&mut self, observed_at_secs: u64) -> BanExpirySummary {
        BanExpirySummary {
            removed_v4: expire_ban_map(&mut self.deny_v4, observed_at_secs),
            removed_v6: expire_ban_map(&mut self.deny_v6, observed_at_secs),
        }
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
            stats: StatsCounters::default(),
        }
    }

    #[must_use]
    pub fn list_bans(&self) -> Vec<BanRecord> {
        let mut records = self
            .deny_v4
            .iter()
            .map(|(ip, entry)| BanRecord {
                ip: IpAddr::V4(*ip),
                entry: *entry,
            })
            .chain(self.deny_v6.iter().map(|(ip, entry)| BanRecord {
                ip: IpAddr::V6(*ip),
                entry: *entry,
            }))
            .collect::<Vec<_>>();
        sort_ban_records(&mut records);
        records
    }
}

#[cfg(target_os = "linux")]
struct LinuxMapRepository {
    map_pin_path: PathBuf,
}

#[cfg(target_os = "linux")]
impl LinuxMapRepository {
    fn open(map_pin_path: &Path) -> Result<Self, RuntimeError> {
        Self::open_config_map(map_pin_path)?;
        Self::open_allow_v4_map(map_pin_path)?;
        Self::open_allow_v6_map(map_pin_path)?;
        Self::open_deny_v4_map(map_pin_path)?;
        Self::open_deny_v6_map(map_pin_path)?;
        Self::open_icmp_rules_map(map_pin_path)?;
        Self::open_stats_map(map_pin_path)?;

        Ok(Self {
            map_pin_path: map_pin_path.to_path_buf(),
        })
    }

    fn write_config(&mut self, config: RuntimeConfig) -> Result<(), RuntimeError> {
        let mut map = Self::open_config_map(&self.map_pin_path)?;
        map.set(CONFIG_MAP_KEY, config, 0)
            .map_err(|source| RuntimeError::MapOperation {
                map: MAP_NAME_CONFIG,
                operation: "set_config",
                source,
            })
    }

    fn replace_allowlist(&mut self, addresses: &[IpAddr]) -> Result<(), RuntimeError> {
        let mut allow_v4 = Self::open_allow_v4_map(&self.map_pin_path)?;
        let mut allow_v6 = Self::open_allow_v6_map(&self.map_pin_path)?;

        clear_hash_map(&mut allow_v4, MAP_NAME_ALLOW_V4, "clear_allow_v4")?;
        clear_hash_map(&mut allow_v6, MAP_NAME_ALLOW_V6, "clear_allow_v6")?;

        for address in addresses {
            match address {
                IpAddr::V4(ip) => allow_v4
                    .insert(Ipv4AddrKey::new(ip.octets()), 1, 0)
                    .map_err(|source| RuntimeError::MapOperation {
                        map: MAP_NAME_ALLOW_V4,
                        operation: "insert_allow_v4",
                        source,
                    })?,
                IpAddr::V6(ip) => allow_v6
                    .insert(Ipv6AddrKey::new(ip.octets()), 1, 0)
                    .map_err(|source| RuntimeError::MapOperation {
                        map: MAP_NAME_ALLOW_V6,
                        operation: "insert_allow_v6",
                        source,
                    })?,
            }
        }

        Ok(())
    }

    fn replace_denylist(&mut self, addresses: &[IpAddr]) -> Result<(), RuntimeError> {
        let mut deny_v4 = Self::open_deny_v4_map(&self.map_pin_path)?;
        let mut deny_v6 = Self::open_deny_v6_map(&self.map_pin_path)?;

        clear_hash_map(&mut deny_v4, MAP_NAME_DENY_V4, "clear_deny_v4")?;
        clear_hash_map(&mut deny_v6, MAP_NAME_DENY_V6, "clear_deny_v6")?;

        for address in addresses {
            match address {
                IpAddr::V4(ip) => deny_v4
                    .insert(
                        Ipv4AddrKey::new(ip.octets()),
                        BanEntryV4::manual_indefinite(0),
                        0,
                    )
                    .map_err(|source| RuntimeError::MapOperation {
                        map: MAP_NAME_DENY_V4,
                        operation: "insert_deny_v4",
                        source,
                    })?,
                IpAddr::V6(ip) => deny_v6
                    .insert(
                        Ipv6AddrKey::new(ip.octets()),
                        BanEntryV4::manual_indefinite(0),
                        0,
                    )
                    .map_err(|source| RuntimeError::MapOperation {
                        map: MAP_NAME_DENY_V6,
                        operation: "insert_deny_v6",
                        source,
                    })?,
            }
        }

        Ok(())
    }

    fn replace_icmp_rules(&mut self, rules: &[IcmpRule]) -> Result<(), RuntimeError> {
        if rules.len() > ICMP_RULE_MAP_CAPACITY as usize {
            return Err(RuntimeError::IcmpRuleCapacity {
                actual: rules.len(),
                limit: ICMP_RULE_MAP_CAPACITY as usize,
            });
        }

        let mut map = Self::open_icmp_rules_map(&self.map_pin_path)?;
        clear_hash_map(&mut map, MAP_NAME_ICMP_RULES, "clear_icmp_rules")?;

        for rule in rules {
            map.insert(*rule, 1, 0)
                .map_err(|source| RuntimeError::MapOperation {
                    map: MAP_NAME_ICMP_RULES,
                    operation: "insert_icmp_rule",
                    source,
                })?;
        }

        Ok(())
    }

    fn upsert_deny_v4(&mut self, ip: Ipv4Addr, entry: BanEntryV4) -> Result<(), RuntimeError> {
        let mut map = Self::open_deny_v4_map(&self.map_pin_path)?;
        map.insert(Ipv4AddrKey::new(ip.octets()), entry, 0)
            .map_err(|source| RuntimeError::MapOperation {
                map: MAP_NAME_DENY_V4,
                operation: "upsert_deny_v4",
                source,
            })
    }

    fn upsert_deny_v6(&mut self, ip: Ipv6Addr, entry: BanEntryV4) -> Result<(), RuntimeError> {
        let mut map = Self::open_deny_v6_map(&self.map_pin_path)?;
        map.insert(Ipv6AddrKey::new(ip.octets()), entry, 0)
            .map_err(|source| RuntimeError::MapOperation {
                map: MAP_NAME_DENY_V6,
                operation: "upsert_deny_v6",
                source,
            })
    }

    fn remove_deny_v4(&mut self, ip: Ipv4Addr) -> Result<bool, RuntimeError> {
        remove_pinned_ban(
            Self::open_deny_v4_map(&self.map_pin_path)?,
            MAP_NAME_DENY_V4,
            Ipv4AddrKey::new(ip.octets()),
        )
    }

    fn remove_deny_v6(&mut self, ip: Ipv6Addr) -> Result<bool, RuntimeError> {
        remove_pinned_ban(
            Self::open_deny_v6_map(&self.map_pin_path)?,
            MAP_NAME_DENY_V6,
            Ipv6AddrKey::new(ip.octets()),
        )
    }

    fn snapshot(&self) -> Result<RepositorySnapshot, RuntimeError> {
        let config = Self::open_config_map(&self.map_pin_path)?
            .get(&CONFIG_MAP_KEY, 0)
            .map_err(|source| RuntimeError::MapOperation {
                map: MAP_NAME_CONFIG,
                operation: "get_config",
                source,
            })?;
        let allow_v4_entries = count_keys(
            Self::open_allow_v4_map(&self.map_pin_path)?,
            MAP_NAME_ALLOW_V4,
        )?;
        let allow_v6_entries = count_keys(
            Self::open_allow_v6_map(&self.map_pin_path)?,
            MAP_NAME_ALLOW_V6,
        )?;
        let deny_v4_entries = count_keys(
            Self::open_deny_v4_map(&self.map_pin_path)?,
            MAP_NAME_DENY_V4,
        )?;
        let deny_v6_entries = count_keys(
            Self::open_deny_v6_map(&self.map_pin_path)?,
            MAP_NAME_DENY_V6,
        )?;
        let icmp_rule_entries = count_keys(
            Self::open_icmp_rules_map(&self.map_pin_path)?,
            MAP_NAME_ICMP_RULES,
        )?;
        let stats = Self::open_stats_map(&self.map_pin_path)?
            .get(&STATS_MAP_KEY, 0)
            .map_err(|source| RuntimeError::MapOperation {
                map: MAP_NAME_STATS,
                operation: "get_stats",
                source,
            })?;

        Ok(RepositorySnapshot {
            config,
            allow_v4_entries,
            allow_v6_entries,
            deny_v4_entries,
            deny_v6_entries,
            icmp_rule_entries,
            stats,
        })
    }

    fn expire_bans(&mut self, observed_at_secs: u64) -> Result<BanExpirySummary, RuntimeError> {
        Ok(BanExpirySummary {
            removed_v4: expire_pinned_ban_map(
                Self::open_deny_v4_map(&self.map_pin_path)?,
                MAP_NAME_DENY_V4,
                observed_at_secs,
            )?,
            removed_v6: expire_pinned_ban_map(
                Self::open_deny_v6_map(&self.map_pin_path)?,
                MAP_NAME_DENY_V6,
                observed_at_secs,
            )?,
        })
    }

    fn list_bans(&self) -> Result<Vec<BanRecord>, RuntimeError> {
        let mut records = collect_pinned_bans(
            Self::open_deny_v4_map(&self.map_pin_path)?,
            MAP_NAME_DENY_V4,
            |key| IpAddr::V4(Ipv4Addr::from(key.octets)),
        )?;
        records.extend(collect_pinned_bans(
            Self::open_deny_v6_map(&self.map_pin_path)?,
            MAP_NAME_DENY_V6,
            |key| IpAddr::V6(Ipv6Addr::from(key.octets)),
        )?);
        sort_ban_records(&mut records);
        Ok(records)
    }

    fn open_map(path: &Path, name: &'static str) -> Result<MapData, RuntimeError> {
        let map_path = path.join(name);
        MapData::from_pin(&map_path).map_err(|source| RuntimeError::MapOpen {
            map: name,
            path: map_path,
            source,
        })
    }

    fn open_config_map(path: &Path) -> Result<Array<MapData, RuntimeConfig>, RuntimeError> {
        Array::try_from(Map::Array(Self::open_map(path, MAP_NAME_CONFIG)?)).map_err(|source| {
            RuntimeError::MapOpen {
                map: MAP_NAME_CONFIG,
                path: path.join(MAP_NAME_CONFIG),
                source,
            }
        })
    }

    fn open_allow_v4_map(
        path: &Path,
    ) -> Result<BpfHashMap<MapData, Ipv4AddrKey, u8>, RuntimeError> {
        BpfHashMap::try_from(Map::HashMap(Self::open_map(path, MAP_NAME_ALLOW_V4)?)).map_err(
            |source| RuntimeError::MapOpen {
                map: MAP_NAME_ALLOW_V4,
                path: path.join(MAP_NAME_ALLOW_V4),
                source,
            },
        )
    }

    fn open_allow_v6_map(
        path: &Path,
    ) -> Result<BpfHashMap<MapData, Ipv6AddrKey, u8>, RuntimeError> {
        BpfHashMap::try_from(Map::HashMap(Self::open_map(path, MAP_NAME_ALLOW_V6)?)).map_err(
            |source| RuntimeError::MapOpen {
                map: MAP_NAME_ALLOW_V6,
                path: path.join(MAP_NAME_ALLOW_V6),
                source,
            },
        )
    }

    fn open_deny_v4_map(
        path: &Path,
    ) -> Result<BpfHashMap<MapData, Ipv4AddrKey, BanEntryV4>, RuntimeError> {
        BpfHashMap::try_from(Map::HashMap(Self::open_map(path, MAP_NAME_DENY_V4)?)).map_err(
            |source| RuntimeError::MapOpen {
                map: MAP_NAME_DENY_V4,
                path: path.join(MAP_NAME_DENY_V4),
                source,
            },
        )
    }

    fn open_deny_v6_map(
        path: &Path,
    ) -> Result<BpfHashMap<MapData, Ipv6AddrKey, BanEntryV4>, RuntimeError> {
        BpfHashMap::try_from(Map::HashMap(Self::open_map(path, MAP_NAME_DENY_V6)?)).map_err(
            |source| RuntimeError::MapOpen {
                map: MAP_NAME_DENY_V6,
                path: path.join(MAP_NAME_DENY_V6),
                source,
            },
        )
    }

    fn open_icmp_rules_map(path: &Path) -> Result<BpfHashMap<MapData, IcmpRule, u8>, RuntimeError> {
        BpfHashMap::try_from(Map::HashMap(Self::open_map(path, MAP_NAME_ICMP_RULES)?)).map_err(
            |source| RuntimeError::MapOpen {
                map: MAP_NAME_ICMP_RULES,
                path: path.join(MAP_NAME_ICMP_RULES),
                source,
            },
        )
    }

    fn open_stats_map(path: &Path) -> Result<Array<MapData, StatsCounters>, RuntimeError> {
        Array::try_from(Map::Array(Self::open_map(path, MAP_NAME_STATS)?)).map_err(|source| {
            RuntimeError::MapOpen {
                map: MAP_NAME_STATS,
                path: path.join(MAP_NAME_STATS),
                source,
            }
        })
    }
}

#[cfg(target_os = "linux")]
fn clear_hash_map<K, V>(
    map: &mut BpfHashMap<MapData, K, V>,
    name: &'static str,
    operation: &'static str,
) -> Result<(), RuntimeError>
where
    K: Pod,
    V: Pod,
{
    let keys = map
        .keys()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| RuntimeError::MapOperation {
            map: name,
            operation,
            source,
        })?;

    for key in keys {
        map.remove(&key)
            .map_err(|source| RuntimeError::MapOperation {
                map: name,
                operation,
                source,
            })?;
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn count_keys<K, V>(
    map: BpfHashMap<MapData, K, V>,
    name: &'static str,
) -> Result<usize, RuntimeError>
where
    K: Pod,
    V: Pod,
{
    map.keys()
        .collect::<Result<Vec<_>, _>>()
        .map(|keys| keys.len())
        .map_err(|source| RuntimeError::MapOperation {
            map: name,
            operation: "count_keys",
            source,
        })
}

fn expire_ban_map<K>(map: &mut HashMap<K, BanEntryV4>, observed_at_secs: u64) -> usize
where
    K: Copy + Eq + Hash,
{
    let expired_keys = map
        .iter()
        .filter_map(|(key, entry)| is_expired_ban(entry, observed_at_secs).then_some(*key))
        .collect::<Vec<_>>();

    let removed = expired_keys.len();

    for key in expired_keys {
        map.remove(&key);
    }

    removed
}

fn sort_ban_records(records: &mut [BanRecord]) {
    records.sort_by(|left, right| left.ip.to_string().cmp(&right.ip.to_string()));
}

fn is_expired_ban(entry: &BanEntryV4, observed_at_secs: u64) -> bool {
    let observed_at_ns = observed_at_secs.saturating_mul(1_000_000_000);
    entry.expires_at_ns != 0 && entry.expires_at_ns <= observed_at_ns
}

fn manual_ban_entry(created_at_secs: u64, duration_secs: Option<u64>) -> BanEntryV4 {
    let created_at_ns = created_at_secs.saturating_mul(1_000_000_000);
    let expires_at_ns = duration_secs
        .map(|duration| created_at_secs.saturating_add(duration).saturating_mul(1_000_000_000))
        .unwrap_or(0);

    BanEntryV4 {
        created_at_ns,
        expires_at_ns,
        ..BanEntryV4::manual_indefinite(created_at_ns)
    }
}

fn ban_entry_expires_at_secs(entry: BanEntryV4) -> Option<u64> {
    (entry.expires_at_ns != 0).then_some(entry.expires_at_ns / 1_000_000_000)
}

fn format_optional_unix_timestamp_secs(timestamp_secs: Option<u64>) -> String {
    timestamp_secs
        .map(format_unix_timestamp_secs)
        .unwrap_or_else(|| "never".to_string())
}

#[cfg(target_os = "linux")]
fn expire_pinned_ban_map<K>(
    mut map: BpfHashMap<MapData, K, BanEntryV4>,
    name: &'static str,
    observed_at_secs: u64,
) -> Result<usize, RuntimeError>
where
    K: Copy + Pod,
{
    let keys = map
        .keys()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| RuntimeError::MapOperation {
            map: name,
            operation: "collect_expiry_keys",
            source,
        })?;

    let mut removed = 0;

    for key in keys {
        let entry = map
            .get(&key, 0)
            .map_err(|source| RuntimeError::MapOperation {
                map: name,
                operation: "get_expiry_entry",
                source,
            })?;

        if is_expired_ban(&entry, observed_at_secs) {
            map.remove(&key)
                .map_err(|source| RuntimeError::MapOperation {
                    map: name,
                    operation: "remove_expired_ban",
                    source,
                })?;
            removed += 1;
        }
    }

    Ok(removed)
}

#[cfg(target_os = "linux")]
fn remove_pinned_ban<K>(
    mut map: BpfHashMap<MapData, K, BanEntryV4>,
    name: &'static str,
    key: K,
) -> Result<bool, RuntimeError>
where
    K: Copy + Pod + PartialEq,
{
    let keys = map
        .keys()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| RuntimeError::MapOperation {
            map: name,
            operation: "collect_remove_keys",
            source,
        })?;

    if !keys.contains(&key) {
        return Ok(false);
    }

    map.remove(&key)
        .map_err(|source| RuntimeError::MapOperation {
            map: name,
            operation: "remove_deny_entry",
            source,
        })?;

    Ok(true)
}

#[cfg(target_os = "linux")]
fn collect_pinned_bans<K, F>(
    map: BpfHashMap<MapData, K, BanEntryV4>,
    name: &'static str,
    to_ip: F,
) -> Result<Vec<BanRecord>, RuntimeError>
where
    K: Copy + Pod,
    F: Fn(K) -> IpAddr,
{
    let keys = map
        .keys()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| RuntimeError::MapOperation {
            map: name,
            operation: "collect_list_keys",
            source,
        })?;

    let mut records = Vec::with_capacity(keys.len());
    for key in keys {
        let entry = map
            .get(&key, 0)
            .map_err(|source| RuntimeError::MapOperation {
                map: name,
                operation: "get_list_entry",
                source,
            })?;
        records.push(BanRecord {
            ip: to_ip(key),
            entry,
        });
    }

    Ok(records)
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

    #[must_use]
    pub fn failure_details(&self) -> Vec<String> {
        self.checks
            .iter()
            .filter(|check| check.status == CheckStatus::Fail)
            .map(|check| format!("{}: {}", check.name, check.detail))
            .collect()
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
    checks.push(privilege_check());
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
fn privilege_check() -> EnvironmentCheck {
    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        EnvironmentCheck {
            name: "privileges",
            status: CheckStatus::Pass,
            detail: "running with root privileges".to_string(),
        }
    } else {
        EnvironmentCheck {
            name: "privileges",
            status: CheckStatus::Fail,
            detail: format!(
                "effective uid {euid} does not have the required privileges; rerun as root to attach XDP and manage pinned maps"
            ),
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
    #[cfg(target_os = "linux")]
    #[error("failed to open pinned map '{map}' at '{path}': {source}")]
    MapOpen {
        map: &'static str,
        path: PathBuf,
        source: MapError,
    },
    #[cfg(target_os = "linux")]
    #[error("map operation '{operation}' failed for '{map}': {source}")]
    MapOperation {
        map: &'static str,
        operation: &'static str,
        source: MapError,
    },
    #[error("ICMP rule count {actual} exceeds map capacity {limit}")]
    IcmpRuleCapacity { actual: usize, limit: usize },
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use walle_common::{AccessMode, BanEntryV4, BanReasonCode, BanSource, IcmpMode};
    use walle_policy::{IcmpAllowRule, WalleConfig};

    use super::{InMemoryMapRepository, RuntimeController, manual_ban_entry};

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
        config.policy.access.mode = AccessMode::WhitelistOnly;
        config.policy.access.allowlist = vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))];
        config.policy.access.denylist = vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2))];
        config.interfaces = vec![walle_policy::InterfacePolicy {
            name: "eth0".to_string(),
            xdp_mode: walle_policy::XdpMode::Driver,
            filters: walle_policy::InterfaceFilters {
                icmp: walle_policy::IcmpPolicy {
                    mode: IcmpMode::AllowRulesActive,
                    allow_rules: vec![IcmpAllowRule {
                        match_type: walle_common::IcmpMatchType::RawBytesExact,
                        payload_hex: "6162".to_string(),
                        enabled: true,
                    }],
                },
            },
        }];

        controller
            .sync_policy_for_interface(&config, &config.interfaces[0])
            .unwrap();
        let snapshot = controller.snapshot();

        assert_eq!(snapshot.access_mode, AccessMode::WhitelistOnly);
        assert_eq!(snapshot.allow_v4_entries, 1);
        assert_eq!(snapshot.deny_v4_entries, 1);
        assert_eq!(snapshot.icmp_rule_entries, 1);
    }

    #[test]
    fn in_memory_repository_expires_temporary_bans_only() {
        let mut repo = InMemoryMapRepository::default();
        repo.upsert_deny_v4(
            Ipv4Addr::new(192, 0, 2, 10),
            BanEntryV4 {
                created_at_ns: 1,
                expires_at_ns: 2_000_000_000,
                ..BanEntryV4::default()
            },
        );
        repo.upsert_deny_v4(
            Ipv4Addr::new(192, 0, 2, 11),
            BanEntryV4::manual_indefinite(1),
        );

        let summary = repo.expire_bans(2);
        let snapshot = repo.snapshot();

        assert_eq!(summary.removed_v4, 1);
        assert_eq!(summary.removed_v6, 0);
        assert_eq!(snapshot.deny_v4_entries, 1);
    }

    #[test]
    fn runtime_controller_cleanup_reduces_snapshot_counts() {
        let mut controller = RuntimeController::new(Some("eth0".to_string()));
        controller
            .apply_ssh_ban(crate::detector::SshBanDecision {
                ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42)),
                matched_failures: 5,
                observed_at_secs: 10,
                expires_at_secs: 20,
            })
            .unwrap();

        assert_eq!(controller.snapshot().deny_v4_entries, 1);

        let summary = controller.expire_bans(20).unwrap();

        assert_eq!(summary.removed_v4, 1);
        assert_eq!(controller.snapshot().deny_v4_entries, 0);
    }

    #[test]
    fn runtime_controller_manual_ban_lists_and_unbans_entries() {
        let mut controller = RuntimeController::new(Some("eth0".to_string()));
        controller
            .add_manual_ban(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 10, Some(30))
            .unwrap();

        let listed = controller.list_bans().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)));
        assert_eq!(listed[0].entry.source, BanSource::Manual);
        assert_eq!(listed[0].entry.reason, BanReasonCode::Manual);
        assert_eq!(listed[0].entry.created_at_ns, 10_000_000_000);
        assert_eq!(listed[0].entry.expires_at_ns, 40_000_000_000);

        assert!(controller
            .remove_ban(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)))
            .unwrap());
        assert!(controller.list_bans().unwrap().is_empty());
    }

    #[test]
    fn manual_ban_helper_supports_indefinite_and_temporary_entries() {
        let temporary = manual_ban_entry(5, Some(20));
        assert_eq!(temporary.created_at_ns, 5_000_000_000);
        assert_eq!(temporary.expires_at_ns, 25_000_000_000);

        let indefinite = manual_ban_entry(5, None);
        assert_eq!(indefinite.created_at_ns, 5_000_000_000);
        assert_eq!(indefinite.expires_at_ns, 0);
    }
}
