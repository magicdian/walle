# Database Guidelines

> Database patterns and conventions for this project.

---

## Overview

`walle` does not have a relational database in MVP.

The project has two distinct state categories:

* runtime enforcement state in BPF maps
* operator configuration in control-plane config files or validated command input

Do not introduce a SQL database by default. A persistent database should only be added if the product later requires durable history, complex querying, or multi-entity management that cannot be handled by configuration files and runtime maps.

---

## Query Patterns

Use explicit state-access layers instead of ad-hoc reads and writes:

* all BPF map access should go through a dedicated runtime or map repository layer
* control-plane code should work with typed policy objects, not raw byte buffers
* compile high-level rules into runtime-ready structures before writing them into maps
* batch updates where mode changes need multiple map writes to stay logically consistent

Prefer idempotent upserts for operator commands such as allow, ban, unban, and mode change.

---

## Migrations

MVP does not use schema migrations.

If durable local persistence is introduced later:

* use explicit versioned schema migrations
* keep runtime BPF map evolution separate from storage schema evolution
* add compatibility notes for loader and daemon startup

For BPF maps, treat layout changes as versioned contract changes. Do not silently change entry layouts once data-plane code depends on them.

---

## Naming Conventions

For BPF map-like runtime state:

* map names should reflect behavior, for example `allow_v4`, `deny_v4`, `config`, `icmp_rules`, `stats`
* map key and value structs should include version-safe field names
* timestamps should use explicit units in names, for example `expires_at_ns`
* enums crossing user space and eBPF boundaries should use stable discriminants

If a database is added later:

* table names use `snake_case`
* index names use `idx_<table>_<field>`
* migrations are append-only and reviewed like API changes

---

## Common Mistakes

* Treating BPF maps as if they were an untyped key-value scratchpad.
* Encoding business logic directly into map bytes instead of using shared structs.
* Adding persistence too early when config files and runtime state are enough.
* Mixing control-plane desired state with live packet-path counters in the same storage abstraction.

## Scenario: Runtime Map Repository Contract

### 1. Scope / Trigger

* Trigger: Any change that adds or updates control-plane state written into BPF maps or their in-memory phase equivalent.

### 2. Signatures

* `RuntimeController::sync_policy(&WalleConfig) -> Result<(), RuntimeError>`
* `RuntimeController::apply_ssh_ban(SshBanDecision)`
* `InMemoryMapRepository::write_config(RuntimeConfig)`
* `InMemoryMapRepository::replace_allowlist(&[IpAddr])`
* `InMemoryMapRepository::replace_denylist(&[IpAddr])`
* `InMemoryMapRepository::replace_icmp_rules(&[IcmpRule])`

### 3. Contracts

* `config` map stores one singleton config entry.
* allow and deny state are split by IP family.
* manual denylist replacement writes indefinite ban entries.
* detector-originated SSH bans must preserve:
  * `source = SshDetector`
  * `reason = SshAuthFailures`
  * `created_at_ns`
  * `expires_at_ns`

### 4. Validation & Error Matrix

* Valid `WalleConfig` -> runtime sync succeeds.
* Invalid policy compilation -> `RuntimeError::Policy`.
* IPv4 and IPv6 addresses must be stored in separate repositories/maps.
* Whitelist precedence must remain a shared-type rule, not reimplemented ad hoc in the repository layer.

### 5. Good/Base/Bad Cases

* Good:
  * one IPv4 allow entry and one IPv6 allow entry produce separate counts
  * SSH detector ban writes the expected metadata into deny state
* Base:
  * empty allowlist and denylist are valid
  * empty ICMP compiled rule set is valid when ICMP rules are disabled
* Bad:
  * mixing operator-facing config blobs directly into repository storage
  * silently changing deny entry semantics without updating shared structs

### 6. Tests Required

* repository tests must assert IPv4 and IPv6 separation
* runtime sync tests must assert access mode, deny counts, and ICMP compiled rule counts
* SSH detector integration tests must assert ban writeback updates deny state

### 7. Wrong vs Correct

#### Wrong

* Store raw `String` mode names and untyped payload blobs directly in the repository layer.

#### Correct

* Compile operator-facing policy into typed runtime structs before repository writes.

Current scaffold examples:

* [`walle-common runtime structs`](E:/coding/github_projects/walle/crates/walle-common/src/lib.rs): map-safe structs and enums
* [`walle-policy config schema`](E:/coding/github_projects/walle/crates/walle-policy/src/lib.rs): operator-facing config separated from runtime structs
* [`walle-daemon runtime controller`](E:/coding/github_projects/walle/crates/walle-daemon/src/runtime.rs): runtime config sync boundary

## Scenario: Default Config File And Interface Policy Contract

### 1. Scope / Trigger

* Trigger: Any change to on-host config file loading, operator-facing policy schema, multi-interface attachment behavior, or the boundary between global detectors and interface-scoped packet filters.

### 2. Signatures

* `walle run`
* `WalleConfig::load_default() -> Result<WalleConfig, PolicyError>`
* `WalleConfig::load_from_path(&Path) -> Result<WalleConfig, PolicyError>`
* `WalleConfig::validate() -> Result<(), PolicyError>`
* `WalleConfig::interfaces() -> &[InterfacePolicy]`
* `WalleDaemon::new(WalleConfig, DaemonOptions) -> Result<WalleDaemon, DaemonError>`
* `WalleDaemon::startup() -> Result<(), DaemonError>`

### 3. Contracts

* `walle run` must default to loading `/etc/walle/config.toml` when no override path is provided.
* `/etc/walle/config.toml` stores desired operator policy only; runtime locks, pid files, sockets, and pinned BPF maps must not be treated as editable config state.
* The operator-facing config schema must separate:
  * global detector policy
  * global access policy
  * global logging policy
  * interface-scoped packet filters and attachment targets
* SSH protection is a global detector contract in v1:
  * one detector policy is configured for the host
  * detector-produced bans remain global runtime deny state
  * v1 does not introduce interface-scoped SSH deny maps
* ICMP policy is interface-scoped in v1:
  * each protected interface declares its own ICMP filter mode
  * interfaces may differ, for example one interface uses `AllowRulesActive` while another uses `Disabled`
* Protected interfaces must be declared explicitly in config; startup must not guess the default egress or infer attachment targets from host routing state.
* Exact-match ICMP payload rules must use an operator-facing hex string field such as `payload_hex = "09070108"` in config and compile that value into canonical `IcmpRule` bytes.
* User-space log verbosity must be configured in `/etc/walle/config.toml` through a typed global log-level field rather than relying on deployment-only environment variables.
* Empty interface names, duplicate interface declarations, invalid hex payload strings, and enabled ICMP rules with empty payloads are validation failures.

### 4. Validation & Error Matrix

* Missing default config file at `/etc/walle/config.toml` -> typed config load failure with the path preserved.
* TOML parse failure -> typed config parse failure with source context.
* Duplicate interface declaration -> typed validation failure.
* Empty interface name -> typed validation failure.
* Invalid `payload_hex` -> typed validation failure.
* `icmp.mode = "allow_rules_active"` with an enabled rule whose payload exceeds `ICMP_RULE_PAYLOAD_CAPACITY` -> typed validation failure.
* Valid config with multiple interfaces and different ICMP modes -> config validation succeeds and daemon startup plans one attachment per declared interface.
* Valid config with global SSH enabled and ICMP disabled on one interface -> daemon startup succeeds and the interface still participates in access-policy enforcement without ICMP allow rules.

### 5. Good/Base/Bad Cases

* Good:
  * `/etc/walle/config.toml` defines `eth0` with ICMP allow rules and `eth1` with ICMP disabled, and startup preserves that difference.
  * `/etc/walle/config.toml` defines `policy.logging.level = "info"` so local runs and systemd services share the same verbosity contract.
  * SSH detector policy is configured once and applies to host-level ban decisions without duplicating detector blocks per interface.
  * operators write `payload_hex` values that compile into exact-match `IcmpRule` entries without exposing raw byte arrays in TOML.
* Base:
  * a single declared interface with ICMP disabled remains valid.
  * multiple declared interfaces may share the same ICMP policy without requiring a separate abstraction first.
* Bad:
  * deriving protected interfaces implicitly from the system default route.
  * mixing detector configuration into per-interface filter blocks and forcing duplicate SSH policy declarations.
  * storing runtime-only state such as pinned map paths inside the editable policy file as if it were operator policy.

### 6. Tests Required

* config parsing tests must cover loading `/etc/walle/config.toml` semantics via the default-load helper.
* config validation tests must cover:
  * duplicate interfaces
  * empty interface names
  * invalid `payload_hex`
  * payloads above `ICMP_RULE_PAYLOAD_CAPACITY`
* policy compilation tests must assert `payload_hex` converts into the same canonical `IcmpRule` bytes as CLI-provided hex payloads.
* daemon startup tests must assert multi-interface config produces one planned attachment per declared interface.
* daemon/runtime tests must assert SSH detector policy remains global while interface ICMP modes can differ.

### 7. Wrong vs Correct

#### Wrong

* Keep a single top-level `icmp` block and a single optional `interface` field, then try to retrofit multi-interface behavior with ad-hoc CLI overrides.

#### Correct

* Model operator policy explicitly: global SSH detector and access policy, plus a list of declared interfaces that each own their interface-local packet filters.

## Scenario: Multi-Interface Status And Runtime Stats Contract

### 1. Scope / Trigger

* Trigger: Any change to `walle status`, runtime snapshot structs, per-interface stats exposure, or aggregation across multiple declared interfaces.

### 2. Signatures

* `walle status`
* `WalleDaemon::snapshot() -> StatusSnapshot`
* `RuntimeController::snapshot() -> RuntimeSnapshot`
* `LinuxMapRepository::snapshot() -> Result<RepositorySnapshot, RuntimeError>`

### 3. Contracts

* Status output must treat declared interfaces as first-class runtime units; it must not collapse multi-interface state into one synthetic primary-interface record.
* Status must expose one per-interface snapshot containing at least:
  * interface name
  * runtime backend kind
  * access mode
  * interface-local ICMP mode
  * allow / deny entry counts
  * ICMP rule count
  * packet-path stats counters
* Status must also expose one aggregate summary across all selected interfaces.
* Per-interface packet-path counters come from the interface-scoped `stats` map pinned under that interface's map directory.
* When live pinned maps are not available, status may fall back to configured policy counts for static policy entries, but packet counters must remain explicit zeroes instead of fabricated values.
* Global access policy remains host-level config, but because maps are per-interface, allow / deny entry counts in status are reported per runtime instance after sync.
* SSH detector bans remain global policy decisions, but status must show the resulting deny entry count in each interface runtime because each runtime carries its own deny map copy in v1.

### 4. Validation & Error Matrix

* Valid config with two interfaces and no pinned maps -> status returns two per-interface snapshots with configured policy counts and zeroed live counters.
* Valid config with two interfaces and pinned runtime maps -> status returns two per-interface snapshots populated from the pinned repositories.
* Missing pinned map directory for one interface -> status keeps that interface snapshot in configured fallback mode instead of failing the entire command.
* Existing pinned map path with unreadable or incompatible maps -> typed runtime error from the repository boundary.

### 5. Good/Base/Bad Cases

* Good:
  * `eth0` and `eth1` appear separately in status and can show different ICMP modes and rule counts.
  * aggregate packet counters equal the sum of the reported per-interface counters.
  * zero live counters are shown explicitly when the daemon has not yet attached or synced maps.
* Base:
  * a single-interface config still produces one per-interface snapshot plus one aggregate summary.
* Bad:
  * reporting only the first configured interface and hiding the rest.
  * fabricating packet counters from config instead of reading them from runtime stats maps.
  * mixing global config summary with per-interface live stats without making the boundary explicit.

### 6. Tests Required

* daemon snapshot tests must assert multi-interface configs return one snapshot item per interface.
* snapshot tests must assert per-interface ICMP mode differences are preserved.
* runtime repository tests must assert stats counters are included in snapshots.
* aggregate snapshot tests must assert packet counters are summed correctly across interfaces.

### 7. Wrong vs Correct

#### Wrong

* Keep `status` tied to `runtimes.first()` and treat the rest of the interfaces as an opaque count.

#### Correct

* Build status from all selected runtimes, preserve per-interface policy differences, and aggregate counters explicitly at the CLI boundary.

## Scenario: ICMP Runtime Config And Dataplane Contract

### 1. Scope / Trigger

* Trigger: Any change to `RuntimeConfig`, ICMP mode semantics, pinned `config` map updates, or XDP ICMP decision logic.

### 2. Signatures

* `WalleConfig::runtime_config() -> RuntimeConfig`
* `RuntimeController::sync_policy(&WalleConfig) -> Result<(), RuntimeError>`
* `LinuxMapRepository::replace_icmp_rules(&[IcmpRule]) -> Result<(), RuntimeError>`
* `LinuxMapRepository::write_config(RuntimeConfig) -> Result<(), RuntimeError>`
* `attach_linux(interface: &str, object_path: PathBuf, map_pin_path: PathBuf) -> Result<XdpAttachment, XdpError>`
* `walle_ebpf::xdp::apply_icmp_policy(&RuntimeConfig, PacketAction, IcmpPacketKind, bool) -> PacketAction`
* `evaluate_ipv4(&XdpContext, &RuntimeConfig) -> Result<PacketAction, ()>`
* `evaluate_ipv6(&XdpContext, &RuntimeConfig) -> Result<PacketAction, ()>`
* `cargo run -p xtask -- emit-bpftool-icmp-rule <payload-bytes> [map-path]`
* `cargo run -p xtask -- emit-bpftool-clear-icmp-rule <payload-bytes> [map-path]`

### 3. Contracts

* The pinned `config` map remains a singleton entry keyed by `CONFIG_MAP_KEY = 0`.
* `RuntimeConfig::icmp_mode` must keep stable shared discriminants:
  * `Disabled = 0`
  * `DropAll = 1`
  * `AllowRulesActive = 2`
* Control-plane sync must write ICMP mode through the typed `RuntimeConfig` contract, even when operators inspect or override the live map with `bpftool`.
* `DropAll` means:
  * ingress ICMP/ICMPv6 echo request packets are dropped
  * ingress ICMP/ICMPv6 echo reply packets are allowed to follow the base access verdict
  * non-echo ICMP packets currently follow the ICMP drop branch unless a more specific rule is introduced later
* `AllowRulesActive` keeps the policy contract (`rule_hit => allow`, miss => drop) using the shared `icmp_rules` hash map as a presence set keyed by canonical exact-match `IcmpRule` bytes.
* The pinned `icmp_rules` map contract is:
  * map type: `HashMap`
  * key: full `IcmpRule` bytes (`70` bytes with the current C layout)
  * value: `u8` presence marker (`1` for enabled entries)
* Control-plane sync and `bpftool` writes must serialize the full canonical `IcmpRule` into the map key; slot-based array updates are no longer valid.
* Exact raw-byte rule matching applies to ICMP echo request/reply payload bytes only; dynamic ICMP header fields such as checksum, identifier, and sequence are not part of the match.
* Exact payload matching is only supported when the echo payload length fits within `ICMP_RULE_PAYLOAD_CAPACITY`; longer payloads fall through as rule misses.
* The XDP path must build one canonical lookup rule from the bounded echo payload and perform a single hash lookup; verifier-hostile slot scans are not allowed.
* When the loader encounters a pinned-map directory from an older schema, it must remove the known pinned map files before loading the object so the new schema can be pinned cleanly.

### 4. Validation & Error Matrix

* Valid runtime sync with `icmp_mode = Disabled` -> config map write succeeds and dataplane keeps the base access verdict for ICMP traffic.
* Valid runtime sync with `icmp_mode = DropAll` -> config map write succeeds and ingress echo requests are dropped.
* Valid runtime sync with `icmp_mode = DropAll` plus locally initiated `ping` -> ingress echo replies remain allowed.
* Valid runtime sync with `icmp_mode = AllowRulesActive` and a matching exact echo-payload rule -> dataplane allows the ICMP packet.
* Valid runtime sync with `icmp_mode = AllowRulesActive` and no matching rule -> dataplane drops the ICMP packet.
* Valid runtime sync with `icmp_mode = AllowRulesActive` and echo payload length above `ICMP_RULE_PAYLOAD_CAPACITY` -> dataplane treats the packet as a rule miss.
* Valid startup with stale pinned maps from an older `icmp_rules` schema -> loader removes the old pins and startup continues with freshly pinned maps.
* Invalid `RuntimeConfig` map access or map open failure -> `RuntimeError::MapOperation`.
* Verifier-unsafe ICMP dataplane changes that prevent XDP attach are release-blocking and must not be hidden behind optimistic config sync.

### 5. Good/Base/Bad Cases

* Good:
  * external echo request traffic is dropped while a locally initiated `ping` still receives echo replies
  * an exact raw-byte echo payload rule allows the matching request and its reply while non-matching payloads are dropped
  * `ping -s 4 -p 09070108 <target>` succeeds after the matching rule is inserted, while `ping -s 4 -p 09070109 <target>` misses and is dropped
  * the daemon attaches XDP successfully and syncs the typed config map before packet tests begin
* Base:
  * `icmp_mode = Disabled` with no ICMP rules keeps previous access behavior unchanged
  * an empty ICMP rule set remains valid and causes ICMP packets to miss / drop under `AllowRulesActive`
* Bad:
  * treating `DropAll` as "drop every ingress ICMP packet including replies" when operators expect outbound reachability to continue
  * including dynamic ICMP echo header bytes in the rule contract and making stable RTT probes impossible

### 6. Tests Required

* unit tests must assert ICMP packet classification for echo request vs echo reply across IPv4 and IPv6
* unit tests must assert `DropAll` drops echo requests and keeps echo replies
* dataplane tests or verifier-safe helper tests must assert exact-match ICMP rule hits, misses, and over-capacity misses
* helper tests must assert `bpftool` command generation uses the serialized `IcmpRule` as the key and delete operations address the same key bytes
* system validation must cover:
  * successful real XDP attach
  * successful startup after a schema-changing map reload path
  * `DropAll` live map toggle
  * outbound `ping` success under `DropAll` because replies are still allowed
  * `AllowRulesActive` live-map validation with a matching payload ping success and a non-matching payload ping failure
* exact-match dataplane support must keep real XDP attach working on the supported kernel baseline

### 7. Wrong vs Correct

#### Wrong

* Define `DropAll` loosely as "drop ICMP" and let the dataplane also discard echo replies, breaking locally initiated connectivity checks.
* Model `icmp_rules` as a slot-scanned array in the dataplane and rely on nested per-slot byte comparisons, causing verifier state explosion and failed attach on real kernels.

#### Correct

* Treat ICMP mode as a typed runtime contract: drop ingress echo requests, preserve ingress echo replies, and keep verifier-safe attachability as part of the feature definition.
* Represent exact-match ICMP rules as canonical `IcmpRule` hash keys so the dataplane performs one bounded payload copy and one hash lookup per packet.

## Scenario: Manual Ban Lifecycle And Live Runtime Command Contract

### 1. Scope / Trigger

* Trigger: Any change to `walle ban add`, `walle ban remove`, `walle ban list`, runtime deny-entry mutation, or ban expiry coordination between CLI and pinned-map backends.

### 2. Signatures

* `walle ban add <ip> [duration_secs]`
* `walle ban remove <ip>`
* `walle ban list`
* `WalleDaemon::add_manual_ban(IpAddr, Option<u64>) -> Result<(), DaemonError>`
* `WalleDaemon::remove_ban(IpAddr) -> Result<usize, DaemonError>`
* `WalleDaemon::list_bans() -> Result<BanStatusSnapshot, DaemonError>`
* `RuntimeController::add_manual_ban(IpAddr, u64, Option<u64>) -> Result<(), RuntimeError>`
* `RuntimeController::remove_ban(IpAddr) -> Result<bool, RuntimeError>`
* `RuntimeController::list_bans() -> Result<Vec<BanRecord>, RuntimeError>`

### 3. Contracts

* Manual bans are live-runtime operations; they must mutate active pinned-map or connected runtime backends rather than editing `config.toml`.
* `walle ban add <ip>` with no duration writes an indefinite manual ban:
  * `source = Manual`
  * `reason = Manual`
  * `expires_at_ns = 0`
* `walle ban add <ip> <duration_secs>` writes a temporary manual ban whose expiry is derived from `created_at_secs + duration_secs`.
* `walle ban remove <ip>` removes the deny entry from every active runtime backend and reports how many interfaces were updated.
* `walle ban list` must return one per-interface runtime snapshot with:
  * interface name
  * runtime backend kind
  * ordered ban records
* CLI ban commands must first connect to existing live runtime backends; they must not silently fall back to transient in-memory state.
* Before manual mutation or listing, runtime code should run expiry cleanup so stale temporary bans do not remain visible.

### 4. Validation & Error Matrix

* valid live runtime + `walle ban add 198.51.100.10` -> manual indefinite deny entry is written to every connected interface backend.
* valid live runtime + `walle ban add 198.51.100.10 30` -> temporary manual deny entry is written with `expires_at_ns > 0`.
* valid live runtime + `walle ban remove 198.51.100.10` -> CLI succeeds and reports the number of interfaces where the ban existed.
* valid live runtime + expired temporary bans present -> cleanup removes them before `walle ban list` output is rendered.
* no active pinned runtime backend -> `DaemonError::NoActiveRuntime`.
* live map open or delete failure during remove/list -> typed `RuntimeError` from the repository boundary.

### 5. Good/Base/Bad Cases

* Good:
  * `walle run` is active on two interfaces, and `walle ban add 203.0.113.9 60` produces one deny entry in each interface runtime.
  * `walle ban list` shows manual and detector bans with their source/reason metadata and expiry timestamps.
  * `walle ban remove 203.0.113.9` returns a non-zero interface update count after removing the active ban.
* Base:
  * a live runtime with zero bans returns an empty list successfully.
  * an indefinite manual ban survives expiry cleanup because `expires_at_ns = 0`.
* Bad:
  * mutating only the in-process default `InMemoryMapRepository` when no live runtime exists and presenting the result as a successful operator action.
  * forgetting expiry cleanup before listing and showing stale temporary bans as still active.

### 6. Tests Required

* runtime tests must assert manual ban creation preserves `Manual` source/reason metadata and the expected expiry semantics.
* runtime tests must assert manual ban removal updates snapshots and clears listed entries.
* daemon / CLI-path tests or review must assert commands fail when no live runtime backend is available.
* repository tests must keep IPv4 / IPv6 deny state separated while listing and removing entries.

### 7. Wrong vs Correct

#### Wrong

* Let `walle ban add` mutate an isolated in-memory repository when no pinned maps are active, creating a false sense that the host is protected.

#### Correct

* Treat ban commands as live-runtime operations: connect to active backends first, fail explicitly when they do not exist, and keep manual ban metadata aligned with the shared deny-entry contract.
