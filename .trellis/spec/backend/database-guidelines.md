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
