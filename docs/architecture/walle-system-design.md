# Walle System Design v0

## Overview

`walle` is a Rust-first Linux CLI firewall focused on high-performance enforcement with eBPF/XDP.

The product is intentionally split into:

* a control plane in user space
* a detector pipeline in user space
* a data plane in eBPF/XDP

This split keeps packet-path logic small and predictable while allowing richer detection logic outside the kernel.

## Product Scope

### In Scope for MVP

* CLI-driven lifecycle management
* IP-based whitelist and blacklist enforcement in XDP
* explicit access-control modes
* SSH abuse detection in user space with BPF map updates
* ICMP control with raw-byte exact-match allow rules

### Out of Scope for MVP

* full HTTP malicious traffic detection
* TLS-aware application-layer inspection
* distributed synchronization across hosts
* GUI or web console
* non-Linux platforms

## Architecture

```text
SSH logs / journald / future detectors
                |
                v
      +----------------------+
      |   detector service   |
      |  ban decision logic  |
      +----------------------+
                |
                v
      +----------------------+
      |  control plane API   |
      |  map update logic    |
      +----------------------+
                |
                v
      +----------------------+
      |   shared BPF maps    |
      | config / allow / ban |
      +----------------------+
                |
                v
      +----------------------+
      |      XDP program     |
      |  allow / drop fast   |
      +----------------------+
                |
                v
           network ingress
```

## Main Components

### CLI

Responsibilities:

* start and stop the service stack
* inspect active mode and rule state
* manage allowlist and denylist entries
* configure SSH and ICMP policy
* expose health, counters, and diagnostics

Planned commands:

* `walle run`
* `walle status`
* `walle access-mode get`
* `walle access-mode set <mode>`
* `walle ban add <ip>`
* `walle ban remove <ip>`
* `walle ban list`
* `walle allow add <ip>`
* `walle allow remove <ip>`
* `walle allow list`
* `walle ssh protect enable`
* `walle ssh protect disable`
* `walle ssh policy set ...`
* `walle icmp drop enable`
* `walle icmp drop disable`
* `walle icmp allow add ...`
* `walle icmp allow list`

### Detector Service

Responsibilities:

* subscribe to SSH-related signals
* identify abusive sources using configurable thresholds
* write ban and unban decisions into shared state
* attach metadata for observability and future policy evolution

MVP detection source:

* prefer event-driven journal or log subscription
* do not use eBPF to parse generic log text in MVP

Future detector sources:

* SSH-specific hooks
* protocol-specific detectors for HTTP or other services
* operator-driven feeds or threat-intel importers

### XDP Data Plane

Responsibilities:

* load current access mode from config map
* evaluate source IP against allow and deny state
* enforce ICMP control
* export counters for passes, drops, and map hits

Non-goals:

* deep SSH authentication analysis
* full HTTP semantic inspection
* regex-heavy matching in the packet path

## Shared State Model

### Config Map

Purpose:

* store singleton runtime configuration for packet-path logic

Suggested fields:

* `access_mode`
  * `whitelist_only`
  * `blacklist_only`
  * `blacklist_with_whitelist_exception`
* `icmp_mode`
  * disabled
  * drop_all
  * allow_rules_active
* `icmp_match_capability`
  * keep room for future match types
* `default_action`
* `version`
* `flags`

Implementation note:

* use a singleton key such as `0`
* treat config updates as explicit versioned writes

### Allowlist Maps

Purpose:

* hold explicitly allowed source identities for fast-path decisions

MVP recommendation:

* separate IPv4 and IPv6 exact-match maps
* exact IP entries only in first version

Future extension:

* prefix-based entries with LPM trie if needed

### Denylist Maps

Purpose:

* hold banned source identities and their enforcement metadata

Suggested fields:

* `expires_at`
* `reason_code`
* `source`
  * manual
  * ssh_detector
  * future_http_detector
* `created_at`
* `flags`

Policy note:

* whitelist always wins over blacklist if the same IP exists in both

### SSH Containment Maps

Purpose:

* hold source identities that should be redirected into `sshjail` on later SSH connection attempts

Suggested fields:

* `created_at`
* `expires_at`
* `trigger`
  * invalid_user
  * gp_signal_observed
  * gp_decision_emitted

Policy note:

* containment state coexists with deny state
* containment takes precedence only for SSH redirection decisions
* if `sshjail` is unavailable or full, normal deny or drop behavior remains active

### ICMP Rule Maps

Purpose:

* define allow exceptions when ICMP filtering is active

MVP rule shape:

* `match_type`
  * `raw_bytes_exact`
* `payload_length`
* `payload_bytes`
* `enabled`

Future rule shape:

* keep room for `string_exact` and `regex`
* compile richer control-plane rules into a simpler runtime representation where possible

### Stats Maps

Purpose:

* export counters for visibility and debugging

Suggested counters:

* packets allowed
* packets dropped
* allowlist hits
* denylist hits
* ICMP rule hits
* parser failures

## Access-Control Semantics

### `whitelist_only`

* allow only listed sources
* drop all other sources

### `blacklist_only`

* drop listed sources
* allow all other sources

### `blacklist_with_whitelist_exception`

* evaluate whitelist first
* if not explicitly allowed, apply blacklist
* otherwise use normal default allow behavior

Conflict rule:

* whitelist has priority in all modes

## SSH Enforcement Flow

```text
journal event / ssh signal
      |
      v
parse source IP and failure reason
      |
      v
update detector counters and threshold window
      |
      v
threshold exceeded?
  | yes
  v
write deny entry to BPF map with expiry metadata
      |
      v
XDP drops later packets from that source
```

With `gp.strategy = "contain"` and `sshjail` enabled, the SSH flow gains a second path:

* the default containment trigger is `decision_emitted`
* after ban, later SSH connection attempts from that source are marked in a contain map
* `tc` ingress and egress programs rewrite the SSH destination and source ports to a daemon-owned in-process `sshjail` listener
* `sshjail` binds `0.0.0.0:0` by default, receives the kernel-assigned dynamic port at startup, and that real port is written into the runtime config map before traffic steering begins
* if `invalid_user_force_ban_enabled = true`, explicit `Invalid user` log events can skip the threshold wait and go directly to a ban decision; whether later SSH attempts are dropped or redirected into `sshjail` is still controlled by the configured GP strategy
* if `sshjail` reaches its session cap, new containment decisions fail open back to ban or drop rather than mutating host `iptables` or `nftables` state

### SSH Policy Model

MVP:

* configurable failure threshold
* configurable time window
* configurable ban duration

Future:

* escalation tiers
* permanent bans
* trusted identities or exception policies
* correlation with metadata such as SSH implementation fingerprint

## SSH Identity Signals

There are multiple candidate identity signals, but they have different trust levels:

* source IP
  * strongest enforcement primitive
  * weak identity under NAT or IP churn
* SSH implementation fingerprint
  * useful for heuristics and observability
  * not strong enough for automatic allowlisting
* client public key fingerprint
  * stronger identity
  * typically only visible during authentication flows

Decision:

* keep the XDP path IP-centric
* store any future fingerprint metadata in user-space detector state first
* do not auto-allow a new IP only because it matches a previously seen SSH fingerprint

## ICMP Enforcement Flow

```text
packet enters XDP
      |
      v
is ICMP enabled?
  | no -> continue normal allow or deny evaluation
  | yes
  v
drop all?
  | yes -> drop
  | no
  v
extract payload bytes and compare against exact-match rules
  | hit -> allow
  | miss -> drop
```

## HTTP Extension Point

HTTP is intentionally not an MVP detector.

What we should preserve now:

* a detector interface that can publish IP allow or deny decisions
* deny entry metadata identifying the rule source
* CLI and status output that can show why an entry exists

What we should not promise now:

* content-based HTTP inspection at XDP
* TLS decryption
* WAF-equivalent semantics

## BTF and Portability

BTF and CO-RE should be treated as first-class portability tools, but not as a complete portability guarantee by themselves.

Key points:

* If `walle` uses CO-RE style relocations, the running kernel needs authoritative BTF information available to the loader.
* For many packet-only XDP paths that mostly parse stable UAPI network headers, BTF is less critical than it is for programs that depend on kernel-internal structs.
* The moment a BPF program depends on kernel type layouts or richer kernel context, BTF-backed portability becomes much more important.

Distribution implications:

* Users should not need to compile the eBPF program on their own machines for normal installation.
* `walle` should ship prebuilt user-space binaries and prebuilt BPF objects.
* Startup should perform runtime environment checks for:
  * minimum supported kernel baseline
  * kernel eBPF support
  * XDP support on the selected interface
  * required helpers and map types
  * availability of kernel BTF when the selected program path requires it

Fallback strategy:

* If a target machine lacks the capabilities needed by the selected feature set, fail with a precise diagnostic instead of attempting silent degradation.
* BTF absence should be surfaced as an environment compatibility error when a CO-RE dependent program is selected.
* Local compilation may help align build artifacts with the host environment, but it cannot compensate for missing kernel features.

Supported baseline decision:

* Start with Linux kernel `5.15` as the official minimum supported baseline for `walle`.
* Treat support for older kernels as out of scope unless later testing proves a lower floor is worth the compatibility cost.

## Suggested Rust Workspace Layout

```text
Cargo.toml
crates/
  walle-cli/
  walle-daemon/
  walle-common/
  walle-policy/
  walle-ebpf/
xtask/
docs/
  architecture/
fixtures/
```

Suggested crate responsibilities:

* `walle-cli`
  * clap-based CLI entrypoints for the user-facing `walle` binary
* `walle-daemon`
  * long-running detector and loader runtime library
* `walle-common`
  * shared plain data types used across crates
* `walle-policy`
  * control-plane rule schemas and validation
* `walle-ebpf`
  * no-std eBPF/XDP program code
* `xtask`
  * build, bundle, and development automation

## Testing Strategy

### Unit Tests

* policy parsing and validation
* access-mode precedence
* SSH threshold logic
* ICMP rule normalization

### Integration Tests

* CLI to daemon control flow
* map update paths
* allowlist and denylist conflict handling

### System Tests

* XDP attach and detach lifecycle
* SSH ban flow from event to drop
* ICMP drop and allow behavior

## Delivery Phases

### Phase 0

* finalize PRD
* write system design
* bootstrap repo guidelines

### Phase 1

* scaffold Rust workspace
* create CLI shell and daemon shell
* define shared data structures and config schema

### Phase 2

* implement XDP data plane with manual map management
* support access modes and IP list precedence
* expose status and counters

### Phase 3

* implement SSH detector with fixed-threshold banning
* support ban expiration and unban flow

### Phase 4

* implement ICMP drop and raw-byte allow rules
* validate rule compiler and packet-path behavior

### Phase 5

* add future extension points for richer detectors and policies

## Open Items for Post-Scaffold Review

These are intentionally deferred until the first code slice exists:

* exact BPF map types and memory limits
* whether IPv4 and IPv6 share a generic key layout or use separate maps
* whether the daemon directly embeds the loader or uses a dedicated crate
* whether persistent local state is needed beyond config files
