# Quality Guidelines

> Code quality standards for backend development.

---

## Overview

`walle` is a security-sensitive systems project. The quality bar should prioritize correctness, explicitness, and debuggability over cleverness.

Every change should be evaluated across:

* control-plane correctness
* packet-path safety
* operational recovery behavior
* compatibility of shared structs and map layouts

---

## Forbidden Patterns

* `unwrap` and `expect` in daemon or loader runtime paths.
* Silent changes to BPF map key or value layouts.
* Re-implementing policy precedence separately in CLI, daemon, and XDP.
* Stringly-typed mode or rule handling where enums should be used.
* Adding speculative complexity such as a database or HTTP API before a concrete need exists.
* Per-packet logging in the hot path.
* Hidden global mutable state in control-plane crates.

In eBPF code specifically:

* no heap allocation assumptions
* no complex regex engines in MVP
* no unsafe parsing without bounds checks

---

## Required Patterns

* Shared structs and enums for data crossing user-space and eBPF boundaries.
* Explicit access-mode precedence tests.
* Version-aware config and map updates.
* Clear separation between detector logic and XDP enforcement logic.
* Structured logging for significant control-plane events.
* Small, reviewable crates with obvious ownership boundaries.

Before adding a new helper or utility, search for an existing abstraction first.

---

## Testing Requirements

At minimum:

* unit tests for policy parsing and validation
* unit tests for SSH threshold logic
* unit tests for access-mode conflict precedence
* integration tests for map update flows
* system-level validation for XDP attach, allow, and drop behavior before release

For future bug fixes:

* add a regression test when the bug can reasonably be isolated
* document non-testable kernel or environment constraints if a full automated test is not possible

---

## Code Review Checklist

* Does the change keep packet-path behavior simple and bounded?
* Are shared structs or enums updated safely across all layers?
* Is whitelist-over-blacklist precedence preserved?
* Does the change add enough logs or counters to debug failures?
* Are user-visible errors actionable?
* Are new dependencies justified for a systems-security tool?
* Does the implementation match [`docs/architecture/walle-system-design.md`](E:/coding/github_projects/walle/docs/architecture/walle-system-design.md)?

Current scaffold examples:

* [`walle-common tests`](E:/coding/github_projects/walle/crates/walle-common/src/lib.rs): precedence tests at the shared-type layer
* [`walle-policy tests`](E:/coding/github_projects/walle/crates/walle-policy/src/lib.rs): config validation tests
* [`walle-ebpf helper`](E:/coding/github_projects/walle/crates/walle-ebpf/src/lib.rs): minimal packet-path logic reused from shared policy

## Scenario: GP Core And Protocol Adapter Contract

### 1. Scope / Trigger

* Trigger: Any change to guard-point (`gp`) policy schema, daemon-side GP execution contracts, SSH GP adapter behavior, or future protocol adapters such as HTTP.

### 2. Signatures

* `walle_policy::GpPolicy`
* `walle_policy::GpStrategyKind`
* `walle_policy::GpTriggerMode`
* `walle_policy::SshProtectionPolicy { gp: GpPolicy }`
* `walle_daemon::gp::GpExecutor::execute(GpAdapterRequest) -> GpExecutionOutcome`
* `walle_daemon::gp::GpAdapterRequest::Ssh(SshGpRequest)`
* `WalleDaemon::process_ssh_log_line(&str, u64) -> Result<Option<SshBanDecision>, DaemonError>`
* `WalleDaemon::poll_ssh_sources(u64) -> Result<SshIngestSummary, DaemonError>`
* `WalleDaemon::replay_ssh_log_file(PathBuf, u64, u64) -> Result<SshIngestSummary, DaemonError>`

### 3. Contracts

* GP core must stay protocol-agnostic:
  * use generic strategy and trigger enums in policy
  * keep protocol-specific payload mapping in adapter-specific request types
* SSH v1 integration point is a protocol adapter, not a special-case bypass of GP core.
* `GpTriggerMode` must support both:
  * suspicious signal observed
  * enforcement decision emitted
* GP execution is observational / extensible in v1:
  * `observe` may succeed normally
  * unimplemented strategies such as `degrade` or `contain` must return a typed fail-open outcome instead of aborting the SSH defense path
* Baseline SSH enforcement remains authoritative:
  * SSH ban writeback and deny-map behavior must continue even if GP execution is unavailable
* User-facing config and install defaults must expose the SSH GP sub-policy under:
  * `[detectors.ssh.gp]`
  * `enabled`
  * `strategy`
  * `trigger_mode`

### 4. Validation & Error Matrix

* valid config with omitted `[detectors.ssh.gp]` block -> GP defaults to disabled `observe` / `all`
* valid config with `trigger_mode = "signal_observed"` -> pre-ban SSH trigger points may execute GP, post-ban trigger points must be filtered
* valid config with `trigger_mode = "decision_emitted"` -> post-ban SSH trigger points may execute GP, pre-ban trigger points must be filtered
* valid config with `strategy = "observe"` and GP enabled -> executor returns an observed outcome
* valid config with `strategy = "degrade"` or `strategy = "contain"` and GP enabled -> executor returns `failed_open` outcome and baseline SSH processing continues
* invalid future implementation that hard-codes SSH-only semantics into GP core -> reject in review; protocol-specific fields belong in the adapter payload, not the core policy enum surface

### 5. Good/Base/Bad Cases

* Good:
  * a parsed SSH failure event reaches GP through `SshGpRequest` and can be filtered or observed by generic GP core logic
  * a ban decision reaches GP and still applies deny-map updates even if the selected GP strategy is not yet implemented
  * `walle ssh policy-show` exposes GP enablement, strategy, and trigger mode so operators can reason about behavior
* Base:
  * GP disabled means the executor returns a disabled outcome and the rest of SSH processing continues as before
  * v1 only wires the SSH adapter, while leaving room for future adapters such as HTTP without core refactors
* Bad:
  * putting SSH-specific usernames, auth reasons, or shell semantics directly into `GpPolicy`
  * letting GP failure prevent `apply_ssh_ban_to_all` from running
  * adding packet-path changes in XDP as part of GP framework scaffolding

### 6. Tests Required

* policy tests must assert GP defaults, nested TOML parsing, and trigger-mode helper behavior
* GP core tests must assert:
  * disabled outcome
  * trigger filtering
  * observe success
  * unimplemented strategy fail-open behavior
* daemon tests must assert:
  * pre-ban SSH trigger reaches GP
  * post-ban SSH trigger reaches GP
  * unavailable GP strategy does not break deny-map updates
* install-template tests must assert `[detectors.ssh.gp]` appears in the generated default config

### 7. Wrong vs Correct

#### Wrong

* Build `ssh-gp` as ad-hoc daemon logic first, then try to retrofit a generic GP framework later.

#### Correct

* Keep a generic GP core for strategy / trigger / outcome semantics, and translate SSH-specific detector events into that core through an adapter-specific request type.

## Scenario: SSH Jail Containment And Invalid-User Force-Ban Contract

### 1. Scope / Trigger

* Trigger: Any change to `sshjail`, SSH detector fast-ban behavior, SSH containment map semantics, XDP/tc SSH steering, or policy fields under `[detectors.ssh]` and `[detectors.ssh.gp]`.

### 2. Signatures

* `walle_policy::SshProtectionPolicy { invalid_user_force_ban_enabled: bool, gp: GpPolicy }`
* `walle_policy::GpPolicy { strategy: GpStrategyKind, trigger_mode: GpTriggerMode, sshjail: SshJailPolicy }`
* `walle_daemon::detector::SshDetectorService::force_ban(IpAddr, u64) -> Option<SshBanDecision>`
* `walle_daemon::WalleDaemon::process_ssh_log_line(&str, u64) -> Result<Option<SshBanDecision>, DaemonError>`
* `walle_daemon::WalleDaemon::apply_ssh_ban_to_all(SshBanDecision) -> Result<(), DaemonError>`
* `walle_daemon::WalleDaemon::apply_ssh_contain_to_all(IpAddr, u64, u64, SshContainTrigger) -> Result<(), DaemonError>`
* `walle_daemon::runtime::RuntimeController::apply_ssh_contain(...) -> Result<(), DaemonError>`
* `walle_ebpf::xdp::evaluate_access_with_containment(&RuntimeConfig, bool, bool, bool, u8, u16) -> PacketAction`

### 3. Contracts

* `invalid_user_force_ban_enabled = true` means explicit `Invalid user` log lines bypass the SSH failure threshold and emit an immediate `SshBanDecision`.
* The invalid-user fast path is ban-only. It must not directly redirect traffic into `sshjail`.
* Whether later SSH attempts enter `sshjail` is controlled only by GP containment:
  * `strategy = "contain"`
  * matching `trigger_mode`
* `gp.trigger_mode = "decision_emitted"` means the contain entry is written only after a ban decision exists.
* A source may exist in both deny and contain maps at the same time.
* For contained sources, only TCP traffic targeting `RuntimeConfig.protected_ssh_port` may bypass XDP deny so tc ingress can rewrite it to `RuntimeConfig.ssh_jail_port`.
* Non-SSH traffic from the same banned source must still be dropped by XDP.
* If `sshjail` is unavailable or full, GP containment must fail open back to normal ban/drop behavior.

### 4. Validation & Error Matrix

* valid config with `invalid_user_force_ban_enabled = false` -> invalid-user lines follow the normal threshold path
* valid config with `invalid_user_force_ban_enabled = true` and GP disabled -> invalid-user lines ban immediately; later traffic is dropped
* valid config with `invalid_user_force_ban_enabled = true`, `gp.enabled = true`, `strategy = "contain"`, `trigger_mode = "decision_emitted"` -> invalid-user lines ban immediately and later SSH attempts are redirected to `sshjail`
* contain entry present + deny entry present + TCP destination is protected SSH port -> XDP must return `Allow`
* contain entry present + deny entry present + TCP destination is not protected SSH port -> XDP must return `Drop`
* contain entry present + deny entry present + non-TCP traffic -> XDP must return `Drop`

### 5. Good/Base/Bad Cases

* Good:
  * first invalid-user attempt hits the real `sshd`, produces one log line, and emits an immediate ban decision
  * second SSH attempt from the same source is passed through XDP, rewritten by tc, and lands in `sshjail`
  * ICMP and non-SSH TCP from the same source continue to be dropped
* Base:
  * normal failed-password traffic still uses threshold counting when `invalid_user_force_ban_enabled` is off
* Bad:
  * invalid-user fast path directly writes contain without a ban decision
  * XDP deny takes precedence over contain for protected SSH traffic and prevents tc redirect from ever running
  * contain is treated as a general allow for all traffic from a banned source

### 6. Tests Required

* policy parsing tests must assert `invalid_user_force_ban_enabled` is loaded from TOML
* daemon tests must assert:
  * invalid-user fast path emits a one-shot `SshBanDecision`
  * invalid-user fast path does not require `sshjail` by itself
  * post-ban GP containment still preserves baseline ban flow
* `walle-ebpf` tests must assert:
  * contained SSH traffic overrides deny for the protected SSH port
  * contained non-SSH TCP does not override deny
  * contained non-TCP traffic does not override deny

### 7. Wrong vs Correct

#### Wrong

* Treat `invalid_user_force_ban_enabled` as a direct redirect switch and couple it to `sshjail` startup or contain-map writes.

#### Correct

* Keep invalid-user fast handling as a detector-side ban shortcut, and let GP containment decide whether later SSH attempts are redirected after the ban decision boundary.
