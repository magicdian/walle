# brainstorm: gp defense mechanism framework

## Goal

Extend the existing defense architecture with a GP (guard point) countermeasure framework so the system can do more than ban and drop abusive sources. The intent is to add graduated response options after suspicious activity is detected, while staying aligned with the current split between user-space detection/control and XDP fast-path enforcement. The framework should support protocol-specific adapters such as `ssh-gp` now and `http-gp` in the future.

## What I already know

* The repo already has an SSH detector pipeline in user space that parses SSH failure signals and emits per-IP ban decisions.
* The daemon already writes SSH ban decisions into runtime deny maps, and the XDP data plane enforces allow/drop based on blacklist state.
* The current XDP action model is packet verdict oriented (`Allow` / `Drop`), with no existing concept of TCP response forgery, active packet crafting, or userspace redirection targets.
* The architecture document explicitly keeps the packet path small and predictable, while allowing richer detector/control logic in user space.
* The user originally proposed a new GP mechanism with two candidate countermeasure modes:
  * lightweight mode: for blacklisted devices, reply with deceptive TCP-level signals such as fake ACK behavior to increase attacker delay or congestion
  * heavyweight mode: redirect suspicious SSH sessions to a fake SSH server that exposes a deceptive shell-like REPL with common commands such as `sudo`, `su`, `cd`, `ls`, `pwd`, and `uname`
* The heavyweight mode is expected to adapt behavior based on the username attempted by the attacker and intentionally keep the session captive rather than exiting cleanly.
* The user now wants the design boundary widened so GP can evolve into:
  * a protocol-agnostic core GP framework
  * protocol-specific adapters such as `ssh-gp` and future `http-gp`

## Assumptions (temporary)

* V1 implementation still starts from the existing SSH detector rather than moving protocol parsing into XDP.
* The first delivered version is a framework only: extensible, switchable, and test-heavy, without implementing real deceptive packet or fake-shell behavior yet.
* Any future heavyweight deception path would require user-space components and likely a new redirect/control contract beyond the current deny-map-only model.
* The core GP framework should be generic enough that future protocol adapters can plug in without redesigning the executor contract.

## Open Questions

* None at the moment.

## Requirements (evolving)

* Introduce a generic GP core framework plus protocol-specific adapter boundaries.
* Preserve the existing SSH detector -> runtime enforcement flow as the first integrated adapter path.
* First version must be extensible and explicitly switchable.
* First version must be testable through a comprehensive unit-test suite.
* First version must be wired into the existing SSH defense flow.
* First version must emit structured observability signals indicating whether GP was enabled, which strategy was selected, and when a GP execution point was reached.
* The framework must support both earlier SSH-event trigger points and ban-decision trigger points.
* GP execution must be fail-open relative to the baseline SSH defense chain:
  * if GP is unavailable or fails, normal SSH ban/drop behavior must continue
  * failures must still be observable through typed outcomes and structured logs
* Keep the design explicit about which parts live in XDP versus user space.
* Follow existing project patterns:
  * strong typed policy/config validation in `walle-policy`
  * daemon-owned orchestration in `walle-daemon`
  * structured logs for significant control-plane behavior
  * avoid expanding XDP semantics in this iteration unless explicitly required
* The core GP contract must not encode SSH-only concepts as its primary abstraction.

## Acceptance Criteria (evolving)

* [ ] GP v1 scope is framework-first rather than real countermeasure execution.
* [ ] The framework exposes a typed, explicit, and switchable GP core policy/executor model.
* [ ] The framework is wired into the existing SSH defense flow through an SSH-specific adapter with a placeholder execution path.
* [ ] The framework has a defined contract for future protocol adapters, GP strategies, and execution points.
* [ ] Structured observability covers GP enablement, selected strategy, and trigger handling.
* [ ] Structured observability covers GP execution outcomes, including fail-open behavior when GP execution fails or is unavailable.
* [ ] Unit tests cover config validation, enable/disable behavior, strategy selection semantics, pre-ban and post-ban trigger handling, execution triggering, and default/fallback behavior.
* [ ] Out-of-scope items are explicit to avoid overbuilding the first version.

## Definition of Done (team quality bar)

* Tests added/updated (unit/integration where appropriate)
* Lint / typecheck / CI green
* Docs/notes updated if behavior changes
* Rollout/rollback considered if risky

## Out of Scope (explicit)

* Real `http-gp` implementation in the first version
* Real deceptive packet crafting such as fake ACK responses in the first version
* Real fake SSH service, session redirection, or shell emulation in the first version
* Undocumented packet-path behavior changes without a defined contract
* Production-grade honeypot realism in the first version
* Changing baseline ban/drop enforcement semantics when GP fails

## Research Notes

### What similar patterns already exist in this repo

* `walle-policy` defines typed config structures plus `validate()` rules and crate-local unit tests.
* `walle-daemon` owns detector-to-enforcement orchestration and applies SSH ban decisions across runtimes.
* `walle` prefers structured logging in user space and simple, bounded packet-path behavior in XDP.

### Constraints from this repo/project

* Current XDP/runtime contract is verdict-oriented and deny-map-based, not active-response-based.
* Shared behavior should stay typed and explicit rather than stringly configured.
* This is a security-sensitive project, so default/fallback behavior must be obvious and testable.
* Existing SSH flow naturally exposes at least two useful GP trigger boundaries:
  * parsed SSH failure event observed
  * SSH ban decision emitted
* The user explicitly wants GP to remain non-critical: it may add value when available, but it must not weaken the existing defense path when unavailable.
* The user explicitly wants the architecture to avoid a future split/rewrite when `http-gp` or other protocol adapters are introduced.

### Feasible approaches here

**Approach A: Policy and contract only**

* How it works:
  * Add GP policy/config types and validation, but do not wire them into the runtime flow yet.
* Pros:
  * Lowest implementation risk.
  * Cleanest scope.
* Cons:
  * Feature is mostly structural and not yet exercised by the daemon path.

**Approach B: Generic core plus SSH adapter integration path** (Recommended)

* How it works:
  * Add generic GP policy/config types, strategy enums, and a daemon-side execution interface, then invoke it from the existing SSH decision flow through an SSH-specific adapter using a no-op or placeholder strategy.
* Pros:
  * Framework is exercised end-to-end in the real control flow.
  * Future lightweight/heavyweight strategies and future protocol adapters have stable insertion points.
  * Unit tests can cover more realistic semantics.
* Cons:
  * Slightly larger scope than config-only.

**Approach C: Generic core plus adapter integration plus shadow observability mode** (Chosen)

* How it works:
  * Same as Approach B, but also record structured events or counters whenever GP would trigger.
* Pros:
  * Better operability and safer rollout path for future real strategies.
* Cons:
  * Adds more surface area in v1.

## Decision (ADR-lite)

**Context**: The original idea includes both lightweight packet deception and heavyweight fake SSH confinement, but the current architecture only has a mature SSH detector plus deny-map enforcement path. The user also wants future protocol adapters such as `http-gp` without reworking the GP core.

**Decision**: Start with a generic GP core framework that is extensible, switchable, wired into the existing SSH decision flow through an SSH adapter, and covered by comprehensive unit tests before implementing real countermeasure behavior.

**Consequences**: This preserves architectural clarity and reduces risk while ensuring the framework is exercised in real control flow. The framework now needs explicit trigger typing and an executor contract that can evolve without forcing future refactors when real strategies or new protocol adapters are added. GP is intentionally non-critical and fail-open relative to baseline enforcement.

## Technical Approach

The current preferred direction is:

* introduce a generic GP core contract with:
  * enable/disable switch
  * strategy kind
  * trigger kind
  * typed execution outcome
* define an SSH-specific adapter layer that maps:
  * SSH suspicious event observed
  * SSH ban decision emitted
  into GP trigger payloads
* add a daemon-side GP execution interface that accepts typed adapter payloads via the generic core contract and returns a typed execution outcome
* use fail-open execution semantics so GP outcome reporting never blocks baseline SSH ban/drop enforcement
* ship v1 with placeholder strategies plus structured logs/observability instead of real countermeasure behavior
* keep XDP semantics unchanged in v1

## Technical Notes

* Relevant implementation files identified so far:
  * `crates/walle-daemon/src/detector.rs`
  * `crates/walle-daemon/src/lib.rs`
  * `crates/walle-policy/src/lib.rs`
  * `crates/walle-ebpf/src/main.rs`
  * `crates/walle-common/src/lib.rs`
* Relevant docs:
  * `docs/architecture/walle-system-design.md`
  * `.trellis/spec/guides/cross-layer-thinking-guide.md`
* Current architecture constraint:
  * XDP fast path currently models allow/drop decisions, not active TCP deception or redirect orchestration.
* Likely extension points:
  * SSH policy shape in `walle-policy`
  * decision metadata in daemon/runtime shared state
  * new enforcement mode enum or auxiliary redirect map/contract
