# Implement real XDP runtime roadmap

## Goal

Move `walle` from a control-plane and detector scaffold into a runnable Linux firewall by introducing a real XDP attach path, shared BPF-map runtime state, long-running service loops, and deployment packaging.

## What I already know

* `walle-ebpf` currently exposes helper logic only and does not define or attach a real XDP program.
* `walle-daemon` currently syncs policy into an `InMemoryMapRepository`, so runtime state is not shared with any kernel dataplane.
* SSH ingestion already supports incremental file reads and a journald abstraction, but the daemon does not run a persistent follow loop.
* Ban writes exist, but expiry, cleanup, and unban lifecycle behavior are incomplete.
* ICMP policy contracts exist in `walle-common` and `walle-policy`, but they are not enforced in a real packet path.
* Linux runtime installation, service management, and packaging strategy are not yet implemented.

## Requirements

* Track each major missing production capability as a dedicated child task.
* Preserve the intended dependency order so foundational work lands before dependent features.
* Keep Linux-only runtime behavior behind clear compatibility checks where development on non-Linux hosts remains possible.
* Use existing runtime and policy contracts unless implementation reveals contract gaps that must be documented explicitly.

## Acceptance Criteria

* [ ] A parent roadmap task exists with child tasks covering the requested workstreams.
* [ ] Each child task has a PRD describing scope, dependencies, and acceptance criteria.
* [ ] The first foundational task is selected and activated for implementation.

## Technical Approach

Recommended implementation order:

1. Real XDP loader and interface attach
2. Real BPF map runtime backend
3. SSH follow service loop
4. Ban lifecycle management
5. ICMP dataplane enforcement
6. Linux service install flow
7. Distribution and install strategy

This order keeps packet-path and shared-state primitives ahead of higher-level automation and packaging work.

## Decision (ADR-lite)

**Context**: The requested work spans multiple layers with strong dependencies.

**Decision**: Track the effort as one parent roadmap with seven executable child tasks, and start implementation from the XDP attach foundation.

**Consequences**: Task tracking stays explicit, but some later tasks may need PRD updates once the lower-level loader and map abstractions settle.

## Out of Scope

* GUI or browser-based management
* Non-Linux runtime support
* Distributed synchronization across hosts

## Technical Notes

Relevant current files:

* `crates/walle-ebpf/src/lib.rs`
* `crates/walle-daemon/src/runtime.rs`
* `crates/walle-daemon/src/detector.rs`
* `crates/walle-cli/src/main.rs`
* `docs/architecture/walle-system-design.md`
