# Implement ban lifecycle management

## Goal

Complete the runtime lifecycle for bans by supporting expiry, cleanup, and explicit unban behavior instead of only inserting deny entries.

## Requirements

* Distinguish indefinite manual bans from expiring detector bans.
* Add cleanup logic that removes expired bans from runtime state.
* Add explicit unban operations for operator-driven removal.
* Ensure lifecycle behavior is observable through status or list commands.

## Acceptance Criteria

* [x] Expired bans are removed automatically from runtime state.
* [x] Manual bans persist until explicitly removed.
* [x] Unban behavior updates runtime state consistently for both control-plane and detector-created entries.

## Technical Approach

* Extend `RuntimeController` and repository backends with manual add, remove, and list operations.
* Keep detector bans expiring through the existing runtime cleanup path.
* Surface manual ban lifecycle through `walle ban add`, `walle ban remove`, and `walle ban list`.
* Require a live runtime backend for CLI ban mutation commands instead of silently mutating transient in-memory state.

## Decision (ADR-lite)

**Context**: Runtime ban expiry already existed, but operator-driven ban mutation was still a CLI placeholder.

**Decision**: Implement explicit manual ban lifecycle on top of the live pinned-map runtime backend and expose it through the existing `ban` command group.

**Consequences**: Manual commands now act on live runtime state only. If no active runtime backend exists, the CLI fails with a precise action hint.

## Out of Scope

* Persisting manual ban changes back into `config.toml`
* Adding structured machine-readable CLI output for ban listing

## Technical Notes

Dependencies:

* Depends on the real BPF map backend.
* Interacts with SSH follow loop timing and CLI/runtime command semantics.
* Implemented in `crates/walle-daemon/src/runtime.rs`, `crates/walle-daemon/src/lib.rs`, and `crates/walle-cli/src/main.rs`.
