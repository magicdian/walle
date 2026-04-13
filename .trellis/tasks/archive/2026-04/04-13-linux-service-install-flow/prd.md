# Implement Linux service install flow

## Goal

Provide a Linux-native installation and lifecycle flow that places `walle` into system runtime paths, sets up service management, and performs startup-time capability checks.

## Requirements

* Add CLI-driven install and uninstall flows.
* Install service definitions for `systemd`, with a fallback strategy when `systemd` is unavailable.
* Check runtime prerequisites such as privileges, bpffs readiness, and BTF availability before starting.
* Keep failure messages explicit so operators know how to remediate missing prerequisites.

## Acceptance Criteria

* [x] The CLI exposes install and uninstall operations for Linux runtime deployment.
* [x] Service definitions or scripts are generated or installed for the supported init system path.
* [x] Startup checks fail with actionable diagnostics when required runtime capabilities are missing.

## Technical Approach

* Add a dedicated installer module in `walle-daemon` so service lifecycle logic remains outside CLI parsing.
* Copy the current `walle` executable and selected eBPF object into stable runtime paths.
* Write a `systemd` unit when `systemd` is available, otherwise write a fallback runner script.
* Preserve `/etc/walle/config.toml` on uninstall.
* Fail `startup()` early when environment checks report missing privileges, bpffs, kernel baseline, BTF, or interface requirements.

## Decision (ADR-lite)

**Context**: `walle run` could attach and manage runtime state, but there was no operator-facing installation path and startup checks only logged compatibility issues.

**Decision**: Introduce `walle install` / `walle uninstall`, generate `systemd` or fallback-script assets, and make startup compatibility failures hard errors.

**Consequences**: Linux deployment is now explicit and testable, and service startup fails earlier with more actionable diagnostics.

## Out of Scope

* Running `systemctl daemon-reload` automatically
* Supporting non-Linux install targets
* Managing distro-native package managers in this slice

## Technical Notes

Dependencies:

* Depends on the real loader and runtime backend.
* Packaging details may evolve further in the distribution strategy task.
* Implemented in `crates/walle-daemon/src/install.rs`, `crates/walle-daemon/src/lib.rs`, `crates/walle-daemon/src/runtime.rs`, and `crates/walle-cli/src/main.rs`.
