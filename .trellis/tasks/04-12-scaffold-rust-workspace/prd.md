# Scaffold Rust workspace and CLI skeleton

## Goal

Create the first implementation scaffold for `walle`: a Rust workspace with clear crate boundaries, a usable CLI shell, shared runtime data structures, an initial policy schema, and placeholder daemon / eBPF modules that compile cleanly.

## Requirements

* Create a workspace rooted at `Cargo.toml`.
* Add crates for:
  * `walle-cli`
  * `walle-daemon`
  * `walle-common`
  * `walle-policy`
  * `walle-ebpf`
  * `xtask`
* Keep user-space and packet-path concerns clearly separated.
* Make the workspace compile with `cargo check`.
* Add an initial CLI surface that reflects the product design at a high level.
* Add shared enums and structs for access mode, ban metadata, ICMP matching, and runtime configuration.
* Add policy-level config structures and lightweight validation.
* Keep the eBPF crate as a phase-1 placeholder rather than overcommitting to a loader framework before the next task.

## Acceptance Criteria

* [ ] Root workspace and member manifests exist.
* [ ] `cargo check` succeeds.
* [ ] `walle-cli` exposes the initial command hierarchy.
* [ ] `walle-common` defines shared runtime-safe types.
* [ ] `walle-policy` defines operator-facing config types and validation.
* [ ] `walle-daemon` exposes a compilable service shell with detector/runtime modules.
* [ ] `walle-ebpf` exists as a `no_std` data-plane placeholder.

## Technical Notes

* Follow [`docs/architecture/walle-system-design.md`](E:/coding/github_projects/walle/docs/architecture/walle-system-design.md).
* Follow backend guidelines under [`.trellis/spec/backend/`](E:/coding/github_projects/walle/.trellis/spec/backend/index.md).
* Phase 1 intentionally stops before real XDP attach/load implementation.
