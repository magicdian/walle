# Directory Structure

> How backend code is organized in this project.

---

## Overview

`walle` should use a Rust workspace with clear crate boundaries between:

* a user-facing CLI binary
* long-running daemon logic
* shared policy and type definitions
* NSS identity-overlay integration
* PAM trap integration
* eBPF/XDP program code
* build and developer automation

Because the project is greenfield, this file is a contract for the first scaffold rather than a summary of existing code.

---

## Directory Layout

```text
Cargo.toml
crates/
  walle-cli/
    src/
  walle-daemon/
    src/
      detector/
      policy/
      runtime/
  walle-common/
    src/
  walle-nss/
    src/
  walle-pam/
    src/
  walle-policy/
    src/
  walle-ebpf/
    src/
xtask/
  src/
docs/
  architecture/
fixtures/
```

---

## Module Organization

Use these ownership rules:

* `walle-cli`
  * command parsing for the user-facing `walle` binary
  * output formatting
  * no packet-path business logic
* `walle-daemon`
  * runtime library for service lifecycle
  * detector pipelines
  * map synchronization
  * runtime orchestration
* `walle-common`
  * plain shared structs and enums that do not pull in heavy runtime dependencies
* `walle-nss`
  * NSS identity-overlay glue used by `sshd` account lookups
  * no daemon lifecycle or packet-path logic
* `walle-pam`
  * PAM auth/account/session trap glue used by `sshd`
  * capture only the PAM-facing data needed for overlay trap behavior
* `walle-policy`
  * config schema
  * validation
  * rule compilation from operator-facing config into runtime-friendly structures
* `walle-ebpf`
  * eBPF-safe data structures
  * XDP parsing and actions
  * no allocations, panics, or control-plane concerns
* `xtask`
  * local development commands such as build, test, bundle, and attach helpers

Avoid "misc" crates or generic utility dumping grounds. If a new module cannot be clearly placed, revisit the architecture before adding it.

---

## Naming Conventions

* Crates use `kebab-case` names prefixed with `walle-` when they are product-owned workspace crates.
* Rust modules and files use `snake_case`.
* eBPF-facing structs should use explicit names that reflect map or packet semantics, for example `AccessModeConfig`, `BanEntryV4`, `IcmpRule`.
* Avoid vague names such as `manager`, `helper`, `utils`, or `common` at the module level unless the scope is extremely obvious.
* Separate IPv4 and IPv6 types when it keeps the fast path simpler and avoids ambiguous layouts.

Prefer files organized by capability, not by framework artifact. For example, `detector/ssh.rs` is better than `services/service1.rs`.

---

## Examples

Current scaffold examples:

* [`walle-cli main`](E:/coding/github_projects/walle/crates/walle-cli/src/main.rs): the user-facing `walle` binary entrypoint and command tree
* [`walle-daemon lib`](E:/coding/github_projects/walle/crates/walle-daemon/src/lib.rs): runtime orchestration boundary kept outside CLI parsing
* [`walle-daemon detector`](E:/coding/github_projects/walle/crates/walle-daemon/src/detector.rs): SSH detector module ownership
* [`walle-nss lib`](E:/coding/github_projects/walle/crates/walle-nss/src/lib.rs): NSS identity-overlay boundary
* [`walle-pam lib`](E:/coding/github_projects/walle/crates/walle-pam/src/lib.rs): PAM trap boundary
* [`walle-ebpf lib`](E:/coding/github_projects/walle/crates/walle-ebpf/src/lib.rs): packet-path placeholder code
