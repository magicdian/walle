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
