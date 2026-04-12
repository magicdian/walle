# Backend Development Guidelines

> Best practices for backend development in this project.

---

## Overview

This directory contains the bootstrap backend guidelines for `walle`.

`walle` is currently a greenfield Rust + eBPF/XDP CLI project, so these files document:

* decisions already made during product planning
* conventions the first implementation must follow
* explicit non-goals for MVP

These guidelines should be updated again after the first Rust workspace and eBPF crates exist, so the examples section can reference real code instead of target locations.

---

## Guidelines Index

| Guide | Description | Status |
|-------|-------------|--------|
| [Directory Structure](./directory-structure.md) | Module organization and file layout | Bootstrapped v0 |
| [Database Guidelines](./database-guidelines.md) | Runtime state, persistence, map-backed data | Bootstrapped v0 |
| [Error Handling](./error-handling.md) | Error types, handling strategies | Bootstrapped v0 |
| [Quality Guidelines](./quality-guidelines.md) | Code standards, forbidden patterns | Bootstrapped v0 |
| [Logging Guidelines](./logging-guidelines.md) | Structured logging, log levels | Bootstrapped v0 |

---

## How to Use These Guidelines

1. Treat these files as the source of truth while scaffolding the first implementation.
2. When a code path exists, replace target-path examples with real file references.
3. Keep these docs aligned with [`docs/architecture/walle-system-design.md`](E:/coding/github_projects/walle/docs/architecture/walle-system-design.md).
4. If implementation diverges from these files, update the docs immediately instead of letting them drift.

---

**Language**: All documentation should be written in **English**.
