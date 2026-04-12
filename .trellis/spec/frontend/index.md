# Frontend Development Guidelines

> Best practices for frontend development in this project.

---

## Overview

`walle` does not have a browser frontend in MVP.

These files exist so future UI work does not appear without boundaries. For now, they document:

* why frontend work is out of scope
* where future UI code should live if introduced
* the standards any future UI must follow

---

## Guidelines Index

| Guide | Description | Status |
|-------|-------------|--------|
| [Directory Structure](./directory-structure.md) | Module organization and file layout | Deferred by product scope |
| [Component Guidelines](./component-guidelines.md) | Component patterns, props, composition | Deferred by product scope |
| [Hook Guidelines](./hook-guidelines.md) | Custom hooks, data fetching patterns | Deferred by product scope |
| [State Management](./state-management.md) | Local state, global state, server state | Deferred by product scope |
| [Quality Guidelines](./quality-guidelines.md) | Code standards, forbidden patterns | Deferred by product scope |
| [Type Safety](./type-safety.md) | Type patterns, validation | Deferred by product scope |

---

## How to Use These Guidelines

1. Do not introduce a frontend package unless the product scope changes explicitly.
2. If a UI is added later, update these files before large-scale implementation.
3. Keep any future UI clearly separated from the Rust CLI and daemon workspace.

---

**Language**: All documentation should be written in **English**.
