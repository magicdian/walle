# Component Guidelines

> How components are built in this project.

---

## Overview

No browser component system exists in MVP.

If UI work is introduced later, components should be thin, composable, and clearly separated from security policy logic.

---

## Component Structure

Future component files should prefer:

* a single exported component per file
* colocated tests when practical
* minimal view-only helpers inside the same file
* extraction of non-visual logic into hooks or controller modules

---

## Props Conventions

* Props should use explicit interfaces or type aliases.
* Avoid `any`, broad index signatures, or unvalidated config blobs.
* Components should receive normalized UI-facing data, not raw daemon responses when a view model layer is warranted.

---

## Styling Patterns

This project has no styling system today.

If a web UI is added later:

* choose one styling approach and document it first
* avoid mixing multiple styling systems in the same app
* preserve a utilitarian operational tool aesthetic over marketing-style UI

---

## Accessibility

Any future UI must support keyboard navigation, clear status semantics, and readable state transitions. Firewall tooling is operational software, so error visibility matters as much as visual polish.

---

## Common Mistakes

* Embedding business logic directly in view components.
* Hiding destructive or security-sensitive actions behind unclear UI affordances.
* Creating a UI package before there is a stable control-plane contract.
