# Type Safety

> Type safety patterns in this project.

---

## Overview

There is no TypeScript frontend in MVP.

If a future UI is introduced, type safety must follow the control-plane contracts already defined by the Rust backend and policy schema.

---

## Type Organization

* Shared contract types should be generated or mirrored from a single source of truth where practical.
* UI-only view models can live near the consuming feature.
* Do not duplicate backend enums manually in many places.

---

## Validation

If a UI accepts operator input, validate it at both the UI boundary and the backend boundary. UI validation improves usability; backend validation preserves correctness.

---

## Common Patterns

* Prefer discriminated unions for mode or rule variants.
* Keep runtime validation aligned with compile-time types.
* Use explicit transform layers for display-specific formatting.

---

## Forbidden Patterns

* `any`
* broad unchecked type assertions
* duplicating backend contract types without review
* using plain strings for security-sensitive enum-like values
