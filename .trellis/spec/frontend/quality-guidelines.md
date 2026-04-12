# Quality Guidelines

> Code quality standards for frontend development.

---

## Overview

Frontend work is not part of MVP, but any future UI should meet the same clarity and safety expectations as the backend.

---

## Forbidden Patterns

* Shipping a UI without a documented control-plane contract.
* Embedding firewall policy logic in components.
* Unclear destructive actions for ban, allow, or mode changes.
* Silent form coercions for security-sensitive values.

---

## Required Patterns

* Explicit validation for operator input.
* Clear state transitions for destructive or high-impact actions.
* Accessibility and keyboard support for any operational dashboard or console.

---

## Testing Requirements

If a UI is added later:

* unit-test state transforms and validation
* integration-test mutation flows for rule changes
* verify error rendering for daemon and validation failures

---

## Code Review Checklist

* Does the UI reflect the real backend contract?
* Are risky operations clearly labeled and confirmable?
* Is state synchronized correctly after mutations?
* Does the change keep policy logic outside the presentation layer?
