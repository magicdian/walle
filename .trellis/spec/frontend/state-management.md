# State Management

> How state is managed in this project.

---

## Overview

There is no frontend state-management system in MVP.

If a UI is added later, it should distinguish clearly between:

* local presentation state
* server or daemon state
* user input being edited

---

## State Categories

* Local state
  * dialog visibility
  * form progress
* Server state
  * mode status
  * ban list
  * counters
* Derived state
  * filtered views
  * grouped diagnostics

---

## When to Use Global State

Only promote state to global when multiple distant UI surfaces need the same live value and prop passing becomes noisy. Do not create a global store for convenience alone.

---

## Server State

Server or daemon state should be treated as authoritative. UI caches must be invalidated explicitly after mutations that change firewall behavior.

---

## Common Mistakes

* Mixing draft form state with live daemon state.
* Re-encoding backend enums into unrelated frontend string literals.
* Building optimistic UI flows for destructive actions without a rollback story.
