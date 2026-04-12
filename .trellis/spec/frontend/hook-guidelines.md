# Hook Guidelines

> How hooks are used in this project.

---

## Overview

There are no React hooks in MVP because there is no React application.

If a future UI uses React, hooks should be reserved for UI-side stateful composition and data fetching, not for embedding firewall policy logic.

---

## Custom Hook Patterns

* Use hooks to wrap view state, polling, subscriptions, and mutation flows.
* Keep hooks focused on one capability.
* Put protocol or policy validation in shared contracts, not in ad-hoc hook code.

---

## Data Fetching

Future UI data fetching should go through a single documented mechanism. Do not mix multiple fetching libraries casually.

If real-time status is needed, prefer subscription or polling abstractions that can be tested without tying components to transport details.

---

## Naming Conventions

* Hooks must be prefixed with `use`.
* Names should reflect the user-visible capability, for example `useBanList`, `useAccessMode`, `useIcmpRules`.

---

## Common Mistakes

* Turning hooks into hidden service locators.
* Fetching unvalidated backend data directly in multiple places.
* Spreading the same side-effect logic across many hooks instead of centralizing it.
