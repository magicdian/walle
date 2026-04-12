# Directory Structure

> How frontend code is organized in this project.

---

## Overview

There is no frontend code in MVP.

If a future web UI or terminal UI is added, it must be isolated from the packet-path and daemon runtime crates. UI code should not live inside core firewall logic crates.

---

## Directory Layout

```text
apps/
  console/        # optional future web console
crates/
  walle-tui/      # optional future terminal UI
```

---

## Module Organization

* Web UI, if ever added, should be feature-oriented, not page-fragment oriented.
* Terminal UI should remain a thin presentation layer over the same control-plane interfaces used by the CLI.
* UI packages must not directly own firewall policy logic; they consume validated control-plane APIs and schemas.

Do not create ad-hoc shared folders that blur boundaries between UI and core runtime crates.

---

## Naming Conventions

* Web app feature folders use `kebab-case`.
* React or UI component filenames use `PascalCase` if introduced.
* Shared schema or contract modules should mirror backend naming to reduce translation errors.

If no UI exists, do not create placeholder component trees just to satisfy structure preferences.

---

## Examples

There are no frontend examples yet by design.
