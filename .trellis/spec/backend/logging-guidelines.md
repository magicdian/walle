# Logging Guidelines

> How logging is done in this project.

---

## Overview

`walle` should default to structured logging in user space and counters in the XDP data plane.

Recommended stack:

* `tracing` for instrumentation
* `tracing-subscriber` for formatting and filtering
* human-readable output for local CLI workflows
* JSON output for daemon and service environments when needed

Kernel-side eBPF programs should not rely on chatty logs. Use counters and explicit telemetry maps for hot-path observability.

---

## Log Levels

* `debug`
  * per-step control-plane operations
  * detector state transitions during development
* `info`
  * service start and stop
  * XDP attach and detach success
  * mode changes
  * ban and unban decisions
* `warn`
  * suspicious but recoverable detector conditions
  * map update retries
  * malformed events that are skipped
* `error`
  * attach failures
  * unrecoverable config issues
  * repeated map synchronization failures

Do not log one line per packet in production paths.

---

## Structured Logging

Include stable fields when available:

* `component`
* `event`
* `interface`
* `ip`
* `access_mode`
* `reason`
* `ban_source`
* `expires_at`
* `result`

Field names should stay consistent across CLI, daemon, and future integrations.

---

## What to Log

* daemon startup and shutdown
* config load and validation results
* XDP attach and detach operations
* access-mode changes
* allowlist and denylist mutations
* SSH detector threshold hits
* unban events
* ICMP policy changes
* repeated parser or map access failures
* version and compatibility information on startup

Prefer one well-structured event over multiple partially redundant lines.

---

## What NOT to Log

* private keys
* secrets or credentials
* full raw packet payloads by default
* regex source patterns if they contain sensitive data in future rule systems
* noisy per-packet decisions in hot paths
* duplicate stack traces for the same failure loop

## Scenario: SSH Detector Operational Logs

### 1. Scope / Trigger

* Trigger: Any change to SSH source selection, live ingestion, ban thresholding, or runtime ban application.

### 2. Signatures

* `SshDetectorService::log_startup()`
* `log_environment_report(&EnvironmentReport)`
* runtime ban application debug events in `RuntimeController::apply_ssh_ban`

### 3. Contracts

* startup logging must include resolved SSH sources
* environment logging must include compatibility result and kernel release when available
* runtime SSH ban writeback must log:
  * `ip`
  * `matched_failures`
  * `expires_at_secs`

### 4. Validation & Error Matrix

* successful source planning -> `info` log
* detector configuration details -> `debug` log
* detected log truncation or rotation -> `warn` log
* environment verification details -> `debug` log per check

### 5. Good/Base/Bad Cases

* Good:
  * one structured startup log shows the actual selected SSH sources
  * one structured runtime event shows when a detector ban is applied
* Base:
  * no new SSH lines can produce no extra logs beyond polling summaries
* Bad:
  * logging entire auth log lines verbatim at info level
  * logging raw packet payloads or secrets while diagnosing SSH ingestion

### 6. Tests Required

* tests should assert source-resolution behavior even if they do not snapshot logs directly
* code review should verify new detector log lines use stable structured fields

### 7. Wrong vs Correct

#### Wrong

* Emit unstructured strings like `"banned something from ssh log"` with no IP or source context.

#### Correct

* Emit stable structured fields such as `component=ssh-detector`, `event=source_plan`, `ip`, and `expires_at_secs`.

Current scaffold examples:

* [`walle-daemon lib`](E:/coding/github_projects/walle/crates/walle-daemon/src/lib.rs): lifecycle logging
* [`walle-daemon detector`](E:/coding/github_projects/walle/crates/walle-daemon/src/detector.rs): detector config logging
* [`walle-daemon runtime`](E:/coding/github_projects/walle/crates/walle-daemon/src/runtime.rs): runtime sync logging

## Scenario: Config-Driven Log Level Contract

### 1. Scope / Trigger

* Trigger: Any change to tracing initialization, operator-facing log verbosity, or service deployment logging behavior.

### 2. Signatures

* `WalleConfig::logging_policy() -> &LoggingPolicy`
* `policy.logging.level`
* `init_tracing(LogLevel)`
* `walle run`

### 3. Contracts

* User-space log level must be sourced from `config.toml`, not require `RUST_LOG` to be set in the environment.
* The operator-facing field lives in global policy config as `policy.logging.level`.
* Supported values are the typed set `trace`, `debug`, `info`, `warn`, and `error`.
* Default config behavior must produce `info` logs when no explicit level is configured.
* The same config-driven level must apply to local CLI runs and service-managed runs such as systemd.

### 4. Good/Base/Bad Cases

* Good:
  * operators set `policy.logging.level = "debug"` once and get the same verbosity in foreground runs and systemd service restarts.
* Base:
  * omitted logging config falls back to `info`.
* Bad:
  * keeping production log level only in service-unit environment variables while config owns the rest of the runtime contract.

### 5. Tests Required

* policy parsing tests must cover explicit logging level values and default fallback behavior.
