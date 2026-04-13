# Error Handling

> How errors are handled in this project.

---

## Overview

`walle` has three different error domains and they should stay distinct:

* CLI input and operator-facing usage errors
* daemon runtime and integration errors
* eBPF/XDP decision-path failures

Each layer should use the narrowest error style that still preserves enough context for debugging.

---

## Error Types

Recommended conventions:

* use typed errors with `thiserror` in library crates
* use `anyhow` only at binary boundaries where errors are collected and rendered
* define domain errors by capability, for example:
  * `ConfigError`
  * `MapUpdateError`
  * `AttachError`
  * `DetectorError`
* keep eBPF-side error signaling explicit through counters, flags, or fallback actions instead of pretending kernel-side code can propagate rich Rust errors

Map external library errors into product-owned types before they cross crate boundaries.

---

## Error Handling Patterns

* Add context at boundary crossings, for example "failed to attach XDP program to interface".
* Return typed errors from library code instead of formatting strings early.
* Convert errors into user-facing messages only at CLI presentation boundaries.
* In long-running services, prefer handling and logging recoverable errors over crashing the daemon.
* In XDP code, default to the safest explicit action for parser failures and count them in stats.

Do not use panics for expected runtime conditions such as invalid user input, missing config entries, or transient attach failures.

---

## API Error Responses

The project currently has no HTTP API in MVP.

Equivalent operator-facing behavior should be:

* CLI exits non-zero on failure
* human-readable summary on stderr
* optional structured log event with more detail in daemon mode
* clear distinction between:
  * validation errors
  * environment or permissions errors
  * runtime attach or map errors

If a machine-readable API is introduced later, it should preserve stable error codes distinct from presentation text.

---

## Common Mistakes

* Using `unwrap` or `expect` in long-running daemon code.
* Returning stringly-typed errors from lower layers.
* Hiding whether a failure happened in detector logic, control-plane sync, or XDP attachment.
* Logging an error without enough structured context to reproduce the issue.

## Scenario: SSH Ingestion Errors

### 1. Scope / Trigger

* Trigger: Any change to SSH log ingestion, file readers, journald readers, or detector polling entrypoints.

### 2. Signatures

* `SshLogIngestor::poll_lines() -> Result<Vec<String>, SshIngestError>`
* `SshLogIngestor::read_all_lines_from_file(PathBuf) -> Result<Vec<String>, SshIngestError>`
* `WalleDaemon::poll_ssh_sources(u64) -> Result<SshIngestSummary, DaemonError>`
* `WalleDaemon::replay_ssh_log_file(PathBuf, u64, u64) -> Result<SshIngestSummary, DaemonError>`

### 3. Contracts

* file read failures must keep the source path in the error
* seek failures must keep the source path in the error
* journald unsupported on non-Linux hosts must return a typed unsupported error
* daemon boundaries should expose ingestion failures as `DaemonError::SshIngest`

### 4. Validation & Error Matrix

* missing log file -> `SshIngestError::ReadLogFile`
* seek failure -> `SshIngestError::SeekLogFile`
* non-Linux journald path -> `SshIngestError::UnsupportedJournald`
* `journalctl` spawn failure -> `SshIngestError::Journalctl`
* `journalctl` non-zero exit -> `SshIngestError::JournalctlFailed`

### 5. Good/Base/Bad Cases

* Good:
  * daemon caller receives a typed ingestion error with source context
  * replaying a valid SSH log file yields a summary instead of partial side effects only
* Base:
  * polling with no new lines returns an empty summary
* Bad:
  * swallowing journald failure and pretending no events exist
  * returning plain strings with no source path information

### 6. Tests Required

* file cursor tests must cover incremental reads
* replay tests must cover full-file reads
* non-Linux code paths must compile cleanly even if journald runtime is unavailable

### 7. Wrong vs Correct

#### Wrong

* Convert every ingestion failure to `"ssh detector failed"` at the lower layer.

#### Correct

* Preserve source-specific typed errors in the detector layer and map them into `DaemonError` only at the daemon boundary.

Current scaffold examples:

* [`walle-daemon error`](E:/coding/github_projects/walle/crates/walle-daemon/src/error.rs): daemon-owned typed error boundary
* [`walle-cli main`](E:/coding/github_projects/walle/crates/walle-cli/src/main.rs): binary-boundary error rendering for the unified `walle` executable
* [`walle-policy errors`](E:/coding/github_projects/walle/crates/walle-policy/src/lib.rs): validation-focused typed errors
