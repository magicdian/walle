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
* Letting the OS default `SIGINT` / `SIGTERM` path terminate the process before runtime cleanup has a chance to run.

## Scenario: Foreground Shutdown And Runtime Cleanup

### 1. Scope / Trigger

* Trigger: Any change to `walle run`, daemon foreground loops, signal handling, XDP/tc ownership, pinned map cleanup, or sshjail lifecycle.

### 2. Signatures

* `walle_cli::run_command(RunArgs) -> Result<()>`
* `walle_daemon::WalleDaemon::run() -> Result<DaemonRunOutcome, DaemonError>`
* `walle_daemon::WalleDaemon::run_ssh_follow_loop(...)`
* `walle_daemon::xdp::XdpAttachment`
* `walle_daemon::sshjail::SshJailService`

### 3. Contracts

* Foreground `walle run` must intercept operator shutdown signals such as `SIGINT` and `SIGTERM`.
* Shutdown requests must translate into a normal Rust return path instead of abrupt process death.
* Graceful shutdown must release managed runtime resources before success is reported:
  * XDP links
  * tc classifiers
  * managed map pins
  * sshjail listener threads
* If signal-handler installation fails, the daemon must return a typed setup error instead of silently running without cleanup guarantees.

### 4. Validation & Error Matrix

* `Ctrl+C` during foreground follow loop -> loop exits cleanly and returns `DaemonRunOutcome::ShutdownRequested`
* bounded foreground follow loop reaches iteration limit -> returns `DaemonRunOutcome::ForegroundLoopCompleted`
* signal handler registration failure -> `DaemonError::InstallSignalHandler`
* graceful teardown path removes managed map pins -> no stale pin files remain for the owned interface

### 5. Good/Base/Bad Cases

* Good:
  * operator presses `Ctrl+C`, daemon logs a shutdown request, releases runtime resources, and exits without leaving tc redirect state behind
* Base:
  * startup-only code paths that do not enter the foreground loop may return `StartupOnly`
* Bad:
  * `Ctrl+C` kills the process through the default signal action before `Drop` or explicit cleanup runs
  * CLI prints a normal loop-complete message after a signal-triggered stop

### 6. Tests Required

* daemon tests must cover in-process shutdown propagation through the foreground loop
* runtime cleanup tests must cover managed pin-file removal without requiring live eBPF attach

### 7. Wrong vs Correct

#### Wrong

* Treat `Ctrl+C` as “just another exit” and assume kernel-managed resources disappear automatically.

#### Correct

* Convert shutdown signals into an explicit control-path outcome, then release managed runtime resources before returning success to the CLI.

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

## Scenario: Linux Install, Startup Compatibility, And Release Bundle Errors

### 1. Scope / Trigger

* Trigger: Any change to `walle install`, `walle uninstall`, daemon startup compatibility checks, live-runtime availability checks, or `xtask build-release`.

### 2. Signatures

* `walle install [--root <path>] [--xdp-object <path>]`
* `walle uninstall [--root <path>]`
* `walle run [--interface <name>] [--xdp-object <path>]`
* `install::install(InstallOptions) -> Result<InstallReport, InstallError>`
* `install::uninstall(UninstallOptions) -> Result<UninstallReport, InstallError>`
* `install::resolve_xdp_object(Option<&Path>, &Path) -> Result<PathBuf, InstallError>`
* `WalleDaemon::startup() -> Result<(), DaemonError>`
* `xdp::attach(&str, Option<&Path>, Option<&Path>) -> Result<XdpAttachment, XdpError>`
* `xdp::attach_xdp_program_with_fallback(&mut Xdp, &str) -> Result<&'static str, XdpError>`
* `WalleDaemon::add_manual_ban(...) -> Result<(), DaemonError>`
* `WalleDaemon::list_bans() -> Result<BanStatusSnapshot, DaemonError>`
* `cargo run -p xtask -- build-release`

### 3. Contracts

* Install / uninstall failures must stay in the installer boundary as typed `InstallError` values until the CLI renders them.
* Installing into `/` without root privileges must fail explicitly; do not attempt partial writes and do not silently downgrade the target path.
* Missing eBPF release objects during install must mention the searched paths and the operator remediation path.
* Install and runtime default object lookup must search in this order when `--xdp-object` is absent:
  * `walle-ebpf` next to the current executable
  * `../lib/walle/walle-ebpf` relative to the current executable when binary path is `.../bin/walle`
  * workspace fallback `target/bpfel-unknown-none/release/walle-ebpf`
* Runtime XDP attach must prefer `driver` mode first and fallback to `skb/generic` only when driver mode returns `EOPNOTSUPP`/`ENOTSUP`.
* If both driver and fallback attach fail, error text must preserve both failure causes (`driver_error`, `generic_error`) for operator diagnosis.
* `WalleDaemon::startup()` must fail fast with `DaemonError::EnvironmentIncompatible` when compatibility checks contain any hard failures.
* Ban commands that require active pinned maps must fail with `DaemonError::NoActiveRuntime` instead of pretending the action succeeded.
* `xtask build-release` must fail if either:
  * the release `walle` binary cannot be built
  * the release `walle-ebpf` object cannot be built
  * the release bundle archive cannot be created

### 4. Validation & Error Matrix

* non-Linux host install request -> `InstallError::UnsupportedHost`
* install into `/` without root -> `InstallError::MissingPrivileges`
* explicit `--xdp-object` path missing -> `InstallError::MissingXdpObject`
* implicit install object lookup miss (adjacent + bundled + workspace all missing) -> `InstallError::MissingXdpObject` with full `searched` list
* startup with missing bpffs / missing BTF / unsupported kernel / missing privileges -> `DaemonError::EnvironmentIncompatible`
* runtime implicit object lookup miss -> `XdpError::MissingObject` with full `searched` list
* runtime driver attach returns `EOPNOTSUPP` / `ENOTSUP` -> emit fallback warning and retry in `skb/generic`
* runtime driver attach fails with non-mode-support error -> fail with `XdpError::ProgramAttach` (`mode = "driver"`)
* runtime driver attach mode-not-supported and fallback attach also fails -> `XdpError::ProgramAttachFallback`
* `walle ban list` with no active runtime backend -> `DaemonError::NoActiveRuntime`
* `xtask build-release` userspace build failure -> command exits non-zero with release-build context
* `xtask build-release` eBPF build failure -> command exits non-zero with eBPF-build context
* `xtask build-release` tar packaging failure -> command exits non-zero with archive-build context

### 5. Good/Base/Bad Cases

* Good:
  * installing with a valid binary + eBPF object returns concrete output paths and selected service-manager mode.
  * startup on an unsupported host fails before attempting XDP attach and prints actionable compatibility details.
  * on cloud interfaces without driver support, runtime logs one fallback warning and attaches successfully in `skb/generic` mode.
  * `cargo run -p xtask -- build-release` produces one bundle that always contains both `walle` and `walle-ebpf`.
* Base:
  * uninstall can succeed even when some managed files are already absent.
  * a custom non-`/` install root is allowed without root checks so packaging tests can stage files in temp directories.
* Bad:
  * allowing install to partially copy files before returning a vague permission error.
  * letting startup continue after a known compatibility failure and only surfacing the problem later in the attach path.
  * failing immediately on driver-mode `ENOTSUP` without attempting a generic fallback on interfaces that support only `skb/generic`.
  * publishing a release artifact that contains the userspace binary but omits the eBPF object.

### 6. Tests Required

* installer tests must assert systemd asset generation, config preservation, and uninstall cleanup behavior.
* installer and runtime path-resolution tests must assert bundled layout lookup (`bin/walle` + `lib/walle/walle-ebpf`) before workspace fallback.
* daemon tests or review must confirm startup returns a typed compatibility error before XDP attach on failed environment checks.
* XDP tests or review must confirm:
  * driver attach path is attempted first
  * `ENOTSUP` / `EOPNOTSUPP` triggers fallback to `skb/generic`
  * fallback success logs selected `xdp_mode`
  * dual-failure surfaces `ProgramAttachFallback`
* manual validation must cover `cargo run -p xtask -- build-release` and confirm the produced archive includes both `bin/walle` and `lib/walle/walle-ebpf`.
* shell wrapper validation must keep `scripts/build_release.sh` as a thin pass-through to the `xtask` command.

### 7. Wrong vs Correct

#### Wrong

* Rely on README instructions alone and assume release engineering will remember to include the eBPF object next to the userspace binary.
* Assume all Linux 5.15 hosts can attach XDP in driver mode without interface-level capability fallback.

#### Correct

* Encode release bundling and installer/runtime attach behavior as typed contracts: deterministic object lookup, driver-first attach with explicit `skb/generic` fallback for mode-not-supported errors, and actionable diagnostics when attach still fails.
