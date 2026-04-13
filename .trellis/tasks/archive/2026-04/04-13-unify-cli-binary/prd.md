# Unify CLI Binary and Remove Daemon Executable

## Goal
Provide a single user-facing `walle` binary for distribution while keeping the runtime implementation in a reusable library crate.

## Requirements
- Rename the user-facing executable from `walle-cli` to `walle`.
- Remove the standalone `walle-daemon` executable from normal workspace build outputs.
- Keep the existing runtime implementation available as a library for the `walle` binary.
- Keep `run` as the only service start command.
- Add single-instance protection to `walle run` so it exits when another active instance already holds the runtime lock.
- Reserve a `reload` command shape for future configuration reload work without implementing reload behavior now.

## Acceptance Criteria
- [ ] `cargo build` no longer produces a `target/debug/walle-daemon` executable.
- [ ] `cargo build` produces a `target/debug/walle` executable.
- [ ] `walle run` fails with a clear error when another active instance is already running.
- [ ] Existing operator control commands continue to be available from the unified `walle` binary.
- [ ] The codebase still keeps runtime/service logic outside the CLI command parsing layer.

## Technical Notes
- Use a user-space single-instance mechanism that does not depend on inferring eBPF attach state.
- Treat this as a command/runtime contract change and keep future `reload` behavior extensible.
- Do not implement config reload signaling or map refresh in this task.

## Contract Notes
- Binary contract:
  - `cargo build` should emit a host executable named `walle`.
  - `cargo build` should not emit a host executable named `walle-daemon`.
- Command contract:
  - `walle run` starts the runtime in foreground mode.
  - `walle reload` exists only as a reserved command placeholder and must return a clear "not implemented" style error.
- Runtime lock contract:
  - If an active instance already holds the runtime lock, `walle run` must exit without attempting another attach.
  - If the lock is stale, a new `walle run` may recover it and continue startup.

## Good / Base / Bad Cases
- Good: first `walle run` acquires the lock, starts normally, and leaves the runtime logic in library code.
- Base: `walle reload` parses as a valid command and exits with a clear unimplemented error.
- Bad: a second `walle run` proceeds into XDP attach despite another active instance already running.
