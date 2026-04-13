# Implement SSH follow service loop

## Goal

Turn the existing SSH ingestion primitives into a persistent detector loop that continuously follows configured sources and feeds ban decisions into runtime state.

## Requirements

* Add a long-running daemon loop around the existing file and journald ingestion primitives.
* Handle idle polling, backoff, and recoverable source errors without crashing the service immediately.
* Keep detector parsing and threshold logic separate from loop orchestration.
* Feed resulting ban decisions into the runtime backend continuously.

## Acceptance Criteria

* [ ] The daemon can stay running and follow configured SSH sources over time.
* [ ] Recoverable read errors are logged and retried.
* [ ] New SSH failures observed after startup can produce runtime ban writes.

## Technical Notes

Dependencies:

* Best implemented after the real BPF map backend exists.
* Likely touches `crates/walle-daemon/src/detector.rs`, `crates/walle-daemon/src/lib.rs`, and CLI entrypoints.
