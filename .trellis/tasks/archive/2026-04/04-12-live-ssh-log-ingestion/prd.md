# Implement live SSH log ingestion

## Goal

Turn the SSH detector into a live-ingestion subsystem by adding real log-source readers for SSH auth logs and journald-backed sources, plus daemon and CLI entrypoints that exercise those readers.

## Requirements

* Support incremental reading from SSH log files such as `/var/log/auth.log` and `/var/log/secure`.
* Preserve file offsets across polling calls and handle log truncation or rotation safely.
* Add a journald-backed source implementation suitable for Linux runtime use.
* Keep detector parsing and threshold logic separate from source reading.
* Add daemon methods to poll configured SSH sources and apply resulting bans.
* Add CLI commands for:
  * polling configured SSH sources
  * replaying an arbitrary SSH log file through the detector
* Keep the implementation compilable and testable on non-Linux development hosts.

## Acceptance Criteria

* [ ] File-backed SSH log ingestion is implemented and tested.
* [ ] Journald-backed source code exists behind a runtime-compatible path.
* [ ] Daemon can poll sources and apply bans into runtime state.
* [ ] CLI exposes ingestion-oriented commands.
* [ ] `cargo check` and `cargo test` pass.
