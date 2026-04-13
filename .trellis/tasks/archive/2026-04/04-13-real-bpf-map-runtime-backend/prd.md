# Implement real BPF map runtime backend

## Goal

Replace the daemon's in-memory runtime repository with real BPF map reads and writes so user-space policy changes are reflected in kernel-visible shared state.

## Requirements

* Introduce a runtime repository backed by real BPF map handles.
* Support config, allowlist, denylist, and ICMP rule synchronization.
* Preserve IPv4 and IPv6 key handling using the contracts in `walle-common`.
* Make the backend work with pinned or loader-owned map handles from the XDP attach layer.
* Keep an inspectable snapshot path for status reporting.

## Acceptance Criteria

* [ ] Policy sync writes to real BPF maps instead of the in-memory repository on Linux.
* [ ] Runtime snapshot and list/status flows read counts from the real backend.
* [ ] The backend has tests or structure that validates key/value encoding and replace/update behavior.
* [ ] The code remains compilable on non-Linux hosts via clear fallback boundaries.

## Technical Notes

Dependencies:

* Depends on the real XDP loader and shared map definitions.
* Enables later ban lifecycle and SSH follow loop integration.
