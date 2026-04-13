# Implement Linux service install flow

## Goal

Provide a Linux-native installation and lifecycle flow that places `walle` into system runtime paths, sets up service management, and performs startup-time capability checks.

## Requirements

* Add CLI-driven install and uninstall flows.
* Install service definitions for `systemd`, with a fallback strategy when `systemd` is unavailable.
* Check runtime prerequisites such as privileges, bpffs readiness, and BTF availability before starting.
* Keep failure messages explicit so operators know how to remediate missing prerequisites.

## Acceptance Criteria

* [ ] The CLI exposes install and uninstall operations for Linux runtime deployment.
* [ ] Service definitions or scripts are generated or installed for the supported init system path.
* [ ] Startup checks fail with actionable diagnostics when required runtime capabilities are missing.

## Technical Notes

Dependencies:

* Depends on the real loader and runtime backend.
* Packaging details may evolve further in the distribution strategy task.
