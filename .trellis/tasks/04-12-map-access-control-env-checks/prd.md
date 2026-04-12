# Implement map-backed access control and environment checks

## Goal

Advance `walle` from phase-1 scaffolding into a phase-2 control-plane implementation by introducing explicit map contracts, a runtime repository abstraction for access-control state, and Linux environment compatibility checks for kernel, XDP, and BTF-related prerequisites.

## Requirements

* Add explicit map identity and key/value contract code for config, allowlist, denylist, ICMP rules, and stats.
* Add a runtime repository abstraction in `walle-daemon` for map-backed access-control state.
* Implement an in-memory repository that mirrors the intended BPF map behavior for phase-2 testing.
* Sync access policy and runtime config into the repository from daemon startup.
* Preserve whitelist-over-blacklist precedence.
* Add Linux environment checks for:
  * supported OS
  * kernel baseline
  * `/sys/kernel/btf/vmlinux`
  * `/sys/fs/bpf`
* Expose environment verification through CLI.
* Keep actual XDP loader attachment out of scope for this slice.

## Acceptance Criteria

* [ ] Shared map names and key/value contracts are defined in code.
* [ ] Daemon runtime can apply config, allowlist, and denylist into a repository abstraction.
* [ ] CLI can print environment verification results.
* [ ] Unit tests cover precedence and repository sync behavior.
* [ ] `cargo check` and `cargo test` pass.

## Technical Notes

* This task should prepare for a later real loader integration instead of introducing framework lock-in too early.
* The repository abstraction should make real BPF map wiring a replaceable backend, not a redesign.
