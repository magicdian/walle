# Implement real XDP loader and interface attach

## Goal

Replace the helper-only `walle-ebpf` scaffold with a real Linux XDP loading path that can open the BPF object, attach it to a target interface, and expose shared map handles for the rest of the runtime.

## Requirements

* Introduce a real XDP program target for Linux builds.
* Define shared BPF maps for config, allowlists, denylists, ICMP rules, and stats.
* Add userspace loader logic that loads the BPF object and attaches it to a chosen network interface.
* Keep non-Linux builds compiling by gating Linux-specific code appropriately.
* Surface attach/load failures with actionable error messages.

## Acceptance Criteria

* [ ] `walle-ebpf` contains a real XDP program and shared map definitions for Linux builds.
* [ ] The daemon or a dedicated runtime component can load and attach the XDP program to an interface.
* [ ] Loader errors identify missing interface, incompatible runtime, or attach failure conditions.
* [ ] Existing cargo checks remain green on the development host.

## Technical Notes

Dependencies:

* Must land before the real BPF map backend and ICMP dataplane enforcement.
* Will likely touch `crates/walle-ebpf`, `crates/walle-daemon`, `crates/walle-common`, and workspace manifests/tooling.
