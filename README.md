# walle

eBPF based firewall.

## Workspace

This repository now contains the phase-1 Rust workspace scaffold for:

* `walle-cli`
* `walle-daemon`
* `walle-common`
* `walle-policy`
* `walle-ebpf`
* `xtask`

The current focus is architecture, policy schema, and control-plane boundaries. Real XDP attach and runtime map integration will land in the next implementation slices.
