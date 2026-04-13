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

## XDP Development

The repository now includes a real XDP program target and an aya-based attach path for development.

```bash
cargo run -p xtask -- build-ebpf
cargo run -p walle-cli -- run --interface eth0
```

`build-ebpf` now produces the optimized release BPF object by default. Use `--debug` only when you explicitly want the debug artifact.

Use `--xdp-object <path>` to override the default object path and `--map-pin-path <path>` to override the default bpffs pin directory.
