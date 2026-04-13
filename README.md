# walle

eBPF/XDP based Linux firewall.

## Workspace

This repository now contains the phase-1 Rust workspace scaffold for:

* `walle` (built from the `walle-cli` crate)
* `walle-daemon` runtime library
* `walle-common`
* `walle-policy`
* `walle-ebpf`
* `xtask`

The current workspace includes:

* real XDP attach and pinned-map runtime integration
* SSH detector ingestion and ban writeback
* ICMP dataplane enforcement
* Linux install / uninstall flow with `systemd` and fallback-script outputs

## XDP Development

The repository now includes a real XDP program target and an aya-based attach path for development.

```bash
cargo run -p xtask -- build-ebpf
cargo build -p walle-cli
./target/debug/walle run --interface eth0
```

`build-ebpf` now produces the optimized release BPF object by default. Use `--debug` only when you explicitly want the debug artifact.

Use `--xdp-object <path>` to override the default object path and `--map-pin-path <path>` to override the default bpffs pin directory.

## Linux Install

Build release artifacts:

```bash
cargo run -p xtask -- build-ebpf
cargo build -p walle-cli --release
```

Create a release bundle that includes both the userspace binary and the eBPF object:

```bash
cargo run -p xtask -- build-release
```

The bundle is written to `target/release-bundle/walle-v<version>-linux-<arch>.tar.gz`.

If you prefer a shell entrypoint, `./scripts/build_release.sh` is a thin wrapper around the same `xtask` command.

Install onto a Linux host:

```bash
sudo ./target/release/walle install \
  --xdp-object ./target/bpfel-unknown-none/release/walle-ebpf
```

The install flow writes:

* `/usr/local/bin/walle`
* `/usr/local/lib/walle/walle-ebpf`
* `/etc/walle/config.toml`
* `/etc/systemd/system/walle.service` when `systemd` is available
* `/usr/local/lib/walle/walle-run.sh` when `systemd` is unavailable

After install:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now walle
sudo systemctl status walle
```

When `systemd` is unavailable, run the fallback script directly:

```bash
sudo /usr/local/lib/walle/walle-run.sh
```

The runtime currently expects:

* Linux kernel `>= 5.15`
* root privileges
* bpffs mounted at `/sys/fs/bpf`
* kernel BTF at `/sys/kernel/btf/vmlinux`

More detail is documented in [docs/operations/linux-install-and-distribution.md](docs/operations/linux-install-and-distribution.md).
