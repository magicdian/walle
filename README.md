# walle

eBPF/XDP based Linux firewall.

## Workspace

This repository now contains the phase-1 Rust workspace scaffold for:

* `walle` (built from the `walle-cli` crate)
* `walle-daemon` runtime library
* `walle-common`
* `walle-policy`
* `walle-ebpf`
* `walle-nss`
* `walle-pam`
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
cargo build -p walle-nss --release
cargo build -p walle-pam --release
```

Create a release bundle that includes the userspace binary, the eBPF object, the NSS identity-overlay module, and the PAM trap module:

```bash
cargo run -p xtask -- build-release
```

The bundle is written to `target/release-bundle/walle-v<version>-linux-<arch>.tar.gz`.

For local validation, you can also build a debug bundle with the same contents:

```bash
cargo run -p xtask -- build-debug
```

The debug bundle is written to `target/debug-bundle/walle-v<version>-linux-<arch>-debug.tar.gz`.
The debug bundle keeps the user-space binaries on the debug profile while still packaging the optimized release `walle-ebpf` object for loader compatibility.

For end-to-end host validation from the debug bundle, see [docs/operations/debug-bundle-test-guide.md](docs/operations/debug-bundle-test-guide.md).

If you prefer a shell entrypoint, `./scripts/build_release.sh` is a thin wrapper around the same `xtask` command.

Install onto a Linux host:

```bash
sudo ./target/release/walle install \
  --xdp-object ./target/bpfel-unknown-none/release/walle-ebpf
```

The install flow writes:

* `/usr/local/bin/walle`
* `/usr/local/lib/walle/walle-ebpf`
* `/lib/libnss_walle.so.2`
* `/usr/local/lib/walle/pam_walle.so`
* `/usr/local/lib/walle/walle-ssh-overlay.conf.sample`
* `/usr/local/lib/walle/walle-nsswitch.conf.sample`
* `/usr/local/lib/walle/walle-sshd-pam.conf.sample`
* `/usr/local/lib/walle/walle-ssh-overlay-shell`
* `/etc/walle/config.toml`
* `/etc/systemd/system/walle.service` when `systemd` is available
* `/usr/local/lib/walle/walle-run.sh` when `systemd` is unavailable

After install:

```bash
sudo ldconfig
sudo systemctl daemon-reload
sudo systemctl enable --now walle
sudo systemctl status walle
```

If you want the SSH identity overlay, install the managed hooks:

```bash
sudo /usr/local/bin/walle ssh overlay install-hooks
sudo sshd -t
sudo systemctl restart ssh || sudo service ssh restart
```

The hook installer:

* shows only changed patch hunks before writing, with surrounding context
* colorizes additions and deletions on ANSI-capable terminals
* requires explicit confirmation
* creates backups under `/etc/walle/ssh-overlay-hooks/`
* fails closed if the host already has conflicting `AuthorizedKeysCommand` settings, required PAM anchors are missing, or `passwd:` / `group:` / `shadow:` are missing from `nsswitch.conf`
* adds a managed `initgroups:` block when that entry is absent

Related lifecycle commands:

```bash
sudo /usr/local/bin/walle ssh overlay hook-status
sudo /usr/local/bin/walle ssh overlay hook-disable
sudo /usr/local/bin/walle ssh overlay hook-restore-backup
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
