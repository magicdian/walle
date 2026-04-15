# Linux Install And Distribution Strategy

## Goal

Define the supported release artifact layout, on-host install layout, runtime compatibility baseline, and operator-facing failure guidance for Linux deployments of `walle`.

## Release Artifact Layout

Normal Linux releases should ship prebuilt artifacts:

* `walle`
  * user-facing CLI binary
* `walle-ebpf`
  * prebuilt XDP/eBPF object
* `libnss_walle.so.2`
  * NSS identity-overlay module for runtime trap users
* `pam_walle.so`
  * PAM trap module for overlay password and account/session success
* release notes / install instructions

Operators should not need to compile the eBPF object on the target host for normal installation.

For local validation and non-production troubleshooting, `xtask build-debug` may also produce a debug bundle with the same layout under `target/debug-bundle/`. The release bundle remains the default distribution artifact. The debug bundle keeps user-space artifacts on the debug profile while packaging the optimized release `walle-ebpf` object for target-host loader compatibility. For end-to-end overlay validation, see `docs/operations/debug-bundle-test-guide.md`.

## Installed Layout

`walle install` writes the following managed files by default:

* `/usr/local/bin/walle`
* `/usr/local/lib/walle/walle-ebpf`
* `/lib/libnss_walle.so.2`
* `/usr/local/lib/walle/pam_walle.so`
* `/usr/local/lib/walle/walle-ssh-overlay.conf.sample`
* `/usr/local/lib/walle/walle-nsswitch.conf.sample`
* `/usr/local/lib/walle/walle-sshd-pam.conf.sample`
* `/usr/local/lib/walle/walle-ssh-overlay-shell`
* `/etc/walle/config.toml`
  * created only when absent
  * preserved by `walle uninstall`

Service-manager specific outputs:

* `systemd` available:
  * `/etc/systemd/system/walle.service`
* `systemd` unavailable:
  * `/usr/local/lib/walle/walle-run.sh`

The installed service and fallback script both execute:

```bash
/usr/local/bin/walle run --xdp-object /usr/local/lib/walle/walle-ebpf
```

This keeps runtime object lookup independent from the build workspace.

## Runtime Compatibility Baseline

Current supported baseline:

* Linux only
* kernel `>= 5.15`
* root privileges for runtime attach and bpffs map management
* bpffs mounted at `/sys/fs/bpf`
* kernel BTF available at `/sys/kernel/btf/vmlinux`

Current product stance:

* fail fast with precise diagnostics
* do not silently degrade to a non-XDP mode
* treat missing BTF as unsupported for the current shipped runtime path

Even though packet-only XDP paths may eventually relax the BTF dependency, the current install contract keeps BTF mandatory because startup compatibility checks enforce it.

## Install And Uninstall Flow

Install:

1. Resolve the current `walle` executable.
2. Resolve the eBPF object from:
   * `--xdp-object <path>`, if provided
   * `walle-ebpf` next to the current executable
   * `../lib/walle/walle-ebpf` relative to the current executable (`bin/walle` release layout)
   * workspace default `target/bpfel-unknown-none/release/walle-ebpf`
3. Resolve the NSS module from:
   * `libnss_walle.so.2` or `libnss_walle.so` next to the current executable
   * `../lib/libnss_walle.so.2` relative to the current executable (`bin/walle` release layout)
   * workspace fallbacks `target/release/libnss_walle.so` and `target/debug/libnss_walle.so`
4. Resolve the PAM module from:
   * `pam_walle.so` or `libpam_walle.so` next to the current executable
   * `../lib/walle/pam_walle.so` relative to the current executable (`bin/walle` release layout)
   * workspace fallbacks `target/release/libpam_walle.so` and `target/debug/libpam_walle.so`
5. Copy managed artifacts into the install layout.
6. Create `/etc/walle/config.toml` if it does not already exist.
7. Write SSH overlay samples and the trap-login shell wrapper.
8. Write a `systemd` unit when `systemd` is available; otherwise write a fallback runner script.

SSH overlay host-config activation now runs through dedicated overlay hook commands instead of top-level `walle install`:

* `walle ssh overlay install-hooks`
* `walle ssh overlay hook-status`
* `walle ssh overlay hook-disable`
* `walle ssh overlay hook-restore-backup`

`install-hooks`:

* previews only changed hunks in a patch-style format, with surrounding context
* colorizes additions and deletions on ANSI-capable terminals
* requires explicit confirmation before writing
* creates backups under `/etc/walle/ssh-overlay-hooks/`
* inserts Walle-managed markers around the SSH/PAM/NSS edits
* fails closed if the host already has conflicting `AuthorizedKeysCommand` settings, required PAM anchors are missing, or `passwd:` / `group:` / `shadow:` are missing from `nsswitch.conf`
* adds a managed `initgroups:` block when that entry is absent

`hook-disable` removes Walle-managed hook content while preserving unrelated operator edits made after installation.

`hook-restore-backup` restores the pre-hook backup files exactly.

After installing the NSS module, run `ldconfig` before enabling the overlay so the loader cache sees `libnss_walle.so.2`.

Runtime (`walle run` without `--xdp-object`) follows the same executable-relative lookup order before using the workspace fallback path.

When attaching XDP, runtime now prefers `driver` mode first and automatically falls back to `skb/generic` if the interface reports mode-not-supported (`EOPNOTSUPP` / `ENOTSUP`).

Uninstall:

1. Remove managed binary, object, and service artifacts.
2. Remove managed SSH overlay assets plus the installed NSS and PAM modules.
3. Preserve `/etc/walle/config.toml` by default so operator policy is not destroyed.

## Operator Failure Guidance

Common install/runtime failures and expected guidance:

| Failure | Meaning | Operator action |
|---------|---------|-----------------|
| missing eBPF object | install source bundle is incomplete | build with `cargo run -p xtask -- build-ebpf` or pass `--xdp-object` |
| missing NSS module | identity-overlay install source is incomplete | build with `cargo build -p walle-nss --release` or use a release bundle that includes `libnss_walle.so.2` |
| missing PAM module | password/account/session trap install source is incomplete | build with `cargo build -p walle-pam --release` or use a release bundle that includes `pam_walle.so` |
| existing `AuthorizedKeysCommand` or unexpected PAM/NSS layout | host config is outside Walle's strict managed-hook contract | remove the conflicting config manually or restore the host to the documented baseline before rerunning `walle ssh overlay install-hooks` |
| missing root privileges | install or runtime attach is not allowed | rerun install / run as `root` |
| missing bpffs mount | pinned map path is unavailable | mount bpffs at `/sys/fs/bpf` |
| missing kernel BTF | current runtime path is unsupported on this host | install kernel BTF package or use a supported kernel |
| kernel below `5.15` | host is outside the supported baseline | upgrade kernel or use a supported host |
| active runtime backend not found for `ban` commands | no live pinned maps currently exist | start `walle run` directly or install and launch the service |

## Deferred Items

Out of scope for this slice:

* distro-native package formats such as `.deb` or `.rpm`
* automatic `systemctl daemon-reload` execution from within `walle install`
* automatic config migration between future schema versions
* support for non-`systemd` service managers beyond the fallback runner script
