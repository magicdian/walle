# Linux Install And Distribution Strategy

## Goal

Define the supported release artifact layout, on-host install layout, runtime compatibility baseline, and operator-facing failure guidance for Linux deployments of `walle`.

## Release Artifact Layout

Normal Linux releases should ship prebuilt artifacts:

* `walle`
  * user-facing CLI binary
* `walle-ebpf`
  * prebuilt XDP/eBPF object
* release notes / install instructions

Operators should not need to compile the eBPF object on the target host for normal installation.

## Installed Layout

`walle install` writes the following managed files by default:

* `/usr/local/bin/walle`
* `/usr/local/lib/walle/walle-ebpf`
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
   * workspace default `target/bpfel-unknown-none/release/walle-ebpf`
3. Copy managed artifacts into the install layout.
4. Create `/etc/walle/config.toml` if it does not already exist.
5. Write a `systemd` unit when `systemd` is available; otherwise write a fallback runner script.

Uninstall:

1. Remove managed binary, object, and service artifacts.
2. Preserve `/etc/walle/config.toml` by default so operator policy is not destroyed.

## Operator Failure Guidance

Common install/runtime failures and expected guidance:

| Failure | Meaning | Operator action |
|---------|---------|-----------------|
| missing eBPF object | install source bundle is incomplete | build with `cargo run -p xtask -- build-ebpf` or pass `--xdp-object` |
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
