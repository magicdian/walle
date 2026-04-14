# Fix Install eBPF Lookup Path For Distribution Bundle

## Goal
Make `walle install` and `walle run` resolve the eBPF object correctly in packaged/distributed environments without relying on developer workspace paths.

## Requirements
- Update install-time eBPF object discovery to support release bundle layout.
- Update runtime (`walle run`) default eBPF object discovery to support release bundle layout.
- Candidate path should include executable-relative `../lib/walle/walle-ebpf`.
- Keep explicit `--xdp-object` behavior unchanged.
- Preserve actionable error message with searched paths.
- XDP attach should try `driver` mode first, and fallback to `skb/generic` when driver mode is not supported by the interface.

## Acceptance Criteria
- [ ] Running `./bin/walle install` in bundle root where `lib/walle/walle-ebpf` exists succeeds in locating object.
- [ ] Running `walle run` without `--xdp-object` in installed or release-bundle layout can locate the object without workspace path dependency.
- [ ] Existing local-dev fallback path still works where appropriate.
- [ ] Missing-object errors still report all searched paths.
- [ ] Unit tests cover executable-relative bundle lookup for install and runtime path resolution.
- [ ] On interfaces that do not support driver mode, runtime attempts `skb/generic` automatically instead of failing immediately.

## Technical Notes
- Primary changes expected in `crates/walle-daemon/src/install.rs` and `crates/walle-daemon/src/xdp.rs`.
- Avoid hard dependency on source checkout path at runtime in release environments.
