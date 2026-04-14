# Identity overlay install and release integration

## Goal

Make the identity overlay deployable by shipping the NSS module, trap-login shell wrapper, and operator-facing sample fragments through install and release workflows.

## Status

Completed on 2026-04-14 as part of the parent identity-overlay task.

## Implemented

* `walle install` now installs:
  * `libnss_walle.so.2`
  * `walle-ssh-overlay-shell`
  * `walle-ssh-overlay.conf.sample`
  * `walle-nsswitch.conf.sample`
* CLI install output now reports these paths and next-step guidance.
* Release bundles now include the NSS module.
* README and operations docs describe manual `sshd_config` / `nsswitch.conf` merge steps and `ldconfig`.

## Key Files

* `crates/walle-daemon/src/install.rs`
* `crates/walle-cli/src/main.rs`
* `xtask/src/main.rs`
* `README.md`
* `docs/operations/linux-install-and-distribution.md`

## Follow-up

* Distro-specific NSS libdir variants may need a later packaging pass.
