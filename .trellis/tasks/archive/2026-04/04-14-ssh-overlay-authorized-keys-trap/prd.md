# OpenSSH key trap via blacklist and AuthorizedKeysCommand

## Goal

Use OpenSSH-native auth hooks to trap blacklisted keys, and runtime trap identities, into `sshjail` on the same SSH connection.

## Status

Completed on 2026-04-14 as part of the parent identity-overlay task.

## Implemented

* Static + dynamic blacklist key matching
* `AuthorizedKeysCommand` decision path
* Pending trap token persistence
* Synthetic forced-command authorized-key lines that launch `walle ssh overlay trap-shell --token ...`
* Fail-open behavior when runtime or containment is inactive

## Key Files

* `crates/walle-daemon/src/ssh_overlay.rs`
* `crates/walle-cli/src/main.rs`

## Follow-up

* Password-path same-connection trap is explicitly out of scope for this child and belongs to the PAM child task.
