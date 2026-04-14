# Runtime NSS identity overlay and trap login entrypoint

## Goal

Expose runtime trap identities to `sshd` through NSS while `walle` is active, and provide a trap-login entrypoint for shell-based sessions that do not use pending public-key tokens.

## Status

Completed on 2026-04-14 as part of the parent identity-overlay task.

## Implemented

* Runtime invalid-user promotion into typed trap identities
* Ephemeral trap identity persistence under `<root>/gp/ssh/state/trap_identities.runtime`
* `walle-nss` passwd/group/shadow/initgroups hooks
* Trap-login shell path and local trap-login entrypoint
* Runtime reset behavior that clears overlay state when `walle` stops

## Key Files

* `crates/walle-daemon/src/ssh_overlay.rs`
* `crates/walle-daemon/src/sshjail.rs`
* `crates/walle-nss/src/lib.rs`

## Follow-up

* Password auth for these identities still needs a PAM hook.
