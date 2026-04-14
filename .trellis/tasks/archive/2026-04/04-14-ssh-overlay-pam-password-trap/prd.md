# Invalid-user password trap via PAM overlay hook

## Goal

Complete same-connection password trapping for runtime overlay identities without changing real-user password login behavior.

## Status

Completed on 2026-04-14. This was the final gap in the current identity-overlay implementation.

## Why It Exists

* `NSS` can make a runtime trap identity appear as a valid user.
* `AuthorizedKeysCommand` can complete same-connection trap for public-key auth.
* Password authentication success still belongs to `PAM`, so invalid-user password trap is not complete yet.

## Requirements

* Detect trap identities during password auth.
* Record presented passwords only for trap identities.
* Return success only for trap identities that are intentionally being trapped.
* Fail open for real users and for overlay-unavailable states.
* Preserve ordinary `PAM` behavior for legitimate accounts.

## Acceptance Criteria

* [x] A runtime trap identity can log in with arbitrary password input and land in `sshjail` on the same connection.
* [x] Real users still authenticate through ordinary PAM configuration with no behavior regression.
* [x] Presented passwords are recorded only for trap identities, not for benign sessions.
* [x] Overlay/PAM failures fail open for legitimate users.

## Likely Key Files

* `crates/walle-daemon/src/ssh_overlay.rs`
* `crates/walle-daemon/src/sshjail.rs`
* `crates/walle-nss/src/lib.rs`
* `crates/walle-pam/src/lib.rs`
* `crates/walle-daemon/src/install.rs`
* `crates/walle-cli/src/main.rs`
* `xtask/src/main.rs`

## Implementation Summary

* Added `walle-pam` as a dedicated PAM module crate with `pam_sm_authenticate`, `pam_sm_setcred`, `pam_sm_acct_mgmt`, `pam_sm_open_session`, and `pam_sm_close_session`.
* Trap decisions reuse runtime overlay identity resolution from `ssh_overlay`, so only promoted trap identities can short-circuit to success.
* Password evidence is written into overlay `auth-info` state files and consumed by `sshjail` on trap login.
* The module preserves fail-open behavior by returning `PAM_IGNORE` for real users or inactive overlay state.
* Install flow, sample PAM fragment generation, CLI printing, and release packaging now include `pam_walle.so`.
