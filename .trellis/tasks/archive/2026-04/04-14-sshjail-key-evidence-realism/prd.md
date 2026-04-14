# sshjail key evidence and virtual ssh persistence realism

## Goal

Capture higher-value inbound SSH key evidence inside `sshjail` and keep common attacker `.ssh` persistence commands coherent in the virtual filesystem.

## Status

Completed on 2026-04-14 as part of the parent identity-overlay task.

## Implemented

* Inbound public-key capture records stable key material and fingerprints instead of algorithm-only metadata.
* First-seen attacker public keys are promoted into the dynamic blacklist store.
* Common `.ssh` rewrite flows such as `rm -rf .ssh`, `mkdir .ssh`, `echo ... >> authorized_keys`, and chmod-style hardening mutate virtual state coherently.
* The outbound fake-`ssh` path keeps the existing metadata-only no-secret boundary.

## Key Files

* `crates/walle-daemon/src/sshjail.rs`
* `crates/walle-policy/src/lib.rs`

## Follow-up

* Future enhancements should stay within the same evidence-vs-secret boundary.
