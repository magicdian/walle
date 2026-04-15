# brainstorm: automate system config install rollback

## Goal

Automate the SSH overlay host-config activation path so `walle install` no longer depends on manual edits to `/etc/ssh/sshd_config`, `/etc/nsswitch.conf`, and `/etc/pam.d/sshd`, while keeping the change reversible through explicit backups and clearly delimited Walle-managed config blocks.

## What I already know

* The current install flow copies managed artifacts and writes sample fragments, but intentionally does not modify host config files automatically.
* Current operator docs require manual merge of:
  * `/usr/local/lib/walle/walle-ssh-overlay.conf.sample` into `sshd_config`
  * `/usr/local/lib/walle/walle-nsswitch.conf.sample` into `/etc/nsswitch.conf`
  * `/usr/local/lib/walle/walle-sshd-pam.conf.sample` into `/etc/pam.d/sshd`
* The required insertion positions are already documented in code/specs:
  * `files` must stay before `walle` in `nsswitch.conf`
  * PAM `auth` must be before `@include common-auth`
  * PAM `account` must be after `pam_nologin.so` and before `@include common-account`
  * PAM `session` must be after `pam_keyinit.so` and before `@include common-session`
* Current uninstall removes Walle-managed binaries/modules/sample assets, but does not revert host config edits because those edits are still manual.
* The user wants Walle-owned inserted content wrapped in comment markers such as:
  * `# managed by walle start`
  * `# managed by walle end`
* The user also wants backup + rollback so the host can return to baseline safely.
* The user prefers SSH GP hook activation to be managed under `walle ssh overlay ...` rather than extending top-level `install`.
* Current preferred entrypoint is `walle ssh overlay install-hooks`.

## Assumptions (temporary)

* This feature remains Linux-only and stays within the existing installer boundary.
* Walle should edit only text config files it already documents as manual integration points.
* Managed markers should allow idempotent re-runs and straightforward cleanup.
* Backup behavior should be deterministic and discoverable by operators.

## Open Questions

* None at the moment.

## Requirements (evolving)

* Automatically update `/etc/ssh/sshd_config`, `/etc/nsswitch.conf`, and `/etc/pam.d/sshd` through a dedicated SSH overlay hook-install command.
* Keep top-level `walle install` focused on the existing artifact/service installation behavior.
* Expose SSH GP hook activation under `walle ssh overlay install-hooks`.
* Preserve the documented insertion ordering rules for NSS/PAM/sshd integration.
* Wrap Walle-managed inserted config with start/end markers so future updates and removal are deterministic.
* Create backups before the first managed edit of each target file.
* Support rollback/removal without forcing operators to manually edit the files.
* Keep install/uninstall behavior safe on repeated runs.
* During install, show operators a git-diff-like preview of config-file changes before or while applying the SSH GP hook edits.
* Require explicit user confirmation after showing the diff preview before writing host config changes.
* Include the operational surface needed to inspect and fully roll back the SSH GP hook state in MVP, rather than leaving it to manual file handling.
* Use strict validation for host config edits: if a target file already has conflicting settings or the expected insertion anchors are missing, abort without modifying host config.

## Acceptance Criteria (evolving)

* [ ] `walle ssh overlay install-hooks` can activate the SSH overlay without manual merge steps for the three target host files.
* [ ] Managed config blocks are clearly delimited and can be found/replaced reliably.
* [ ] Backup files are created before modifying existing host config.
* [ ] Re-running install is idempotent and does not duplicate managed blocks.
* [ ] Rollback/removal behavior is explicit and tested.
* [ ] Install output shows a readable patch-style preview for each changed host config file.
* [ ] `walle ssh overlay install-hooks` pauses for confirmation after showing the preview and writes changes only after explicit approval.
* [ ] Operators can inspect current SSH GP hook managed state and backup availability through a dedicated status command.
* [ ] Operators can explicitly restore the pre-install backup version of managed host config files through a dedicated rollback command.
* [ ] If host config already contains conflicting settings, or required anchors are missing, Walle aborts safely without partial config edits.
* [ ] Existing install/uninstall typed error handling stays intact.
* [ ] Operator docs describe the new activation and rollback flow.

## Definition of Done (team quality bar)

* Tests added or updated for install/uninstall config-edit behavior
* Lint / typecheck / CI-relevant checks green
* Docs/spec updated for new installer behavior
* Rollback path considered and validated

## Out of Scope (explicit)

* Supporting non-Linux targets
* Managing arbitrary distro-specific SSH/PAM layout variants beyond the current documented contract
* Replacing real `sshd` behavior outside the existing overlay integration points

## Research Notes

### What the current repo does

* `crates/walle-daemon/src/install.rs` installs binaries/modules and writes sample overlay fragments, but does not edit host config files.
* `crates/walle-daemon/src/ssh_overlay.rs` already defines the canonical rendered fragment content and placement notes.
* `docs/operations/linux-install-and-distribution.md` and `docs/operations/debug-bundle-test-guide.md` document manual merge and manual cleanup today.
* `.trellis/spec/backend/ssh-overlay-and-bundle-contract.md` defines the exact NSS/PAM ordering contract we must preserve.

### Constraints from this repo/project

* The feature touches install/uninstall behavior and host config integration, so it needs typed installer errors and rollback-safe behavior.
* PAM placement is positional, not pure append-only.
* `nsswitch.conf` is sensitive to ordering; `files` must remain first.
* `sshd_config` may already contain operator-managed `AuthorizedKeysCommand` settings, so naive append/replace risks breaking the host.

### Feasible approaches here

**Approach A: Extend `walle install` / `walle uninstall` to manage host config directly** (Recommended)

* How it works:
  * installer writes backups, inserts or updates Walle-marked blocks at validated positions, and uninstall removes or restores them.
* Pros:
  * single operator workflow
  * matches the user's stated goal
  * keeps activation tightly coupled to install state
* Cons:
  * installer becomes responsible for more host mutation logic
  * uninstall semantics need to be chosen carefully

### Current direction

* Use the SSH overlay command family for hook lifecycle operations:
  * `walle ssh overlay install-hooks`
  * `walle ssh overlay hook-status`
  * `walle ssh overlay hook-disable`
  * `walle ssh overlay hook-restore-backup`

## Decision (draft)

**Context**: The repo currently separates artifact installation from manual SSH overlay activation. The requested UX is automatic activation, but the user now wants that lifecycle to live under the SSH overlay command surface instead of top-level install.

**Decision**: Keep top-level `walle install` unchanged and add dedicated SSH overlay hook lifecycle commands, with `walle ssh overlay install-hooks` as the main activation entrypoint.

**Consequences**:

* Artifact installation and host SSH-hook mutation stay conceptually separate.
* The SSH overlay command family becomes the long-term home for status / disable / restore-backup operations.
* Hook installation still needs backup creation, positional edits, idempotency, preview rendering, and rollback-safe behavior.

## Decision (ADR-lite): install confirmation

**Context**: Automatic host-config mutation is risky, especially for SSH and PAM files. The user wants the exact edit preview to be visible before the change lands.

**Decision**: `walle ssh overlay install-hooks` should render a patch-style preview and require explicit confirmation before writing the changes.

**Consequences**:

* Interactive installs become safer by default.
* Non-interactive automation may need an explicit future bypass flag if the project later wants scriptable installs.
* The installer needs a small confirmation UX layer in the CLI boundary.

## Decision (ADR-lite): MVP scope boundary

**Context**: The initial feature request focused on auto-install + rollback, but the user also wants a more complete operator workflow around visibility and explicit recovery.

**Decision**: Expand MVP beyond raw file editing alone to include:

* SSH GP hook activation through `walle ssh overlay install-hooks`
* patch-style preview + confirmation
* default managed-block removal through `walle ssh overlay hook-disable`
* explicit backup-restore command
* status/inspection command for current managed-hook state

**Consequences**:

* This becomes a cross-cutting SSH overlay operator UX slice rather than a narrow file-edit patch.
* CLI command placement should be chosen carefully now so the operational surface can evolve cleanly later.

## Decision (ADR-lite): rollback policy

**Context**: The user wants both safe automation and safe rollback. Full-file restore is safer for exact rollback, but risks discarding unrelated operator changes made after install.

**Decision**: Use a mixed rollback model.

**Consequences**:

* Default uninstall or disable behavior should remove only Walle-managed blocks delimited by markers.
* The installer should still create backups before the first managed edit.
* Walle should expose an explicit restore-from-backup path for operators who want full-file restoration.
* This preserves post-install operator edits by default while still allowing a hard rollback path.

## Decision (ADR-lite): merge and safety policy

**Context**: The feature edits `sshd_config`, `nsswitch.conf`, and PAM configuration, which are security-sensitive system files. The user explicitly prefers the strictest behavior.

**Decision**: Use strict validation and fail closed for hook installation.

**Consequences**:

* Walle must not attempt smart merging when it detects an existing `AuthorizedKeysCommand` or an unexpected host layout.
* Walle must validate the expected insertion anchors for PAM and NSS before writing.
* If any target file is unsafe to edit, Walle should report the reason and abort the hook install rather than applying a partial merge.
* This reduces convenience on unusual hosts, but minimizes the chance of corrupting security-critical configuration.

## Technical Notes

* Relevant files inspected:
  * `crates/walle-daemon/src/install.rs`
  * `crates/walle-daemon/src/ssh_overlay.rs`
  * `crates/walle-cli/src/main.rs`
  * `docs/operations/linux-install-and-distribution.md`
  * `docs/operations/debug-bundle-test-guide.md`
  * `.trellis/spec/backend/ssh-overlay-and-bundle-contract.md`
  * `.trellis/spec/backend/error-handling.md`
* Current CLI output still tells operators to manually review sample files and merge them into host config after install.
