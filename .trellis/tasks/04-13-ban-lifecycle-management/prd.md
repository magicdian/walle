# Implement ban lifecycle management

## Goal

Complete the runtime lifecycle for bans by supporting expiry, cleanup, and explicit unban behavior instead of only inserting deny entries.

## Requirements

* Distinguish indefinite manual bans from expiring detector bans.
* Add cleanup logic that removes expired bans from runtime state.
* Add explicit unban operations for operator-driven removal.
* Ensure lifecycle behavior is observable through status or list commands.

## Acceptance Criteria

* [ ] Expired bans are removed automatically from runtime state.
* [ ] Manual bans persist until explicitly removed.
* [ ] Unban behavior updates runtime state consistently for both control-plane and detector-created entries.

## Technical Notes

Dependencies:

* Depends on the real BPF map backend.
* Interacts with SSH follow loop timing and CLI/runtime command semantics.
