# Implement ICMP dataplane enforcement

## Goal

Lower the existing ICMP policy and runtime contract into the XDP packet path so `drop_all` and allow-rule modes are enforced by the kernel dataplane.

## Requirements

* Parse ICMP traffic in the XDP program safely within verifier constraints.
* Enforce `Disabled`, `DropAll`, and `AllowRulesActive` semantics from runtime config.
* Match exact raw-byte allow rules using the shared ICMP rule map contract.
* Update stats counters for ICMP hits and parser failures.

## Acceptance Criteria

* [ ] XDP evaluation enforces ICMP mode from runtime config.
* [ ] Exact-match ICMP allow rules are honored when the mode is active.
* [ ] Counter behavior reflects rule hits and parser failures where applicable.

## Technical Notes

Dependencies:

* Depends on the real XDP loader and real BPF map backend.
* May require contract adjustments in `walle-common` if verifier-friendly encoding differs.
