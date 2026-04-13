# Implement ICMP dataplane enforcement

## Goal

Lower the existing ICMP policy and runtime contract into the XDP packet path so `drop_all` and allow-rule modes are enforced by the kernel dataplane.

## Requirements

* Parse ICMP traffic in the XDP program safely within verifier constraints.
* Enforce `Disabled`, `DropAll`, and `AllowRulesActive` semantics from runtime config.
* Match exact raw-byte allow rules against ICMP echo payload bytes, not dynamic ICMP header fields.
* Update stats counters for ICMP hits and parser failures.
* Render audit-facing time output in user-space logs and CLI output as formatted timestamps instead of raw Unix-second values.

## Acceptance Criteria

* [x] XDP evaluation enforces ICMP mode from runtime config.
* [x] Exact-match ICMP echo-payload allow rules are honored when the mode is active.
* [x] Counter behavior reflects rule hits and parser failures where applicable.
* [x] Audit-facing log and CLI time output uses a human-readable formatted timestamp string.

## Technical Notes

Dependencies:

* Depends on the real XDP loader and real BPF map backend.
* The live `icmp_rules` runtime contract may use a verifier-friendly keyed lookup representation instead of slot-scanning arrays.
* Keep runtime map/shared-struct time units unchanged; only the presentation layer should switch away from raw Unix-second output.
