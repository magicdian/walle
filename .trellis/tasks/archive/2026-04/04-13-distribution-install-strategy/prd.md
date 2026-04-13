# Define distribution and install strategy

## Goal

Define how `walle` should be packaged, distributed, and installed on target Linux hosts, including compatibility boundaries and operator-facing failure guidance.

## Requirements

* Decide the expected prebuilt artifact layout for releases.
* Define environment self-check behavior and failure messaging during installation.
* Capture the intended CO-RE and BTF compatibility strategy.
* Document how packaging expectations interact with the install/uninstall CLI flow.

## Acceptance Criteria

* [x] A concrete packaging and install strategy is documented in a task PRD or follow-up design note.
* [x] Compatibility assumptions for CO-RE and BTF are explicit.
* [x] Failure modes and operator guidance are captured for future implementation.

## Technical Approach

* Capture the release artifact layout and installed file layout in a dedicated design note.
* Tie the documented install layout to the real installer implementation and startup checks.
* Make the current Linux baseline explicit: kernel `>= 5.15`, root privileges, bpffs, and BTF.
* Document failure guidance for missing runtime backends, missing eBPF objects, and missing kernel capabilities.

## Decision (ADR-lite)

**Context**: The codebase now has a working install flow, but release/distribution expectations were still implicit.

**Decision**: Document a prebuilt-binary + prebuilt-eBPF-object strategy with an explicit on-host layout and explicit runtime compatibility boundaries.

**Consequences**: Packaging expectations are now concrete enough for future build tooling and release automation, while leaving distro-native packaging for a later slice.

## Out of Scope

* Final `.deb` / `.rpm` packaging
* Cross-distro automation beyond the documented file layout
* Supporting kernels below `5.15`

## Technical Notes

Dependencies:

* Informed by the Linux service install flow and real loader behavior.
* May initially result in documentation and build-tooling changes rather than runtime code.
* Documented in `docs/operations/linux-install-and-distribution.md` and summarized in `README.md`.
