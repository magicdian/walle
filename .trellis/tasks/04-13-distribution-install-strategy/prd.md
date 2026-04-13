# Define distribution and install strategy

## Goal

Define how `walle` should be packaged, distributed, and installed on target Linux hosts, including compatibility boundaries and operator-facing failure guidance.

## Requirements

* Decide the expected prebuilt artifact layout for releases.
* Define environment self-check behavior and failure messaging during installation.
* Capture the intended CO-RE and BTF compatibility strategy.
* Document how packaging expectations interact with the install/uninstall CLI flow.

## Acceptance Criteria

* [ ] A concrete packaging and install strategy is documented in a task PRD or follow-up design note.
* [ ] Compatibility assumptions for CO-RE and BTF are explicit.
* [ ] Failure modes and operator guidance are captured for future implementation.

## Technical Notes

Dependencies:

* Informed by the Linux service install flow and real loader behavior.
* May initially result in documentation and build-tooling changes rather than runtime code.
