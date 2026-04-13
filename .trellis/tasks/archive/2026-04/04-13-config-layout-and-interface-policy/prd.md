# Design default config layout and per-interface policy model

## Goal
Define the operator-facing configuration layout for `walle`, including the default on-host config path, the top-level schema split between global detectors and interface-bound filters, and the first-version semantics for multi-interface policy application.

## Requirements
- Define the default Linux config file location for `walle run`.
- Define the top-level config schema boundaries between global detector policy and interface-specific packet filters.
- Define how multiple protected interfaces are declared explicitly in config.
- Define first-version semantics for SSH detector scope versus interface-local ICMP policy.
- Define the operator-facing encoding for exact-match ICMP payload rules.
- Define how `walle status` reports multi-interface runtime state instead of collapsing to a single primary interface.
- Define the first-version status/statistics contract for per-interface and aggregate counters.
- Define how user-space log level is configured in `config.toml` for local runs and systemd services.
- Identify the code-spec documents that must be updated before implementation begins.

## Acceptance Criteria
- [ ] A tracked task exists with the agreed configuration design captured in this PRD.
- [ ] The design states that `walle run` defaults to reading `/etc/walle/config.toml`.
- [ ] The design states that SSH detection is global in v1 while ICMP filtering is configured per interface.
- [ ] The design states that protected interfaces are declared explicitly and not inferred at runtime.
- [ ] The design states that ICMP rule payloads use an operator-facing hex representation in config.
- [ ] The design states that `walle status` reports one section per configured interface plus an aggregate summary.
- [ ] The design states that packet-path counters are surfaced per interface and aggregated across all selected interfaces.
- [ ] The design states that user-space log verbosity is configured in `config.toml` with an operator-facing log level field.
- [ ] Required code-spec updates are identified and applied before implementation starts.

## Technical Notes
- This is a cross-layer contract change spanning CLI startup, config parsing, daemon orchestration, and runtime/XDP attachment planning.
- Current code already models multiple configured interfaces in `WalleConfig`, but `status` still reads like a single-primary-interface view and does not surface per-interface counters.
- The first implementation should avoid interface-scoped SSH ban maps; ban results remain global until a later contract explicitly introduces per-interface deny state.
- Runtime stats maps are already interface-scoped because pinned map paths are scoped by interface. The status contract should use that shape instead of flattening everything into one synthetic interface.
