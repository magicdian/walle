# brainstorm: migrate diff preview to similar

## Goal

Replace Walle's hand-rolled unified diff preview implementation for `walle ssh overlay install-hooks` with the Apache-2.0 `similar` crate through normal Cargo dependency management, while preserving the current operator-facing contract: changed hunks only, 10 lines of context, plain-text backend output, and optional ANSI color at the CLI presentation layer.

## What I already know

* Current diff preview generation is implemented manually in `crates/walle-daemon/src/install.rs`.
* The current implementation builds LCS-style ops, merges changed ranges into hunks, and renders unified diff headers.
* Current operator contract already requires:
  * changed hunks only
  * 10 lines of surrounding context
  * backend preview remains plain text
  * CLI may colorize additions/deletions/hunk headers when the terminal supports ANSI
* Current CLI colorization is isolated in `crates/walle-cli/src/main.rs` and can remain unchanged.
* `similar` provides line-based diffing and unified-diff rendering through:
  * `TextDiff::from_lines(...)`
  * `.unified_diff()`
  * `.context_radius(10)`
  * `.header(...)`
  * `.missing_newline_hint(...)`
* `similar` is published under Apache-2.0, which is compatible with this project's Apache-2.0 licensing for normal dependency usage.
* Using `similar` as a Cargo dependency does not require vendoring or git submodules in the normal case.

## Assumptions (temporary)

* We will only migrate the backend diff-generation path used by hook preview rendering.
* `similar` will own diff generation and unified-diff formatting, but not terminal color policy.
* CLI ANSI color output will remain outside `similar`; if we keep colors, they stay in Walle's CLI layer.
* We do not need word-level or inline diff highlighting for this task.
* We are comfortable accepting minor hunk-shape differences from the library as long as the user-facing contract remains satisfied.

## Open Questions

* None currently blocking.

## Requirements (evolving)

* Add `similar` through Cargo dependency management, not submodule.
* Replace the current hand-rolled diff algorithm in `crates/walle-daemon/src/install.rs` with `similar`.
* Preserve `install-hooks` preview behavior:
  * only changed hunks are shown
  * each hunk includes 10 lines of surrounding context
  * preview remains plain text before CLI colorization
  * file headers continue to identify the target file path
* Accept minor library-driven differences in hunk layout or header counts if the contract above remains true.
* Preserve CLI color behavior in `crates/walle-cli/src/main.rs`, unless we explicitly choose to drop color support.
* Do not invent a `similar`-managed color layer if the library does not expose one.
* Preserve existing confirmation / apply / drift-detection flow.
* Keep test coverage for:
  * preview hunk-only rendering
  * CLI ANSI color rendering
  * hook install/apply lifecycle behavior
* Update spec/docs only if the output contract changes or if implementation guidance should mention the use of `similar`.

## Acceptance Criteria (evolving)

* [ ] `install-hooks` preview is still unified diff output with changed hunks only.
* [ ] Preview still includes 10 lines of context around each changed region.
* [ ] Backend preview data contains no ANSI escape sequences.
* [ ] CLI still colorizes add/delete/hunk lines on ANSI-capable terminals.
* [ ] Existing install-hook workflow tests continue to pass.
* [ ] New or updated tests cover the `similar`-based renderer behavior.
* [ ] Cargo dependency addition is limited to the crate(s) that actually need diff generation.
* [ ] Tests assert contract-level preview behavior rather than pinning every hunk-header count emitted by the previous custom implementation.

## Definition of Done (team quality bar)

* Tests added/updated (unit/integration where appropriate)
* Lint / typecheck / CI green
* Docs/notes updated if behavior changes
* Rollout/rollback considered if risky

## Out of Scope (explicit)

* Changing the preview confirmation UX
* Changing CLI color palette or terminal-detection policy
* Adding word-level or side-by-side diff presentation
* Reworking other install / uninstall behavior unrelated to preview rendering
* Vendoring or submoduling third-party source

## Technical Notes

* Current hand-rolled diff implementation:
  * `crates/walle-daemon/src/install.rs::render_unified_diff`
  * `crates/walle-daemon/src/install.rs::build_diff_ops`
  * `crates/walle-daemon/src/install.rs::diff_hunk_ranges`
* Current CLI colorization:
  * `crates/walle-cli/src/main.rs::render_diff_preview`
  * `crates/walle-cli/src/main.rs::colorize_diff_preview`
* Current renderer test that will likely need adjustment:
  * `crates/walle-daemon/src/install.rs::unified_diff_preview_only_shows_changed_hunk_with_context`
* Primary upstream references:
  * <https://github.com/mitsuhiko/similar>
  * <https://docs.rs/similar/latest/similar/struct.TextDiff.html>
  * <https://docs.rs/similar/latest/similar/udiff/struct.UnifiedDiff.html>
* Upstream API currently documents unified diff configuration for:
  * `context_radius`
  * `header`
  * `missing_newline_hint`
* Upstream docs reviewed did not show terminal color APIs for unified diff output, so ANSI styling remains a local CLI concern unless a different library is introduced later.

## Research Notes

### What the current code does

* Builds a line-based diff with an in-house dynamic-programming implementation.
* Merges changed op indices into hunk ranges using fixed context radius `10`.
* Renders unified diff headers manually.
* Delegates ANSI color entirely to the CLI layer.

### Constraints from our repo/project

* The preview contract is already codified in backend specs and tests.
* The install flow is security-sensitive; only the preview renderer should change.
* We should avoid broad output churn that would force doc/spec rewrites without real UX gain.

### Feasible approaches here

**Approach A: `similar` owns diff generation; Walle keeps CLI color** (Recommended)

* How it works:
  * add `similar` to `walle-daemon`
  * replace `render_unified_diff(...)` and delete the local diff algorithm helpers
  * keep CLI colorization and all install/apply logic unchanged
* Pros:
  * smallest blast radius
  * removes the local diff algorithm entirely
  * keeps current architecture and contracts intact
* Cons:
  * test output may shift slightly
  * color remains our responsibility because `similar` does not appear to provide terminal styling APIs

**Approach B: `similar` for diff + drop color support**

* How it works:
  * migrate renderer to `similar`
  * remove ANSI colorization from Walle so the entire preview path is plain text end-to-end
* Pros:
  * simplest architecture
  * no local color heuristics to maintain
* Cons:
  * UX regression relative to current git-like preview
  * conflicts with the user's existing preference for colored diff output

**Approach C: Add another color library on top of `similar`**

* How it works:
  * use `similar` for diff output
  * replace the current manual ANSI strings with a dedicated terminal styling crate
* Pros:
  * centralizes ANSI formatting in a color library
  * may improve terminal capability handling
* Cons:
  * adds another dependency with little immediate value
  * solves a problem the current CLI layer already handles adequately
