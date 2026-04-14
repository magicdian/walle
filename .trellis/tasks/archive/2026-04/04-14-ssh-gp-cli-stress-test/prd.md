# SSH GP CLI Parameter And sshjail Stress Test

## Goal
Quantify resource usage for fake OpenSSH behavior in SSH GP mode and provide an environment-aware `max_session` recommendation for real hosts with different memory sizes.

## Requirements
- Add CLI entry parameters for SSH GP stress testing.
- Include sshjail stress testing up to a target maximum of 1024 sessions.
- Monitor system memory usage during stress execution.
- Produce a final recommended `max_session` value using a 50% memory safety threshold.
- Keep existing runtime and policy behavior backward compatible unless explicitly overridden by CLI options.

## Acceptance Criteria
- [ ] A CLI path exists to run SSH GP + sshjail stress testing with configurable parameters.
- [ ] The stress workflow can attempt up to 1024 concurrent sessions.
- [ ] Memory snapshots are recorded during/after test execution.
- [ ] CLI output includes a computed recommendation for `max_session` based on 50% memory budget.
- [ ] Automated tests cover parsing/validation and recommendation calculation logic.

## Technical Notes
- This task changes CLI contract surface, so policy and error handling must remain typed and explicit.
- Stress test should avoid host-destructive behavior and should fail with actionable messages when prerequisites are missing.
- Recommendation formula should be deterministic and clearly shown in output.
