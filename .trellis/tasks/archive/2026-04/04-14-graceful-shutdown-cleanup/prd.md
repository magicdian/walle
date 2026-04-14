# Graceful shutdown cleanup for walle run

## Goal
Ensure `walle run` exits gracefully on `Ctrl+C` and other termination signals so managed runtime resources are cleaned up instead of being left attached in the kernel.

## Requirements
- `walle run` must intercept shutdown signals instead of relying on the OS default process termination path.
- Foreground shutdown must let Rust teardown run so XDP/tc attachments and sshjail resources are dropped cleanly.
- The follow loop must stop promptly after a shutdown request.
- Shutdown behavior must be covered by automated tests where practical.
- The backend/spec guidance must document the shutdown contract and this failure mode.

## Acceptance Criteria
- [ ] Pressing `Ctrl+C` during `walle run` causes `daemon.run()` to return cleanly instead of abrupt process termination.
- [ ] Graceful shutdown emits clear lifecycle logs for the requested stop and teardown completion.
- [ ] Existing bounded follow-loop behavior remains unchanged.
- [ ] Automated tests cover shutdown request propagation and teardown behavior that can be asserted in-process.
- [ ] Relevant `.trellis/spec/` files are updated to capture the contract.

## Technical Notes
- The current daemon run path has no signal handling and therefore depends on default `SIGINT` behavior.
- Local `aya` source confirms managed XDP/tc links detach on graceful drop, so the key requirement is reaching normal Rust teardown.
- The shutdown mechanism should avoid introducing broad new dependencies if a small local abstraction is sufficient.
