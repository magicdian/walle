# Prefer Event-Driven SSH Ingestion With Watch And Polling Fallback

## Goal
Replace the current fixed-interval SSH ingestion loop with a capability-driven source strategy that prefers event-driven delivery, falls back to file watch when needed, and keeps polling as the final compatibility path.

## Requirements
- Introduce a source abstraction for live SSH ingestion in the daemon detector path.
- Prefer event-driven journald ingestion when the host supports it.
- Fall back to file-watch ingestion for log-file based SSH sources when event-driven journald is not available.
- Keep polling available as the last-resort fallback for compatibility.
- Preserve existing SSH parsing, thresholding, and ban-application behavior.
- Keep detector logic in user space and XDP enforcement logic in the runtime/data-plane path.
- Keep errors typed and source-specific at the detector layer.
- Keep logs structured and avoid noisy empty-loop debug logs in event-driven modes.

## Acceptance Criteria
- [ ] The daemon no longer relies on a single unconditional fixed-interval polling loop for all SSH ingestion.
- [ ] Live SSH ingestion is selected by capability in this priority order: event-driven journald, file watch, polling.
- [ ] The selected ingestion mode is visible in structured startup logs.
- [ ] Existing SSH detector behavior still produces ban decisions from supported SSH failure lines.
- [ ] Unsupported or unavailable event-driven modes cleanly fall back without crashing the daemon.
- [ ] Automated tests cover source selection and at least one live-source fallback path.

## Technical Notes
- Favor an interface owned by `walle-daemon` so journald, file-watch, and polling implementations remain capability-scoped.
- Keep replay helpers and one-shot inspection logic separate from live source implementations where practical.
- Linux-only integrations should compile cleanly behind target guards and return typed unsupported errors when needed.
