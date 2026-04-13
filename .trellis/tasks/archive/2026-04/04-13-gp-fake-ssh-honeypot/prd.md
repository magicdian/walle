# GP SSH jail containment

## Goal

Build a real `gp` containment capability for SSH attacks by adding an internal `sshjail` service: a fake OpenSSH-like server with a purely simulated interactive shell. The system should keep attacker sessions inside a controlled, no-side-effect environment, increase observation value, and fit the existing `walle` SSH detector + GP execution model without weakening baseline ban enforcement.

## What I already know

* The repository already has an SSH detector pipeline that parses auth failures, emits ban decisions, and writes deny entries into runtime maps.
* The repository already has a `gp` execution boundary in [`crates/walle-daemon/src/gp.rs`](/home/github_projects/walle/crates/walle-daemon/src/gp.rs), but `degrade` and `contain` are placeholders that currently fail open.
* `GpPolicy` currently exposes only:
  * `enabled`
  * `strategy`
  * `trigger_mode`
* The daemon initializes `GpExecutor` from `config.ssh_policy().gp` in [`crates/walle-daemon/src/lib.rs`](/home/github_projects/walle/crates/walle-daemon/src/lib.rs).
* The current repo has no TCP listener, SSH protocol implementation, or async runtime dependency.
* The project is backend-only in MVP. Any solution must stay in Rust userspace / daemon space and follow existing typed config, error, and structured logging conventions.
* The user wants a fake SSH environment with a REPL-like shell, multiple concurrent sessions, and a configurable session cap to avoid excessive memory use.
* The shell must not produce real side effects. Commands should return believable fake results only.
* The user wants the MVP to resemble `OpenSSH` as closely as practical rather than only implementing a minimal handshake.
* The user wants the shell persona to adapt to the requested SSH username, for example presenting a `tomcat`-like environment when the attacker targets `tomcat`.
* The user wants `sshjail` command activity to be audit-recorded to files, with a configurable storage path such as `/tmp` or a persistent directory.
* If the operator does not configure an audit directory, the default path should be `/tmp/walle/gp/ssh`.
* The user wants a hybrid persona model:
  * high-frequency accounts get more detailed, role-specific fake environments
  * unknown accounts fall back to a generic template
* Even for fallback personas, the shell prompt should preserve the attacker-requested username and use either the current system hostname or a configurable/randomized fake hostname to improve realism.
* The user prefers the default prompt hostname strategy to use a generated fake hostname rather than the real system hostname.
* The user wants an additional SSH-policy-level shortcut: if an attacker attempts a username that does not exist on the host, that access can be treated as directly malicious and sent to `sshjail` without waiting for the normal ban threshold.
* The user approved these first-class high-fidelity persona templates for MVP:
  * `root`
  * `admin`
  * `ubuntu`
  * `tomcat`
  * `www-data`
* The user wants these first-class templates to simulate the corresponding environment as convincingly as practical within the no-side-effect model.

## Assumptions (temporary)

* First version should optimize for safe containment + telemetry, not protocol-perfect SSH emulation.
* First version should keep current SSH ban enforcement active even if the honeypot path is unavailable.
* The fake shell filesystem and session state should be in-memory only for MVP.
* The fake shell should intentionally support only a curated command subset and reject or fake all other commands.
* The solution should avoid introducing any real process execution, PTY allocation, system shell, or filesystem writes.
* Containment applies to subsequent new SSH connections from an already-detected source, not to hijacking an already-established SSH session.
* The `sshjail` service should run inside the `walle` daemon process as an internal component, not as a separately managed external process.
* The default containment trigger should be post-ban, while the framework should preserve configurability for earlier trigger points because the GP framework already models this boundary.
* A persistent in-process listener with lazy per-connection session allocation is preferable to starting and stopping the listener on demand for each attacker.
* The first version should aim for a high-believability `OpenSSH`-style experience, but still within a bounded emulation model rather than protocol-perfect parity with every OpenSSH behavior.
* For sources already in `contain`, `sshjail` should accept authentication and enter the fake shell directly rather than simulating additional auth failures.
* Audit storage should default to `/tmp/walle/gp/ssh`, while allowing operators to override the base directory explicitly.
* MVP persona modeling should use a small set of curated high-frequency account templates plus a generic fallback template for all other usernames.
* The default prompt hostname strategy should use a generated fake hostname, while still allowing operator override.
* The direct-to-`sshjail` invalid-user shortcut should key off `sshd` log events that explicitly report `Invalid user`, rather than adding separate local account existence lookups in MVP.
* The first-class persona set for MVP is fixed to `root`, `admin`, `ubuntu`, `tomcat`, and `www-data`; all other usernames use a generic fallback.

## Open Questions

* None at the moment.

## Requirements (evolving)

* Implement a real `contain` path for SSH `gp`.
* The `contain` trigger point for MVP is post-detection / post-ban style containment of subsequent new connections from the same source IP.
* Add an internal `sshjail` service that can present an OpenSSH-like greeting and authentication success flow.
* `sshjail` should aim to look close to `OpenSSH` in bannering and interactive behavior.
* For contained connections, `sshjail` should accept authentication and enter the fake shell directly instead of simulating additional login failures.
* Add a simulated shell session that supports a limited command set:
  * `uname`
  * `sudo`
  * `su`
  * `pwd`
  * `ls`
  * `exit`
  * `cd`
* Keep per-session state isolated and purely virtual.
* Shell presentation should adapt to the SSH username requested by the attacker, including prompt style, home directory, and plausible command output persona for that user profile.
* MVP should include detailed first-class templates for high-frequency usernames and a generic fallback template for unknown usernames.
* Fallback personas should still preserve the attacker-requested username in prompts and environment presentation.
* The first-class persona set for MVP is:
  * `root`
  * `admin`
  * `ubuntu`
  * `tomcat`
  * `www-data`
* First-class personas should emulate likely directory layout, prompt shape, home path, visible top-level directories, and command responses for the associated account role as convincingly as possible without touching the real host.
* Allow multiple concurrent sessions with a configurable maximum.
* If `sshjail` reaches its configured concurrent-session cap, new contained SSH attempts must fall back to existing deny/drop enforcement.
* Enforce resource limits:
  * global session cap
  * per-session idle timeout
  * per-session lifetime cap
  * bounded transcript / output buffering
* Record telemetry for:
  * source IP
  * username and password attempts if visible
  * session lifecycle
  * command transcript
  * rejection reasons
  * containment execution outcome
* Persist `sshjail` audit logs to files using a configurable base directory so operators can choose temporary or persistent storage.
* If the operator does not configure an audit path, `sshjail` should write under `/tmp/walle/gp/ssh`.
* `sshjail` prompt hostnames should default to a generated fake hostname instead of the real system hostname.
* Add an SSH-policy-level fast path so `sshd` log events reporting `Invalid user` can be classified as malicious immediately and diverted to `sshjail` without waiting for threshold-based banning.
* Preserve fail-open semantics for GP:
  * if containment fails, normal SSH detection and ban path must still work
* Extend policy/config in a typed way instead of ad hoc environment variables.
* Introduce an explicit redirect/control contract instead of implying that the current XDP packet verdict path can directly hand TCP sessions to a local userspace server.
* The `sshjail` listener should be hosted inside the daemon process with explicit lifecycle management and bounded resource ownership.
* The listener should be bound during daemon startup, while per-connection session state is allocated only when a redirected connection is actually accepted.
* Preserve GP trigger configurability so operators can still choose `signal_observed`, `decision_emitted`, or `all`, while the default containment behavior uses `decision_emitted`.
* Model containment as a state that coexists with denylist state, with containment taking precedence specifically for SSH redirection decisions while deny semantics continue to apply elsewhere.

## Acceptance Criteria (evolving)

* [ ] `contain` no longer reports `strategy_unavailable` for the implemented SSH path.
* [ ] The daemon can start the internal `sshjail` containment component under typed config.
* [ ] The fake shell supports concurrent in-memory sessions up to a configured cap.
* [ ] When `sshjail` capacity is exhausted, contained SSH traffic falls back to deny/drop behavior.
* [ ] The shell persona changes based on the requested SSH username.
* [ ] High-frequency usernames render more specific fake environments, while unknown usernames use a believable generic fallback.
* [ ] `root`, `admin`, `ubuntu`, `tomcat`, and `www-data` each have distinct persona behavior that is visibly different from the generic fallback.
* [ ] Supported commands return deterministic fake responses without touching the real OS.
* [ ] Unsupported commands return believable but safe responses without side effects.
* [ ] Session logs and structured telemetry capture connection and command activity.
* [ ] `sshjail` audit transcripts are written to the configured filesystem location.
* [ ] Without explicit configuration, `sshjail` audit transcripts are written under `/tmp/walle/gp/ssh`.
* [ ] Contained connections are admitted into `sshjail` without extra simulated auth-failure loops.
* [ ] Without explicit hostname configuration, `sshjail` prompts use a generated fake hostname.
* [ ] When the direct-invalid-user shortcut is enabled and `sshd` emits an `Invalid user` event, the source is diverted to `sshjail` without waiting for the normal threshold ban flow.
* [ ] If containment startup or execution fails, baseline detector/ban behavior continues.
* [ ] Unit tests cover fake session state transitions and command handling.
* [ ] Integration or daemon-level tests cover GP contain execution and fail-open behavior.

## Definition of Done

* Tests added or updated for config parsing, GP execution, and fake shell behavior.
* `cargo test` passes for affected crates.
* Logging remains structured and uses stable fields.
* Errors remain typed at library boundaries.
* Documentation and default config template are updated if operator-facing behavior changes.

## Out of Scope (explicit)

* Real command execution, PTY allocation, or launching a system shell.
* Any feature intended to damage third-party systems, congest attacker networks, or force remote resource exhaustion.
* High-fidelity SSH implementation parity with a production OpenSSH server.
* Full Unix command coverage beyond a curated MVP set.
* Durable database persistence.
* HTTP API or browser UI.

## Research Notes

### What similar tools/patterns suggest

* A believable honeypot usually separates:
  * connection handling
  * protocol/session state
  * virtual filesystem / command emulation
  * transcript logging
* Safe honeypots keep all attacker-visible state virtual and avoid executing host binaries.
* Session caps, timeouts, and bounded logs are mandatory to keep attacker interaction from turning into self-DoS.
* High-believability SSH deception often depends more on coherent prompts, user personas, filesystem layout, and transcript consistency than on implementing every corner of the SSH protocol.
* A practical MVP can combine a curated set of role-specific templates such as web/service accounts with a generic fallback, as long as prompt/user/home-directory details stay internally consistent.

### Constraints from this repo/project

* `walle` currently centers around:
  * SSH log ingestion
  * GP execution hooks
  * XDP runtime enforcement
* There is no existing userspace socket server or async runtime.
* Config is represented by typed policy structs in [`crates/walle-policy/src/lib.rs`](/home/github_projects/walle/crates/walle-policy/src/lib.rs).
* Daemon lifecycle logging and fail-open strategy handling already exist and should be extended rather than bypassed.

### Feasible approaches here

**Approach A: Dedicated fake SSH listener** (Lowest implementation risk)

* How it works:
  * add a separate configurable fake SSH listener in userspace
  * it always serves the fake environment on its configured bind address / port
  * `gp contain` is mostly policy/logging/session-management integration
* Pros:
  * easiest to implement safely
  * minimal interference with current detector / ban flow
  * easiest to test
* Cons:
  * weakest "containment" story
  * attacker must reach the honeypot listener directly
  * does not automatically capture traffic already targeting real `sshd`

**Approach B: Host-owned fake SSH on protected port** (Recommended if the host can dedicate port 22)

* How it works:
  * `walle` owns the SSH listening port and always serves the fake environment
  * detector / GP policy still decides logging, throttling, and containment metadata
* Pros:
  * operationally simple once deployed
  * strong capture rate for inbound SSH probes
  * no per-IP redirect machinery required
* Cons:
  * cannot coexist with a real SSH server on the same port
  * changes deployment assumptions significantly

**Approach C: Selective redirect after detector signals** (Chosen)

* How it works:
  * real SSH path remains
  * after threshold or trigger hit, matching sources are steered into the fake SSH service
* Pros:
  * best match for the user's "containment after detection" goal
  * can preserve a real admin SSH path for benign clients
* Cons:
  * requires new traffic steering/proxy mechanics not present in the repo today
  * much more cross-layer complexity
  * likely needs explicit NAT/proxy design beyond current XDP denylist model

## Decision (ADR-lite)

**Context**: The user wants `gp contain` to redirect suspicious SSH traffic into a fake OpenSSH environment rather than only observe or occupy a dedicated alternate port. The current repo already has SSH detection, GP trigger points, and ban enforcement, but no redirect or proxy layer.

**Decision**: Use selective redirect as the target architecture for MVP, with an internal `sshjail` fake OpenSSH service as the redirect target.

**Consequences**:

* `contain` now becomes a real execution mode rather than a placeholder.
* The implementation must add a redirect/control contract in addition to the `sshjail` server itself.
* Because current detection comes from `sshd` auth log signals, the simplest realizable MVP semantics are:
  * attacker reaches real SSH first
  * detector observes failures
  * GP marks the source for containment
* future new connections from that source are redirected to `sshjail`
* Hijacking the already-established failing SSH session would require a front-proxy / man-in-the-middle style design that is materially more complex than the current detector-driven architecture.
* The redirect path must be modeled as an additional control-plane/data-plane contract; current XDP behavior alone is not sufficient to steer a TCP SSH connection into a local userspace listener.
* The `sshjail` target should live inside the `walle` daemon process.

## Redirect Direction (ADR-lite)

**Context**: The MVP needs to steer contained SSH traffic to a local `sshjail` listener while preserving the existing XDP path and avoiding mutation of operator-managed `iptables` / `nftables` rules.

**Decision**: Prefer a `tc`-based redirect path over `iptables` / `nftables` rule injection, with the `sshjail` listener running inside the `walle` daemon process.

**Consequences**:

* The implementation stays self-contained inside `walle` rather than depending on host firewall rule mutation.
* The redirect path becomes more kernel-hook-specific and more complex than using `REDIRECT` in netfilter.
* We will need a new runtime contract for "contained SSH sources" plus a `tc` attachment / steering mechanism in addition to the existing XDP program.
* The recommended listener lifecycle is:
  * bind the in-process `sshjail` listener during daemon startup
  * allocate session state only when a redirected connection is accepted
  * if capacity is exhausted, let the connection fall back to deny/drop behavior

## Trigger Timing (ADR-lite)

**Context**: The user wants the product to target already-banned devices by default, but the original GP framework already reserved configurable trigger timing.

**Decision**: Keep trigger timing configurable through the existing GP trigger model, but define the default fake OpenSSH containment behavior around the post-ban trigger (`decision_emitted`).

**Consequences**:

* The current config surface remains conceptually aligned with commit `d45e7753c3b92c99a65d7294f0597745b3c758a9`.
* MVP semantics stay conservative and are less likely to capture benign users who merely mistyped credentials.
* Future operator tuning can still enable earlier pre-ban diversion if desired, but that is not the default product posture.

## Contain-vs-Deny Semantics (ADR-lite)

**Context**: The user wants already-banned sources to be redirected to `sshjail` on later SSH attempts, but the current runtime model already has IP-wide denylist semantics.

**Decision**: Keep `deny` and `contain` as separate coexisting states, and define containment as higher priority for SSH redirection decisions on the protected SSH path.

**Consequences**:

* A source can remain formally banned while still being steered into `sshjail` for matching SSH traffic.
* The general deny model does not need to be weakened or globally redefined.
* The implementation needs a distinct runtime contract for contained SSH sources rather than overloading the existing deny maps.
* Evaluation order must be explicit:
  * matching SSH containment rule
  * then SSH redirect path if `sshjail` capacity is available
  * otherwise existing deny/drop semantics

## Technical Notes

* Files inspected:
  * [`crates/walle-daemon/src/gp.rs`](/home/github_projects/walle/crates/walle-daemon/src/gp.rs)
  * [`crates/walle-daemon/src/lib.rs`](/home/github_projects/walle/crates/walle-daemon/src/lib.rs)
  * [`crates/walle-policy/src/lib.rs`](/home/github_projects/walle/crates/walle-policy/src/lib.rs)
  * [`crates/walle-daemon/src/install.rs`](/home/github_projects/walle/crates/walle-daemon/src/install.rs)
  * [`docs/architecture/walle-system-design.md`](/home/github_projects/walle/docs/architecture/walle-system-design.md)
* Relevant backend guidance read:
  * [`.trellis/spec/backend/database-guidelines.md`](/home/github_projects/walle/.trellis/spec/backend/database-guidelines.md)
  * [`.trellis/spec/backend/error-handling.md`](/home/github_projects/walle/.trellis/spec/backend/error-handling.md)
  * [`.trellis/spec/backend/logging-guidelines.md`](/home/github_projects/walle/.trellis/spec/backend/logging-guidelines.md)
* Early design constraints:
  * config additions should stay typed and validated in `walle-policy`
  * daemon-owned failures should use typed errors and fail open where containment is optional
* session telemetry should use structured logs, not ad hoc string dumps
* file-backed `sshjail` audit logs need a typed config contract for storage directory, naming, and retention/bounding behavior
* virtual shell state should stay separate from runtime enforcement state and BPF maps
* prompt realism needs a typed hostname strategy contract:
  * real system hostname
  * operator-configured fake hostname
  * generated fake hostname
* the direct-invalid-user shortcut needs a typed policy/config contract and should integrate with the existing detector reason model instead of adding a separate username-existence subsystem in MVP
* current SSH detector input is log-derived from `sshd`, so redirect decisions naturally occur after at least one auth event has already reached the real SSH service
* there is no existing redirect, NAT, transparent proxy, or TCP session handoff mechanism in the repo today
* current eBPF/XDP runtime only exposes allow/drop semantics through [`PacketAction`](/home/github_projects/walle/crates/walle-common/src/lib.rs) and the XDP program returns `XDP_PASS` or `XDP_DROP`; it does not currently encode local-port redirection semantics
* the chosen MVP direction should avoid modifying host `iptables` / `nftables` rules
* audit file persistence needs bounded naming and directory-creation behavior so `/tmp/walle/gp/ssh` works out of the box but user-specified directories remain supported
* persona design needs a small, explicit template inventory rather than ad hoc per-command branching:
  * prompt format
  * home directory
  * default working directory
  * visible top-level directories
  * command response variants per persona

## Technical Approach

The current preferred direction is:

* extend `walle-policy` with typed `sshjail` and redirect policy settings
* extend the SSH detector / GP request path so `Invalid user` and post-ban triggers can mark a source for SSH containment
* add a distinct runtime repository contract for contained SSH sources, separate from deny entries
* introduce a `tc`-based redirect path for contained SSH traffic that targets an internal `sshjail` listener
* implement an in-process `sshjail` service with:
  * OpenSSH-like banner / auth-success flow
  * session cap and timeouts
  * per-persona virtual filesystem / prompt state
  * transcript audit file output
* keep fail-open semantics so redirect or `sshjail` failures preserve baseline ban/drop behavior

## Implementation Plan (small PRs)

* PR1: policy and runtime contracts for SSH containment state, config, and audit path defaults
* PR2: detector / GP integration for post-ban contain and `Invalid user` shortcut
* PR3: in-process `sshjail` listener, session manager, and audit transcript writer
* PR4: persona templates, fake shell command handling, hostname strategy, and capacity fallback behavior
* PR5: `tc` redirect integration, end-to-end tests, and docs/config template updates
