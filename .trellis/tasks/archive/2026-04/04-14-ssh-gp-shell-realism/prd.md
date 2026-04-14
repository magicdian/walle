# brainstorm: ssh gp shell realism

## Goal

Improve the SSH GP `sshjail` fake shell so reconnaissance feels substantially closer to a real Ubuntu host. The shell should expose a believable Linux environment, keep interactive and non-interactive command behavior aligned, and avoid obvious contradictions that reveal the environment is synthetic.

## What I already know

* The current implementation lives primarily in `crates/walle-daemon/src/sshjail.rs`, with GP orchestration in `crates/walle-daemon/src/gp.rs`.
* The repository already defines an executable contract for this area in backend quality guidelines under `SSH Jail Virtual Shell Fidelity Contract`.
* `sshjail` already supports a shared `ShellState` for interactive shell input and SSH `exec_request`, which is the right architectural direction.
* The current fake shell already supports `pwd`, `uname`, `ls`, `cd`, `sudo`, `su`, `whoami`, `id`, `hostname`, `echo`, `nproc`, `free`, `cat`, `ifconfig`, `ip`, `which`, `command -v`, `test -f`, and `clear`.
* The current fake shell already emulates several attacker probe scripts through `bash -c`, including:
  * `uname -m`
  * `nproc`
  * `free -k | awk '/^Mem:/{print $2}'`
  * `cat /etc/os-release 2>/dev/null | grep -E '^(NAME|PRETTY_NAME)=' | head -1`
  * `which <tool> 2>/dev/null || command -v <tool> 2>/dev/null`
  * `test -f <path> && echo 'found'`
  * `<tool> --version 2>/dev/null || <tool> --help 2>/dev/null | head -1`
* The current virtual host model already includes:
  * Ubuntu 22.04.4 banner and kernel facts
  * several fake binaries (`apt`, `apt-get`, `dpkg`, `snap`, `pip`, `pip3`, `ifconfig`, `ip`)
  * fake network interfaces (`lo`, `eth0`)
  * persona-specific filesystem trees for `root`, `ubuntu`, `admin`, `tomcat`, and `www-data`
* Current tests already cover:
  * exec-style recon probes
  * non-root probe parity
  * root directory traversal and `cat` path typing
  * basic `ifconfig` and `ip addr show <iface>` output
* The user-observed realism gaps are concrete:
  * `cd` with no argument currently does not behave like a normal shell home-directory jump
  * `ls /` shows directories such as `boot`, but `cd boot` fails
  * `/bin` is exposed but effectively empty from the attacker's perspective
  * common commands such as `tree` are missing
  * `ps` without believable `sshd` and related processes makes the host state feel inconsistent
  * interactive shell `Tab` currently does not offer believable command or path completion
  * more realistic command coverage is desired for both interactive and non-interactive use
  * `ping` should be synthetic only: no real network access, plausible random public IP for domain targets, and latency around 30-50 ms
* From the current implementation:
  * `ShellState::handle_cd` relies on `VirtualFilesystem::resolve_path`, and `resolve_path("~")` currently resolves to the current directory rather than the login home
  * root-level listing is broader than the actually populated traversable directory graph, which can surface obvious contradictions during exploration

## Assumptions (temporary)

* We should keep the fake shell strictly no-side-effect and must not execute host commands.
* Deep realism has now been selected over a smaller MVP, but internal consistency still matters more than raw command count.
* The MVP should focus on Linux reconnaissance and navigation commands commonly used by scanners and human intruders after login.
* Synthetic outputs can be deterministic per session or semi-randomized if internal consistency is preserved.
* Limited host reads are acceptable if they are used as low-risk input material for synthetic rendering instead of being exposed verbatim.

## Open Questions

* None currently blocking.

## Requirements (evolving)

* Fix contradictions between exposed filesystem layout and traversable paths.
* Keep interactive shell behavior and `exec_request` behavior aligned through the same virtual host model.
* Expand the believable Linux command surface beyond the current baseline with deeper reconnaissance coverage.
* Support session-stable pseudo-randomized realism where useful, so outputs look alive without contradicting other observed host facts.
* Add synthetic `ping` support without real network traffic.
* Add more common post-login Linux reconnaissance outputs, likely including process, disk, uptime, Java/runtime, and networking views.
* Cover the first implementation batch comprehensively across:
  * general reconnaissance core
  * web-host runtime and config footprints
  * login, operator, and maintenance traces
* Add believable `ssh`, `sshd`, and process/network views so `ps`, socket inspection, and related host traces remain internally consistent.
* Keep outputs close to common Ubuntu/Linux expectations for attacker reconnaissance flows.
* It is acceptable to derive some facts from the host at session creation time, but attacker-visible output must not leak real host-sensitive information.
* No shell command may cause a real write or other attacker-driven side effect on the host.
* If the attacker uses the fake environment as a jump box, the system may record outbound `ssh` attempt metadata and session transcript details, but must not intercept or exfiltrate passwords, private keys, agent material, or equivalent credentials.
* Interactive shell mode should support believable `Tab` completion for at least command names and current-directory paths.

## Acceptance Criteria (evolving)

* [ ] If a directory is shown by `ls`, traversal commands such as `cd` do not obviously contradict it.
* [ ] Supported commands produce plausible output in both interactive shell use and non-interactive `bash -c` / `exec_request` probes.
* [ ] `ping` never triggers real network traffic and returns plausible synthetic output.
* [ ] Session-stable synthetic facts remain internally consistent across related commands during one SSH session.
* [ ] Unsupported commands fail in a believable Linux-like way rather than exposing implementation seams.
* [ ] Tests cover newly added high-value recon paths, session consistency, and the user-reported contradiction cases.
* [ ] Any host-derived facts exposed to the attacker are normalized or redacted so they do not reveal the real protected host identity, topology, or sensitive runtime details.
* [ ] No supported command path performs a real write to the host filesystem or other attacker-controlled side effect.
* [ ] The first batch includes believable coverage for:
  * general recon commands such as `ping`, `tree`, `ls -l/-la`, `ps`, `ss` or `netstat`, `df -h`, `uptime`, `env`, `java -version`, `python3 --version`
  * web-host-oriented probes such as `nginx`, `apache2`, `mysql`, `php`, and `tomcat` runtime/config footprints
  * operator-history probes such as `last`, `w`, `who`, `history`, `crontab -l`, and selected log-file reads
* [ ] `ps` and related views show believable SSH daemon and service processes that match the fake host story.
* [ ] Any supported outbound `ssh` observation path is limited to metadata and transcript capture; it does not collect passwords or secret key material.
* [ ] Interactive shell `Tab` completion produces believable command or path suggestions instead of only ringing the terminal bell.

## Definition of Done (team quality bar)

* Tests added or updated where behavior can be isolated
* Lint / typecheck / CI-relevant checks green
* Docs or notes updated if behavior contract changes
* Risk of attacker-visible contradictions reduced for the covered command surface

## Out of Scope (explicit)

* Executing real host binaries or spawning a real PTY
* Real network activity from fake commands
* Full bash compatibility, shell scripting support, or arbitrary pipelines
* Stateful package management, process management, or service control with real side effects
* Perfect emulation of every Linux distribution or every installed package
* Full interactive support for every possible command-line flag combination
* Credential interception or exfiltration from attacker-initiated outbound SSH sessions

## Technical Notes

* Relevant files inspected:
  * `crates/walle-daemon/src/sshjail.rs`
  * `crates/walle-daemon/src/gp.rs`
  * `docs/architecture/walle-system-design.md`
  * `.trellis/spec/backend/error-handling.md`
  * `.trellis/spec/backend/logging-guidelines.md`
  * `.trellis/spec/backend/quality-guidelines.md`
* Architecture notes:
  * `gp.strategy = "contain"` redirects later SSH attempts into `sshjail` after the ban decision path.
  * `sshjail` is expected to be believable but still fail-open operationally if unavailable or full.
  * Current code already exposes stable per-session inputs we can build on: `session_id`, `peer_addr`, and `started_at`.
  * Newly confirmed product constraint: limited host inspection is allowed, but outputs must stay sanitized and side-effect free.
* Quality contract notes:
  * shared model for shell, filesystem, and exec probes is already the intended pattern
  * listed directories must remain traversable
  * fake shell support must remain no-side-effect

## Research Notes

### What similar tools do

* Cowrie's medium-interaction shell model is built around a fake filesystem plus command emulation rather than running real host commands.
* Cowrie keeps filesystem metadata and file content as explicit modeled data, and each visitor sees an isolated writable copy for the session.
* Cowrie also distinguishes between pure emulation and higher-interaction backends, but the higher-interaction path relies on proxying to a real system or dynamic backend.

### Constraints from our repo/project

* `walle` explicitly requires no host command execution, no host PTY allocation, and no reading live command output from the real OS.
* The project already wants one shared virtual host model for both interactive shell and `exec_request` probe handling.
* This code path sits in a security-sensitive daemon, so correctness, deterministic behavior, and testability matter more than cleverness.

### Feasible approaches here

**Approach A: Structured session-scoped virtual host snapshot** (Recommended)

* How it works:
  * Build one `VirtualHostSnapshot` when the shell session is created.
  * Seed stable synthetic facts from session inputs such as username, hostname, peer IP, and session id.
  * Drive filesystem, `ping`, uptime, process list, disk usage, package/runtime probes, and network views from that one snapshot.
* Pros:
  * strongest internal consistency
  * easiest to extend without contradictions
  * interactive shell and `exec_request` naturally stay aligned
  * good testability because outputs derive from structured state
* Cons:
  * requires a larger refactor up front
  * more data modeling work before command count increases

**Approach B: Template-first command expansion**

* How it works:
  * Keep the current structure mostly intact and add more command handlers with hand-authored outputs.
  * Patch contradictions opportunistically.
* Pros:
  * fastest to ship initially
  * smallest refactor
* Cons:
  * contradiction risk grows quickly
  * harder to keep `ping`, `ps`, `df`, `uptime`, logs, and filesystem facts aligned
  * maintenance cost increases as command surface broadens

**Approach C: Layered hybrid snapshot + command family responders**

* How it works:
  * Create a structured snapshot only for core host facts.
  * Keep command handlers, but make them render from shared fact groups such as filesystem, networking, processes, packages, and runtime tools.
* Pros:
  * better consistency than template-first
  * lower refactor cost than a fully centralized snapshot engine
  * practical path for adding many commands quickly
* Cons:
  * still leaves some risk of drift between command families
  * weaker long-term coherence than a more centralized snapshot model

## Decision (ADR-lite)

**Context**: Deep shell realism is required, but the project must remain no-side-effect and should not expose the real protected host to the attacker.

**Decision**: Use Approach C, a layered hybrid model. Build shared host fact groups and session-stable synthetic state, then let command families render from those shared facts. Limited host reads are allowed only as sanitized input material.

**Consequences**:

* Better consistency than ad hoc command templates, with less refactor cost than a fully centralized snapshot engine.
* We must define a clear boundary between safe host-derived inputs and attacker-visible synthetic outputs.
* Verification must include both realism consistency and non-leak / no-write safety checks.

## Technical Approach

Use a layered hybrid model inside `sshjail`:

* introduce shared fact groups for:
  * sanitized host seed inputs
  * session-stable synthetic host identity
  * filesystem and file metadata
  * network interfaces and `ping` targets
  * process/runtime view
  * login and operator traces
* keep command handlers in `ShellState`, but make each handler render from those shared fact groups instead of hard-coded one-off strings wherever practical
* preserve one execution model for:
  * interactive shell commands
  * `exec_request`
  * supported `bash -c` reconnaissance probes
* use host reads only as bounded inputs during session setup or snapshot generation, then normalize/sanitize before exposure
* keep all supported commands read-only from the host perspective
* if outbound `ssh` support is emulated or observed, limit capture to destination, username, options, timestamps, and transcript-level auditing rather than secrets
