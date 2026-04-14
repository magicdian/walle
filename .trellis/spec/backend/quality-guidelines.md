# Quality Guidelines

> Code quality standards for backend development.

---

## Overview

`walle` is a security-sensitive systems project. The quality bar should prioritize correctness, explicitness, and debuggability over cleverness.

Every change should be evaluated across:

* control-plane correctness
* packet-path safety
* operational recovery behavior
* compatibility of shared structs and map layouts

---

## Forbidden Patterns

* `unwrap` and `expect` in daemon or loader runtime paths.
* Silent changes to BPF map key or value layouts.
* Re-implementing policy precedence separately in CLI, daemon, and XDP.
* Stringly-typed mode or rule handling where enums should be used.
* Adding speculative complexity such as a database or HTTP API before a concrete need exists.
* Per-packet logging in the hot path.
* Hidden global mutable state in control-plane crates.

In eBPF code specifically:

* no heap allocation assumptions
* no complex regex engines in MVP
* no unsafe parsing without bounds checks

---

## Required Patterns

* Shared structs and enums for data crossing user-space and eBPF boundaries.
* Explicit access-mode precedence tests.
* Version-aware config and map updates.
* Clear separation between detector logic and XDP enforcement logic.
* Structured logging for significant control-plane events.
* A graceful shutdown path for any runtime that owns XDP, tc, pinned maps, sockets, or worker threads.
* Small, reviewable crates with obvious ownership boundaries.

Before adding a new helper or utility, search for an existing abstraction first.

---

## Testing Requirements

At minimum:

* unit tests for policy parsing and validation
* unit tests for SSH threshold logic
* unit tests for access-mode conflict precedence
* integration tests for map update flows
* system-level validation for XDP attach, allow, and drop behavior before release

For future bug fixes:

* add a regression test when the bug can reasonably be isolated
* document non-testable kernel or environment constraints if a full automated test is not possible
* if the bug involves process shutdown, add coverage for the in-process stop signal or control-path propagation even when the real OS signal cannot be asserted in unit tests

---

## Code Review Checklist

* Does the change keep packet-path behavior simple and bounded?
* Are shared structs or enums updated safely across all layers?
* Is whitelist-over-blacklist precedence preserved?
* Does the change add enough logs or counters to debug failures?
* Are user-visible errors actionable?
* Are new dependencies justified for a systems-security tool?
* Does the implementation match [`docs/architecture/walle-system-design.md`](E:/coding/github_projects/walle/docs/architecture/walle-system-design.md)?
* If the code owns runtime hooks or listeners, does `Ctrl+C` / service stop release them through a tested graceful path?

Current scaffold examples:

* [`walle-common tests`](E:/coding/github_projects/walle/crates/walle-common/src/lib.rs): precedence tests at the shared-type layer
* [`walle-policy tests`](E:/coding/github_projects/walle/crates/walle-policy/src/lib.rs): config validation tests
* [`walle-ebpf helper`](E:/coding/github_projects/walle/crates/walle-ebpf/src/lib.rs): minimal packet-path logic reused from shared policy

## Scenario: GP Core And Protocol Adapter Contract

### 1. Scope / Trigger

* Trigger: Any change to guard-point (`gp`) policy schema, daemon-side GP execution contracts, SSH GP adapter behavior, or future protocol adapters such as HTTP.

### 2. Signatures

* `walle_policy::GpPolicy`
* `walle_policy::GpStrategyKind`
* `walle_policy::GpTriggerMode`
* `walle_policy::SshProtectionPolicy { gp: GpPolicy }`
* `walle_daemon::gp::GpExecutor::execute(GpAdapterRequest) -> GpExecutionOutcome`
* `walle_daemon::gp::GpAdapterRequest::Ssh(SshGpRequest)`
* `WalleDaemon::process_ssh_log_line(&str, u64) -> Result<Option<SshBanDecision>, DaemonError>`
* `WalleDaemon::poll_ssh_sources(u64) -> Result<SshIngestSummary, DaemonError>`
* `WalleDaemon::replay_ssh_log_file(PathBuf, u64, u64) -> Result<SshIngestSummary, DaemonError>`

### 3. Contracts

* GP core must stay protocol-agnostic:
  * use generic strategy and trigger enums in policy
  * keep protocol-specific payload mapping in adapter-specific request types
* SSH v1 integration point is a protocol adapter, not a special-case bypass of GP core.
* `GpTriggerMode` must support both:
  * suspicious signal observed
  * enforcement decision emitted
* GP execution is observational / extensible in v1:
  * `observe` may succeed normally
  * unimplemented strategies such as `degrade` or `contain` must return a typed fail-open outcome instead of aborting the SSH defense path
* Baseline SSH enforcement remains authoritative:
  * SSH ban writeback and deny-map behavior must continue even if GP execution is unavailable
* User-facing config and install defaults must expose the SSH GP sub-policy under:
  * `[detectors.ssh.gp]`
  * `enabled`
  * `strategy`
  * `trigger_mode`

### 4. Validation & Error Matrix

* valid config with omitted `[detectors.ssh.gp]` block -> GP defaults to disabled `observe` / `all`
* valid config with `trigger_mode = "signal_observed"` -> pre-ban SSH trigger points may execute GP, post-ban trigger points must be filtered
* valid config with `trigger_mode = "decision_emitted"` -> post-ban SSH trigger points may execute GP, pre-ban trigger points must be filtered
* valid config with `strategy = "observe"` and GP enabled -> executor returns an observed outcome
* valid config with `strategy = "degrade"` or `strategy = "contain"` and GP enabled -> executor returns `failed_open` outcome and baseline SSH processing continues
* invalid future implementation that hard-codes SSH-only semantics into GP core -> reject in review; protocol-specific fields belong in the adapter payload, not the core policy enum surface

### 5. Good/Base/Bad Cases

* Good:
  * a parsed SSH failure event reaches GP through `SshGpRequest` and can be filtered or observed by generic GP core logic
  * a ban decision reaches GP and still applies deny-map updates even if the selected GP strategy is not yet implemented
  * `walle ssh policy-show` exposes GP enablement, strategy, and trigger mode so operators can reason about behavior
* Base:
  * GP disabled means the executor returns a disabled outcome and the rest of SSH processing continues as before
  * v1 only wires the SSH adapter, while leaving room for future adapters such as HTTP without core refactors
* Bad:
  * putting SSH-specific usernames, auth reasons, or shell semantics directly into `GpPolicy`
  * letting GP failure prevent `apply_ssh_ban_to_all` from running
  * adding packet-path changes in XDP as part of GP framework scaffolding

### 6. Tests Required

* policy tests must assert GP defaults, nested TOML parsing, and trigger-mode helper behavior
* GP core tests must assert:
  * disabled outcome
  * trigger filtering
  * observe success
  * unimplemented strategy fail-open behavior
* daemon tests must assert:
  * pre-ban SSH trigger reaches GP
  * post-ban SSH trigger reaches GP
  * unavailable GP strategy does not break deny-map updates
* install-template tests must assert `[detectors.ssh.gp]` appears in the generated default config

### 7. Wrong vs Correct

#### Wrong

* Build `ssh-gp` as ad-hoc daemon logic first, then try to retrofit a generic GP framework later.

#### Correct

* Keep a generic GP core for strategy / trigger / outcome semantics, and translate SSH-specific detector events into that core through an adapter-specific request type.

## Scenario: SSH Jail Containment And Invalid-User Force-Ban Contract

### 1. Scope / Trigger

* Trigger: Any change to `sshjail`, SSH detector fast-ban behavior, SSH containment map semantics, XDP/tc SSH steering, or policy fields under `[detectors.ssh]` and `[detectors.ssh.gp]`.

### 2. Signatures

* `walle_policy::SshProtectionPolicy { invalid_user_force_ban_enabled: bool, gp: GpPolicy }`
* `walle_policy::GpPolicy { strategy: GpStrategyKind, trigger_mode: GpTriggerMode, sshjail: SshJailPolicy }`
* `walle_daemon::detector::SshDetectorService::force_ban(IpAddr, u64) -> Option<SshBanDecision>`
* `walle_daemon::WalleDaemon::process_ssh_log_line(&str, u64) -> Result<Option<SshBanDecision>, DaemonError>`
* `walle_daemon::WalleDaemon::apply_ssh_ban_to_all(SshBanDecision) -> Result<(), DaemonError>`
* `walle_daemon::WalleDaemon::apply_ssh_contain_to_all(IpAddr, u64, u64, SshContainTrigger) -> Result<(), DaemonError>`
* `walle_daemon::runtime::RuntimeController::apply_ssh_contain(...) -> Result<(), DaemonError>`
* `walle_ebpf::xdp::evaluate_access_with_containment(&RuntimeConfig, bool, bool, bool, u8, u16) -> PacketAction`

### 3. Contracts

* `invalid_user_force_ban_enabled = true` means explicit `Invalid user` log lines bypass the SSH failure threshold and emit an immediate `SshBanDecision`.
* The invalid-user fast path is ban-only. It must not directly redirect traffic into `sshjail`.
* Whether later SSH attempts enter `sshjail` is controlled only by GP containment:
  * `strategy = "contain"`
  * matching `trigger_mode`
* `gp.trigger_mode = "decision_emitted"` means the contain entry is written only after a ban decision exists.
* A source may exist in both deny and contain maps at the same time.
* For contained sources, only TCP traffic targeting `RuntimeConfig.protected_ssh_port` may bypass XDP deny so tc ingress can rewrite it to `RuntimeConfig.ssh_jail_port`.
* Non-SSH traffic from the same banned source must still be dropped by XDP.
* If `sshjail` is unavailable or full, GP containment must fail open back to normal ban/drop behavior.

### 4. Validation & Error Matrix

* valid config with `invalid_user_force_ban_enabled = false` -> invalid-user lines follow the normal threshold path
* valid config with `invalid_user_force_ban_enabled = true` and GP disabled -> invalid-user lines ban immediately; later traffic is dropped
* valid config with `invalid_user_force_ban_enabled = true`, `gp.enabled = true`, `strategy = "contain"`, `trigger_mode = "decision_emitted"` -> invalid-user lines ban immediately and later SSH attempts are redirected to `sshjail`
* contain entry present + deny entry present + TCP destination is protected SSH port -> XDP must return `Allow`
* contain entry present + deny entry present + TCP destination is not protected SSH port -> XDP must return `Drop`
* contain entry present + deny entry present + non-TCP traffic -> XDP must return `Drop`

### 5. Good/Base/Bad Cases

* Good:
  * first invalid-user attempt hits the real `sshd`, produces one log line, and emits an immediate ban decision
  * second SSH attempt from the same source is passed through XDP, rewritten by tc, and lands in `sshjail`
  * ICMP and non-SSH TCP from the same source continue to be dropped
* Base:
  * normal failed-password traffic still uses threshold counting when `invalid_user_force_ban_enabled` is off
* Bad:
  * invalid-user fast path directly writes contain without a ban decision
  * XDP deny takes precedence over contain for protected SSH traffic and prevents tc redirect from ever running
  * contain is treated as a general allow for all traffic from a banned source

### 6. Tests Required

* policy parsing tests must assert `invalid_user_force_ban_enabled` is loaded from TOML
* daemon tests must assert:
  * invalid-user fast path emits a one-shot `SshBanDecision`
  * invalid-user fast path does not require `sshjail` by itself
  * post-ban GP containment still preserves baseline ban flow
* `walle-ebpf` tests must assert:
  * contained SSH traffic overrides deny for the protected SSH port
  * contained non-SSH TCP does not override deny
  * contained non-TCP traffic does not override deny

### 7. Wrong vs Correct

#### Wrong

* Treat `invalid_user_force_ban_enabled` as a direct redirect switch and couple it to `sshjail` startup or contain-map writes.

#### Correct

* Keep invalid-user fast handling as a detector-side ban shortcut, and let GP containment decide whether later SSH attempts are redirected after the ban decision boundary.

## Scenario: SSH Jail Virtual Shell Fidelity Contract

### 1. Scope / Trigger

* Trigger: Any change to `crates/walle-daemon/src/sshjail.rs` fake-shell command handling, persona filesystems, interactive REPL state, streaming commands, outbound SSH observation, or SSH `exec_request` probe emulation.

### 2. Signatures

* `ShellState::execute_line(&str) -> CommandResult`
* `ShellState::execute_tokens(&[String]) -> CommandResult`
* `ShellState::ingest_input(&[u8]) -> Vec<ShellEvent>`
* `ShellState::prepare_interactive_ping(&str) -> Option<PingRequest>`
* `ShellState::handle_tab_completion() -> TabCompletion`
* `ShellState::try_execute_probe_script(&str) -> Option<CommandResult>`
* `SshJailHandler::start_exec_ping_stream(...)`
* `SshJailHandler::start_ping_stream(...)`
* `ShellState::handle_cat(&[String]) -> CommandResult`
* `ShellState::handle_ifconfig(&[String]) -> CommandResult`
* `ShellState::handle_ip(&[String]) -> CommandResult`
* `ShellState::handle_ps(&[String]) -> CommandResult`
* `ShellState::handle_ss(&[String]) -> CommandResult`
* `ShellState::handle_df(&[String]) -> CommandResult`
* `ShellState::handle_history(&[String]) -> CommandResult`
* `ShellState::handle_ssh(&[String]) -> CommandResult`
* `VirtualHostFacts::populate_filesystem(&mut VirtualFilesystem)`
* `VirtualFilesystem::ensure_identity(&ShellIdentity)`
* `VirtualFilesystem::resolve_path(&str, &str) -> String`
* `VirtualFilesystem::list(&str, bool) -> Option<Vec<String>>`
* `VirtualFilesystem::is_dir(&str) -> bool`
* `VirtualFilesystem::is_file(&str) -> bool`
* `VirtualFilesystem::read_file(&str) -> Option<&str>`
* `parse_ping_request(&[String]) -> Option<PingRequest>`
* `render_synthetic_ping(u64, &str, &PingRequest) -> String`
* `parse_ssh_invocation(&[String]) -> Option<SshInvocation>`

### 3. Contracts

* Interactive shell behavior and `exec_request` behavior must share one virtual host model:
  * command discovery
  * file existence
  * directory traversal
  * host/banner facts
  * basic network interface facts
  * process list and listening socket views
  * operator history and login traces
  * runtime and web-host footprints
* If a directory is exposed by `ls`, `cd` into that path must succeed unless the output itself is being changed in the same patch.
* Persona home directories must be populated as traversable directory trees, not only flat `ls` output lists.
* `cd` with no argument must return the current identity to its login home directory.
* `cat` must distinguish three cases:
  * file -> return deterministic fake contents
  * directory -> return `Is a directory` with non-zero exit semantics
  * missing path -> return `No such file or directory` with non-zero exit semantics
* Supported reconnaissance commands in both interactive and `bash -c '...'` forms must include:
  * `uname -m`
  * `uname -a`
  * `nproc`
  * `free -k | awk '/^Mem:/{print $2}'`
  * `cat /etc/os-release 2>/dev/null | grep -E '^(NAME|PRETTY_NAME)=' | head -1`
  * `which <tool> 2>/dev/null || command -v <tool> 2>/dev/null`
  * `test -f <path> && echo 'found'`
  * `<tool> --version 2>/dev/null || <tool> --help 2>/dev/null | head -1`
  * `<tool> -version 2>&1 | head -1` for stderr-first tools such as `java` and `ssh`
* Basic Ubuntu-style network inspection must stay believable:
  * `ifconfig`
  * `ifconfig <iface>`
  * `ip addr`
  * `ip addr show <iface>`
  * `ss -lntp`
  * `netstat -lntp`
* The broader recon surface must stay internally consistent across related commands:
  * `ps`
  * `df -h`
  * `uptime`
  * `env`
  * `tree`
  * `history`
  * `last`
  * `w`
  * `who`
  * `crontab -l`
  * `java`, `java -version`, `javac`
  * `python`, `python3 --version`
  * `nginx`, `apache2`, `mysql`, `php`, and Tomcat footprint reads
* Interactive shell mode must support believable stateful behavior:
  * `Tab` completion for command names and current-path fragments
  * continuous `ping` that can be interrupted with `Ctrl-C`
  * hidden-input prompts where typed secrets are not echoed
  * lightweight Python REPL mode with prompt transitions between `>>> ` and the normal shell prompt
  * per-session attacker history for interactive commands, including silent-success commands such as `cd`
* Synthetic `ping` must remain fully fake:
  * no real DNS or network traffic
  * deterministic target resolution within a session
  * plausible public IPv4 for domain targets
  * latency samples in the 30-50 ms band
* Outbound `ssh` observation is metadata-only:
  * capture destination, username, options, forwarding count, and transcript-visible behavior
  * never capture or store typed passwords, key contents, or equivalent secret material
* Fake-shell support must remain no-side-effect:
  * no host command execution
  * no host PTY allocation
  * no reading live command output from the real OS

### 4. Validation & Error Matrix

* valid `cd` with no argument after moving away from home -> succeeds and returns `pwd` to the login home
* valid `cd loot` from a `root` session after `ls` lists `loot` -> succeeds and updates `pwd`
* valid `cd boot` after `cd /` -> succeeds when `/boot` is listed
* valid `cat credentials.txt` inside `/root/loot` -> returns deterministic fake file contents
* valid `cat .` while current path is a directory -> returns `cat: .: Is a directory` and non-zero exit
* missing path `cat /missing/file` -> returns `No such file or directory` and non-zero exit
* valid `ifconfig` -> returns loopback plus primary ethernet interface blocks
* valid `ifconfig lo` -> returns only loopback block
* unknown interface `ifconfig eth9` -> returns device-not-found style failure
* valid `bash -c 'which apt 2>/dev/null || command -v apt 2>/dev/null'` -> returns the configured fake binary path
* valid `bash -c 'java -version 2>&1 | head -1'` -> returns a believable synthetic version header
* valid `ss -lntp` or `netstat -lntp` -> returns a listening SSH socket view aligned with the fake process table
* valid `ping -c 2 example.com` -> returns two synthetic replies and summary output with exit status `0`
* valid interactive `ping example.com` -> starts a stream and only stops on `Ctrl-C` or explicit count completion
* valid `python` -> enters Python REPL mode and changes the prompt to `>>> `
* valid `exit()` inside Python REPL -> returns to normal shell mode
* valid `ssh -p 2222 -i ~/.ssh/id_ed25519 deploy@example.net` -> switches to hidden-input password prompt and emits one metadata audit event
* repeated password submissions in hidden-input mode -> return permission-denied style messages without echoing or storing the entered secret
* `history` after interactive commands such as `ls`, `uptime`, `python`, and `cd /` -> includes those attacker-visible commands in order
* tab completion on `his<Tab>` -> expands to `history `
* tab completion on ambiguous command prefix such as `p<Tab>` -> shows a suggestion menu rather than choosing arbitrarily

### 5. Good/Base/Bad Cases

* Good:
  * a contained root session can `ls`, `cd`, inspect `ps`, `ss`, `df`, `history`, and `cat /var/log/auth.log` without contradictory host facts
  * a contained `tomcat` session still benefits from the same shared Ubuntu host facts for `bash -c` reconnaissance probes, runtime tooling, and service footprints
  * an attacker can start `ping`, interrupt it with `Ctrl-C`, then immediately resume normal shell use with a clean prompt
  * an attacker can attempt outbound `ssh` and the system records only invocation metadata while the fake prompt never reveals captured secrets
* Base:
  * unsupported commands may still return `command not found` when they are outside the supported fake-shell contract
  * fake file contents may be static as long as they remain internally consistent
  * lightweight REPL emulation is acceptable as long as prompt transitions and basic `print(...)` flows stay believable
* Bad:
  * listing a directory name in `ls` while `cd` into the same path fails
  * implementing `exec_request` probe support against one data source and interactive shell paths against another
  * returning `command not found` for `cat` on a valid directory path instead of a path-type-aware error
  * implementing `ping` by invoking host networking or leaking real resolver results
  * recording typed outbound-SSH passwords in audit logs, session history, or captured transcript state
  * making `ps`, `ss`, `netstat`, and `/var/log/auth.log` tell different stories about whether SSH or Tomcat is present

### 6. Tests Required

* shell tests must assert `cd` with no argument returns to the login home directory
* shell tests must assert a listed root directory is traversable and updates `pwd`
* shell tests must assert `cat` on:
  * a fake file
  * a directory
  * a missing path
* shell tests must assert the real observed `bash -c` reconnaissance probes keep returning deterministic outputs
* shell tests must assert non-root personas still share the supported probe surface
* shell tests must assert `ifconfig` and `ip addr show <iface>` return plausible interface output and unknown interfaces fail
* shell tests must assert `ss` / `netstat`, `ps`, `df`, `uptime`, `env`, and runtime version commands render believable outputs
* shell tests must assert web-host config and login-trace views such as `tree /etc`, `cat /var/log/auth.log`, `last`, `who`, `history`, and `crontab -l`
* shell tests must assert interactive history includes both visible commands and silent-success commands such as `cd`
* shell tests must assert outbound `ssh`:
  * emits metadata audit events
  * transitions to hidden-input prompt mode
  * does not echo or retain typed secrets in history
* shell tests must assert interactive `ping` preparation and tab completion behavior

### 7. Wrong vs Correct

#### Wrong

* Hard-code `ls`, `ps`, `ss`, `ping`, or outbound `ssh` output strings independently, while the underlying virtual host state, interactive modes, and audit boundaries tell a different story.

#### Correct

* Treat fake-shell realism as a shared executable contract: directory listings, traversal, file reads, reconnaissance probes, streaming commands, prompt state transitions, and outbound-SSH metadata observation all derive from the same virtual host state and the same no-secret, no-side-effect boundary.
