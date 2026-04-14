# Improve sshjail credential capture and SSH persistence realism

## Goal

Improve `sshjail` so it preserves higher-value attacker evidence during contained SSH sessions and makes common SSH persistence behavior look more believable. The immediate user-driven motivation is twofold: capture attacker-supplied SSH public keys as evidence, and make `.ssh`-related persistence commands produce coherent in-jail state instead of stopping at transcript metadata.

## What I already know

* The current implementation lives primarily in `crates/walle-daemon/src/sshjail.rs`.
* `sshjail` already writes per-session audit logs to files under the configurable `audit_dir`, which defaults to `/tmp/walle/gp/ssh`.
* Inbound password auth is already captured verbatim in the session audit log via `auth_password user=<user> password=<password>`.
* Inbound public-key auth currently records only the algorithm in `auth_publickey_offered` / `auth_publickey`; it does not preserve the offered key material or a stable fingerprint.
* The fake outbound `ssh` command intentionally captures metadata only. Current backend quality guidance explicitly forbids storing typed outbound passwords or key contents in that path.
* The virtual filesystem already includes `~/.ssh` for several personas, including the generic fallback persona, but the shell does not currently emulate filesystem-mutating command chains such as:
  * `rm -rf .ssh`
  * `mkdir .ssh`
  * `echo "<pubkey>" >> .ssh/authorized_keys`
  * `chmod -R go= ~/.ssh`
* As a result, attacker persistence attempts can be recorded in the transcript today, but they do not reliably produce coherent post-command filesystem state inside the jail.
* The existing `SshJailPolicy` exposes runtime controls such as:
  * protected/listen ports
  * session caps and timeouts
  * audit directory
  * hostname strategy
* There is no existing typed policy for credential material retention, credential fingerprint indexing, or key-based contain/block decisions.
* This task spans multiple layers if detection behavior changes:
  * inbound SSH auth handler
  * session audit persistence
  * possible threat-intel or detector-side reuse
  * possible GP containment decision path
* The user wants to push beyond evidence-only capture and build a general credential/IOC pipeline for `gp`, starting with SSH public-key identity as a first-class signal.
* The user proposed a mode where:
  * password-based attempts from currently unbanned IPs continue to the real system `sshd`
  * key-based attempts from currently unbanned IPs are checked against a blacklist of previously observed malicious keys
  * non-blacklisted keys continue to the real `sshd`
  * blacklisted keys are diverted directly into `sshjail`
* The user wants this design to be complete and careful, not a narrow point fix.
* The user prefers a high-transparency SSH front door:
  * normal users must not be impacted
  * compatibility should include shell login, `scp`, `sftp`, `pty`, and common SSH behavior
  * `walle` may listen on a random internal port while traffic aimed at port `22` is redirected to it
* The user suggested that after a benign user is classified as normal, later traffic in that session ideally should bypass the front door rather than continue flowing through it.
* The user also wants higher-fidelity server imitation:
  * do not hard-code an Ubuntu 22.04 identity forever
  * align visible SSH/server persona with the host's real `sshd` / OS where possible
* The user does not want `walle` to replace the real `sshd` for benign traffic.
* The user accepts that traffic may pass through `walle`, but prefers the real system `sshd` to remain the final authority and session implementation for legitimate access.
* The user is exploring whether a failed public-key auth on the real `sshd` could still be converted into a same-connection handoff to `sshjail` by having the front door notice the failure reason and substitute a fake success.
* The user wants `walle` to behave like an overlay:
  * while `walle` is active, SSH behavior is augmented by `walle`
  * when `walle` exits, the host falls back to ordinary `sshd`
* The user is exploring an overlay “valid user list”:
  * start empty at `walle` boot
  * when `sshd` emits `Invalid user <name>`, record that username in runtime state
  * during the same `walle` lifetime, later attempts using that username should be diverted directly into `sshjail`

## Assumptions (temporary)

* Inbound attacker-supplied credentials inside `sshjail` are intentionally treated as forensic evidence, not as secrets belonging to the protected host.
* The stricter “do not store secrets” boundary for fake outbound `ssh` should remain intact unless there is a deliberate spec change that narrows the rule to outbound-only behavior.
* The first implementation should prefer stable, typed evidence capture such as key fingerprints and structured audit records before attempting a broader intelligence subsystem.
* Session-local fake filesystem mutation is acceptable as long as it remains fully virtual and never touches the host filesystem outside audit storage.
* Automatically classifying future sessions by previously seen attacker key material is useful, but it introduces a separate policy and false-positive boundary from simple evidence capture.
* A design that relies on SSH public-key identity before handing a session to the real `sshd` must be SSH-aware in userspace or at a higher layer than the current IP-centric XDP gate.
* If the front door must classify on SSH auth method or offered public key, it will necessarily participate in the SSH session itself rather than acting as a pure packet forwarder.
* Preserving the real `sshd` as the final authority is strongly aligned with preserving `/etc/ssh/sshd_config` semantics for legitimate users.
* Intercepting a backend `sshd` auth failure after the fact is materially different from influencing `sshd`'s authorization decision before it emits success/failure.
* A pure TCP front door cannot classify on username because the username appears inside SSH userauth messages that are only visible to an SSH endpoint.
* Therefore, a runtime trap-username list is feasible only if:
  * `walle` owns enough of the SSH protocol to see usernames directly, or
  * the trap list is enforced inside `sshd` / NSS / auth hooks rather than in a pure relay

## Open Questions

* None at the moment.

## Requirements (evolving)

* Preserve higher-value inbound SSH credential evidence for contained sessions.
* Add stable capture for attacker-supplied SSH public-key material, or at minimum a deterministic fingerprint derived from it.
* Keep the current outbound fake-`ssh` “metadata-only” safety boundary explicit unless the product decision intentionally changes it.
* Improve jail realism for the observed persistence flow that rewrites `~/.ssh/authorized_keys`.
* Ensure the fake filesystem state remains coherent after supported persistence-oriented commands run inside the jail.
* Keep all mutation strictly virtual and session-scoped or persona-scoped within the jail model; no host-side command execution or host file writes beyond audit logs.
* If future detection is added, make it typed and explainable:
  * what exact key representation is stored
  * how matching works
  * what policy action a match triggers
  * where false-positive boundaries are handled
* Support a future-capable credential IOC model rather than hard-coding only one key type into one narrow rule path.
* Preserve the existing `XDP`/`tc` data plane as a fast IP/port enforcement layer unless we deliberately redesign the packet path.
* Prefer OpenSSH native hooks plus runtime overlay state as the first implementation path.
* Keep the real `sshd` as the final authority and session implementation for legitimate users.
* Preserve legitimate-user behavior and `sshd_config` semantics as a hard requirement, including `scp`, `sftp`, `pty`, and common forwarding/session features.
* Learned invalid-user trap usernames should be runtime-only overlay state:
  * present while `walle` is active
  * cleared when `walle` stops or restarts
  * not persisted as durable host identity changes in the first version
* The first observed `Invalid user <name>` event should immediately promote `<name>` into the runtime trap-username overlay.
* The first version should support a combined static + dynamic SSH public-key blacklist model:
  * static source such as `/etc/walle/blacklist_keys`
  * dynamic runtime-learned blacklist keys persisted to disk
* Dynamic blacklist persistence may reuse the same base-directory discovery/defaulting approach as existing SSH GP audit storage, but decision-state files must remain separate from session audit logs.
* If the operator does not configure a persistent root path, dynamic blacklist state may default under `/tmp/walle/`.
* The configured path should be treated as a root directory, not a single output file path.
* Under that root, evidence and decision state should live in separate subtrees.
* The first observed inbound SSH public key inside `sshjail` should immediately promote that key into the dynamic blacklist store.

## Acceptance Criteria (evolving)

* [x] A contained inbound SSH session that offers a public key produces stable evidence beyond `algorithm=<type>`.
* [x] Supported `.ssh` persistence commands produce coherent virtual filesystem state inside the jail.
* [x] The fake outbound `ssh` path keeps its intended no-secret capture boundary unless explicitly redefined.
* [x] Audit persistence remains file-backed and operator-configurable.
* [x] If key-based future detection is included, repeat access with the same captured key material can be matched deterministically and routed according to explicit policy.
* [x] The chosen architecture makes clear which layer can and cannot inspect SSH identity material.
* [x] Runtime invalid-user trap usernames are promoted into an ephemeral identity overlay while `walle` is active.
* [x] The identity overlay install path includes an NSS module, trap-login shell wrapper, and operator-facing `sshd_config` / `nsswitch.conf` samples.
* [x] Invalid-user password attempts can be same-connection trapped into `sshjail` without affecting real-user password logins.

## Definition of Done

* Relevant backend specs and executable contracts are updated before or alongside implementation.
* `cargo test -p walle-daemon` passes.
* Any new detection behavior has tests for good/base/bad cases and explicit false-positive boundaries.
* Audit behavior remains typed, reviewable, and compatible with existing session logging.
* The chosen integration path is fail-open for legitimate traffic when `walle` overlay components are unavailable.

## Out of Scope (explicit)

* Reusing captured attacker credentials to initiate real outbound access from the host.
* Storing or replaying host-side administrator secrets.
* Full shell-script emulation beyond the specific SSH persistence behaviors we choose to support.
* A generic threat-intel framework for every credential type unless explicitly included in this task.

## Research Notes

### Repo constraints

* `sshjail` currently records session events as flat audit log lines, not as a structured database.
* Policy already validates `audit_dir`, but there is no typed retention or evidence-index configuration.
* Existing shell realism work intentionally kept fake outbound `ssh` as metadata-only.
* The current eBPF/XDP path in `crates/walle-ebpf/src/main.rs` evaluates IP/protocol/port and contain-map state. It does not parse or decrypt SSH authentication payloads.
* The current architecture doc already states:
  * keep the XDP path IP-centric
  * store fingerprint metadata in user-space first
  * do not make automatic decisions solely from a fingerprint match at the XDP layer

### Protocol constraints

* SSH public-key authentication occurs in the `ssh-userauth` protocol above the transport layer.
* The SSH authentication protocol assumes the lower layer already provides confidentiality and integrity.
* Therefore, the public key offered by the client is visible to an SSH-speaking endpoint, but not to the existing packet-level XDP gate.
* A packet/TCP redirect can move a new connection from port `22` to a daemon-owned internal port, but it cannot trivially remove a proxy from the middle of the same already-established SSH connection after auth succeeds.
* If a front door terminates enough of SSH to inspect auth method or offered key, that same front door remains on the critical path for the life of the session unless we introduce a much more specialized connection-handoff mechanism.
* For public-key logins in particular, a front door that terminates SSH cannot simply open a new backend SSH connection “using the client's private key”; the private key never leaves the client.
* RFC 4252 defines `SSH_MSG_USERAUTH_FAILURE` as carrying only:
  * the authentication methods that may continue
  * a partial-success boolean
  It does not carry a rich machine-readable reason such as “key not present in authorized_keys”.
* Therefore, a front door that is only relaying encrypted SSH traffic cannot infer the specific backend failure reason from the wire response alone.
* RFC 4252 also states that if the requested username does not exist, authentication must not be accepted.
* Therefore, same-connection “invalid user -> accepted into jail” is not something a stock `sshd` can do for a nonexistent local user unless we first make that username valid in an overlay sense.

### Feasible approaches here

**Approach A: Evidence-only capture** (lowest scope)

* How it works:
  * record inbound public-key fingerprint and optionally the full offered public key in the session audit log
  * add session-local fake `.ssh` mutation support for the persistence commands we have observed
* Pros:
  * directly solves the evidence gap
  * limited policy surface
  * low false-positive risk because no automatic enforcement depends on the captured key
* Cons:
  * does not help auto-contain future sessions before the normal detector path triggers

**Approach B: Evidence capture + reusable key intelligence** (likely best product value)

* How it works:
  * do everything in Approach A
  * normalize offered public keys into a stable fingerprint
  * persist an index of seen malicious key fingerprints
  * allow later sessions presenting the same key to bypass threshold waiting and enter `sshjail` directly
* Pros:
  * converts observation into an operational containment signal
  * aligns with the user’s “same key => directly malicious” idea
* Cons:
  * needs a typed policy and storage contract
  * needs explicit handling for malformed keys, duplicate sightings, TTL/retention, and false positives

**Approach C: General credential IOC pipeline**

* How it works:
  * capture passwords, public keys, and selected command-derived IOCs under one reusable subsystem
  * feed that subsystem into detector and policy decisions
* Pros:
  * most extensible long-term
* Cons:
  * too broad for the immediate gap
  * highest design and testing cost

### Feasible front-door architectures for SSH identity decisions

**Front-Door A: Keep XDP IP-centric, do key intelligence only after `sshjail` capture**

* How it works:
  * XDP/tc continue deciding only by IP and contain-map state
  * malicious key intelligence is learned inside `sshjail` and reused only after an IP is already routed there by other triggers
* Pros:
  * fits current architecture exactly
  * lowest implementation risk
* Cons:
  * cannot divert a brand-new IP directly to `sshjail` based on key identity alone

### Feasible `sshd`-integrated architectures for same-connection decisions

**SSHD Hook A: `RevokedKeys` / KRL only**

* How it works:
  * maintain `/etc/walle/blacklist_keys` as a text list or OpenSSH KRL
  * configure `sshd` `RevokedKeys` to refuse those keys
* Pros:
  * keeps real `sshd` fully authoritative
  * simple and natively supported by OpenSSH
* Cons:
  * only yields hard refusal
  * does not route the current session into `sshjail`

**SSHD Hook B: `AuthorizedKeysCommand`-driven trap** (strong candidate)

* How it works:
  * `sshd` remains the public protocol authority for legitimate users
  * `AuthorizedKeysCommand` receives the offered key / fingerprint via OpenSSH tokens such as `%k` and `%f`
  * for benign keys, normal `AuthorizedKeysFile` / existing auth flow remains unchanged
  * for blacklisted keys, the helper returns a synthetic `authorized_keys` entry with restrictive options and a forced command that launches a `walle` jail session
* Pros:
  * same-connection decision happens inside the real `sshd` auth pipeline
  * preserves `sshd_config` semantics for legitimate users better than an SSH-terminating front proxy
  * avoids trying to rewrite an already-failed encrypted response in flight
* Cons:
  * depends on OpenSSH auth-hook behavior and valid-user constraints
  * needs careful design for target username validity, PTY/subsystem handling, and audit boundaries

**SSHD Hook C: PAM / custom patch / custom auth module**

* How it works:
  * integrate at a deeper auth hook inside or adjacent to `sshd`
  * on blacklist match, deliberately succeed into a controlled restricted session
* Pros:
  * maximal control
* Cons:
  * highest operational and maintenance cost

**SSHD Hook D: NSS / identity overlay users** (candidate for invalid-user trap)

* How it works:
  * `walle` maintains a runtime trap-username list, e.g. `tomcat`
  * while active, an NSS overlay or sshd-specific identity hook makes those trap usernames appear as valid synthetic accounts only to the SSH auth path
  * those synthetic accounts are mapped to a restricted `walle`-owned jail session with forced command / disabled forwarding / controlled home and shell semantics
  * when `walle` stops, the overlay disappears and those usernames revert to “invalid user”
* Pros:
  * matches the user's overlay mental model closely
  * keeps the real `sshd` as protocol authority
  * allows same-connection trap for previously learned invalid usernames
* Cons:
  * much more invasive than a detector-only cache
  * risks affecting broader NSS consumers unless tightly scoped
  * requires careful semantics for UID/GID/home/shell, audit, and cleanup

## Decision (ADR-lite)

**Context**: The user wants same-connection traps where possible, but does not want `walle` to become the full SSH authority for benign traffic. Legitimate sessions must continue to inherit real `sshd` semantics and features.

**Decision**: Prefer `OpenSSH` native hooks plus runtime overlay state as the first implementation direction. Do not base the design on a full SSH-terminating front proxy for legitimate users. Use deeper `sshd` integration only if native hooks cannot satisfy a required trap path.

**Consequences**:

* Legitimate-user behavior remains anchored in the real `sshd`.
* Key-based same-connection traps should be designed around `AuthorizedKeysCommand`, `RevokedKeys`, and adjacent OpenSSH mechanisms.
* Learned invalid-user traps likely require an identity overlay or `sshd`-adjacent user-resolution hook, not a pure network front door.
* `walle` startup/shutdown can approximate an overlay model:
  * active -> additional trap identities and auth decisions exist
  * inactive -> host reverts to ordinary `sshd` behavior

## Trap Username Lifetime (ADR-lite)

**Context**: The user wants invalid usernames learned during attack traffic to behave like an overlay while `walle` is active, without permanently mutating host identity semantics.

**Decision**: Learned trap usernames are runtime-only state for the current `walle` process lifetime.

**Consequences**:

* `walle` restart clears the learned invalid-username overlay.
* The first version avoids long-lived false positives caused by stale learned usernames.
* This matches the desired “Magisk overlay” mental model:
  * `walle` active -> extra trap usernames exist
  * `walle` inactive -> host returns to ordinary `sshd` behavior

## Trap Username Promotion (ADR-lite)

**Context**: The project already treats explicit `Invalid user` events as directly malicious when `invalid_user_force_ban_enabled` is active. The user wants fast learning for runtime overlay trap usernames rather than waiting for repeated observations.

**Decision**: The first observed `Invalid user <name>` event immediately promotes `<name>` into the runtime trap-username overlay for the current `walle` lifetime.

**Consequences**:

* Promotion is simple and deterministic.
* Later attempts using the same nonexistent username can be trapped immediately during the same `walle` run.
* The false-positive boundary depends on correctly determining whether a username is actually nonexistent in the system identity sources at the time of observation.
* Because the state is runtime-only, restart clears any accidentally learned names.

## Blacklist Key Source (ADR-lite)

**Context**: The user wants `blacklist_keys` to support both operator-curated static entries and runtime-learned malicious keys, with the learned portion automatically persisted to disk.

**Decision**: The first version should use a combined static + dynamic blacklist model for SSH public keys.

**Consequences**:

* Static blacklist entries remain operator-auditable and manually managed.
* Runtime-learned malicious keys can survive `walle` restarts if the dynamic store path is persistent.
* The dynamic blacklist store should be a typed decision-state file or directory, not a byproduct of raw session logs.
* Reusing the audit base-path defaulting behavior is acceptable, but evidence logs and enforcement inputs must remain logically separate.
* If no explicit persistent path is configured, the dynamic store may live under `/tmp/walle/`, which makes learning opportunistic rather than durable across reboots.

## Dynamic Blacklist Promotion (ADR-lite)

**Context**: The user wants runtime learning to have immediate operational value rather than remaining evidence-only. Because any key presented inside `sshjail` is already attacker-controlled input to a containment environment, the user prefers immediate promotion into the dynamic blacklist.

**Decision**: The first observed inbound SSH public key inside `sshjail` immediately promotes that key into the dynamic on-disk blacklist.

**Consequences**:

* Repeated use of the same key can be matched across future sessions and restarts when the dynamic store is persistent.
* The false-positive boundary is intentionally aggressive: being seen inside `sshjail` is itself treated as sufficient malicious evidence.
* Dynamic blacklist writes must be deduplicated and atomic to avoid log-style growth and corruption.

## Path Layout Contract (ADR-lite)

**Context**: The user wants `/tmp/walle` to act as the default root path, while allowing operators to override that root and keep both audit evidence and decision state underneath it.

**Decision**: Introduce a root-path contract for SSH GP storage. Use the configured root if provided; otherwise default to `/tmp/walle`. Store evidence and decision state in separate subdirectories under that root.

**Consequences**:

* The default layout can evolve toward a shape such as:
  * `<root>/gp/ssh/sessions/...`
  * `<root>/gp/ssh/state/blacklist_keys.dynamic`
* Operators can move the whole SSH GP storage tree by changing one root-path setting.
* Audit review, deduplication, and rollback stay cleaner because raw session evidence and derived blacklist state are not intermingled.

**Front-Door B: Add an SSH-aware front proxy/terminator in userspace** (recommended if key-based pre-routing is required)

* How it works:
  * a daemon-owned SSH front door receives inbound SSH first
  * it performs enough of the SSH handshake/auth negotiation to observe auth method and offered public key
  * it decides:
    * password or unknown key -> relay/hand off to real `sshd`
    * blacklisted malicious key -> terminate into `sshjail`
* Pros:
  * the only clean way to make pre-routing decisions on SSH key identity
  * keeps XDP fast and simple
  * gives a single place for typed credential IOC policy
* Cons:
  * materially larger architecture change
  * requires SSH-aware proxying/termination, not just tc port rewrite
  * creates a new user-visible compatibility surface for benign SSH clients unless we deliberately preserve host keys, feature support, and backend behavior
  * the proxy generally cannot disappear mid-session after a benign classification; it becomes the SSH front door for the entire connection

**Front-Door C: AF_XDP/raw-packet userspace interception with custom SSH parsing**

* How it works:
  * redirect SSH traffic into userspace at packet level and implement enough TCP/SSH processing there to classify and steer
* Pros:
  * maximum control
* Cons:
  * extreme complexity for MVP
  * effectively reinvents a transport-aware front proxy with worse operational risk

### User impact framing for an SSH front door

If `walle` becomes the public SSH front door, normal-user impact depends on how transparent we require it to be.

**Impact areas for benign users**

* Host identity:
  * if the front door presents a different server host key, users will see host key mismatch warnings
  * reusing the existing host host keys minimizes that impact
* Auth compatibility:
  * password, publickey, keyboard-interactive, MFA/PAM-backed flows, and account restrictions must remain compatible
  * if benign sessions must still end up on the real system account, we need an explicit backend auth/session model rather than assuming a transparent handoff to `sshd`
* Session feature parity:
  * interactive shell
  * `exec`
  * PTY allocation
  * SCP / SFTP subsystem
  * local/remote/dynamic port forwarding
  * agent forwarding
  * keepalives and disconnect behavior
* Reliability:
  * the front door becomes part of the critical path for all inbound SSH
  * fail-open vs fail-closed behavior must be explicitly chosen
* Performance:
  * an extra userspace hop should add only small latency, but connection setup and backend proxying become additional overhead
* Audit/privacy:
  * the front door necessarily sees auth method selection and may see credential material used to proxy authentication

**Perception risk for malicious users**

* Low-skill automated bots likely will not notice a redirect if the presented SSH server looks consistent and `sshjail` remains believable.
* Skilled operators may notice if any of the following diverge from the real host:
  * host key
  * banner / server version
  * algorithm negotiation
  * auth-method ordering
  * timing and retry behavior
  * forwarding / subsystem support
  * shell realism after login

**Design implication**

* If we require key-based pre-routing before real `sshd`, the clean architecture is a true SSH-aware front proxy.
* The more transparent we want it to be for normal users, the closer it becomes to a production-grade SSH bastion with high protocol fidelity, not just a detector.
* Redirecting new port-22 flows to a random internal port is feasible with the current `tc` rewrite model.
* Bypassing the front door for the remainder of the same benign SSH session is not a realistic baseline assumption; the design should assume the front door stays in path for the full connection.
* If the real `sshd` must remain the session authority for legitimate traffic, then a pure or near-pure TCP relay preserves `sshd_config` best but loses the ability to inspect SSH public-key identity before backend delivery.
* If same-connection diversion is required while keeping `sshd` authoritative, the practical decision point should move into `sshd`'s auth/authorization hooks, not into a relay that tries to rewrite backend failure after the fact.
* The user's proposed runtime invalid-user trap list is conceptually sound, but only as an `sshd`/identity overlay or as a true SSH-terminating front door. It is not achievable with a pure TCP relay front door alone.

## Technical Notes

* Files already inspected:
  * `crates/walle-daemon/src/sshjail.rs`
  * `crates/walle-policy/src/lib.rs`
  * `.trellis/spec/backend/quality-guidelines.md`
  * `.trellis/spec/guides/cross-layer-thinking-guide.md`
  * `docs/architecture/walle-system-design.md`
  * `crates/walle-ebpf/src/main.rs`
* Concrete repo findings:
  * inbound password capture exists
  * inbound public-key capture is currently algorithm-only
  * fake filesystem contains `.ssh` in multiple personas
  * shell mutation support is missing for the observed persistence command chain
  * XDP currently only gates on IP/protocol/port plus contain/deny state
  * `sshjail` currently advertises a fixed `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5` server ID and Ubuntu-like runtime/OS strings
  * `sshjail` already tries to reuse the system `sshd` host key when readable, which is a good starting point for transparency
* Cross-layer boundary to define before implementation if Approach B or C is chosen:
  * auth event -> evidence record -> storage/index -> detector/policy lookup -> GP contain decision
* Source-backed protocol notes:
  * RFC 4252 says the SSH authentication protocol runs on top of the SSH transport layer and assumes confidentiality/integrity from lower layers
  * RFC 4252 section 7 shows the client public key blob is carried in `SSH_MSG_USERAUTH_REQUEST`
  * RFC 4253 section 6.3 says that after key exchange, packet payload fields are encrypted
  * RFC 4252 section 5.1 defines authentication failure responses in terms of remaining methods plus partial-success state, not detailed backend failure causes
* OpenSSH `sshd_config` documents:
  * `RevokedKeys` for refusing listed public keys
  * `AuthorizedKeysCommand` for consulting an external key-authority helper, with `%f` fingerprint and `%k` offered-key tokens
  * `AuthorizedKeysCommand` runs only for valid users and only after usual `AuthorizedKeysFile` lookup misses

## Current Route (locked)

The current implementation path is now explicitly locked to `NSS/PAM/sshd hook`, not a general-purpose SSH front door.

* Real users must continue to land on the real system `sshd`.
* `walle` must not become the primary SSH server for benign traffic.
* `scp`, `sftp`, `pty`, forwarding, and existing `sshd_config` behavior must remain anchored in `sshd`.
* `XDP/tc` remains an IP/port containment layer for already-contained sources; it is not the pre-auth identity router.
* Username existence overlay is handled with `NSS`.
* Public-key same-connection trap is handled with `AuthorizedKeysCommand`.
* Password same-connection trap for overlay identities requires `PAM`; `NSS` alone cannot make password auth succeed.

## Current Design

### Layer responsibilities

**`sshjail`**

* Captures inbound attacker credentials as evidence once a session is already contained.
* Promotes first-seen attacker public keys into the dynamic blacklist store.
* Emulates attacker `.ssh` persistence behavior inside the virtual filesystem.
* Provides the local trap shell entrypoints used after an `sshd` auth hook decides to trap.

**Dynamic/static blacklist state**

* Static blacklist source remains operator-managed, e.g. `/etc/walle/blacklist_keys`.
* Dynamic learned keys are persisted under `<root>/gp/ssh/state/blacklist_keys.dynamic`.
* Decision-state files stay separate from session audit logs under `<root>/gp/ssh/sessions/...`.

**NSS identity overlay**

* Runtime `Invalid user <name>` events promote `<name>` into an in-memory/runtime-persisted overlay file under `<root>/gp/ssh/state/trap_identities.runtime`.
* Synthetic trap identities get a high-range UID/GID, trap home under `<root>/gp/ssh/trap-home/<user>`, and a trap-login shell.
* `files` stays before `walle` in `nsswitch.conf` so real accounts always win.
* Overlay state is cleared on `walle` stop/restart.

**OpenSSH public-key hook**

* `AuthorizedKeysCommand` evaluates the offered key and current username.
* If the key is blacklisted, or the username is already a trap identity, the helper returns a synthetic forced-command authorized-key line.
* The forced command launches `walle ssh overlay trap-shell --token ...`, preserving same-connection trap behavior for the key path.
* If `walle` runtime is inactive or containment is disabled, the helper fails open and returns nothing.

**Trap-login shell wrapper**

* Trap identities use `/usr/local/lib/walle/walle-ssh-overlay-shell`.
* The wrapper translates sshd login-shell `-c <cmd>` invocations into `SSH_ORIGINAL_COMMAND` and then executes `walle ssh overlay trap-login`.
* This keeps overlay identities usable for shell and remote-command entry without replacing `sshd`.

**Future PAM hook**

* Required only for password same-connection trap on overlay identities.
* Intended behavior:
  * detect trap identity during password auth
  * record the presented password as evidence
  * return success only for trap identities
  * leave real users on ordinary PAM behavior
* This module must fail open for real users and for overlay-unavailable states.

### Authentication flow

**Public-key path**

1. Client reaches real `sshd`.
2. `NSS` resolves real users first; runtime trap identities are visible only after `files`.
3. `AuthorizedKeysCommand` receives `%u/%U/%h/%t/%k/%f`.
4. If the key or username hits trap policy, sshd accepts the synthetic key and forces the trap shell.
5. `walle` consumes the pending trap token and opens a local trapped session.

**Invalid-user password path today**

1. First invalid username attempt hits real `sshd` and generates `Invalid user`.
2. `walle` learns that username into runtime trap identity state.
3. Later attempts no longer fail at user lookup because `NSS` makes the synthetic user visible.
4. Password auth still belongs to PAM, so same-connection trap is not complete yet.

**Invalid-user password path target**

1. Steps 1-3 above remain unchanged.
2. `pam_walle` recognizes the trap identity.
3. The module records the presented password and returns success for trap identities only.
4. Session starts through the trap-login shell wrapper and lands in `sshjail`.

## Implemented Scope Snapshot

### Implemented

* Inbound SSH public-key evidence capture and dynamic blacklist promotion in `sshjail`
* Virtual `.ssh` mutation realism for common persistence commands
* Static + dynamic blacklist key matching
* Key-based same-connection trap via `AuthorizedKeysCommand`
* Runtime invalid-user promotion into typed trap identities
* `walle-nss` NSS module with passwd/group/shadow/initgroups hooks
* Trap-login shell wrapper rendering and trap-login entrypoint
* Installer/release packaging for:
  * `libnss_walle.so.2`
  * `walle-ssh-overlay-shell`
  * `walle-ssh-overlay.conf.sample`
  * `walle-nsswitch.conf.sample`
* CLI support for printing overlay config samples
* Targeted tests for overlay state, installer paths, trap-login, and NSS buffer filling

### Not implemented yet

* Operator rollout automation for editing `sshd_config` / `/etc/nsswitch.conf` (kept manual by design)
* Real-host validation matrix for multiple Linux distros / libdir layouts

## Task Breakdown

### Phase 1: Evidence and realism

* [x] Capture inbound public keys with stable material/fingerprint in `sshjail`
* [x] Persist learned malicious keys to a dynamic blacklist store
* [x] Emulate attacker `.ssh` rewrite/persistence commands inside the virtual filesystem
* [x] Preserve the outbound fake-`ssh` no-secret boundary

### Phase 2: Key-based same-connection trap

* [x] Add static + dynamic blacklist key evaluation
* [x] Add `AuthorizedKeysCommand` trap decision logic
* [x] Add pending trap records and forced-command handoff into `sshjail`
* [x] Keep the key path fail-open when runtime or containment is inactive

### Phase 3: Runtime invalid-user overlay

* [x] Promote `Invalid user` events into runtime trap usernames
* [x] Promote trap usernames into typed trap identities with synthetic UID/GID/home/shell
* [x] Clear overlay identity state when `walle` stops or restarts
* [x] Add trap-login entrypoint for shell sessions without pending public-key tokens

### Phase 4: Install and operator integration

* [x] Build and package `walle-nss`
* [x] Install the NSS module into the target root
* [x] Install a trap-login shell wrapper matching the synthetic shell path
* [x] Install `sshd_config` and `nsswitch.conf` sample fragments
* [x] Update release bundle and operator documentation

### Phase 5: Password-path completion

* [x] Design `pam_walle` module boundaries and fail-open behavior
* [x] Implement same-connection trap for password auth on overlay identities
* [x] Record presented password evidence only for trap identities
* [x] Validate that real-user PAM flows remain unchanged

## Progress Summary

Current task state is implementation-complete across all five phases. Remaining follow-up work is operational hardening, not a gap in the agreed feature set.

## Child Tasks

* [x] `04-14-sshjail-key-evidence-realism`
  * scope: inbound key evidence capture and virtual `.ssh` persistence realism
* [x] `04-14-ssh-overlay-authorized-keys-trap`
  * scope: static/dynamic blacklist matching and same-connection key trap via `AuthorizedKeysCommand`
* [x] `04-14-ssh-overlay-nss-identity-runtime`
  * scope: runtime invalid-user promotion, typed trap identities, `walle-nss`, and trap-login entrypoint
* [x] `04-14-ssh-overlay-install-release-integration`
  * scope: install/release packaging, shell wrapper, config samples, and operator docs
* [x] `04-14-ssh-overlay-pam-password-trap`
  * scope: same-connection password trap for overlay identities with fail-open real-user behavior
