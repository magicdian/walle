# SSH Overlay And Bundle Contract

> Executable contracts for the SSH overlay path, runtime state layout, and distribution bundle behavior.

---

## Scenario: SSH Overlay Activation Contract

### 1. Scope / Trigger

* Trigger: Any change to the `sshd` integration path, overlay CLI subcommands, NSS/PAM activation, or operator-facing install samples.

### 2. Signatures

* CLI helper:
  * `walle ssh overlay authorized-keys --user %u --uid %U --home %h --key-type %t --key-base64 %k --fingerprint %f`
  * `walle ssh overlay trap-shell --token <token>`
  * `walle ssh overlay trap-login`
  * `walle ssh overlay print-sshd-config`
  * `walle ssh overlay print-nsswitch-config`
  * `walle ssh overlay print-pam-config`
* Install-rendered files:
  * `/usr/local/lib/walle/walle-ssh-overlay.conf.sample`
  * `/usr/local/lib/walle/walle-nsswitch.conf.sample`
  * `/usr/local/lib/walle/walle-sshd-pam.conf.sample`
  * `/usr/local/lib/walle/walle-ssh-overlay-shell`
* Real host config fragments:
  * `AuthorizedKeysCommand /usr/local/bin/walle ssh overlay authorized-keys --user %u --uid %U --home %h --key-type %t --key-base64 %k --fingerprint %f`
  * `AuthorizedKeysCommandUser root`
  * `passwd: files walle systemd`
  * `group: files walle systemd`
  * `shadow: files walle`
  * `initgroups: files walle`
  * `auth    [success=done default=ignore] /usr/local/lib/walle/pam_walle.so`
  * `account [success=done default=ignore] /usr/local/lib/walle/pam_walle.so`
  * `session [success=done default=ignore] /usr/local/lib/walle/pam_walle.so`

### 3. Contracts

* Real users must continue to authenticate against the real host `sshd`; Walle is an overlay, not a replacement SSH server for legitimate traffic.
* `files` must stay before `walle` in `/etc/nsswitch.conf` so real system identities win before runtime trap identities.
* The PAM lines must be inserted in the documented order:
  * `auth` before `@include common-auth`
  * `account` after `pam_nologin.so` and before `@include common-account`
  * `session` after `pam_keyinit.so` and before `@include common-session`
* `AuthorizedKeysCommand` must fail open when the daemon runtime lock is absent, config load fails, or GP containment is disabled.
* `trap-shell` and `trap-login` are different entrypoints:
  * `trap-shell` consumes a pending forced-command token
  * `trap-login` resolves the runtime trap identity by UID
* `trap-login` is only valid for NSS-promoted runtime identities. It must not be used as a generic replacement for the forced-command trap path.

### 4. Validation & Error Matrix

| Condition | Expected Behavior |
|----------|-------------------|
| daemon inactive | `authorized-keys` prints nothing and real `sshd` continues normally |
| GP containment disabled | `authorized-keys` prints nothing and real `sshd` continues normally |
| real user + non-blacklisted key | real `sshd` evaluates normal host key policy |
| real user + blacklisted key | local trap session opens with `entrypoint=sshd_overlay trigger=blacklisted_key` |
| runtime trap username + password path | PAM/NSS overlay may land in local trap login |
| invalid username first seen | real `sshd` logs invalid user, Walle promotes runtime trap identity, detector may ban/contain later attempts |

### 5. Good/Base/Bad Cases

* Good:
  * `root` with a blacklisted key lands in a local trap session while normal users remain unaffected.
  * `tomcat` first appears as an invalid user in real `sshd`, then becomes a runtime trap identity for the lifetime of that daemon process.
* Base:
  * if operators only merge the `sshd_config` fragment, blacklisted-key trap can still work for real valid users, while invalid-user overlay behavior remains incomplete without NSS/PAM.
* Bad:
  * putting `walle` before `files` in `nsswitch.conf`
  * inserting PAM lines after `common-*` includes
  * treating the overlay as a generic front-door and bypassing real `sshd` for legitimate traffic

### 6. Tests Required

* CLI parsing tests for:
  * `ssh overlay authorized-keys`
  * `ssh overlay print-sshd-config`
  * `ssh overlay print-nsswitch-config`
  * `ssh overlay print-pam-config`
* daemon/overlay tests for:
  * forced-command rendering for static or dynamic blacklist hits
  * runtime trap-username overlay rendering
  * runtime fail-open when daemon or containment is inactive
* host validation assertions:
  * `sshd -t` succeeds after merging the sample fragments
  * a legitimate real user still reaches the real host account space

### 7. Wrong vs Correct

#### Wrong

```text
passwd: walle files systemd
```

#### Correct

```text
passwd: files walle systemd
```

---

## Scenario: SSH Overlay State Layout And Capture Boundary Contract

### 1. Scope / Trigger

* Trigger: Any change to `SshOverlayPaths`, runtime state reset behavior, dynamic key capture, trap identity persistence, or `sshjail` shell-side persistence emulation.

### 2. Signatures

* `crates/walle-daemon/src/ssh_overlay.rs::SshOverlayPaths::from_policy(&SshJailPolicy)`
* `crates/walle-daemon/src/ssh_overlay.rs::SshOverlayPaths::reset_runtime_state()`
* `crates/walle-daemon/src/ssh_overlay.rs::SshOverlayRuntimeState::prepare_runtime_state()`
* `crates/walle-daemon/src/ssh_overlay.rs::evaluate_authorized_keys_trap(...)`
* `crates/walle-daemon/src/sshjail.rs::capture_inbound_public_key(...)`
* `crates/walle-daemon/src/sshjail.rs::try_execute_echo_redirection(...)`

### 3. Contracts

* `root_dir` is the base directory, not the `gp/ssh` leaf.
* The derived layout is fixed:
  * `<root_dir>/gp/ssh/sessions`
  * `<root_dir>/gp/ssh/state/blacklist_keys.dynamic`
  * `<root_dir>/gp/ssh/state/trap_usernames.runtime`
  * `<root_dir>/gp/ssh/state/trap_identities.runtime`
  * `<root_dir>/gp/ssh/state/auth-info/`
  * `<root_dir>/gp/ssh/state/pending_traps/`
  * `<root_dir>/gp/ssh/trap-home/`
* `trap_usernames.runtime` and `trap_identities.runtime` are runtime-only state:
  * created while the daemon is active
  * cleared on daemon startup reset
  * cleared on graceful shutdown
* `blacklist_keys.dynamic` is persistent state:
  * it survives daemon restart
  * it is loaded into the dynamic blacklist store on `sshjail` startup
* `blacklist_keys.dynamic` only records public keys observed during SSH authentication inside `sshjail`:
  * `auth_publickey_offered`
  * `auth_publickey`
* Writing to `.ssh/authorized_keys` from inside the fake shell updates only the virtual filesystem and session transcript. It does **not** automatically update `blacklist_keys.dynamic`.

### 4. Validation & Error Matrix

| Condition | Expected Behavior |
|----------|-------------------|
| `root_dir = "/tmp/walle"` | state resolves under `/tmp/walle/gp/ssh/...` |
| `root_dir = "/tmp/walle/gp/ssh"` | duplicated path shape such as `/tmp/walle/gp/ssh/gp/ssh/...`; treat as operator misconfiguration |
| first invalid user attempt | runtime trap files appear, dynamic blacklist file may still be absent |
| second contained attempt enters `sshjail` and offers a key | `blacklist_keys.dynamic` is created or appended |
| daemon restart after key capture | runtime trap files reset, dynamic blacklist file remains |
| shell `echo "...key..." > .ssh/authorized_keys` | fake file changes; dynamic blacklist file remains unchanged unless that key was also seen during auth |

### 5. Good/Base/Bad Cases

* Good:
  * use `root_dir = "/tmp/walle"` and let Walle derive the `gp/ssh` subtree.
  * validate dynamic blacklist by first seeding a key in `sshjail`, then reconnecting as a real existing user such as `root`.
* Base:
  * `trap_usernames.runtime` and `trap_identities.runtime` can be used for same-process invalid-user follow-up traps only.
* Bad:
  * expecting `trap_identities.runtime` to survive daemon restart
  * expecting a shell-side `authorized_keys` write to populate `blacklist_keys.dynamic`
  * configuring `root_dir` to the already-expanded `gp/ssh` leaf

### 6. Tests Required

* overlay tests must assert:
  * runtime-state reset clears only `.runtime`, auth-info, pending traps, and trap-home directories
  * dynamic blacklist store persists and deduplicates
  * trap username and trap identity stores persist runtime records while the process is alive
* `sshjail` tests must assert:
  * inbound auth-layer public keys persist into the dynamic blacklist store
  * shell persistence commands update the virtual filesystem for `.ssh/authorized_keys`
* host validation assertions:
  * `grep` in the latest session log shows `entrypoint=sshd_overlay trigger=blacklisted_key` for a real valid user hit

### 7. Wrong vs Correct

#### Wrong

```toml
root_dir = "/tmp/walle/gp/ssh"
```

#### Correct

```toml
root_dir = "/tmp/walle"
```

---

## Scenario: Bundle And Install Artifact Contract

### 1. Scope / Trigger

* Trigger: Any change to `xtask build-release`, `xtask build-debug`, install-time artifact discovery, or bundle layout documentation.

### 2. Signatures

* `cargo run -p xtask -- build-release`
* `cargo run -p xtask -- build-debug`
* `crates/walle-daemon/src/install.rs::resolve_xdp_object(...)`
* `crates/walle-daemon/src/install.rs::resolve_nss_module(...)`
* `crates/walle-daemon/src/install.rs::resolve_pam_module(...)`
* Installed targets:
  * `/usr/local/bin/walle`
  * `/usr/local/lib/walle/walle-ebpf`
  * `/lib/libnss_walle.so.2`
  * `/usr/local/lib/walle/pam_walle.so`

### 3. Contracts

* Release bundle layout is:
  * `bin/walle`
  * `lib/walle/walle-ebpf`
  * `lib/libnss_walle.so.2`
  * `lib/walle/pam_walle.so`
* Debug bundle keeps user-space artifacts on the Cargo debug profile but still packages the optimized release `walle-ebpf`.
* This mixed-profile rule is intentional and mandatory until the debug BPF profile becomes loader-safe on target hosts.
* Install resolution must accept workspace PAM build artifacts named `libpam_walle.so` and stage them as installed `pam_walle.so`.
* Install resolution must accept workspace NSS build artifacts named `libnss_walle.so` and stage them as installed `libnss_walle.so.2`.

### 4. Validation & Error Matrix

| Condition | Expected Behavior |
|----------|-------------------|
| `build-release` | archive under `target/release-bundle/` with release user-space artifacts and release `walle-ebpf` |
| `build-debug` | archive under `target/debug-bundle/` with debug user-space artifacts and release `walle-ebpf` |
| bundle install from extracted `bin/walle` | relative lookup resolves `../lib/walle/walle-ebpf`, `../lib/libnss_walle.so.2`, and `../lib/walle/pam_walle.so` |
| workspace install without staged `pam_walle.so` | fallback accepts `target/<profile>/libpam_walle.so` |
| workspace install without staged `libnss_walle.so.2` | fallback accepts `target/<profile>/libnss_walle.so` |

### 5. Good/Base/Bad Cases

* Good:
  * `xtask build-debug` is used for host validation while still shipping the release eBPF object.
  * install runs from an extracted bundle and resolves all three companion artifacts relative to the binary.
* Base:
  * workspace-local install may fall back to Cargo build outputs when no bundle is present.
* Bad:
  * packaging the debug-profile `walle-ebpf` into host-validation bundles
  * assuming Cargo emits `pam_walle.so` instead of `libpam_walle.so`
  * documenting bundle layout without matching install-time search paths

### 6. Tests Required

* `xtask` tests must assert:
  * release and debug bundle names differ
  * debug and release bundle directories differ
* install tests must assert:
  * bundle-relative resolution for eBPF, NSS, and PAM artifacts
  * workspace PAM fallback accepts `libpam_walle.so`
  * rendered install samples point to `/usr/local/bin/walle` and installed artifact paths
* host validation assertions:
  * extracted debug bundle contains the expected files
  * installed host path `/usr/local/lib/walle/walle-ebpf` is loadable by the target runtime

### 7. Wrong vs Correct

#### Wrong

* Treat `build-debug` as "build every artifact on the debug profile", including `walle-ebpf`.

#### Correct

* Treat `build-debug` as "debug user-space bundle with release `walle-ebpf`", because host loader compatibility is part of the bundle contract.
