# Debug Bundle Validation Guide

## Goal

Provide a repeatable end-to-end validation flow for `walle` using the debug bundle produced by:

```bash
cargo run -p xtask -- build-debug
```

This guide is intended for local lab hosts and non-production SSH overlay verification.

The debug bundle uses debug user-space binaries and the optimized release `walle-ebpf` object. This is intentional: the current debug BPF profile is not shipped for host validation because its loader-time relocation shape is not stable enough for the target runtime path.

## Scope

The flow validates:

* debug bundle extraction and layout
* `walle install` using the debug bundle layout
* manual SSH overlay activation
* runtime invalid-user promotion
* same-connection password trap via `pam_walle`
* same-connection key trap via `AuthorizedKeysCommand`
* `sshjail` evidence persistence

It does not validate:

* production packaging policy
* distro-specific service management differences beyond `systemd`
* cross-distro PAM path variance beyond the shipped sample fragment

## Prerequisites

### Build Host

Generate the debug bundle:

```bash
cargo run -p xtask -- build-debug
```

Expected artifact:

```bash
target/debug-bundle/walle-v<version>-linux-<arch>-debug.tar.gz
```

### Target Host

Required:

* Linux host with OpenSSH server
* root access
* kernel and runtime prerequisites already documented in `linux-install-and-distribution.md`
* `UsePAM yes` in the real `sshd` configuration
* a real SSH account available for regression checks

Recommended:

* disposable VM or lab host
* dedicated test source IP or jump host
* `journalctl` or auth log access during validation

Note:

* `libpam-dev` / `pam-devel` is not required to use the debug bundle.
* The target host still needs a normal PAM runtime environment, which is typically already present when `sshd` uses PAM.

## Bundle Layout Check

Copy and extract the debug bundle on the target host:

```bash
mkdir -p /tmp/walle-debug
tar -C /tmp/walle-debug -xzf walle-v<version>-linux-<arch>-debug.tar.gz
cd /tmp/walle-debug/walle-v<version>-linux-<arch>-debug
find . -maxdepth 3 -type f | sort
```

Expected key files:

* `bin/walle`
* `lib/walle/walle-ebpf`
* `lib/libnss_walle.so.2`
* `lib/walle/pam_walle.so`
* `share/doc/walle/README.md`
* `share/doc/walle/linux-install-and-distribution.md`

Note:

* `bin/walle` comes from the debug Cargo profile.
* `lib/walle/walle-ebpf` comes from the release BPF profile on purpose.

## Install From The Debug Bundle

Run install from the extracted bundle so the executable-relative lookup path is exercised:

```bash
sudo ./bin/walle install
```

Expected installed artifacts:

* `/usr/local/bin/walle`
* `/usr/local/lib/walle/walle-ebpf`
* `/lib/libnss_walle.so.2`
* `/usr/local/lib/walle/pam_walle.so`
* `/usr/local/lib/walle/walle-ssh-overlay.conf.sample`
* `/usr/local/lib/walle/walle-nsswitch.conf.sample`
* `/usr/local/lib/walle/walle-sshd-pam.conf.sample`
* `/usr/local/lib/walle/walle-ssh-overlay-shell`

Verify:

```bash
sudo test -x /usr/local/bin/walle
sudo test -f /usr/local/lib/walle/walle-ebpf
sudo test -f /lib/libnss_walle.so.2
sudo test -f /usr/local/lib/walle/pam_walle.so
sudo test -f /usr/local/lib/walle/walle-ssh-overlay.conf.sample
sudo test -f /usr/local/lib/walle/walle-nsswitch.conf.sample
sudo test -f /usr/local/lib/walle/walle-sshd-pam.conf.sample
```

Refresh the loader cache after NSS install:

```bash
sudo ldconfig
```

## Enable The SSH Overlay

Install the managed hooks:

```bash
sudo /usr/local/bin/walle ssh overlay install-hooks
```

Review the preview, confirm the changes, then validate `sshd` before restart.

Validate `sshd` before restart:

```bash
sudo sshd -t
```

Restart SSH:

```bash
sudo systemctl restart ssh || sudo service ssh restart
```

## Start `walle`

Start the daemon in foreground with debug-oriented logs:

```bash
sudo RUST_LOG=info,walle_daemon::runtime=debug /usr/local/bin/walle run \
  --interface eth0 \
  --xdp-object /usr/local/lib/walle/walle-ebpf \
  --foreground \
  --ssh-follow-iterations 600 \
  --ssh-poll-interval-ms 1000
```

Use the correct interface name for the host under test.

## Validation Matrix

### 1. Real User Regression Check

Confirm an existing legitimate account still reaches the real host:

```bash
ssh <real-user>@<host>
```

Expected:

* login behavior is unchanged
* no trap shell
* no `sshjail` transcript for that session

### 2. Invalid User Promotion

From another host, attempt a non-existent username:

```bash
ssh tomcat@<host>
```

Expected on the first attempt:

* normal authentication failure
* real `sshd` logs an `Invalid user` event
* `walle` promotes `tomcat` into runtime trap identity state

Inspect runtime state:

```bash
sudo cat /tmp/walle/gp/ssh/state/trap_usernames.runtime
sudo cat /tmp/walle/gp/ssh/state/trap_identities.runtime
```

Expected:

* `tomcat` appears in both runtime files

### 3. Password Same-Connection Trap

Retry the same promoted username:

```bash
ssh tomcat@<host>
```

Expected on the second attempt:

* arbitrary password succeeds
* session lands in `sshjail`
* the session is not the real host account space

Check password evidence and audit:

```bash
sudo find /tmp/walle/gp/ssh/state/auth-info -maxdepth 1 -type f | sort
sudo tail -n 200 /tmp/walle/gp/ssh/sessions/*.log
```

Expected audit indicators:

* `auth_password user=tomcat password=<submitted>`
* `auth_succeeded`
* trap-shell or trap-login command path evidence

### 4. Key Same-Connection Trap

Add a known test key or fingerprint to the static blacklist:

```bash
sudo tee /etc/walle/blacklist_keys >/dev/null <<'EOF'
<openssh-public-key-or-sha256-fingerprint>
EOF
```

Attempt login with that key:

```bash
ssh -i /path/to/testkey anyuser@<host>
```

Expected:

* `AuthorizedKeysCommand` returns a forced-command trap entry
* session lands in `sshjail` on the same connection
* audit log records the inbound key evidence

Check state and audit:

```bash
sudo tail -n 200 /tmp/walle/gp/ssh/sessions/*.log
sudo cat /tmp/walle/gp/ssh/state/blacklist_keys.dynamic 2>/dev/null || true
```

### 5. Fail-Open Regression Check

Temporarily stop `walle` while leaving the overlay configuration in place:

```bash
sudo pkill -f '/usr/local/bin/walle run' || true
```

Retry a legitimate login:

```bash
ssh <real-user>@<host>
```

Expected:

* real-user auth still follows ordinary `sshd` behavior
* overlay helpers fail open when daemon runtime state is inactive

## Troubleshooting

### `sshd -t` fails after PAM merge

Check:

* absolute module path is `/usr/local/lib/walle/pam_walle.so`
* inserted lines are in the correct sections of `/etc/pam.d/sshd`
* the host `sshd` is actually built with PAM support

### Real users are unexpectedly trapped

Check:

* `passwd: files walle systemd` still keeps `files` first
* only truly invalid users were promoted into runtime trap identity state
* you did not replace the real system shell for legitimate accounts

### Password trap does not trigger on second invalid-user attempt

Check:

* `UsePAM yes`
* sample PAM fragment was merged into `/etc/pam.d/sshd`
* trap identity exists in `/tmp/walle/gp/ssh/state/trap_identities.runtime`
* `walle` is still running and holding the runtime lock

### Key trap does not trigger

Check:

* sample `AuthorizedKeysCommand` fragment was merged
* containment strategy is enabled in `config.toml`
* the presented key or fingerprint matches `/etc/walle/blacklist_keys`

## Cleanup

Disable overlay edits through the managed hook command if the host should return to baseline behavior, then uninstall:

```bash
sudo /usr/local/bin/walle ssh overlay hook-disable
sudo /usr/local/bin/walle uninstall
```

Optional runtime state cleanup:

```bash
sudo rm -rf /tmp/walle/gp/ssh
```
