# Improve GP REPL shell realism from real attacker log

## Goal

Use the real `sshjail` attacker transcript at `/tmp/walle/gp/ssh/session-1776107197-2-118_25_183_68.log` to close fidelity gaps in the fake shell so post-containment SSH sessions look more like a real Linux host during automated reconnaissance.

## What I already know

* The current fake shell in `crates/walle-daemon/src/sshjail.rs` supports a small interactive subset such as `uname`, `ls`, `cd`, `sudo`, and `su`.
* The real attacker in the provided log mostly used SSH `exec_request`, not an interactive REPL loop.
* The observed command pattern is dominated by `bash -c '...'` probes for:
  * system fingerprinting: `uname -m`, `uname -a`, `nproc`, `free -k`, `cat /etc/os-release`
  * package-manager discovery: `which ...`, `command -v ...`, `test -f ... && echo 'found'`
  * package-manager version checks: `apt --version`, `apt-get --version`, `yum --version`, `apk --version`, `dnf --version`, `dpkg --version`, `rpm --version`, `pacman --version`, `zypper --version`, `pip --version`, `pip3 --version`, `conda --version`, and similar fallbacks
* Current command handling is shell-agnostic only in a minimal sense; persona differences mainly live in identity and fake filesystem setup.
* Current unsupported commands return `bash: <cmd>: command not found`, which makes automated recon against `exec_request` look obviously fake when common probes fail too uniformly.
* Manual interactive testing exposed a second realism gap:
  * directories listed by `ls` such as `loot` and `scripts` are not always traversable with `cd`
  * `cat` behavior is not aligned with path type semantics
  * common Ubuntu-style network inspection such as `ifconfig` is missing

## Assumptions

* This task should stay strictly no-side-effect: no real command execution, no host shell, no PTY tricks, and no filesystem reads from the real OS for command results.
* The right scope is to emulate the attacker's observed recon workflow and make the command layer reusable across all persona templates, while still allowing persona-specific differences where it materially improves realism.
* Deterministic fake outputs are preferable to random outputs because they are easier to test and keep internally consistent.

## Requirements

* Extend `sshjail` command handling to support `exec_request` reconnaissance flows that arrive as `bash -c '...'`.
* Support the specific probe families seen in the real attacker log:
  * `uname -m`
  * `uname -a`
  * `nproc`
  * `free -k | awk '/^Mem:/{print $2}'`
  * `cat /etc/os-release 2>/dev/null | grep -E '^(NAME|PRETTY_NAME)=' | head -1`
  * `which <tool> 2>/dev/null || command -v <tool> 2>/dev/null`
  * `test -f <path1> && echo 'found' || test -f <path2> && echo 'found' || ...`
  * `<tool> --version 2>/dev/null || <tool> --help 2>/dev/null | head -1`
* Do not limit the new support to the `root` persona; shared command behavior must work for other templates and the generic fallback too.
* Preserve persona-specific differences where relevant, such as what tools appear installed, what paths exist, and how identity/home layout looks.
* Keep interactive REPL behavior coherent with exec-mode behavior so the same fake host facts are returned through both paths.
* Ensure interactive directory trees are internally consistent:
  * if `ls` exposes a directory, `cd` into that path should succeed when appropriate
  * nested persona-specific directories should contain believable files or subdirectories
  * `cat` should distinguish between files, directories, and missing paths
* Add a minimal but believable Ubuntu-style network inspection view for interactive shell use, starting with `ifconfig` and aligned virtual interface facts.
* Keep unsupported commands safe and believable.
* Add regression tests for the new command-emulation paths.

## Acceptance Criteria

* [ ] `exec_request` commands matching the real attacker log return believable deterministic outputs instead of generic `command not found`.
* [ ] `bash -c '...'` command wrapping is handled correctly for the supported reconnaissance patterns.
* [ ] Tool/path discovery logic is shared across personas rather than being implemented only for `root`.
* [ ] Persona-specific installed-tool differences remain possible and are covered by at least one test.
* [ ] Existing interactive shell behavior still works after the command-emulation expansion.
* [ ] Interactive directory navigation is coherent with listed directory entries.
* [ ] `cat` returns believable directory-vs-file-vs-missing-path results.
* [ ] Basic interactive network inspection returns plausible Ubuntu-style output.
* [ ] Tests cover at least one full recon flow derived from the provided real log.

## Definition of Done

* `cargo test -p walle-daemon` passes.
* The command-emulation changes stay within typed backend boundaries and keep fail-open behavior unchanged outside the fake shell.
* The implementation remains isolated to virtual shell state and does not execute host commands.

## Out of Scope

* Full Bash parsing or arbitrary shell script emulation.
* Real package managers, real process creation, or reading live host command output.
* Expanding the fake shell into a full Unix clone beyond the reconnaissance patterns needed for this task.

## Technical Notes

* Relevant implementation file: `crates/walle-daemon/src/sshjail.rs`
* Likely shape of the change:
  * introduce a reusable virtual host / persona description layer
  * normalize `bash -c` wrappers into internal subcommands
  * emulate a bounded subset of pipelines and shell fallback patterns seen in the audit log
  * align filesystem/path existence and installed-binary discovery under one source of truth
