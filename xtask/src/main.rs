use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, anyhow, bail};
use walle_common::{
    AccessMode, CONFIG_MAP_KEY, DEFAULT_MAP_PIN_PATH, ICMP_RULE_PAYLOAD_CAPACITY, IcmpMode,
    IcmpRule, MAP_NAME_CONFIG, MAP_NAME_ICMP_RULES, RuntimeConfig,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut args = env::args().skip(1);

    match args.next().as_deref() {
        Some("build-ebpf") => build_ebpf(!args.any(|arg| arg == "--debug")),
        Some("build-release") => build_release(),
        Some("verify-icmp-rule") => verify_icmp_rule(args.collect()),
        Some("emit-bpftool-config") => emit_bpftool_config(args.collect()),
        Some("emit-bpftool-icmp-rule") => emit_bpftool_icmp_rule(args.collect()),
        Some("emit-bpftool-clear-icmp-rule") => emit_bpftool_clear_icmp_rule(args.collect()),
        Some(command) => bail!("unknown xtask command '{command}'"),
        None => {
            print_help();
            Ok(())
        }
    }
}

fn build_ebpf(release: bool) -> Result<()> {
    let profile = if release { "release" } else { "debug" };

    let mut command = Command::new("rustup");
    command
        .arg("run")
        .arg("nightly")
        .arg("cargo")
        .arg("build")
        .arg("-Z")
        .arg("build-std=core")
        .arg("-p")
        .arg("walle-ebpf")
        .arg("--bin")
        .arg("walle-ebpf")
        .arg("--features")
        .arg("ebpf")
        .arg("--target")
        .arg("bpfel-unknown-none");
    command.env("RUSTFLAGS", "-Zunstable-options -Cpanic=immediate-abort");

    if release {
        command.arg("--release");
    }

    let status = command.status().context("failed to invoke cargo build")?;
    if !status.success() {
        bail!(
            "eBPF build failed; ensure the nightly toolchain and rust-src are available for `cargo +nightly build -Z build-std=core`"
        );
    }

    println!("built eBPF object: target/bpfel-unknown-none/{profile}/walle-ebpf");
    Ok(())
}

fn build_release() -> Result<()> {
    let root = workspace_root();
    let version = workspace_version(&root)?;
    let arch = release_arch(&root)?;
    let artifact_basename = format!("walle-v{version}-linux-{arch}");
    let release_bundle_dir = root.join("target/release-bundle");
    let stage_root = release_bundle_dir.join(&artifact_basename);
    let artifact_path = release_bundle_dir.join(format!("{artifact_basename}.tar.gz"));

    reset_dir(&stage_root)?;
    fs::create_dir_all(stage_root.join("bin"))
        .with_context(|| format!("failed to create {}", stage_root.join("bin").display()))?;
    fs::create_dir_all(stage_root.join("lib/walle")).with_context(|| {
        format!(
            "failed to create {}",
            stage_root.join("lib/walle").display()
        )
    })?;
    fs::create_dir_all(stage_root.join("share/doc/walle")).with_context(|| {
        format!(
            "failed to create {}",
            stage_root.join("share/doc/walle").display()
        )
    })?;

    run_command(
        cargo_command(&root, &["build", "--release", "-p", "walle-cli"]),
        "failed to build release walle binary",
    )?;
    build_ebpf(true)?;

    copy_file(
        &root.join("target/release/walle"),
        &stage_root.join("bin/walle"),
    )?;
    copy_file(
        &root.join("target/bpfel-unknown-none/release/walle-ebpf"),
        &stage_root.join("lib/walle/walle-ebpf"),
    )?;
    copy_file(
        &root.join("README.md"),
        &stage_root.join("share/doc/walle/README.md"),
    )?;
    copy_file(
        &root.join("LICENSE"),
        &stage_root.join("share/doc/walle/LICENSE"),
    )?;
    copy_file(
        &root.join("docs/operations/linux-install-and-distribution.md"),
        &stage_root.join("share/doc/walle/linux-install-and-distribution.md"),
    )?;

    set_mode(&stage_root.join("bin/walle"), 0o755)?;
    set_mode(&stage_root.join("lib/walle/walle-ebpf"), 0o644)?;
    set_mode(&stage_root.join("share/doc/walle/README.md"), 0o644)?;
    set_mode(&stage_root.join("share/doc/walle/LICENSE"), 0o644)?;
    set_mode(
        &stage_root.join("share/doc/walle/linux-install-and-distribution.md"),
        0o644,
    )?;

    run_command(
        {
            let mut command = Command::new("tar");
            command
                .current_dir(&release_bundle_dir)
                .arg("-czf")
                .arg(&artifact_path)
                .arg(&artifact_basename);
            command
        },
        "failed to create release archive",
    )?;

    println!("{}", artifact_path.display());
    Ok(())
}

fn verify_icmp_rule(args: Vec<String>) -> Result<()> {
    if args.len() != 2 {
        bail!(
            "usage: cargo run -p xtask -- verify-icmp-rule <rule-payload-bytes> <icmp-payload-bytes>\n\
             examples:\n\
               cargo run -p xtask -- verify-icmp-rule 09070108 09070108\n\
               cargo run -p xtask -- verify-icmp-rule \"0x9,0x7,0x1,0x8\" \"0x9,0x7,0x1,0x8\"\n\
               cargo run -p xtask -- verify-icmp-rule 09070108 09070109"
        );
    }

    let rule_bytes = parse_hex_bytes(&args[0]).context("failed to parse rule payload bytes")?;
    let payload_bytes = parse_hex_bytes(&args[1]).context("failed to parse ICMP payload bytes")?;
    let rule = IcmpRule::raw_bytes_exact(&rule_bytes)
        .ok_or_else(|| anyhow!("rule bytes must be 1..=64 bytes"))?;
    let matched = walle_ebpf::xdp::raw_bytes_rule_matches(&rule, &payload_bytes);

    println!("rule_hex:   {}", hex_string(&rule_bytes));
    println!("payload_hex: {}", hex_string(&payload_bytes));
    println!("matched:    {matched}");

    Ok(())
}

fn emit_bpftool_config(args: Vec<String>) -> Result<()> {
    if args.len() < 2 || args.len() > 3 {
        bail!(
            "usage: cargo run -p xtask -- emit-bpftool-config <access-mode> <icmp-mode> [map-path]\n\
             example:\n\
               cargo run -p xtask -- emit-bpftool-config blacklist-only allow-rules-active"
        );
    }

    let access_mode = parse_access_mode(&args[0])?;
    let icmp_mode = parse_icmp_mode(&args[1])?;
    let map_path = args.get(2).cloned().unwrap_or_else(default_config_map_path);
    let config = RuntimeConfig::new(access_mode, icmp_mode, 22, 2222);

    println!(
        "{}",
        format_bpftool_update_command(
            &map_path,
            &CONFIG_MAP_KEY.to_ne_bytes(),
            &serialize_runtime_config(config)
        )
    );

    Ok(())
}

fn emit_bpftool_icmp_rule(args: Vec<String>) -> Result<()> {
    if args.is_empty() || args.len() > 2 {
        bail!(
            "usage: cargo run -p xtask -- emit-bpftool-icmp-rule <payload-bytes> [map-path]\n\
             example:\n\
               cargo run -p xtask -- emit-bpftool-icmp-rule 09070108"
        );
    }

    let payload = parse_hex_bytes(&args[0]).context("failed to parse ICMP payload bytes")?;
    let map_path = args
        .get(1)
        .cloned()
        .unwrap_or_else(default_icmp_rule_map_path);
    let rule = IcmpRule::raw_bytes_exact(&payload).ok_or_else(|| {
        anyhow!("rule payload bytes must be 1..={ICMP_RULE_PAYLOAD_CAPACITY} bytes")
    })?;

    println!(
        "{}",
        format_bpftool_update_command(&map_path, &serialize_icmp_rule(rule), &[1])
    );

    Ok(())
}

fn emit_bpftool_clear_icmp_rule(args: Vec<String>) -> Result<()> {
    if args.is_empty() || args.len() > 2 {
        bail!(
            "usage: cargo run -p xtask -- emit-bpftool-clear-icmp-rule <payload-bytes> [map-path]\n\
             example:\n\
               cargo run -p xtask -- emit-bpftool-clear-icmp-rule 09070108"
        );
    }

    let payload = parse_hex_bytes(&args[0]).context("failed to parse ICMP payload bytes")?;
    let map_path = args
        .get(1)
        .cloned()
        .unwrap_or_else(default_icmp_rule_map_path);
    let rule = IcmpRule::raw_bytes_exact(&payload).ok_or_else(|| {
        anyhow!("rule payload bytes must be 1..={ICMP_RULE_PAYLOAD_CAPACITY} bytes")
    })?;

    println!(
        "{}",
        format_bpftool_delete_command(&map_path, &serialize_icmp_rule(rule))
    );

    Ok(())
}

fn parse_hex_bytes(input: &str) -> Result<Vec<u8>> {
    let normalized = input.trim();
    if normalized.is_empty() {
        bail!("hex byte string cannot be empty");
    }

    let tokenized = normalized.replace(',', " ");
    let has_separators = tokenized.split_whitespace().nth(1).is_some();

    if has_separators || tokenized.contains("0x") || tokenized.contains("0X") {
        return tokenized
            .split_whitespace()
            .map(parse_single_hex_token)
            .collect();
    }

    let compact: String = normalized
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect();
    if compact.len() % 2 != 0 {
        bail!("compact hex string must have an even number of characters");
    }

    let mut bytes = Vec::with_capacity(compact.len() / 2);
    let mut index = 0;
    while index < compact.len() {
        let chunk = &compact[index..index + 2];
        let byte = u8::from_str_radix(chunk, 16)
            .with_context(|| format!("invalid hex byte '{chunk}' at offset {index}"))?;
        bytes.push(byte);
        index += 2;
    }

    Ok(bytes)
}

fn parse_single_hex_token(token: &str) -> Result<u8> {
    let trimmed = token.trim();
    if trimmed.is_empty() {
        bail!("empty hex token is not allowed");
    }

    let value = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);

    if value.is_empty() || value.len() > 2 {
        bail!("hex token '{token}' must contain 1 or 2 hex digits");
    }

    u8::from_str_radix(value, 16).with_context(|| format!("invalid hex token '{token}'"))
}

fn parse_access_mode(input: &str) -> Result<AccessMode> {
    match normalize_cli_name(input).as_str() {
        "blacklistonly" | "blacklist-only" => Ok(AccessMode::BlacklistOnly),
        "whitelistonly" | "whitelist-only" => Ok(AccessMode::WhitelistOnly),
        "blacklistwithwhitelistexception" | "blacklist-with-whitelist-exception" => {
            Ok(AccessMode::BlacklistWithWhitelistException)
        }
        _ => bail!(
            "unknown access mode '{input}', expected one of: blacklist-only, whitelist-only, blacklist-with-whitelist-exception"
        ),
    }
}

fn parse_icmp_mode(input: &str) -> Result<IcmpMode> {
    match normalize_cli_name(input).as_str() {
        "disabled" => Ok(IcmpMode::Disabled),
        "dropall" | "drop-all" => Ok(IcmpMode::DropAll),
        "allowrulesactive" | "allow-rules-active" => Ok(IcmpMode::AllowRulesActive),
        _ => bail!(
            "unknown ICMP mode '{input}', expected one of: disabled, drop-all, allow-rules-active"
        ),
    }
}

fn normalize_cli_name(input: &str) -> String {
    input.trim().to_ascii_lowercase()
}

fn default_config_map_path() -> String {
    format!("{DEFAULT_MAP_PIN_PATH}/{MAP_NAME_CONFIG}")
}

fn default_icmp_rule_map_path() -> String {
    format!("{DEFAULT_MAP_PIN_PATH}/{MAP_NAME_ICMP_RULES}")
}

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or(manifest_dir)
}

fn workspace_version(root: &Path) -> Result<String> {
    let manifest = fs::read_to_string(root.join("Cargo.toml"))
        .with_context(|| format!("failed to read {}", root.join("Cargo.toml").display()))?;
    let mut in_workspace_package = false;

    for raw_line in manifest.lines() {
        let line = raw_line.trim();
        if line.starts_with('[') {
            in_workspace_package = line == "[workspace.package]";
            continue;
        }

        if in_workspace_package {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            if key.trim() == "version" {
                return Ok(value.trim().trim_matches('"').to_string());
            }
        }
    }

    bail!("failed to find workspace.package.version in Cargo.toml");
}

fn release_arch(root: &Path) -> Result<String> {
    if let Ok(arch) = env::var("TARGET_ARCH") {
        let trimmed = arch.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }

    let output = Command::new("uname")
        .arg("-m")
        .current_dir(root)
        .output()
        .context("failed to determine release architecture with `uname -m`")?;
    if !output.status.success() {
        bail!("`uname -m` failed while determining release architecture");
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn reset_dir(path: &Path) -> Result<()> {
    if path.exists() {
        fs::remove_dir_all(path).with_context(|| format!("failed to remove {}", path.display()))?;
    }
    fs::create_dir_all(path).with_context(|| format!("failed to create {}", path.display()))?;
    Ok(())
}

fn copy_file(source: &Path, destination: &Path) -> Result<()> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::copy(source, destination).with_context(|| {
        format!(
            "failed to copy '{}' to '{}'",
            source.display(),
            destination.display()
        )
    })?;
    Ok(())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path)
        .with_context(|| format!("failed to read metadata for {}", path.display()))?
        .permissions();
    permissions.set_mode(mode);
    fs::set_permissions(path, permissions)
        .with_context(|| format!("failed to set mode on {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_mode(path: &Path, _mode: u32) -> Result<()> {
    let _ = path;
    Ok(())
}

fn cargo_command(root: &Path, args: &[&str]) -> Command {
    let mut command = Command::new("cargo");
    command.current_dir(root).args(args);
    command
}

fn run_command(mut command: Command, failure_message: &str) -> Result<()> {
    let status = command
        .status()
        .with_context(|| failure_message.to_string())?;
    if !status.success() {
        bail!("{failure_message}");
    }

    Ok(())
}

fn serialize_runtime_config(config: RuntimeConfig) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(16);
    bytes.extend_from_slice(&config.version.to_ne_bytes());
    bytes.push(config.access_mode as u8);
    bytes.push(config.icmp_mode as u8);
    bytes.push(config.default_action as u8);
    bytes.extend_from_slice(&[0, 0, 0]);
    bytes.extend_from_slice(&config.flags.to_ne_bytes());
    bytes.extend_from_slice(&config.protected_ssh_port.to_ne_bytes());
    bytes.extend_from_slice(&config.ssh_jail_port.to_ne_bytes());
    bytes
}

fn serialize_icmp_rule(rule: IcmpRule) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(70);
    bytes.push(rule.match_type as u8);
    bytes.push(0);
    bytes.extend_from_slice(&rule.payload_length.to_ne_bytes());
    bytes.push(rule.enabled);
    bytes.push(rule.reserved);
    bytes.extend_from_slice(&rule.payload);
    bytes
}

fn format_bpftool_update_command(map_path: &str, key: &[u8], value: &[u8]) -> String {
    format!(
        "sudo bpftool map update pinned {} key hex {} value hex {} any",
        map_path,
        format_hex_bytes(key),
        format_hex_bytes(value)
    )
}

fn format_bpftool_delete_command(map_path: &str, key: &[u8]) -> String {
    format!(
        "sudo bpftool map delete pinned {} key hex {}",
        map_path,
        format_hex_bytes(key)
    )
}

fn format_hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn print_help() {
    println!("xtask commands:");
    println!("  build-ebpf [--debug]");
    println!("  build-release");
    println!("  verify-icmp-rule <rule-payload-bytes> <icmp-payload-bytes>");
    println!("  emit-bpftool-config <access-mode> <icmp-mode> [map-path]");
    println!("  emit-bpftool-icmp-rule <payload-bytes> [map-path]");
    println!("  emit-bpftool-clear-icmp-rule <payload-bytes> [map-path]");
}

#[cfg(test)]
mod tests {
    use super::{
        format_bpftool_delete_command, format_bpftool_update_command, format_hex_bytes,
        parse_access_mode, parse_icmp_mode, serialize_icmp_rule, serialize_runtime_config,
    };
    use walle_common::{AccessMode, CONFIG_MAP_KEY, IcmpMode, IcmpRule, RuntimeConfig};

    #[test]
    fn runtime_config_serialization_matches_c_layout_contract() {
        let bytes = serialize_runtime_config(RuntimeConfig::new(
            AccessMode::BlacklistOnly,
            IcmpMode::AllowRulesActive,
            22,
            2222,
        ));

        assert_eq!(
            bytes,
            vec![2, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 22, 0, 174, 8]
        );
    }

    #[test]
    fn icmp_rule_serialization_matches_expected_prefix() {
        let rule = IcmpRule::raw_bytes_exact(&[0x09, 0x07, 0x01, 0x08]).unwrap();
        let bytes = serialize_icmp_rule(rule);

        assert_eq!(&bytes[..10], &[0, 0, 4, 0, 1, 0, 0x09, 0x07, 0x01, 0x08]);
        assert_eq!(bytes.len(), 70);
    }

    #[test]
    fn bpftool_command_format_is_ready_to_run() {
        let command = format_bpftool_update_command(
            "/sys/fs/bpf/walle/config",
            &CONFIG_MAP_KEY.to_ne_bytes(),
            &[1, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0],
        );

        assert_eq!(
            command,
            "sudo bpftool map update pinned /sys/fs/bpf/walle/config key hex 00 00 00 00 value hex 01 00 00 02 00 00 00 00 00 00 00 00 any"
        );
    }

    #[test]
    fn bpftool_delete_command_format_is_ready_to_run() {
        let rule = IcmpRule::raw_bytes_exact(&[0x09, 0x07, 0x01, 0x08]).unwrap();
        let command = format_bpftool_delete_command(
            "/sys/fs/bpf/walle/icmp_rules",
            &serialize_icmp_rule(rule),
        );

        assert_eq!(
            command,
            "sudo bpftool map delete pinned /sys/fs/bpf/walle/icmp_rules key hex 00 00 04 00 01 00 09 07 01 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        );
    }

    #[test]
    fn parsers_accept_cli_spellings() {
        assert_eq!(
            parse_access_mode("blacklist-with-whitelist-exception").unwrap(),
            AccessMode::BlacklistWithWhitelistException
        );
        assert_eq!(
            parse_icmp_mode("allow-rules-active").unwrap(),
            IcmpMode::AllowRulesActive
        );
    }

    #[test]
    fn hex_formatter_includes_spaces_for_bpftool() {
        assert_eq!(format_hex_bytes(&[0x09, 0x07, 0x01, 0x08]), "09 07 01 08");
    }
}
