use std::{env, process::Command};

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
    let config = RuntimeConfig::new(access_mode, icmp_mode);

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

fn serialize_runtime_config(config: RuntimeConfig) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(12);
    bytes.extend_from_slice(&config.version.to_ne_bytes());
    bytes.push(config.access_mode as u8);
    bytes.push(config.icmp_mode as u8);
    bytes.push(config.default_action as u8);
    bytes.extend_from_slice(&[0, 0, 0]);
    bytes.extend_from_slice(&config.flags.to_ne_bytes());
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
        ));

        assert_eq!(bytes, vec![1, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0]);
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
