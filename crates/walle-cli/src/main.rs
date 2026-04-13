use std::net::IpAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use walle_common::{AccessMode, IcmpMode};
use walle_daemon::logging::{format_unix_timestamp_secs, init_tracing};
use walle_daemon::{DaemonOptions, WalleDaemon};
use walle_policy::{IcmpAllowRule, WalleConfig};

#[derive(Debug, Parser)]
#[command(name = "walle")]
#[command(about = "Rust-first eBPF/XDP firewall CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Run(RunArgs),
    Status,
    VerifyEnv(VerifyEnvArgs),
    AccessMode(AccessModeArgs),
    Ban(BanArgs),
    Allow(AllowArgs),
    Ssh(SshArgs),
    Icmp(IcmpArgs),
}

#[derive(Debug, Args)]
struct RunArgs {
    #[arg(long)]
    interface: Option<String>,
    #[arg(long, default_value_t = true)]
    foreground: bool,
    #[arg(long)]
    xdp_object: Option<PathBuf>,
    #[arg(long)]
    map_pin_path: Option<PathBuf>,
    #[arg(long, default_value_t = 1_000)]
    ssh_poll_interval_ms: u64,
    #[arg(long)]
    ssh_follow_iterations: Option<u64>,
}

#[derive(Debug, Args)]
struct AccessModeArgs {
    #[command(subcommand)]
    command: AccessModeCommand,
}

#[derive(Debug, Args)]
struct VerifyEnvArgs {
    #[arg(long)]
    interface: Option<String>,
}

#[derive(Debug, Subcommand)]
enum AccessModeCommand {
    Get,
    Set { mode: CliAccessMode },
}

#[derive(Debug, Args)]
struct BanArgs {
    #[command(subcommand)]
    command: BanCommand,
}

#[derive(Debug, Subcommand)]
enum BanCommand {
    Add {
        ip: IpAddr,
        duration_secs: Option<u64>,
    },
    Remove {
        ip: IpAddr,
    },
    List,
}

#[derive(Debug, Args)]
struct AllowArgs {
    #[command(subcommand)]
    command: AllowCommand,
}

#[derive(Debug, Subcommand)]
enum AllowCommand {
    Add { ip: IpAddr },
    Remove { ip: IpAddr },
    List,
}

#[derive(Debug, Args)]
struct SshArgs {
    #[command(subcommand)]
    command: SshCommand,
}

#[derive(Debug, Subcommand)]
enum SshCommand {
    Protect {
        #[command(subcommand)]
        command: ToggleCommand,
    },
    PolicyShow,
    Sources,
    InspectLine {
        line: String,
        #[arg(long, default_value_t = 1)]
        repeat: u32,
        #[arg(long, default_value_t = 1)]
        start_at_secs: u64,
        #[arg(long, default_value_t = 1)]
        step_secs: u64,
    },
    PollSources {
        #[arg(long, default_value_t = 1)]
        observed_at_secs: u64,
    },
    ReplayFile {
        path: String,
        #[arg(long, default_value_t = 1)]
        start_at_secs: u64,
        #[arg(long, default_value_t = 1)]
        step_secs: u64,
    },
}

#[derive(Debug, Args)]
struct IcmpArgs {
    #[command(subcommand)]
    command: IcmpCommand,
}

#[derive(Debug, Subcommand)]
enum IcmpCommand {
    Drop {
        #[command(subcommand)]
        command: ToggleCommand,
    },
    Allow {
        #[command(subcommand)]
        command: IcmpAllowCommand,
    },
}

#[derive(Debug, Subcommand)]
enum IcmpAllowCommand {
    Add { hex: String },
    List,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliAccessMode {
    WhitelistOnly,
    BlacklistOnly,
    BlacklistWithWhitelistException,
}

impl From<CliAccessMode> for AccessMode {
    fn from(value: CliAccessMode) -> Self {
        match value {
            CliAccessMode::WhitelistOnly => Self::WhitelistOnly,
            CliAccessMode::BlacklistOnly => Self::BlacklistOnly,
            CliAccessMode::BlacklistWithWhitelistException => Self::BlacklistWithWhitelistException,
        }
    }
}

#[derive(Debug, Subcommand)]
enum ToggleCommand {
    Enable,
    Disable,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    init_tracing();

    let cli = Cli::parse();

    match cli.command {
        Command::Run(args) => run_daemon(args),
        Command::Status => show_status(),
        Command::VerifyEnv(args) => verify_environment(args),
        Command::AccessMode(args) => handle_access_mode(args.command),
        Command::Ban(args) => handle_ban(args.command),
        Command::Allow(args) => handle_allow(args.command),
        Command::Ssh(args) => handle_ssh(args.command),
        Command::Icmp(args) => handle_icmp(args.command),
    }
}

fn run_daemon(args: RunArgs) -> Result<()> {
    let mut daemon = WalleDaemon::new(
        WalleConfig::default(),
        DaemonOptions {
            interface: args.interface,
            foreground: args.foreground,
            xdp_object: args.xdp_object,
            map_pin_path: args.map_pin_path,
            ssh_poll_interval_ms: args.ssh_poll_interval_ms,
            ssh_follow_iterations: args.ssh_follow_iterations,
        },
    )?;

    daemon.run()?;
    if args.foreground {
        println!("walle daemon exited after completing the requested SSH follow loop");
    } else {
        println!("walle daemon startup completed without entering the SSH follow loop");
    }
    Ok(())
}

fn show_status() -> Result<()> {
    let daemon = WalleDaemon::new(WalleConfig::default(), DaemonOptions::default())?;
    let snapshot = daemon.snapshot();

    println!(
        "interface: {}",
        snapshot.interface.as_deref().unwrap_or("unset")
    );
    println!("access_mode: {:?}", snapshot.access_mode);
    println!("icmp_mode: {:?}", snapshot.icmp_mode);
    println!(
        "ssh_protection_enabled: {}",
        snapshot.ssh_protection_enabled
    );
    println!("ssh_failure_threshold: {}", snapshot.ssh_failure_threshold);
    println!("xdp_attached: {}", snapshot.xdp_attached);
    println!("allow_v4_entries: {}", snapshot.allow_v4_entries);
    println!("allow_v6_entries: {}", snapshot.allow_v6_entries);
    println!("deny_v4_entries: {}", snapshot.deny_v4_entries);
    println!("deny_v6_entries: {}", snapshot.deny_v6_entries);
    println!("icmp_rule_entries: {}", snapshot.icmp_rule_entries);

    Ok(())
}

fn verify_environment(args: VerifyEnvArgs) -> Result<()> {
    let daemon = WalleDaemon::new(
        WalleConfig::default(),
        DaemonOptions {
            interface: args.interface,
            foreground: true,
            xdp_object: None,
            map_pin_path: None,
            ssh_poll_interval_ms: 1_000,
            ssh_follow_iterations: Some(0),
        },
    )?;
    let report = daemon.verify_environment();

    println!("compatible: {}", report.is_compatible());
    if let Some(kernel_release) = report.kernel_release {
        println!("kernel_release: {kernel_release}");
    } else {
        println!("kernel_release: unknown");
    }

    for check in report.checks {
        println!("{}: {:?} - {}", check.name, check.status, check.detail);
    }

    Ok(())
}

fn handle_access_mode(command: AccessModeCommand) -> Result<()> {
    match command {
        AccessModeCommand::Get => {
            let config = WalleConfig::default();
            println!("current access mode: {:?}", config.access.mode);
        }
        AccessModeCommand::Set { mode } => {
            let mode: AccessMode = mode.into();
            println!("planned access mode update: {:?}", mode);
        }
    }

    Ok(())
}

fn handle_ban(command: BanCommand) -> Result<()> {
    match command {
        BanCommand::Add { ip, duration_secs } => {
            println!(
                "planned denylist add: ip={ip}, duration_secs={}",
                duration_secs
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "default".to_string())
            );
        }
        BanCommand::Remove { ip } => {
            println!("planned denylist removal: ip={ip}");
        }
        BanCommand::List => {
            println!("planned denylist listing");
        }
    }

    Ok(())
}

fn handle_allow(command: AllowCommand) -> Result<()> {
    match command {
        AllowCommand::Add { ip } => {
            println!("planned allowlist add: ip={ip}");
        }
        AllowCommand::Remove { ip } => {
            println!("planned allowlist removal: ip={ip}");
        }
        AllowCommand::List => {
            println!("planned allowlist listing");
        }
    }

    Ok(())
}

fn handle_ssh(command: SshCommand) -> Result<()> {
    match command {
        SshCommand::Protect { command } => match command {
            ToggleCommand::Enable => println!("planned SSH protection enable"),
            ToggleCommand::Disable => println!("planned SSH protection disable"),
        },
        SshCommand::PolicyShow => {
            let config = WalleConfig::default();
            println!(
                "ssh policy: enabled={}, threshold={}, window_secs={}, ban_duration_secs={}, source_mode={:?}, log_paths={:?}",
                config.ssh.enabled,
                config.ssh.failure_threshold,
                config.ssh.window_secs,
                config.ssh.ban_duration_secs,
                config.ssh.log_source_mode,
                config.ssh.log_file_paths
            );
        }
        SshCommand::Sources => {
            let daemon = WalleDaemon::new(WalleConfig::default(), DaemonOptions::default())?;
            for source in daemon.ssh_sources() {
                match source {
                    walle_daemon::detector::SshResolvedLogSource::Journald => {
                        println!("journald");
                    }
                    walle_daemon::detector::SshResolvedLogSource::LogFile(path) => {
                        println!("logfile: {path}");
                    }
                }
            }
        }
        SshCommand::InspectLine {
            line,
            repeat,
            start_at_secs,
            step_secs,
        } => {
            let mut daemon = WalleDaemon::new(WalleConfig::default(), DaemonOptions::default())?;

            if let Some(event) = daemon.inspect_ssh_log_line(&line) {
                println!("parsed event: ip={}, reason={:?}", event.ip, event.reason);
            } else {
                println!("parsed event: none");
            }

            let mut last_decision = None;
            for index in 0..repeat {
                let observed_at_secs =
                    start_at_secs.saturating_add((index as u64).saturating_mul(step_secs));
                last_decision = daemon.process_ssh_log_line(&line, observed_at_secs)?;
                if let Some(decision) = &last_decision {
                    println!(
                        "ban decision: ip={}, matched_failures={}, expires_at={}",
                        decision.ip,
                        decision.matched_failures,
                        format_unix_timestamp_secs(decision.expires_at_secs)
                    );
                    break;
                }
            }

            if last_decision.is_none() {
                println!("ban decision: none");
            }
        }
        SshCommand::PollSources { observed_at_secs } => {
            let mut daemon = WalleDaemon::new(WalleConfig::default(), DaemonOptions::default())?;
            let summary = daemon.poll_ssh_sources(observed_at_secs)?;
            print_ingest_summary(&summary);
        }
        SshCommand::ReplayFile {
            path,
            start_at_secs,
            step_secs,
        } => {
            let mut daemon = WalleDaemon::new(WalleConfig::default(), DaemonOptions::default())?;
            let summary = daemon.replay_ssh_log_file(path, start_at_secs, step_secs)?;
            print_ingest_summary(&summary);
        }
    }

    Ok(())
}

fn print_ingest_summary(summary: &walle_daemon::detector::SshIngestSummary) {
    println!("lines_read: {}", summary.lines_read);
    println!("matched_failures: {}", summary.matched_failures);
    println!("bans: {}", summary.bans.len());

    for ban in &summary.bans {
        println!(
            "ban: ip={}, matched_failures={}, observed_at={}, expires_at={}",
            ban.ip,
            ban.matched_failures,
            format_unix_timestamp_secs(ban.observed_at_secs),
            format_unix_timestamp_secs(ban.expires_at_secs)
        );
    }
}

fn handle_icmp(command: IcmpCommand) -> Result<()> {
    match command {
        IcmpCommand::Drop { command } => match command {
            ToggleCommand::Enable => println!("planned ICMP drop enable"),
            ToggleCommand::Disable => println!("planned ICMP drop disable"),
        },
        IcmpCommand::Allow { command } => match command {
            IcmpAllowCommand::Add { hex } => {
                let payload = decode_hex_payload(&hex)?;
                let compiled = IcmpAllowRule {
                    match_type: walle_common::IcmpMatchType::RawBytesExact,
                    payload,
                    enabled: true,
                }
                .compile()?;

                println!(
                    "planned ICMP allow rule add: match_type={:?}, payload_length={}",
                    compiled.match_type, compiled.payload_length
                );
            }
            IcmpAllowCommand::List => {
                let mode = IcmpMode::Disabled;
                println!("planned ICMP allow rule listing, current_mode={mode:?}");
            }
        },
    }

    Ok(())
}

fn decode_hex_payload(input: &str) -> Result<Vec<u8>> {
    let trimmed = input.trim();

    if trimmed.len() % 2 != 0 {
        anyhow::bail!("hex payload must contain an even number of characters");
    }

    let mut bytes = Vec::with_capacity(trimmed.len() / 2);
    let mut index = 0;

    while index < trimmed.len() {
        let chunk = &trimmed[index..index + 2];
        let byte = u8::from_str_radix(chunk, 16)
            .with_context(|| format!("invalid hex byte '{chunk}' at offset {index}"))?;
        bytes.push(byte);
        index += 2;
    }

    Ok(bytes)
}
