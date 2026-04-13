use std::net::IpAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use walle_common::{AccessMode, IcmpMode};
use walle_daemon::install::{uninstall, InstallOptions, UninstallOptions};
use walle_daemon::logging::{format_unix_timestamp_secs, init_tracing};
use walle_daemon::{DaemonOptions, WalleDaemon};
use walle_policy::{IcmpAllowRule, LogLevel, WalleConfig};

#[derive(Debug, Parser)]
#[command(name = "walle")]
#[command(about = "Rust-first eBPF/XDP firewall CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Install(InstallArgs),
    Uninstall(UninstallArgs),
    Run(RunArgs),
    Reload,
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
struct InstallArgs {
    #[arg(long)]
    root: Option<PathBuf>,
    #[arg(long)]
    xdp_object: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct UninstallArgs {
    #[arg(long)]
    root: Option<PathBuf>,
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
    let cli = Cli::parse();
    init_tracing(configured_log_level(&cli.command));

    match cli.command {
        Command::Install(args) => install_command(args),
        Command::Uninstall(args) => uninstall_command(args),
        Command::Run(args) => run_command(args),
        Command::Reload => reload_command(),
        Command::Status => show_status(),
        Command::VerifyEnv(args) => verify_environment(args),
        Command::AccessMode(args) => handle_access_mode(args.command),
        Command::Ban(args) => handle_ban(args.command),
        Command::Allow(args) => handle_allow(args.command),
        Command::Ssh(args) => handle_ssh(args.command),
        Command::Icmp(args) => handle_icmp(args.command),
    }
}

fn configured_log_level(command: &Command) -> LogLevel {
    match command {
        Command::Install(_) | Command::Uninstall(_) => LogLevel::Info,
        Command::Reload => LogLevel::Info,
        Command::Ban(_) | Command::Allow(_) | Command::Icmp(_) => LogLevel::Info,
        _ => WalleConfig::load_default()
            .map(|config| config.logging_policy().level)
            .unwrap_or(LogLevel::Info),
    }
}

fn install_command(args: InstallArgs) -> Result<()> {
    let report = walle_daemon::install::install(InstallOptions {
        root: args.root.unwrap_or_else(|| PathBuf::from("/")),
        xdp_object: args.xdp_object,
        service_manager: None,
    })?;

    println!("binary_path: {}", report.binary_path.display());
    println!("xdp_object_path: {}", report.object_path.display());
    println!("config_path: {}", report.config_path.display());
    println!("config_created: {}", report.config_created);
    println!("service_manager: {}", report.service_manager.as_str());
    println!("service_path: {}", report.service_path.display());
    println!(
        "next_step: review {} and start the service or fallback runner",
        walle_policy::DEFAULT_CONFIG_PATH
    );

    Ok(())
}

fn uninstall_command(args: UninstallArgs) -> Result<()> {
    let report = uninstall(UninstallOptions {
        root: args.root.unwrap_or_else(|| PathBuf::from("/")),
    })?;

    println!("removed_paths: {}", report.removed_paths.len());
    for path in report.removed_paths {
        println!("removed: {}", path.display());
    }
    println!(
        "preserved_config_path: {}",
        report.preserved_config_path.display()
    );

    Ok(())
}

fn run_command(args: RunArgs) -> Result<()> {
    let config = load_default_config("walle run")?;
    let mut daemon = WalleDaemon::new(
        config,
        DaemonOptions {
            interface: args.interface,
            foreground: true,
            xdp_object: args.xdp_object,
            map_pin_path: args.map_pin_path,
            ssh_poll_interval_ms: args.ssh_poll_interval_ms,
            ssh_follow_iterations: args.ssh_follow_iterations,
        },
    )?;

    daemon.run()?;
    println!("walle run exited after completing the requested SSH follow loop");
    Ok(())
}

fn reload_command() -> Result<()> {
    anyhow::bail!(
        "reload is reserved for future configuration reload support and is not implemented yet"
    )
}

fn show_status() -> Result<()> {
    let mut daemon = WalleDaemon::new(
        load_default_config("walle status")?,
        DaemonOptions::default(),
    )?;
    daemon.connect_existing_runtime_backends()?;
    let snapshot = daemon.snapshot();

    println!("interfaces: {}", snapshot.totals.interface_count);
    println!(
        "ssh_protection_enabled: {}",
        snapshot.ssh_protection_enabled
    );
    println!("ssh_failure_threshold: {}", snapshot.ssh_failure_threshold);
    println!("xdp_attached: {}", snapshot.xdp_attached);
    println!(
        "xdp_attached_interfaces: {}",
        snapshot.xdp_attached_interfaces
    );
    println!(
        "total_allow_v4_entries: {}",
        snapshot.totals.allow_v4_entries
    );
    println!(
        "total_allow_v6_entries: {}",
        snapshot.totals.allow_v6_entries
    );
    println!("total_deny_v4_entries: {}", snapshot.totals.deny_v4_entries);
    println!("total_deny_v6_entries: {}", snapshot.totals.deny_v6_entries);
    println!(
        "total_icmp_rule_entries: {}",
        snapshot.totals.icmp_rule_entries
    );
    println!(
        "total_packets_allowed: {}",
        snapshot.totals.stats.packets_allowed
    );
    println!(
        "total_packets_dropped: {}",
        snapshot.totals.stats.packets_dropped
    );
    println!(
        "total_allowlist_hits: {}",
        snapshot.totals.stats.allowlist_hits
    );
    println!(
        "total_denylist_hits: {}",
        snapshot.totals.stats.denylist_hits
    );
    println!(
        "total_icmp_rule_hits: {}",
        snapshot.totals.stats.icmp_rule_hits
    );
    println!(
        "total_parser_failures: {}",
        snapshot.totals.stats.parser_failures
    );

    for interface in &snapshot.interfaces {
        println!();
        println!("[interface:{}]", interface.interface);
        println!("backend: {}", interface.runtime_backend.as_str());
        println!("xdp_attached: {}", interface.xdp_attached);
        println!("access_mode: {:?}", interface.access_mode);
        println!("icmp_mode: {:?}", interface.icmp_mode);
        println!("allow_v4_entries: {}", interface.allow_v4_entries);
        println!("allow_v6_entries: {}", interface.allow_v6_entries);
        println!("deny_v4_entries: {}", interface.deny_v4_entries);
        println!("deny_v6_entries: {}", interface.deny_v6_entries);
        println!("icmp_rule_entries: {}", interface.icmp_rule_entries);
        println!("packets_allowed: {}", interface.stats.packets_allowed);
        println!("packets_dropped: {}", interface.stats.packets_dropped);
        println!("allowlist_hits: {}", interface.stats.allowlist_hits);
        println!("denylist_hits: {}", interface.stats.denylist_hits);
        println!("icmp_rule_hits: {}", interface.stats.icmp_rule_hits);
        println!("parser_failures: {}", interface.stats.parser_failures);
    }

    Ok(())
}

fn verify_environment(args: VerifyEnvArgs) -> Result<()> {
    let mut options = DaemonOptions {
        foreground: true,
        xdp_object: None,
        map_pin_path: None,
        ssh_poll_interval_ms: 1_000,
        ssh_follow_iterations: Some(0),
        ..DaemonOptions::default()
    };
    if let Some(interface) = args.interface {
        options.interface = Some(interface);
    }
    let daemon = WalleDaemon::new(load_default_config("walle verify-env")?, options)?;
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
            let config = load_default_config("walle access-mode get")?;
            println!("current access mode: {:?}", config.access_policy().mode);
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
            let mut daemon = WalleDaemon::new(
                load_default_config("walle ban add")?,
                DaemonOptions::default(),
            )?;
            daemon.add_manual_ban(ip, duration_secs)?;
            println!(
                "ban added: ip={ip}, duration_secs={}",
                duration_secs
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "never".to_string())
            );
        }
        BanCommand::Remove { ip } => {
            let mut daemon = WalleDaemon::new(
                load_default_config("walle ban remove")?,
                DaemonOptions::default(),
            )?;
            let removed_interfaces = daemon.remove_ban(ip)?;
            println!("ban removed: ip={ip}, interfaces_updated={removed_interfaces}");
        }
        BanCommand::List => {
            let mut daemon = WalleDaemon::new(
                load_default_config("walle ban list")?,
                DaemonOptions::default(),
            )?;
            let snapshot = daemon.list_bans()?;

            println!("interfaces: {}", snapshot.interfaces.len());
            println!("total_bans: {}", snapshot.total_bans);

            for interface in snapshot.interfaces {
                println!();
                println!("[interface:{}]", interface.interface);
                println!("backend: {}", interface.runtime_backend.as_str());
                println!("bans: {}", interface.bans.len());

                for ban in interface.bans {
                    println!(
                        "ban: ip={}, source={:?}, reason={:?}, created_at={}, expires_at={}",
                        ban.ip,
                        ban.entry.source,
                        ban.entry.reason,
                        format_unix_timestamp_secs(ban.entry.created_at_ns / 1_000_000_000),
                        format_optional_unix_timestamp_secs(
                            (ban.entry.expires_at_ns != 0)
                                .then_some(ban.entry.expires_at_ns / 1_000_000_000)
                        )
                    );
                }
            }
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
            let config = load_default_config("walle ssh policy-show")?;
            println!(
                "ssh policy: enabled={}, threshold={}, window_secs={}, ban_duration_secs={}, source_mode={:?}, log_paths={:?}, gp_enabled={}, gp_strategy={}, gp_trigger_mode={}",
                config.ssh_policy().enabled,
                config.ssh_policy().failure_threshold,
                config.ssh_policy().window_secs,
                config.ssh_policy().ban_duration_secs,
                config.ssh_policy().log_source_mode,
                config.ssh_policy().log_file_paths,
                config.ssh_policy().gp.enabled,
                config.ssh_policy().gp.strategy.as_str(),
                config.ssh_policy().gp.trigger_mode.as_str()
            );
        }
        SshCommand::Sources => {
            let daemon = WalleDaemon::new(
                load_default_config("walle ssh sources")?,
                DaemonOptions::default(),
            )?;
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
            let mut daemon = WalleDaemon::new(
                load_default_config("walle ssh inspect-line")?,
                DaemonOptions::default(),
            )?;

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
            let mut daemon = WalleDaemon::new(
                load_default_config("walle ssh poll-sources")?,
                DaemonOptions::default(),
            )?;
            let summary = daemon.poll_ssh_sources(observed_at_secs)?;
            print_ingest_summary(&summary);
        }
        SshCommand::ReplayFile {
            path,
            start_at_secs,
            step_secs,
        } => {
            let mut daemon = WalleDaemon::new(
                load_default_config("walle ssh replay-file")?,
                DaemonOptions::default(),
            )?;
            let summary = daemon.replay_ssh_log_file(path, start_at_secs, step_secs)?;
            print_ingest_summary(&summary);
        }
    }

    Ok(())
}

fn load_default_config(command_name: &str) -> Result<WalleConfig> {
    WalleConfig::load_default()
        .with_context(|| format!("failed to load /etc/walle/config.toml for `{command_name}`"))
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

fn format_optional_unix_timestamp_secs(timestamp_secs: Option<u64>) -> String {
    timestamp_secs
        .map(format_unix_timestamp_secs)
        .unwrap_or_else(|| "never".to_string())
}

fn handle_icmp(command: IcmpCommand) -> Result<()> {
    match command {
        IcmpCommand::Drop { command } => match command {
            ToggleCommand::Enable => println!("planned ICMP drop enable"),
            ToggleCommand::Disable => println!("planned ICMP drop disable"),
        },
        IcmpCommand::Allow { command } => match command {
            IcmpAllowCommand::Add { hex } => {
                let compiled = IcmpAllowRule {
                    match_type: walle_common::IcmpMatchType::RawBytesExact,
                    payload_hex: hex.clone(),
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
