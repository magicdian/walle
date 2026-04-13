use std::process::ExitCode;

use anyhow::Result;
use tracing_subscriber::EnvFilter;
use walle_daemon::{DaemonOptions, WalleDaemon};
use walle_policy::WalleConfig;

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
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .without_time()
        .init();

    let mut daemon = WalleDaemon::new(
        WalleConfig::default(),
        DaemonOptions {
            foreground: true,
            ..DaemonOptions::default()
        },
    )?;
    daemon.run()?;

    Ok(())
}
