use std::process::ExitCode;

use anyhow::Result;
use walle_daemon::logging::init_tracing;
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
    init_tracing();

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
