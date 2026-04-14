use std::io;
use std::path::PathBuf;

use thiserror::Error;
use walle_policy::PolicyError;

use crate::detector::SshIngestError;
use crate::runtime::RuntimeError;
use crate::xdp::XdpError;

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error("policy validation failed: {0}")]
    InvalidPolicy(#[from] PolicyError),
    #[error("SSH ingest failed: {0}")]
    SshIngest(#[from] SshIngestError),
    #[error("runtime operation failed: {0}")]
    Runtime(#[from] RuntimeError),
    #[error("{0}")]
    RuntimeLock(#[from] RuntimeLockError),
    #[error("XDP operation failed: {0}")]
    Xdp(#[from] XdpError),
    #[error("sshjail is unavailable for containment: {reason}")]
    SshJailUnavailable { reason: String },
    #[error("requested interface '{interface}' is not declared in the loaded config")]
    InterfaceNotConfigured { interface: String },
    #[error("environment compatibility checks failed: {details}")]
    EnvironmentIncompatible { details: String },
    #[error("failed to install shutdown signal handler for {signal}: {source}")]
    InstallSignalHandler {
        signal: &'static str,
        source: io::Error,
    },
    #[error(
        "no active runtime backends were found for {action}; start `walle run` or install the service first"
    )]
    NoActiveRuntime { action: &'static str },
}

#[derive(Debug, Error)]
pub enum RuntimeLockError {
    #[error(
        "another walle instance is already running; pid={}; lock_path={}",
        .owner_pid
            .map(|pid| pid.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        .path.display()
    )]
    AlreadyRunning {
        path: PathBuf,
        owner_pid: Option<u32>,
    },
    #[error("failed to create runtime lock at {}: {source}", .path.display())]
    Create { path: PathBuf, source: io::Error },
    #[error("failed to read existing runtime lock at {}: {source}", .path.display())]
    Read { path: PathBuf, source: io::Error },
    #[error("failed to write runtime lock at {}: {source}", .path.display())]
    Write { path: PathBuf, source: io::Error },
    #[error("failed to remove stale runtime lock at {}: {source}", .path.display())]
    RemoveStale { path: PathBuf, source: io::Error },
}
