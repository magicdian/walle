use thiserror::Error;
use walle_policy::PolicyError;

use crate::detector::SshIngestError;
use crate::runtime::RuntimeError;

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error("policy validation failed: {0}")]
    InvalidPolicy(#[from] PolicyError),
    #[error("SSH ingest failed: {0}")]
    SshIngest(#[from] SshIngestError),
    #[error("runtime operation failed: {0}")]
    Runtime(#[from] RuntimeError),
}
