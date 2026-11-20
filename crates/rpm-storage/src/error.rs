//! Typed storage, packaging, config, and shell-integration errors.

use rpm_core::CryptoError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid path or archive entry: {0}")]
    InvalidPath(String),

    #[error("safety limit exceeded: {0}")]
    LimitExceeded(String),

    #[error("operation cancelled by user")]
    Cancelled,

    #[error("shell integration error: {0}")]
    ShellIntegration(String),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}
