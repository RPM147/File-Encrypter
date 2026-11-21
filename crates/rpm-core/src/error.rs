//! Typed cryptographic and vault-format errors for RPM Encrypter v5.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("authentication failed: wrong password, missing/wrong keyfile, or corrupted vault")]
    AuthenticationFailed,

    #[error("invalid vault format: {0}")]
    InvalidFormat(String),

    #[error("unsupported vault version {0} (expected v5)")]
    UnsupportedVersion(u8),

    #[error("operation not supported: {0}")]
    UnsupportedOperation(String),

    #[error("keyfile is required to unlock this vault")]
    KeyfileRequired,

    #[error("operation cancelled by user")]
    Cancelled,

    #[error("cryptographic primitive failed")]
    CryptoFailure,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
