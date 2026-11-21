//! Pure-Rust Vault Format v5 cryptographic engine.

pub mod constants;
pub mod diff;
pub mod error;
pub mod header;
pub mod hidden;
pub mod kdf;
pub mod mem;
pub mod recovery;
pub mod rs;
mod stealth;
pub use rs::{repair_vault_stream, RepairReport, RsEncoderWriter, RsSeekableReader};
pub mod vault;

pub use constants::{
    MAX_CONTAINER_SIZE, MIN_CONTAINER_SIZE, STEALTH_KDF_PARAMS, VAULT_MAGIC, VAULT_VERSION,
};
pub use diff::{diff_metadata, ChangedEntry, VaultDiff};
pub use error::CryptoError;
pub use header::{Auth, FileManifestEntry, VaultHeader, VaultMetadata};
pub use hidden::{
    decrypt_stream_seekable, decrypt_stream_seekable_with_kdf, decrypt_unlocked_stream,
    encrypt_hidden_stream, inspect_header_seekable, inspect_header_seekable_with_kdf,
    unlock_seekable, unlock_seekable_with_kdf, HiddenEncryptOptions, HiddenEncryptSummary,
    UnlockedVault,
};
pub use kdf::{hash_keyfile_reader, KdfParams};
pub use mem::{SecretBuf, SecretKey};
pub use recovery::{entropy_to_mnemonic, generate_recovery_entropy, mnemonic_to_entropy};
pub use vault::{
    check_integrity, decrypt_chunks_with_key, decrypt_chunks_with_key_at, decrypt_stream,
    encrypt_stream, inspect_header, rekey_stream, EncryptOptions, EncryptSummary, IntegrityReport,
    RekeyOptions, VaultInfo,
};
