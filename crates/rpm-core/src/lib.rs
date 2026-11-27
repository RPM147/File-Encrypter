//! Pure-Rust Vault Format v5 cryptographic engine.

pub mod constants;
pub mod diff;
pub mod error;
pub mod header;
pub mod hidden;
pub mod kdf;
pub mod mem;
pub mod pipeline;
pub mod recovery;
pub mod rs;
mod stealth;
pub use pipeline::{default_pipeline_threads, resolve_pipeline_threads, MAX_PIPELINE_THREADS};
pub use rs::{
    probe_rs_header, repair_vault_stream, repair_vault_stream_with_threads, RepairReport,
    RsEncoderWriter, RsSeekableReader,
};
pub mod vault;

pub use constants::{
    MAX_CONTAINER_SIZE, MIN_CONTAINER_SIZE, STEALTH_KDF_PARAMS, VAULT_MAGIC, VAULT_VERSION,
};
pub use diff::{diff_metadata, ChangedEntry, VaultDiff};
pub use error::CryptoError;
pub use header::{Auth, FileManifestEntry, VaultHeader, VaultMetadata};
pub use hidden::{
    decrypt_stream_seekable, decrypt_stream_seekable_with_kdf,
    decrypt_stream_seekable_with_kdf_and_threads, decrypt_stream_seekable_with_threads,
    decrypt_unlocked_stream, decrypt_unlocked_stream_with_threads, encrypt_hidden_stream,
    encrypt_hidden_stream_with_threads, inspect_header_seekable, inspect_header_seekable_with_kdf,
    inspect_header_seekable_with_kdf_and_threads,
    inspect_header_seekable_with_kdf_threads_and_cancel, unlock_seekable, unlock_seekable_with_kdf,
    unlock_seekable_with_kdf_and_threads, unlock_seekable_with_kdf_threads_and_cancel,
    HiddenEncryptOptions, HiddenEncryptSummary, UnlockedVault,
};
pub use kdf::{hash_keyfile_reader, KdfParams};
pub use mem::{SecretBuf, SecretKey};
pub use recovery::{entropy_to_mnemonic, generate_recovery_entropy, mnemonic_to_entropy};
pub use vault::{
    check_integrity, check_integrity_reader, check_integrity_reader_with_threads,
    check_integrity_reader_with_threads_and_cancel, check_integrity_with_threads,
    check_integrity_with_threads_and_cancel, decrypt_chunks_with_key, decrypt_chunks_with_key_at,
    decrypt_stream, decrypt_stream_with_threads, encrypt_stream, encrypt_stream_with_threads,
    inspect_header, rekey_stream, EncryptOptions, EncryptSummary, IntegrityReport, RekeyOptions,
    VaultInfo,
};
