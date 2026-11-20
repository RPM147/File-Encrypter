//! Pure-Rust Vault Format v5 cryptographic engine.

pub mod constants;
pub mod error;
pub mod header;
pub mod kdf;
pub mod mem;
pub mod recovery;
pub mod vault;

pub use constants::{VAULT_MAGIC, VAULT_VERSION};
pub use error::CryptoError;
pub use header::{Auth, FileManifestEntry, VaultHeader, VaultMetadata};
pub use kdf::{hash_keyfile_reader, KdfParams};
pub use mem::{SecretBuf, SecretKey};
pub use recovery::{entropy_to_mnemonic, generate_recovery_entropy, mnemonic_to_entropy};
pub use vault::{
    check_integrity, decrypt_chunks_with_key, decrypt_stream, encrypt_stream, inspect_header,
    rekey_stream, EncryptOptions, EncryptSummary, IntegrityReport, RekeyOptions, VaultInfo,
};
