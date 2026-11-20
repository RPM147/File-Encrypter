//! Protocol constants for Vault Format v5 (Chunked AEAD).

pub const VAULT_MAGIC: [u8; 4] = *b"RPMV";
pub const VAULT_VERSION: u8 = 5;
pub const CHUNKED_CIPHER_NAME: &str = "AES-256-GCM-CHUNKED";
pub const KDF_NAME: &str = "Argon2id";

pub const AES_KEY_SIZE: usize = 32;
pub const AES_NONCE_SIZE: usize = 12;
pub const AES_TAG_SIZE: usize = 16;
pub const SALT_SIZE: usize = 32;

pub const DEFAULT_CHUNK_SIZE: u32 = 1024 * 1024; // 1 MiB
pub const MIN_CHUNK_SIZE: u32 = 16 * 1024; // 16 KiB
pub const MAX_CHUNK_SIZE: u32 = 16 * 1024 * 1024; // 16 MiB
pub const MAX_HEADER_SIZE: usize = 1024 * 1024; // 1 MiB

// OWASP Argon2id baseline defaults.
pub const DEFAULT_ARGON_MEMORY_KIB: u32 = 65_536; // 64 MiB
pub const DEFAULT_ARGON_ITERATIONS: u32 = 3;
pub const DEFAULT_ARGON_PARALLELISM: u32 = 4;

pub const FLAG_HAS_RECOVERY: u8 = 1 << 0;
pub const FLAG_HAS_KEYFILE: u8 = 1 << 1;
pub const FLAG_COMPRESSED: u8 = 1 << 2;
