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
pub const MIN_CONTAINER_SIZE: u64 = 64 * 1024; // 64 KiB
pub const MAX_CONTAINER_SIZE: u64 = 64 * 1024 * 1024 * 1024; // 64 GiB

pub const HIDDEN_MAGIC: [u8; 4] = *b"RPMH";
pub const HIDDEN_VERSION: u8 = 5;
pub const HIDDEN_FLAG_COMPRESSED: u8 = 1 << 0;
pub const HIDDEN_FLAG_HAS_KEYFILE: u8 = 1 << 1;
pub const HIDDEN_KNOWN_FLAGS: u8 = HIDDEN_FLAG_COMPRESSED | HIDDEN_FLAG_HAS_KEYFILE;
pub const HIDDEN_MINI_HEADER_PLAIN_SIZE: usize = 80;
pub const HIDDEN_MINI_HEADER_WIRE_SIZE: usize =
    AES_NONCE_SIZE + HIDDEN_MINI_HEADER_PLAIN_SIZE + AES_TAG_SIZE;

// OWASP Argon2id baseline defaults.
pub const DEFAULT_ARGON_MEMORY_KIB: u32 = 65_536; // 64 MiB
pub const DEFAULT_ARGON_ITERATIONS: u32 = 3;
pub const DEFAULT_ARGON_PARALLELISM: u32 = 4;

pub const FLAG_HAS_RECOVERY: u8 = 1 << 0;
pub const FLAG_HAS_KEYFILE: u8 = 1 << 1;
pub const FLAG_COMPRESSED: u8 = 1 << 2;
pub const ALL_KNOWN_FLAGS: u8 = FLAG_HAS_RECOVERY | FLAG_HAS_KEYFILE | FLAG_COMPRESSED;

/// The on-wire Stealth format carries no KDF parameters.
pub const STEALTH_KDF_PARAMS: crate::KdfParams = crate::KdfParams::owasp_default();
