//! Argon2id + HKDF-SHA256 key derivation and streaming keyfile hashing.

use std::io::Read;

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::constants::{
    DEFAULT_ARGON_ITERATIONS, DEFAULT_ARGON_MEMORY_KIB, DEFAULT_ARGON_PARALLELISM, SALT_SIZE,
};
use crate::error::CryptoError;
use crate::mem::SecretKey;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::owasp_default()
    }
}

impl KdfParams {
    pub fn owasp_default() -> Self {
        Self {
            memory_kib: DEFAULT_ARGON_MEMORY_KIB,
            iterations: DEFAULT_ARGON_ITERATIONS,
            parallelism: DEFAULT_ARGON_PARALLELISM,
        }
    }

    pub fn fast_test() -> Self {
        Self {
            memory_kib: 8192,
            iterations: 1,
            parallelism: 1,
        }
    }

    pub fn validate(&self) -> Result<(), CryptoError> {
        if !(8192..=4 * 1024 * 1024).contains(&self.memory_kib) {
            return Err(CryptoError::InvalidFormat(format!(
                "invalid Argon2 memory_kib: {}",
                self.memory_kib
            )));
        }
        if !(1..=64).contains(&self.iterations) {
            return Err(CryptoError::InvalidFormat(format!(
                "invalid Argon2 iterations: {}",
                self.iterations
            )));
        }
        if !(1..=64).contains(&self.parallelism) {
            return Err(CryptoError::InvalidFormat(format!(
                "invalid Argon2 parallelism: {}",
                self.parallelism
            )));
        }
        Ok(())
    }
}

/// Stream any keyfile of arbitrary size through SHA-256 without buffering the file.
pub fn hash_keyfile_reader(reader: &mut impl Read) -> Result<SecretKey, CryptoError> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total = 0usize;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n;
    }
    buf.zeroize();
    if total == 0 {
        return Err(CryptoError::InvalidFormat("keyfile cannot be empty".into()));
    }
    let digest: [u8; 32] = hasher.finalize().into();
    Ok(SecretKey::new(digest))
}

/// Derive a 32-byte KEK from `password`, `salt`, and optional `keyfile_hash`.
pub fn derive_kek(
    password: &[u8],
    salt: &[u8; SALT_SIZE],
    params: &KdfParams,
    keyfile_hash: Option<&SecretKey>,
) -> Result<SecretKey, CryptoError> {
    params.validate()?;
    if password.is_empty() {
        return Err(CryptoError::InvalidFormat(
            "password cannot be empty".into(),
        ));
    }

    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(32),
    )
    .map_err(|e| CryptoError::InvalidFormat(format!("invalid Argon2 params: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut raw = [0u8; 32];
    argon
        .hash_password_into(password, salt, &mut raw)
        .map_err(|_| CryptoError::CryptoFailure)?;
    let raw_key = SecretKey::new(raw);
    raw.zeroize();

    let hk_salt = keyfile_hash.map(|k| k.as_bytes().as_slice()).unwrap_or(&[]);
    let hk = Hkdf::<Sha256>::new(Some(hk_salt), raw_key.as_bytes());
    let mut out = [0u8; 32];
    hk.expand(b"rpm-v5-kek", &mut out)
        .map_err(|_| CryptoError::CryptoFailure)?;
    let key = SecretKey::new(out);
    out.zeroize();
    Ok(key)
}

/// Derive a 32-byte recovery KEK from 32-byte BIP-39 entropy.
pub fn derive_recovery_kek(
    entropy: &SecretKey,
    salt: &[u8; SALT_SIZE],
) -> Result<SecretKey, CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), entropy.as_bytes());
    let mut out = [0u8; 32];
    hk.expand(b"rpm-v5-recovery-kek", &mut out)
        .map_err(|_| CryptoError::CryptoFailure)?;
    let key = SecretKey::new(out);
    out.zeroize();
    Ok(key)
}

/// Derive the immutable 7-byte AES-GCM chunk stream nonce prefix for a vault.
pub fn derive_stream_nonce_prefix(
    dek: &SecretKey,
    payload_ctx: &[u8; 32],
) -> Result<[u8; 7], CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(payload_ctx), dek.as_bytes());
    let mut prefix = [0u8; 7];
    hk.expand(b"rpm-v5-stream-nonce", &mut prefix)
        .map_err(|_| CryptoError::CryptoFailure)?;
    Ok(prefix)
}
