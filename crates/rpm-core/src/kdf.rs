//! Argon2id + HKDF-SHA256 key derivation and streaming keyfile hashing.

use std::io::Read;

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

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
        if self.memory_kib < 8 * self.parallelism {
            return Err(CryptoError::InvalidFormat(format!(
                "Argon2 memory_kib ({}) must be at least 8 * parallelism ({})",
                self.memory_kib,
                8 * self.parallelism
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
    let mut digest: [u8; 32] = hasher.finalize().into();
    let key = SecretKey::new(digest);
    digest.zeroize();
    Ok(key)
}

fn derive_kek_with_domain(
    password: &[u8],
    salt: &[u8; SALT_SIZE],
    params: &KdfParams,
    keyfile_hash: Option<&SecretKey>,
    hkdf_info: &[u8],
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

    let mut raw = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password, salt, raw.as_mut())
        .map_err(|_| CryptoError::CryptoFailure)?;
    let raw_key = SecretKey::new(*raw);

    let hk_salt = keyfile_hash.map(|k| k.as_bytes().as_slice()).unwrap_or(&[]);
    let hk = Hkdf::<Sha256>::new(Some(hk_salt), raw_key.as_bytes());
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(hkdf_info, out.as_mut())
        .map_err(|_| CryptoError::CryptoFailure)?;
    Ok(SecretKey::new(*out))
}

/// Derive a 32-byte KEK from `password`, `salt`, and optional `keyfile_hash`.
pub fn derive_kek(
    password: &[u8],
    salt: &[u8; SALT_SIZE],
    params: &KdfParams,
    keyfile_hash: Option<&SecretKey>,
) -> Result<SecretKey, CryptoError> {
    derive_kek_with_domain(password, salt, params, keyfile_hash, b"rpm-v5-kek")
}

/// Derive a domain-separated 32-byte KEK for opening a hidden compartment
/// using the outer container's `container_salt`.
pub fn derive_hidden_kek(
    password: &[u8],
    container_salt: &[u8; SALT_SIZE],
    params: &KdfParams,
    keyfile_hash: Option<&SecretKey>,
) -> Result<SecretKey, CryptoError> {
    let mut h = Sha256::new();
    h.update(b"RPMV5-HIDDEN-ARGON-SALT");
    h.update(container_salt);
    let mut derived_salt: [u8; SALT_SIZE] = h.finalize().into();
    let res = derive_kek_with_domain(
        password,
        &derived_salt,
        params,
        keyfile_hash,
        b"rpm-v5-hidden-kek",
    );
    derived_salt.zeroize();
    res
}

/// Derive a 32-byte recovery KEK from 32-byte BIP-39 entropy.
pub fn derive_recovery_kek(
    entropy: &SecretKey,
    salt: &[u8; SALT_SIZE],
) -> Result<SecretKey, CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), entropy.as_bytes());
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(b"rpm-v5-recovery-kek", out.as_mut())
        .map_err(|_| CryptoError::CryptoFailure)?;
    Ok(SecretKey::new(*out))
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

/// Derive a 5-byte XOR mask for hidden chunk frame headers (`plain_len || final_flag`)
/// so hidden payload chunks remain indistinguishable from random container padding.
pub fn derive_hidden_frame_mask(
    dek: &SecretKey,
    hidden_ctx: &[u8; 32],
    chunk_idx: u32,
) -> Result<[u8; 5], CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(hidden_ctx), dek.as_bytes());
    let mut info = [0u8; 28];
    info[..24].copy_from_slice(b"rpm-v5-hidden-frame-mask");
    info[24..28].copy_from_slice(&chunk_idx.to_be_bytes());
    let mut mask = [0u8; 5];
    hk.expand(&info, &mut mask)
        .map_err(|_| CryptoError::CryptoFailure)?;
    Ok(mask)
}
