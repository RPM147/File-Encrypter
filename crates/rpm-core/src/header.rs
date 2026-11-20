//! Vault Format v5 header serialization, AAD construction, and key-slot unwrapping.

use std::io::{Read, Write};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::constants::{
    AES_KEY_SIZE, AES_NONCE_SIZE, ALL_KNOWN_FLAGS, CHUNKED_CIPHER_NAME, FLAG_COMPRESSED,
    FLAG_HAS_KEYFILE, FLAG_HAS_RECOVERY, KDF_NAME, MAX_CHUNK_SIZE, MAX_HEADER_SIZE, MIN_CHUNK_SIZE,
    SALT_SIZE, VAULT_MAGIC, VAULT_VERSION,
};
use crate::error::CryptoError;
use crate::kdf::{derive_kek, derive_recovery_kek, KdfParams};
use crate::mem::SecretKey;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileManifestEntry {
    pub path: String,
    pub size: u64,
    #[serde(default)]
    pub modified_unix: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultMetadata {
    pub filename: String,
    pub source_type: String,
    pub original_size: u64,
    pub file_count: u64,
    pub created_at: String,
    pub compressed: bool,
    #[serde(default)]
    pub files: Vec<FileManifestEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HeaderKdf {
    pub algorithm: String,
    pub salt: String,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeySlot {
    pub nonce: String,
    pub wrapped_dek: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoverySlot {
    pub salt: String,
    pub nonce: String,
    pub wrapped_dek: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultHeader {
    pub version: u8,
    pub vault_id: String,
    pub cipher: String,
    pub chunk_size: u32,
    pub flags: u8,
    pub kdf: HeaderKdf,
    pub password_slot: KeySlot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_slot: Option<RecoverySlot>,
    pub meta_nonce: String,
    pub encrypted_meta_len: u32,
}

impl VaultHeader {
    pub fn has_recovery(&self) -> bool {
        (self.flags & FLAG_HAS_RECOVERY) != 0 && self.recovery_slot.is_some()
    }

    pub fn has_keyfile(&self) -> bool {
        (self.flags & FLAG_HAS_KEYFILE) != 0
    }

    pub fn is_compressed(&self) -> bool {
        (self.flags & FLAG_COMPRESSED) != 0
    }

    pub fn kdf_params(&self) -> KdfParams {
        KdfParams {
            memory_kib: self.kdf.memory_kib,
            iterations: self.kdf.iterations,
            parallelism: self.kdf.parallelism,
        }
    }

    pub fn password_salt(&self) -> Result<[u8; SALT_SIZE], CryptoError> {
        decode_fixed::<SALT_SIZE>(&self.kdf.salt, "kdf.salt")
    }

    pub fn payload_context(&self) -> [u8; 32] {
        payload_context(
            self.version,
            &self.cipher,
            self.chunk_size,
            self.is_compressed(),
            &self.vault_id,
        )
    }
}

pub fn decode_fixed<const N: usize>(b64: &str, field: &str) -> Result<[u8; N], CryptoError> {
    let raw = B64
        .decode(b64)
        .map_err(|_| CryptoError::InvalidFormat(format!("invalid base64 in {field}")))?;
    raw.try_into()
        .map_err(|_| CryptoError::InvalidFormat(format!("invalid length for {field}")))
}

/// Cryptographic domain context binding all immutable Vault v5 payload
/// parameters (`version`, `cipher`, `chunk_size`, `compressed`, `vault_id`) to
/// metadata, key slots, stream nonce prefix, and every chunk AAD.
pub fn payload_context(
    version: u8,
    cipher: &str,
    chunk_size: u32,
    compressed: bool,
    vault_id: &str,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"RPMV5-CTX");
    h.update([version]);
    h.update((cipher.len() as u32).to_be_bytes());
    h.update(cipher.as_bytes());
    h.update(chunk_size.to_be_bytes());
    h.update([u8::from(compressed)]);
    h.update(vault_id.as_bytes());
    h.finalize().into()
}

pub fn password_slot_aad(
    payload_ctx: &[u8; 32],
    salt: &[u8; SALT_SIZE],
    kdf: &KdfParams,
    has_keyfile: bool,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"RPMV5-PW-SLOT");
    h.update(payload_ctx);
    h.update(salt);
    h.update(kdf.memory_kib.to_be_bytes());
    h.update(kdf.iterations.to_be_bytes());
    h.update(kdf.parallelism.to_be_bytes());
    h.update([u8::from(has_keyfile)]);
    h.finalize().into()
}

pub fn recovery_slot_aad(payload_ctx: &[u8; 32], rec_salt: &[u8; SALT_SIZE]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"RPMV5-REC-SLOT");
    h.update(payload_ctx);
    h.update(rec_salt);
    h.finalize().into()
}

pub fn wrap_dek(kek: &SecretKey, dek: &SecretKey, aad: &[u8]) -> Result<KeySlot, CryptoError> {
    let mut nonce_bytes = [0u8; AES_NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let cipher =
        Aes256Gcm::new_from_slice(kek.as_bytes()).map_err(|_| CryptoError::CryptoFailure)?;
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: dek.as_bytes(),
                aad,
            },
        )
        .map_err(|_| CryptoError::CryptoFailure)?;
    Ok(KeySlot {
        nonce: B64.encode(nonce_bytes),
        wrapped_dek: B64.encode(ct),
    })
}

pub fn unwrap_dek(kek: &SecretKey, slot: &KeySlot, aad: &[u8]) -> Result<SecretKey, CryptoError> {
    let nonce = decode_fixed::<AES_NONCE_SIZE>(&slot.nonce, "slot.nonce")?;
    let wrapped = B64
        .decode(&slot.wrapped_dek)
        .map_err(|_| CryptoError::InvalidFormat("invalid wrapped_dek base64".into()))?;
    let cipher =
        Aes256Gcm::new_from_slice(kek.as_bytes()).map_err(|_| CryptoError::CryptoFailure)?;
    let plain = Zeroizing::new(
        cipher
            .decrypt(Nonce::from_slice(&nonce), Payload { msg: &wrapped, aad })
            .map_err(|_| CryptoError::AuthenticationFailed)?,
    );
    SecretKey::from_slice(&plain).ok_or(CryptoError::AuthenticationFailed)
}

pub fn build_password_slot_and_kdf(
    dek: &SecretKey,
    password: &[u8],
    kdf: &KdfParams,
    keyfile_hash: Option<&SecretKey>,
    payload_ctx: &[u8; 32],
) -> Result<(HeaderKdf, KeySlot), CryptoError> {
    let mut salt = Zeroizing::new([0u8; SALT_SIZE]);
    OsRng.fill_bytes(salt.as_mut());
    let kek = derive_kek(password, &salt, kdf, keyfile_hash)?;
    let aad = password_slot_aad(payload_ctx, &salt, kdf, keyfile_hash.is_some());
    let slot = wrap_dek(&kek, dek, &aad)?;
    let hdr_kdf = HeaderKdf {
        algorithm: KDF_NAME.to_string(),
        salt: B64.encode(*salt),
        memory_kib: kdf.memory_kib,
        iterations: kdf.iterations,
        parallelism: kdf.parallelism,
    };
    Ok((hdr_kdf, slot))
}

pub fn build_recovery_slot(
    dek: &SecretKey,
    recovery_entropy: &SecretKey,
    payload_ctx: &[u8; 32],
) -> Result<RecoverySlot, CryptoError> {
    let mut rec_salt = Zeroizing::new([0u8; SALT_SIZE]);
    OsRng.fill_bytes(rec_salt.as_mut());
    let rec_kek = derive_recovery_kek(recovery_entropy, &rec_salt)?;
    let aad = recovery_slot_aad(payload_ctx, &rec_salt);
    let slot = wrap_dek(&rec_kek, dek, &aad)?;
    Ok(RecoverySlot {
        salt: B64.encode(*rec_salt),
        nonce: slot.nonce,
        wrapped_dek: slot.wrapped_dek,
    })
}

pub fn encrypt_metadata(
    dek: &SecretKey,
    metadata: &VaultMetadata,
    payload_ctx: &[u8; 32],
) -> Result<([u8; AES_NONCE_SIZE], Vec<u8>), CryptoError> {
    let meta_json = Zeroizing::new(
        serde_json::to_vec(metadata).map_err(|e| CryptoError::InvalidFormat(e.to_string()))?,
    );
    let mut nonce = [0u8; AES_NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);
    let cipher =
        Aes256Gcm::new_from_slice(dek.as_bytes()).map_err(|_| CryptoError::CryptoFailure)?;
    let enc = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &meta_json,
                aad: payload_ctx,
            },
        )
        .map_err(|_| CryptoError::CryptoFailure)?;
    Ok((nonce, enc))
}

pub fn decrypt_metadata(
    dek: &SecretKey,
    header: &VaultHeader,
    encrypted_meta: &[u8],
) -> Result<VaultMetadata, CryptoError> {
    let nonce = decode_fixed::<AES_NONCE_SIZE>(&header.meta_nonce, "meta_nonce")?;
    let payload_ctx = header.payload_context();
    let cipher =
        Aes256Gcm::new_from_slice(dek.as_bytes()).map_err(|_| CryptoError::CryptoFailure)?;
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: encrypted_meta,
                    aad: &payload_ctx,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?,
    );
    serde_json::from_slice(&plain)
        .map_err(|e| CryptoError::InvalidFormat(format!("invalid metadata JSON: {e}")))
}

pub fn write_header_and_meta(
    writer: &mut impl Write,
    header: &VaultHeader,
    encrypted_meta: &[u8],
) -> Result<(), CryptoError> {
    let json_bytes =
        serde_json::to_vec(header).map_err(|e| CryptoError::InvalidFormat(e.to_string()))?;
    if json_bytes.len() > MAX_HEADER_SIZE {
        return Err(CryptoError::InvalidFormat(
            "header exceeds maximum allowed size".into(),
        ));
    }
    writer.write_all(&VAULT_MAGIC)?;
    writer.write_all(&[VAULT_VERSION])?;
    writer.write_all(&(json_bytes.len() as u32).to_be_bytes())?;
    writer.write_all(&json_bytes)?;
    writer.write_all(encrypted_meta)?;
    Ok(())
}

fn read_exact_header(reader: &mut impl Read, buf: &mut [u8], msg: &str) -> Result<(), CryptoError> {
    reader.read_exact(buf).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            CryptoError::InvalidFormat(msg.into())
        } else {
            CryptoError::Io(e)
        }
    })
}

pub fn read_header_and_meta(
    reader: &mut impl Read,
) -> Result<(VaultHeader, Vec<u8>, u64), CryptoError> {
    let mut magic = [0u8; 4];
    read_exact_header(reader, &mut magic, "file too short for vault header")?;
    if magic != VAULT_MAGIC {
        return Err(CryptoError::InvalidFormat("invalid magic bytes".into()));
    }

    let mut ver = [0u8; 1];
    read_exact_header(reader, &mut ver, "truncated vault version")?;
    if ver[0] != VAULT_VERSION {
        return Err(CryptoError::UnsupportedVersion(ver[0]));
    }

    let mut len_buf = [0u8; 4];
    read_exact_header(reader, &mut len_buf, "truncated vault header length")?;
    let hlen = u32::from_be_bytes(len_buf) as usize;
    if hlen == 0 || hlen > MAX_HEADER_SIZE {
        return Err(CryptoError::InvalidFormat(format!(
            "invalid header length {hlen}"
        )));
    }

    let mut hdr_bytes = vec![0u8; hlen];
    read_exact_header(reader, &mut hdr_bytes, "truncated vault header JSON")?;
    let header: VaultHeader = serde_json::from_slice(&hdr_bytes)
        .map_err(|e| CryptoError::InvalidFormat(format!("corrupt header JSON: {e}")))?;

    validate_header(&header)?;

    let mlen = header.encrypted_meta_len as usize;
    let mut enc_meta = vec![0u8; mlen];
    read_exact_header(reader, &mut enc_meta, "truncated encrypted metadata block")?;
    let total_header_bytes = 4 + 1 + 4 + (hlen as u64) + (mlen as u64);
    Ok((header, enc_meta, total_header_bytes))
}

pub fn validate_header(header: &VaultHeader) -> Result<(), CryptoError> {
    if header.version != VAULT_VERSION {
        return Err(CryptoError::UnsupportedVersion(header.version));
    }
    if header.cipher != CHUNKED_CIPHER_NAME {
        return Err(CryptoError::InvalidFormat(format!(
            "unsupported cipher: {}",
            header.cipher
        )));
    }
    if (header.flags & !ALL_KNOWN_FLAGS) != 0 {
        return Err(CryptoError::InvalidFormat(format!(
            "unsupported header flags: {:#x}",
            header.flags
        )));
    }
    let has_recovery_flag = (header.flags & FLAG_HAS_RECOVERY) != 0;
    if has_recovery_flag != header.recovery_slot.is_some() {
        return Err(CryptoError::InvalidFormat(
            "header recovery flag inconsistent with recovery_slot".into(),
        ));
    }
    if header.kdf.algorithm != KDF_NAME {
        return Err(CryptoError::InvalidFormat(format!(
            "unsupported KDF: {}",
            header.kdf.algorithm
        )));
    }
    header.kdf_params().validate()?;
    if header.chunk_size < MIN_CHUNK_SIZE || header.chunk_size > MAX_CHUNK_SIZE {
        return Err(CryptoError::InvalidFormat(format!(
            "chunk_size {} outside [{MIN_CHUNK_SIZE}, {MAX_CHUNK_SIZE}]",
            header.chunk_size
        )));
    }
    if header.encrypted_meta_len < 16 || header.encrypted_meta_len as usize > MAX_HEADER_SIZE {
        return Err(CryptoError::InvalidFormat(
            "invalid encrypted_meta_len".into(),
        ));
    }
    if !(16..=128).contains(&header.vault_id.len())
        || !header
            .vault_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(CryptoError::InvalidFormat("invalid vault_id".into()));
    }
    Ok(())
}

pub fn random_dek() -> SecretKey {
    let mut raw = Zeroizing::new([0u8; AES_KEY_SIZE]);
    OsRng.fill_bytes(raw.as_mut());
    SecretKey::new(*raw)
}

pub fn random_vault_id() -> String {
    let mut raw = [0u8; 16];
    OsRng.fill_bytes(&mut raw);
    let mut s = String::with_capacity(32);
    for b in raw {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub enum Auth<'a> {
    Password {
        password: &'a [u8],
        keyfile_hash: Option<&'a SecretKey>,
    },
    RecoveryKey(&'a SecretKey),
}

pub fn unlock_dek(header: &VaultHeader, auth: Auth<'_>) -> Result<SecretKey, CryptoError> {
    let payload_ctx = header.payload_context();
    match auth {
        Auth::Password {
            password,
            keyfile_hash,
        } => {
            if header.has_keyfile() && keyfile_hash.is_none() {
                return Err(CryptoError::KeyfileRequired);
            }
            if !header.has_keyfile() && keyfile_hash.is_some() {
                return Err(CryptoError::AuthenticationFailed);
            }
            let salt = header.password_salt()?;
            let kdf = header.kdf_params();
            let kek = derive_kek(password, &salt, &kdf, keyfile_hash)?;
            let aad = password_slot_aad(&payload_ctx, &salt, &kdf, header.has_keyfile());
            unwrap_dek(&kek, &header.password_slot, &aad)
        }
        Auth::RecoveryKey(entropy) => {
            let rec_slot = header.recovery_slot.as_ref().ok_or_else(|| {
                CryptoError::InvalidFormat("this vault has no recovery slot".into())
            })?;
            let rec_salt = decode_fixed::<SALT_SIZE>(&rec_slot.salt, "recovery_slot.salt")?;
            let rec_kek = derive_recovery_kek(entropy, &rec_salt)?;
            let aad = recovery_slot_aad(&payload_ctx, &rec_salt);
            let slot = KeySlot {
                nonce: rec_slot.nonce.clone(),
                wrapped_dek: rec_slot.wrapped_dek.clone(),
            };
            unwrap_dek(&rec_kek, &slot, &aad)
        }
    }
}
