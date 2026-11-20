//! Vault Format v5 streaming Chunked AEAD encryption, decryption, inspect, and O(1) re-key.

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::constants::{
    AES_NONCE_SIZE, AES_TAG_SIZE, CHUNKED_CIPHER_NAME, DEFAULT_CHUNK_SIZE, FLAG_COMPRESSED,
    FLAG_HAS_KEYFILE, FLAG_HAS_RECOVERY, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE, VAULT_VERSION,
};
use crate::error::CryptoError;
use crate::header::{
    build_password_slot_and_kdf, build_recovery_slot, decrypt_metadata, encrypt_metadata,
    random_dek, random_vault_id, read_header_and_meta, validate_header, write_header_and_meta,
    Auth, VaultHeader, VaultMetadata,
};
use crate::kdf::{derive_stream_nonce_prefix, KdfParams};
use crate::mem::SecretKey;

#[derive(Clone, Debug)]
pub struct EncryptOptions {
    pub kdf: KdfParams,
    pub chunk_size: u32,
    pub recovery_key: Option<SecretKey>,
    pub keyfile_hash: Option<SecretKey>,
    pub compressed: bool,
}

impl Default for EncryptOptions {
    fn default() -> Self {
        Self {
            kdf: KdfParams::default(),
            chunk_size: DEFAULT_CHUNK_SIZE,
            recovery_key: None,
            keyfile_hash: None,
            compressed: true,
        }
    }
}

#[derive(Clone, Debug)]
pub struct EncryptSummary {
    pub vault_id: String,
    pub bytes_encrypted: u64,
    pub chunks_written: u32,
}

#[derive(Clone, Debug)]
pub struct VaultInfo {
    pub version: u8,
    pub vault_id: String,
    pub cipher: String,
    pub chunk_size: u32,
    pub has_recovery: bool,
    pub has_keyfile: bool,
    pub compressed: bool,
    pub argon_memory_kib: u32,
    pub argon_iterations: u32,
    pub argon_parallelism: u32,
    pub metadata: VaultMetadata,
}

#[derive(Clone, Debug)]
pub struct IntegrityReport {
    pub ok: bool,
    pub version: u8,
    pub file_size: u64,
    pub sha256_hex: String,
    pub message: String,
    pub has_keyfile: bool,
    pub has_recovery: bool,
}

fn chunk_nonce(prefix: &[u8; 7], chunk_idx: u32, final_flag: u8) -> [u8; AES_NONCE_SIZE] {
    let mut nonce = [0u8; AES_NONCE_SIZE];
    nonce[..7].copy_from_slice(prefix);
    nonce[7..11].copy_from_slice(&chunk_idx.to_be_bytes());
    nonce[11] = final_flag;
    nonce
}

fn chunk_aad(payload_ctx: &[u8; 32], chunk_idx: u32, final_flag: u8, plain_len: u32) -> [u8; 52] {
    let mut aad = [0u8; 52];
    aad[..11].copy_from_slice(b"RPMV5-CHUNK");
    aad[11..43].copy_from_slice(payload_ctx);
    aad[43..47].copy_from_slice(&chunk_idx.to_be_bytes());
    aad[47] = final_flag;
    aad[48..52].copy_from_slice(&plain_len.to_be_bytes());
    aad
}

fn is_cancelled(cancel: Option<&AtomicBool>) -> bool {
    cancel.is_some_and(|c| c.load(Ordering::Relaxed))
}

fn read_chunk_with_eof(
    reader: &mut impl Read,
    buf: &mut [u8],
    pending: &mut Option<u8>,
) -> io::Result<(usize, bool)> {
    let mut filled = 0usize;
    if let Some(first) = pending.take() {
        buf[0] = first;
        filled = 1;
    }

    while filled < buf.len() {
        let n = reader.read(&mut buf[filled..])?;
        if n == 0 {
            return Ok((filled, true));
        }
        filled += n;
    }

    let mut lookahead = [0u8; 1];
    let n = reader.read(&mut lookahead)?;
    if n == 0 {
        Ok((filled, true))
    } else {
        *pending = Some(lookahead[0]);
        Ok((filled, false))
    }
}

/// Encrypt a plaintext byte stream into Vault Format v5 (`Chunked AEAD`).
pub fn encrypt_stream(
    reader: &mut impl Read,
    writer: &mut impl Write,
    metadata: &VaultMetadata,
    password: &[u8],
    opts: &EncryptOptions,
    mut progress_cb: impl FnMut(u64),
    cancel: Option<&AtomicBool>,
) -> Result<EncryptSummary, CryptoError> {
    if opts.chunk_size < MIN_CHUNK_SIZE || opts.chunk_size > MAX_CHUNK_SIZE {
        return Err(CryptoError::InvalidFormat(format!(
            "chunk_size {} outside [{MIN_CHUNK_SIZE}, {MAX_CHUNK_SIZE}]",
            opts.chunk_size
        )));
    }
    opts.kdf.validate()?;

    let vault_id = random_vault_id();
    let dek = random_dek();
    let payload_ctx = crate::header::payload_context(VAULT_VERSION, opts.chunk_size, &vault_id);

    let (hdr_kdf, password_slot) = build_password_slot_and_kdf(
        &dek,
        password,
        &opts.kdf,
        opts.keyfile_hash.as_ref(),
        &payload_ctx,
    )?;

    let recovery_slot = match opts.recovery_key.as_ref() {
        Some(entropy) => Some(build_recovery_slot(&dek, entropy, &payload_ctx)?),
        None => None,
    };

    let (meta_nonce, enc_meta) = encrypt_metadata(&dek, metadata, &payload_ctx)?;

    let mut flags = 0u8;
    if recovery_slot.is_some() {
        flags |= FLAG_HAS_RECOVERY;
    }
    if opts.keyfile_hash.is_some() {
        flags |= FLAG_HAS_KEYFILE;
    }
    if opts.compressed {
        flags |= FLAG_COMPRESSED;
    }

    let header = VaultHeader {
        version: VAULT_VERSION,
        vault_id: vault_id.clone(),
        cipher: CHUNKED_CIPHER_NAME.to_string(),
        chunk_size: opts.chunk_size,
        flags,
        kdf: hdr_kdf,
        password_slot,
        recovery_slot,
        meta_nonce: B64.encode(meta_nonce),
        encrypted_meta_len: enc_meta.len() as u32,
    };
    write_header_and_meta(writer, &header, &enc_meta)?;

    let prefix = derive_stream_nonce_prefix(&dek, &payload_ctx)?;
    let cipher =
        Aes256Gcm::new_from_slice(dek.as_bytes()).map_err(|_| CryptoError::CryptoFailure)?;

    let mut plain_buf = vec![0u8; opts.chunk_size as usize];
    let mut pending: Option<u8> = None;
    let mut chunk_idx: u32 = 0;
    let mut total_bytes: u64 = 0;

    loop {
        if is_cancelled(cancel) {
            plain_buf.zeroize();
            return Err(CryptoError::Cancelled);
        }

        let (len, is_final) = read_chunk_with_eof(reader, &mut plain_buf, &mut pending)?;
        let final_flag = u8::from(is_final);
        let plain_len_u32 = len as u32;
        let nonce_bytes = chunk_nonce(&prefix, chunk_idx, final_flag);
        let aad = chunk_aad(&payload_ctx, chunk_idx, final_flag, plain_len_u32);

        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &plain_buf[..len],
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::CryptoFailure)?;

        writer.write_all(&plain_len_u32.to_be_bytes())?;
        writer.write_all(&[final_flag])?;
        writer.write_all(&ct)?;

        plain_buf[..len].zeroize();
        total_bytes += len as u64;
        progress_cb(total_bytes);

        chunk_idx = chunk_idx
            .checked_add(1)
            .ok_or_else(|| CryptoError::InvalidFormat("chunk counter overflow".into()))?;
        if is_final {
            break;
        }
    }

    writer.flush()?;
    Ok(EncryptSummary {
        vault_id,
        bytes_encrypted: total_bytes,
        chunks_written: chunk_idx,
    })
}

/// Decrypt a Vault Format v5 stream. Each chunk is authenticated in RAM before
/// a single byte is passed to `writer`.
pub fn decrypt_stream(
    reader: &mut impl Read,
    writer: &mut impl Write,
    auth: Auth<'_>,
    progress_cb: impl FnMut(u64),
    cancel: Option<&AtomicBool>,
) -> Result<VaultMetadata, CryptoError> {
    let (header, enc_meta, _hdr_len) = read_header_and_meta(reader)?;
    let dek = crate::header::unlock_dek(&header, auth)?;
    let metadata = decrypt_metadata(&dek, &header, &enc_meta)?;
    decrypt_chunks_with_key(reader, writer, &header, &dek, progress_cb, cancel)?;
    Ok(metadata)
}

/// Decrypt the chunked payload stream once the header and DEK have already been unlocked.
pub fn decrypt_chunks_with_key(
    reader: &mut impl Read,
    writer: &mut impl Write,
    header: &VaultHeader,
    dek: &SecretKey,
    mut progress_cb: impl FnMut(u64),
    cancel: Option<&AtomicBool>,
) -> Result<u64, CryptoError> {
    let payload_ctx = header.payload_context();
    let prefix = derive_stream_nonce_prefix(dek, &payload_ctx)?;
    let cipher =
        Aes256Gcm::new_from_slice(dek.as_bytes()).map_err(|_| CryptoError::CryptoFailure)?;

    let mut chunk_idx: u32 = 0;
    let mut total_bytes: u64 = 0;
    let mut ct_buf: Vec<u8> = Vec::new();

    loop {
        if is_cancelled(cancel) {
            return Err(CryptoError::Cancelled);
        }

        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                CryptoError::AuthenticationFailed
            } else {
                CryptoError::Io(e)
            }
        })?;
        let plain_len = u32::from_be_bytes(len_buf);
        if plain_len > header.chunk_size {
            return Err(CryptoError::InvalidFormat(format!(
                "chunk length {plain_len} exceeds header chunk_size {}",
                header.chunk_size
            )));
        }

        let mut flag_buf = [0u8; 1];
        reader.read_exact(&mut flag_buf).map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                CryptoError::AuthenticationFailed
            } else {
                CryptoError::Io(e)
            }
        })?;
        let final_flag = flag_buf[0];
        if final_flag > 1 {
            return Err(CryptoError::InvalidFormat(format!(
                "invalid chunk final flag {final_flag}"
            )));
        }
        if plain_len == 0 && final_flag == 0 {
            return Err(CryptoError::InvalidFormat(
                "empty non-final chunk frame".into(),
            ));
        }

        let ct_len = (plain_len as usize) + AES_TAG_SIZE;
        ct_buf.resize(ct_len, 0);
        reader.read_exact(&mut ct_buf).map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                CryptoError::AuthenticationFailed
            } else {
                CryptoError::Io(e)
            }
        })?;

        let nonce_bytes = chunk_nonce(&prefix, chunk_idx, final_flag);
        let aad = chunk_aad(&payload_ctx, chunk_idx, final_flag, plain_len);

        let mut plain = cipher
            .decrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &ct_buf,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?;

        if !plain.is_empty() {
            writer.write_all(&plain)?;
            plain.zeroize();
        }
        total_bytes += plain_len as u64;
        progress_cb(total_bytes);

        if final_flag == 1 {
            let mut trailing = [0u8; 1];
            if reader.read(&mut trailing)? != 0 {
                return Err(CryptoError::AuthenticationFailed);
            }
            break;
        }

        chunk_idx = chunk_idx
            .checked_add(1)
            .ok_or_else(|| CryptoError::InvalidFormat("chunk counter overflow".into()))?;
    }

    writer.flush()?;
    Ok(total_bytes)
}

/// Inspect vault parameters and decrypted metadata without touching the chunk payload.
pub fn inspect_header(reader: &mut impl Read, auth: Auth<'_>) -> Result<VaultInfo, CryptoError> {
    let (header, enc_meta, _hdr_len) = read_header_and_meta(reader)?;
    let dek = crate::header::unlock_dek(&header, auth)?;
    let metadata = decrypt_metadata(&dek, &header, &enc_meta)?;
    Ok(VaultInfo {
        version: header.version,
        vault_id: header.vault_id.clone(),
        cipher: header.cipher.clone(),
        chunk_size: header.chunk_size,
        has_recovery: header.has_recovery(),
        has_keyfile: header.has_keyfile(),
        compressed: (header.flags & FLAG_COMPRESSED) != 0,
        argon_memory_kib: header.kdf.memory_kib,
        argon_iterations: header.kdf.iterations,
        argon_parallelism: header.kdf.parallelism,
        metadata,
    })
}

/// Passwordless structural check + streaming SHA-256 hash of a vault file.
pub fn check_integrity(path: &Path) -> Result<IntegrityReport, CryptoError> {
    let mut f = File::open(path)?;
    let file_size = f.metadata()?.len();
    let header_res = read_header_and_meta(&mut f);

    let (ok, version, message, has_keyfile, has_recovery) = match header_res {
        Ok((hdr, _, _)) => (
            true,
            hdr.version,
            format!(
                "Structure valid (v{}, {}, {} KiB chunk)",
                hdr.version,
                hdr.cipher,
                hdr.chunk_size / 1024
            ),
            hdr.has_keyfile(),
            hdr.has_recovery(),
        ),
        Err(CryptoError::UnsupportedVersion(v)) => {
            return Ok(IntegrityReport {
                ok: false,
                version: v,
                file_size,
                sha256_hex: String::new(),
                message: format!("Unsupported vault version: {v} (expected v5)"),
                has_keyfile: false,
                has_recovery: false,
            });
        }
        Err(err) => {
            return Ok(IntegrityReport {
                ok: false,
                version: 0,
                file_size,
                sha256_hex: String::new(),
                message: err.to_string(),
                has_keyfile: false,
                has_recovery: false,
            });
        }
    };

    let mut hash_file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = hash_file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let sha256_hex: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let full_message = format!("{message}\nSHA-256: {sha256_hex}");

    Ok(IntegrityReport {
        ok,
        version,
        file_size,
        sha256_hex,
        message: full_message,
        has_keyfile,
        has_recovery,
    })
}

/// Parameters for O(1) header key rotation via [`rekey_stream`].
pub struct RekeyOptions<'a> {
    pub old_password: &'a [u8],
    pub new_password: &'a [u8],
    pub old_keyfile_hash: Option<&'a SecretKey>,
    pub new_keyfile_hash: Option<&'a SecretKey>,
    pub new_kdf: Option<KdfParams>,
}

/// O(1) key rotation: re-wrap the DEK under a new password without decrypting payload chunks.
pub fn rekey_stream(
    reader: &mut impl Read,
    writer: &mut impl Write,
    opts: &RekeyOptions<'_>,
    cancel: Option<&AtomicBool>,
) -> Result<(), CryptoError> {
    if is_cancelled(cancel) {
        return Err(CryptoError::Cancelled);
    }

    let (mut header, enc_meta, _hdr_len) = read_header_and_meta(reader)?;
    let dek = crate::header::unlock_dek(
        &header,
        Auth::Password {
            password: opts.old_password,
            keyfile_hash: opts.old_keyfile_hash,
        },
    )?;

    if is_cancelled(cancel) {
        return Err(CryptoError::Cancelled);
    }

    let kdf = opts.new_kdf.unwrap_or_else(|| header.kdf_params());
    kdf.validate()?;
    let payload_ctx = header.payload_context();
    let (hdr_kdf, new_slot) = build_password_slot_and_kdf(
        &dek,
        opts.new_password,
        &kdf,
        opts.new_keyfile_hash,
        &payload_ctx,
    )?;

    header.kdf = hdr_kdf;
    header.password_slot = new_slot;
    if opts.new_keyfile_hash.is_some() {
        header.flags |= FLAG_HAS_KEYFILE;
    } else {
        header.flags &= !FLAG_HAS_KEYFILE;
    }

    validate_header(&header)?;
    write_header_and_meta(writer, &header, &enc_meta)?;

    let mut buf = [0u8; 256 * 1024];
    loop {
        if is_cancelled(cancel) {
            return Err(CryptoError::Cancelled);
        }
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        writer.write_all(&buf[..n])?;
    }
    writer.flush()?;
    Ok(())
}
