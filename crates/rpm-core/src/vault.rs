//! Vault Format v5 streaming Chunked AEAD encryption, decryption, inspect, and O(1) re-key.

use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::constants::{
    AES_NONCE_SIZE, AES_TAG_SIZE, CHUNKED_CIPHER_NAME, DEFAULT_CHUNK_SIZE, FLAG_COMPRESSED,
    FLAG_HAS_KEYFILE, FLAG_HAS_RECOVERY, MAX_CHUNK_SIZE, MAX_CONTAINER_SIZE, MIN_CHUNK_SIZE,
    MIN_CONTAINER_SIZE, SALT_SIZE, VAULT_VERSION,
};
use crate::error::CryptoError;
use crate::header::{
    build_password_slot_and_kdf, build_recovery_slot, decrypt_metadata, encrypt_metadata,
    payload_context_with_container, random_dek, random_vault_id, read_header_and_meta,
    validate_header, write_header_and_meta, Auth, VaultHeader, VaultMetadata,
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
    pub container_size_bytes: Option<u64>,
}

impl Default for EncryptOptions {
    fn default() -> Self {
        Self {
            kdf: KdfParams::default(),
            chunk_size: DEFAULT_CHUNK_SIZE,
            recovery_key: None,
            keyfile_hash: None,
            compressed: true,
            container_size_bytes: None,
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
    pub container_size: Option<u64>,
    pub is_hidden_compartment: bool,
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
    pub chunk_count: u32,
}

pub(crate) struct CountingWriter<W> {
    pub inner: W,
    pub written: u64,
}

impl<W> CountingWriter<W> {
    pub(crate) fn new(inner: W) -> Self {
        Self { inner, written: 0 }
    }
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

pub(crate) fn chunk_nonce(
    prefix: &[u8; 7],
    chunk_idx: u32,
    final_flag: u8,
) -> [u8; AES_NONCE_SIZE] {
    let mut nonce = [0u8; AES_NONCE_SIZE];
    nonce[..7].copy_from_slice(prefix);
    nonce[7..11].copy_from_slice(&chunk_idx.to_be_bytes());
    nonce[11] = final_flag;
    nonce
}

pub(crate) fn chunk_aad(
    payload_ctx: &[u8; 32],
    chunk_idx: u32,
    final_flag: u8,
    plain_len: u32,
) -> [u8; 52] {
    let mut aad = [0u8; 52];
    aad[..11].copy_from_slice(b"RPMV5-CHUNK");
    aad[11..43].copy_from_slice(payload_ctx);
    aad[43..47].copy_from_slice(&chunk_idx.to_be_bytes());
    aad[47] = final_flag;
    aad[48..52].copy_from_slice(&plain_len.to_be_bytes());
    aad
}

pub(crate) fn is_cancelled(cancel: Option<&AtomicBool>) -> bool {
    cancel.is_some_and(|c| c.load(Ordering::Relaxed))
}

pub(crate) fn write_random_padding(
    writer: &mut impl Write,
    mut remaining: u64,
    cancel: Option<&AtomicBool>,
) -> Result<(), CryptoError> {
    let mut buf = [0u8; 64 * 1024];
    while remaining > 0 {
        if is_cancelled(cancel) {
            return Err(CryptoError::Cancelled);
        }
        let want = (buf.len() as u64).min(remaining) as usize;
        OsRng.fill_bytes(&mut buf[..want]);
        writer.write_all(&buf[..want])?;
        remaining -= want as u64;
    }
    Ok(())
}

pub(crate) fn read_chunk_with_eof(
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

pub(crate) fn encrypt_outer_stream_raw(
    reader: &mut impl Read,
    writer: &mut impl Write,
    metadata: &VaultMetadata,
    password: &[u8],
    opts: &EncryptOptions,
    mut progress_cb: impl FnMut(u64),
    cancel: Option<&AtomicBool>,
) -> Result<(EncryptSummary, Option<[u8; SALT_SIZE]>), CryptoError> {
    if opts.chunk_size < MIN_CHUNK_SIZE || opts.chunk_size > MAX_CHUNK_SIZE {
        return Err(CryptoError::InvalidFormat(format!(
            "chunk_size {} outside [{MIN_CHUNK_SIZE}, {MAX_CHUNK_SIZE}]",
            opts.chunk_size
        )));
    }
    if let Some(sz) = opts.container_size_bytes {
        if !(MIN_CONTAINER_SIZE..=MAX_CONTAINER_SIZE).contains(&sz) {
            return Err(CryptoError::InvalidFormat(format!(
                "container_size {sz} outside [{MIN_CONTAINER_SIZE}, {MAX_CONTAINER_SIZE}]"
            )));
        }
    }
    opts.kdf.validate()?;

    let container_salt_raw = if opts.container_size_bytes.is_some() {
        let mut s = [0u8; SALT_SIZE];
        OsRng.fill_bytes(&mut s);
        Some(s)
    } else {
        None
    };

    let vault_id = random_vault_id();
    let dek = random_dek();
    let payload_ctx = payload_context_with_container(
        VAULT_VERSION,
        CHUNKED_CIPHER_NAME,
        opts.chunk_size,
        opts.compressed,
        &vault_id,
        opts.container_size_bytes,
        container_salt_raw.as_ref(),
    );

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
        container_size: opts.container_size_bytes,
        container_salt: container_salt_raw.map(|s| B64.encode(s)),
    };
    write_header_and_meta(writer, &header, &enc_meta)?;

    let prefix = derive_stream_nonce_prefix(&dek, &payload_ctx)?;
    let cipher =
        Aes256Gcm::new_from_slice(dek.as_bytes()).map_err(|_| CryptoError::CryptoFailure)?;

    let mut plain_buf = Zeroizing::new(vec![0u8; opts.chunk_size as usize]);
    let mut pending: Option<u8> = None;
    let mut chunk_idx: u32 = 0;
    let mut total_bytes: u64 = 0;

    loop {
        if is_cancelled(cancel) {
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

    Ok((
        EncryptSummary {
            vault_id,
            bytes_encrypted: total_bytes,
            chunks_written: chunk_idx,
        },
        container_salt_raw,
    ))
}

/// Encrypt a plaintext byte stream into Vault Format v5 (`Chunked AEAD`),
/// optionally padding the output with cryptographically random bytes to `container_size_bytes`.
pub fn encrypt_stream(
    reader: &mut impl Read,
    writer: &mut impl Write,
    metadata: &VaultMetadata,
    password: &[u8],
    opts: &EncryptOptions,
    progress_cb: impl FnMut(u64),
    cancel: Option<&AtomicBool>,
) -> Result<EncryptSummary, CryptoError> {
    let mut cw = CountingWriter::new(writer);
    let (summary, _csalt) = encrypt_outer_stream_raw(
        reader,
        &mut cw,
        metadata,
        password,
        opts,
        progress_cb,
        cancel,
    )?;

    if let Some(target_size) = opts.container_size_bytes {
        if cw.written > target_size {
            return Err(CryptoError::InvalidFormat(format!(
                "encrypted vault ({} bytes) exceeds target container size ({target_size} bytes)",
                cw.written
            )));
        }
        let pad = target_size - cw.written;
        write_random_padding(&mut cw, pad, cancel)?;
    }

    cw.flush()?;
    Ok(summary)
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
    let (header, enc_meta, hdr_len) = read_header_and_meta(reader)?;
    let dek = crate::header::unlock_dek(&header, auth)?;
    let metadata = decrypt_metadata(&dek, &header, &enc_meta)?;
    decrypt_chunks_with_key_at(reader, writer, &header, hdr_len, &dek, progress_cb, cancel)?;
    Ok(metadata)
}

/// Decrypt the chunked payload stream once the header and DEK have already been unlocked
/// (for unpadded vaults where the caller didn't preserve `hdr_bytes_read`).
pub fn decrypt_chunks_with_key(
    reader: &mut impl Read,
    writer: &mut impl Write,
    header: &VaultHeader,
    dek: &SecretKey,
    progress_cb: impl FnMut(u64),
    cancel: Option<&AtomicBool>,
) -> Result<u64, CryptoError> {
    if header.container_size.is_some() {
        return Err(CryptoError::InvalidFormat(
            "padded container decryption requires header offset".into(),
        ));
    }
    decrypt_chunks_with_key_at(reader, writer, header, 0, dek, progress_cb, cancel)
}

/// Decrypt the chunked payload stream starting immediately after `hdr_bytes_read`,
/// validating exact container size if `header.container_size` is present.
pub fn decrypt_chunks_with_key_at(
    reader: &mut impl Read,
    writer: &mut impl Write,
    header: &VaultHeader,
    hdr_bytes_read: u64,
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
    let mut payload_bytes_read: u64 = 0;
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
        payload_bytes_read = payload_bytes_read
            .checked_add(5 + ct_len as u64)
            .ok_or(CryptoError::AuthenticationFailed)?;

        let nonce_bytes = chunk_nonce(&prefix, chunk_idx, final_flag);
        let aad = chunk_aad(&payload_ctx, chunk_idx, final_flag, plain_len);

        let mut plain = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&nonce_bytes),
                    Payload {
                        msg: &ct_buf,
                        aad: &aad,
                    },
                )
                .map_err(|_| CryptoError::AuthenticationFailed)?,
        );

        if !plain.is_empty() {
            writer.write_all(&plain)?;
            plain.zeroize();
        }
        total_bytes += plain_len as u64;
        progress_cb(total_bytes);

        if final_flag == 1 {
            if let Some(target_size) = header.container_size {
                let total_consumed = hdr_bytes_read
                    .checked_add(payload_bytes_read)
                    .ok_or(CryptoError::AuthenticationFailed)?;
                if total_consumed > target_size {
                    return Err(CryptoError::AuthenticationFailed);
                }
                skip_exact(reader, target_size - total_consumed, cancel)?;
            }
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
        compressed: header.is_compressed(),
        argon_memory_kib: header.kdf.memory_kib,
        argon_iterations: header.kdf.iterations,
        argon_parallelism: header.kdf.parallelism,
        container_size: header.container_size,
        is_hidden_compartment: false,
        metadata,
    })
}

struct HashingReader<R: Read> {
    inner: BufReader<R>,
    hasher: Sha256,
}

impl<R: Read> HashingReader<R> {
    fn new(reader: R) -> Self {
        Self {
            inner: BufReader::with_capacity(64 * 1024, reader),
            hasher: Sha256::new(),
        }
    }

    fn drain_and_finalize(mut self) -> io::Result<String> {
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = self.inner.read(&mut buf)?;
            if n == 0 {
                break;
            }
            self.hasher.update(&buf[..n]);
        }
        Ok(self
            .hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect())
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.hasher.update(&buf[..n]);
        }
        Ok(n)
    }
}

fn skip_exact(
    reader: &mut impl Read,
    mut remaining: u64,
    cancel: Option<&AtomicBool>,
) -> Result<(), CryptoError> {
    let mut scratch = [0u8; 64 * 1024];
    while remaining > 0 {
        if is_cancelled(cancel) {
            return Err(CryptoError::Cancelled);
        }
        let want = (scratch.len() as u64).min(remaining) as usize;
        let n = reader.read(&mut scratch[..want])?;
        if n == 0 {
            return Err(CryptoError::AuthenticationFailed);
        }
        remaining -= n as u64;
    }
    Ok(())
}

fn scan_chunk_frames(
    reader: &mut impl Read,
    max_chunk_size: u32,
    hdr_bytes_read: u64,
    container_size: Option<u64>,
) -> Result<u32, String> {
    let mut chunk_count: u32 = 0;
    let mut payload_bytes_read: u64 = 0;
    loop {
        let mut len_buf = [0u8; 4];
        match reader.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                return Err("Truncated chunk payload (missing final chunk)".into());
            }
            Err(e) => return Err(format!("I/O error reading chunk frame: {e}")),
        }

        let plain_len = u32::from_be_bytes(len_buf);
        if plain_len > max_chunk_size {
            return Err(format!(
                "Chunk length {plain_len} exceeds header chunk_size {max_chunk_size}"
            ));
        }

        let mut flag_buf = [0u8; 1];
        match reader.read_exact(&mut flag_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                return Err("Truncated chunk header flags".into());
            }
            Err(e) => return Err(format!("I/O error reading chunk flags: {e}")),
        }
        let final_flag = flag_buf[0];
        if final_flag > 1 {
            return Err(format!("Invalid chunk final flag: {final_flag}"));
        }
        if plain_len == 0 && final_flag == 0 {
            return Err("Invalid empty non-final chunk frame".into());
        }

        let payload_len = (plain_len as u64) + (AES_TAG_SIZE as u64);
        payload_bytes_read = payload_bytes_read
            .checked_add(5 + payload_len)
            .ok_or_else(|| "Payload byte offset overflow".to_string())?;
        if let Err(err) = skip_exact(reader, payload_len, None) {
            return Err(match err {
                CryptoError::AuthenticationFailed => "Truncated chunk ciphertext/tag bytes".into(),
                other => other.to_string(),
            });
        }

        chunk_count = chunk_count
            .checked_add(1)
            .ok_or_else(|| "Chunk counter overflow".to_string())?;

        if final_flag == 1 {
            if let Some(target_size) = container_size {
                let total_consumed = hdr_bytes_read
                    .checked_add(payload_bytes_read)
                    .ok_or_else(|| "Container byte offset overflow".to_string())?;
                if total_consumed > target_size {
                    return Err("Payload exceeds declared container_size".into());
                }
                if let Err(err) = skip_exact(reader, target_size - total_consumed, None) {
                    return Err(match err {
                        CryptoError::AuthenticationFailed => {
                            "Truncated padded container (file shorter than container_size)".into()
                        }
                        other => other.to_string(),
                    });
                }
            }
            let mut trailing = [0u8; 1];
            match reader.read(&mut trailing) {
                Ok(0) => return Ok(chunk_count),
                Ok(_) => {
                    return Err(if container_size.is_some() {
                        "Trailing bytes past container_size".into()
                    } else {
                        "Trailing unauthenticated bytes after final chunk".into()
                    });
                }
                Err(e) => return Err(format!("I/O error checking EOF: {e}")),
            }
        }
    }
}

/// Passwordless single-pass structural check (header + chunk frames) + SHA-256 hash.
pub fn check_integrity(path: &Path) -> Result<IntegrityReport, CryptoError> {
    let f = File::open(path)?;
    let file_size = f.metadata()?.len();
    let mut hr = HashingReader::new(f);

    let (ok, version, summary_msg, has_keyfile, has_recovery, chunk_count) =
        match read_header_and_meta(&mut hr) {
            Ok((hdr, _, hdr_len)) => {
                match scan_chunk_frames(&mut hr, hdr.chunk_size, hdr_len, hdr.container_size) {
                    Ok(chunks) => {
                        let container_note = match hdr.container_size {
                            Some(sz) => format!(", {} B container", sz),
                            None => String::new(),
                        };
                        (
                            true,
                            hdr.version,
                            format!(
                                "Structure valid (v{}, {}, {} KiB chunk, {chunks} chunk(s){container_note})",
                                hdr.version,
                                hdr.cipher,
                                hdr.chunk_size / 1024
                            ),
                            hdr.has_keyfile(),
                            hdr.has_recovery(),
                            chunks,
                        )
                    }
                    Err(msg) => (
                        false,
                        hdr.version,
                        msg,
                        hdr.has_keyfile(),
                        hdr.has_recovery(),
                        0,
                    ),
                }
            }
            Err(CryptoError::UnsupportedVersion(v)) => (
                false,
                v,
                format!("Unsupported vault version: {v} (expected v{VAULT_VERSION})"),
                false,
                false,
                0,
            ),
            Err(err) => (false, 0, err.to_string(), false, false, 0),
        };

    let sha256_hex = hr.drain_and_finalize()?;
    let full_message = format!("{summary_msg}\nSHA-256: {sha256_hex}");

    Ok(IntegrityReport {
        ok,
        version,
        file_size,
        sha256_hex,
        message: full_message,
        has_keyfile,
        has_recovery,
        chunk_count,
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
    if header.container_size.is_some() {
        return Err(CryptoError::UnsupportedOperation(
            "in-place re-key is not available for this vault; decrypt and re-encrypt to change credentials".into(),
        ));
    }
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
