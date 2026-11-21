//! Container-padded plausible deniability (Hidden Vault) v5 engine.
//!
//! Security properties:
//! - Normal padded containers (`EncryptOptions { container_size_bytes: Some(N), .. }`)
//!   and containers holding a hidden compartment share the exact same public
//!   `VaultHeader` layout (`container_size` + `container_salt`, zero hidden flags).
//! - Hidden compartment headers, XOR-masked chunk frame prefixes, chunk payloads,
//!   and the trailing 108-byte AES-GCM mini-header are cryptographically
//!   indistinguishable from random `OsRng` padding bytes.
//! - Failed decryption yields the outer authentication error without revealing
//!   whether a hidden compartment exists.

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::atomic::AtomicBool;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::constants::{
    AES_NONCE_SIZE, AES_TAG_SIZE, HIDDEN_FLAG_COMPRESSED, HIDDEN_FLAG_HAS_KEYFILE,
    HIDDEN_KNOWN_FLAGS, HIDDEN_MAGIC, HIDDEN_MINI_HEADER_PLAIN_SIZE, HIDDEN_MINI_HEADER_WIRE_SIZE,
    HIDDEN_VERSION, MAX_CHUNK_SIZE, MAX_CONTAINER_SIZE, MAX_HEADER_SIZE, MIN_CHUNK_SIZE,
    MIN_CONTAINER_SIZE, SALT_SIZE, VAULT_VERSION,
};
use crate::error::CryptoError;
use crate::header::{
    decrypt_metadata, random_dek, read_header_and_meta, unlock_dek, Auth, VaultHeader,
    VaultMetadata,
};
use crate::kdf::{
    derive_hidden_frame_mask, derive_hidden_kek, derive_stream_nonce_prefix, KdfParams,
};
use crate::mem::SecretKey;
use crate::vault::{
    chunk_aad, chunk_nonce, decrypt_chunks_with_key_at, encrypt_outer_stream_raw, is_cancelled,
    read_chunk_with_eof, write_random_padding, CountingWriter, EncryptOptions, EncryptSummary,
    VaultInfo,
};

#[derive(Clone, Debug)]
pub struct HiddenEncryptOptions {
    pub reed_solomon: bool,
    pub stealth: bool,
    pub kdf: KdfParams,
    pub chunk_size: u32,
    pub container_size_bytes: u64,
    pub decoy_recovery_key: Option<SecretKey>,
    pub decoy_keyfile_hash: Option<SecretKey>,
    pub decoy_compressed: bool,
    pub hidden_keyfile_hash: Option<SecretKey>,
    pub hidden_compressed: bool,
}

impl Default for HiddenEncryptOptions {
    fn default() -> Self {
        Self {
            reed_solomon: false,
            stealth: false,
            kdf: KdfParams::default(),
            chunk_size: crate::constants::DEFAULT_CHUNK_SIZE,
            container_size_bytes: MIN_CONTAINER_SIZE,
            decoy_recovery_key: None,
            decoy_keyfile_hash: None,
            decoy_compressed: true,
            hidden_keyfile_hash: None,
            hidden_compressed: true,
        }
    }
}

#[derive(Clone, Debug)]
pub struct HiddenEncryptSummary {
    pub decoy: EncryptSummary,
    pub hidden_bytes_encrypted: u64,
    pub hidden_chunks_written: u32,
    pub container_size: u64,
}

/// Authenticated outer or hidden vault handle produced by [`unlock_seekable`].
pub enum UnlockedVault {
    ReedSolomon {
        inner: Box<UnlockedVault>,
        repaired: u64,
    },
    Outer {
        header: VaultHeader,
        dek: SecretKey,
        metadata: VaultMetadata,
        hdr_len: u64,
    },
    Stealth {
        info: VaultInfo,
        dek: SecretKey,
        ctx: [u8; 32],
        payload_offset: u64,
    },
    Hidden {
        info: VaultInfo,
        hidden_dek: SecretKey,
        hidden_ctx: [u8; 32],
        chunk_size: u32,
        hidden_data_offset: u64,
        hidden_data_len: u64,
        encrypted_meta_len: u32,
    },
}

impl UnlockedVault {
    pub fn metadata(&self) -> &VaultMetadata {
        match self {
            Self::ReedSolomon { inner, .. } => inner.metadata(),
            Self::Outer { metadata, .. } => metadata,
            Self::Stealth { info, .. } | Self::Hidden { info, .. } => &info.metadata,
        }
    }

    pub fn is_compressed(&self) -> bool {
        match self {
            Self::ReedSolomon { inner, .. } => inner.is_compressed(),
            UnlockedVault::Outer { header, .. } => header.is_compressed(),
            Self::Stealth { info, .. } | Self::Hidden { info, .. } => info.compressed,
        }
    }

    pub fn is_hidden(&self) -> bool {
        match self {
            Self::ReedSolomon { inner, .. } => inner.is_hidden(),
            Self::Hidden { .. } => true,
            _ => false,
        }
    }

    pub fn vault_info(&self) -> VaultInfo {
        match self {
            Self::ReedSolomon { inner, repaired } => {
                let mut info = inner.vault_info();
                info.has_reed_solomon = true;
                info.rs_repaired_bytes = *repaired;
                info
            }
            UnlockedVault::Outer {
                header, metadata, ..
            } => VaultInfo {
                has_reed_solomon: false,
                rs_repaired_bytes: 0,
                is_stealth: false,
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
                metadata: metadata.clone(),
            },
            Self::Stealth { info, .. } | Self::Hidden { info, .. } => info.clone(),
        }
    }
}

fn passwords_equal_ct(a: &[u8], b: &[u8]) -> bool {
    let mut da: [u8; 32] = Sha256::digest(a).into();
    let mut db: [u8; 32] = Sha256::digest(b).into();
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= da[i] ^ db[i];
    }
    da.zeroize();
    db.zeroize();
    diff == 0
}

fn mini_header_aad(
    container_size: u64,
    container_salt: &[u8; SALT_SIZE],
    has_keyfile: bool,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"RPMV5-HIDDEN-MINI-HDR");
    h.update(container_size.to_be_bytes());
    h.update(container_salt);
    h.update([u8::from(has_keyfile)]);
    h.finalize().into()
}

fn hidden_payload_context(
    chunk_size: u32,
    compressed: bool,
    container_size: u64,
    container_salt: &[u8; SALT_SIZE],
    hidden_data_offset: u64,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"RPMV5-HIDDEN-CTX");
    h.update(chunk_size.to_be_bytes());
    h.update([u8::from(compressed)]);
    h.update(container_size.to_be_bytes());
    h.update(container_salt);
    h.update(hidden_data_offset.to_be_bytes());
    h.finalize().into()
}

fn encode_mini_header(
    flags: u8,
    chunk_size: u32,
    encrypted_meta_len: u32,
    hidden_data_offset: u64,
    hidden_data_len: u64,
    hidden_dek: &SecretKey,
    hidden_meta_nonce: &[u8; AES_NONCE_SIZE],
) -> Zeroizing<[u8; HIDDEN_MINI_HEADER_PLAIN_SIZE]> {
    let mut buf = Zeroizing::new([0u8; HIDDEN_MINI_HEADER_PLAIN_SIZE]);
    buf[0..4].copy_from_slice(&HIDDEN_MAGIC);
    buf[4] = HIDDEN_VERSION;
    buf[5] = flags;
    buf[6..8].copy_from_slice(&[0u8; 2]);
    buf[8..12].copy_from_slice(&chunk_size.to_be_bytes());
    buf[12..16].copy_from_slice(&encrypted_meta_len.to_be_bytes());
    buf[16..24].copy_from_slice(&hidden_data_offset.to_be_bytes());
    buf[24..32].copy_from_slice(&hidden_data_len.to_be_bytes());
    buf[32..64].copy_from_slice(hidden_dek.as_bytes());
    buf[64..76].copy_from_slice(hidden_meta_nonce);
    buf[76..80].copy_from_slice(&[0u8; 4]);
    buf
}

struct DecodedMiniHeader {
    compressed: bool,
    has_keyfile: bool,
    chunk_size: u32,
    encrypted_meta_len: u32,
    hidden_data_offset: u64,
    hidden_data_len: u64,
    hidden_dek: SecretKey,
    hidden_meta_nonce: [u8; AES_NONCE_SIZE],
}

fn decode_mini_header(plain: &[u8]) -> Result<DecodedMiniHeader, CryptoError> {
    if plain.len() != HIDDEN_MINI_HEADER_PLAIN_SIZE {
        return Err(CryptoError::AuthenticationFailed);
    }
    if plain[0..4] != HIDDEN_MAGIC || plain[4] != HIDDEN_VERSION {
        return Err(CryptoError::AuthenticationFailed);
    }
    let flags = plain[5];
    if (flags & !HIDDEN_KNOWN_FLAGS) != 0 || plain[6..8] != [0u8; 2] || plain[76..80] != [0u8; 4] {
        return Err(CryptoError::AuthenticationFailed);
    }
    let chunk_size = u32::from_be_bytes(plain[8..12].try_into().unwrap());
    if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) {
        return Err(CryptoError::AuthenticationFailed);
    }
    let encrypted_meta_len = u32::from_be_bytes(plain[12..16].try_into().unwrap());
    if (encrypted_meta_len as usize) < AES_TAG_SIZE
        || (encrypted_meta_len as usize) > MAX_HEADER_SIZE
    {
        return Err(CryptoError::AuthenticationFailed);
    }
    let hidden_data_offset = u64::from_be_bytes(plain[16..24].try_into().unwrap());
    let hidden_data_len = u64::from_be_bytes(plain[24..32].try_into().unwrap());
    let hidden_dek = SecretKey::from_slice(&plain[32..64]).ok_or(CryptoError::CryptoFailure)?;
    let mut hidden_meta_nonce = [0u8; AES_NONCE_SIZE];
    hidden_meta_nonce.copy_from_slice(&plain[64..76]);

    Ok(DecodedMiniHeader {
        compressed: (flags & HIDDEN_FLAG_COMPRESSED) != 0,
        has_keyfile: (flags & HIDDEN_FLAG_HAS_KEYFILE) != 0,
        chunk_size,
        encrypted_meta_len,
        hidden_data_offset,
        hidden_data_len,
        hidden_dek,
        hidden_meta_nonce,
    })
}

fn choose_hidden_pre_pad(
    available_after_outer: u64,
    hidden_metadata: &VaultMetadata,
    hidden_meta_ct_len: u64,
    chunk_size: u32,
) -> u64 {
    let min_chunks = hidden_metadata
        .original_size
        .div_ceil(chunk_size as u64)
        .max(1);
    let tar_slack = (hidden_metadata.file_count.saturating_add(4)).saturating_mul(1024);
    let est_hidden = hidden_meta_ct_len
        .saturating_add(hidden_metadata.original_size)
        .saturating_add(tar_slack)
        .saturating_add(min_chunks.saturating_mul((5 + AES_TAG_SIZE) as u64));
    let slack = available_after_outer.saturating_sub(est_hidden);
    let cap = (slack / 4).min(64 * 1024);
    if cap < 64 {
        return 0;
    }
    let span = cap - 63;
    let mut rand_bytes = [0u8; 8];
    OsRng.fill_bytes(&mut rand_bytes);
    64 + (u64::from_le_bytes(rand_bytes) % span)
}

/// Encrypt decoy (outer) and hidden compartments into one fixed-size padded
/// Vault v5 container with plausible deniability.
#[allow(clippy::too_many_arguments)]
pub fn encrypt_hidden_stream<R1: Read, R2: Read, W: Write>(
    decoy_reader: &mut R1,
    hidden_reader: &mut R2,
    writer: &mut W,
    decoy_metadata: &VaultMetadata,
    hidden_metadata: &VaultMetadata,
    decoy_password: &[u8],
    hidden_password: &[u8],
    opts: &HiddenEncryptOptions,
    decoy_progress: impl FnMut(u64),
    hidden_progress: impl FnMut(u64),
    cancel: Option<&AtomicBool>,
) -> Result<HiddenEncryptSummary, CryptoError> {
    if opts.reed_solomon {
        crate::rs::validate_mode(opts.stealth)?;
        let mut rs = crate::RsEncoderWriter::new(writer)?;
        let summary = encrypt_hidden_inner(
            decoy_reader,
            hidden_reader,
            &mut rs,
            decoy_metadata,
            hidden_metadata,
            decoy_password,
            hidden_password,
            opts,
            decoy_progress,
            hidden_progress,
            cancel,
        )?;
        rs.finish()?;
        Ok(summary)
    } else {
        encrypt_hidden_inner(
            decoy_reader,
            hidden_reader,
            writer,
            decoy_metadata,
            hidden_metadata,
            decoy_password,
            hidden_password,
            opts,
            decoy_progress,
            hidden_progress,
            cancel,
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn encrypt_hidden_inner<R1: Read, R2: Read, W: Write>(
    decoy_reader: &mut R1,
    hidden_reader: &mut R2,
    writer: &mut W,
    decoy_metadata: &VaultMetadata,
    hidden_metadata: &VaultMetadata,
    decoy_password: &[u8],
    hidden_password: &[u8],
    opts: &HiddenEncryptOptions,
    decoy_progress: impl FnMut(u64),
    mut hidden_progress: impl FnMut(u64),
    cancel: Option<&AtomicBool>,
) -> Result<HiddenEncryptSummary, CryptoError> {
    if decoy_password.is_empty() || hidden_password.is_empty() {
        return Err(CryptoError::InvalidFormat(
            "decoy and hidden passwords cannot be empty".into(),
        ));
    }
    if passwords_equal_ct(decoy_password, hidden_password) {
        return Err(CryptoError::InvalidFormat(
            "decoy and hidden passwords must be different".into(),
        ));
    }
    if opts.chunk_size < MIN_CHUNK_SIZE || opts.chunk_size > MAX_CHUNK_SIZE {
        return Err(CryptoError::InvalidFormat(format!(
            "chunk_size {} outside [{MIN_CHUNK_SIZE}, {MAX_CHUNK_SIZE}]",
            opts.chunk_size
        )));
    }
    if !(MIN_CONTAINER_SIZE..=MAX_CONTAINER_SIZE).contains(&opts.container_size_bytes) {
        return Err(CryptoError::InvalidFormat(format!(
            "container_size {} outside [{MIN_CONTAINER_SIZE}, {MAX_CONTAINER_SIZE}]",
            opts.container_size_bytes
        )));
    }
    opts.kdf.validate()?;

    let outer_opts = EncryptOptions {
        reed_solomon: false,
        stealth: opts.stealth,
        kdf: opts.kdf,
        chunk_size: opts.chunk_size,
        recovery_key: opts.decoy_recovery_key.clone(),
        keyfile_hash: opts.decoy_keyfile_hash.clone(),
        compressed: opts.decoy_compressed,
        container_size_bytes: Some(opts.container_size_bytes),
    };

    let mut cw = CountingWriter::new(writer);
    let (decoy_summary, container_salt_opt) = encrypt_outer_stream_raw(
        decoy_reader,
        &mut cw,
        decoy_metadata,
        decoy_password,
        &outer_opts,
        decoy_progress,
        cancel,
    )?;
    let container_salt = container_salt_opt.expect("container_salt generated for container");
    let hidden_end_limit = opts
        .container_size_bytes
        .saturating_sub(HIDDEN_MINI_HEADER_WIRE_SIZE as u64);

    let outer_end = cw.written;
    if outer_end >= hidden_end_limit {
        return Err(CryptoError::InvalidFormat(format!(
            "decoy compartment ({outer_end} bytes) leaves no room in {} byte container",
            opts.container_size_bytes
        )));
    }

    let hidden_meta_json = Zeroizing::new(
        serde_json::to_vec(hidden_metadata)
            .map_err(|e| CryptoError::InvalidFormat(e.to_string()))?,
    );
    let hidden_meta_ct_len = (hidden_meta_json.len() + AES_TAG_SIZE) as u64;
    if hidden_meta_ct_len > MAX_HEADER_SIZE as u64 {
        return Err(CryptoError::InvalidFormat(
            "hidden metadata exceeds maximum header size".into(),
        ));
    }

    let available_after_outer = hidden_end_limit - outer_end;
    let pre_pad = choose_hidden_pre_pad(
        available_after_outer,
        hidden_metadata,
        hidden_meta_ct_len,
        opts.chunk_size,
    );
    write_random_padding(&mut cw, pre_pad, cancel)?;

    let hidden_data_offset = cw.written;
    let hidden_dek = random_dek();
    let hidden_ctx = hidden_payload_context(
        opts.chunk_size,
        opts.hidden_compressed,
        opts.container_size_bytes,
        &container_salt,
        hidden_data_offset,
    );

    let mut hidden_meta_nonce = [0u8; AES_NONCE_SIZE];
    OsRng.fill_bytes(&mut hidden_meta_nonce);
    let hidden_cipher =
        Aes256Gcm::new_from_slice(hidden_dek.as_bytes()).map_err(|_| CryptoError::CryptoFailure)?;
    let enc_hidden_meta = hidden_cipher
        .encrypt(
            Nonce::from_slice(&hidden_meta_nonce),
            Payload {
                msg: &hidden_meta_json,
                aad: &hidden_ctx,
            },
        )
        .map_err(|_| CryptoError::CryptoFailure)?;

    if cw.written.saturating_add(enc_hidden_meta.len() as u64) > hidden_end_limit {
        return Err(CryptoError::InvalidFormat(format!(
            "decoy + hidden compartments exceed {} byte container capacity",
            opts.container_size_bytes
        )));
    }
    cw.write_all(&enc_hidden_meta)?;

    let stream_prefix = derive_stream_nonce_prefix(&hidden_dek, &hidden_ctx)?;
    let mut plain_buf = Zeroizing::new(vec![0u8; opts.chunk_size as usize]);
    let mut pending: Option<u8> = None;
    let mut chunk_idx: u32 = 0;
    let mut hidden_total_bytes: u64 = 0;

    loop {
        if is_cancelled(cancel) {
            return Err(CryptoError::Cancelled);
        }

        let (len, is_final) = read_chunk_with_eof(hidden_reader, &mut plain_buf, &mut pending)?;
        let final_flag = u8::from(is_final);
        let plain_len_u32 = len as u32;
        let frame_wire_len = 5u64 + (len as u64) + (AES_TAG_SIZE as u64);
        if cw.written.saturating_add(frame_wire_len) > hidden_end_limit {
            plain_buf[..len].zeroize();
            return Err(CryptoError::InvalidFormat(format!(
                "decoy + hidden compartments exceed {} byte container capacity",
                opts.container_size_bytes
            )));
        }

        let nonce_bytes = chunk_nonce(&stream_prefix, chunk_idx, final_flag);
        let aad = chunk_aad(&hidden_ctx, chunk_idx, final_flag, plain_len_u32);
        let ct = hidden_cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &plain_buf[..len],
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::CryptoFailure)?;

        let mask = derive_hidden_frame_mask(&hidden_dek, &hidden_ctx, chunk_idx)?;
        let mut frame = [0u8; 5];
        frame[0..4].copy_from_slice(&plain_len_u32.to_be_bytes());
        frame[4] = final_flag;
        for i in 0..5 {
            frame[i] ^= mask[i];
        }

        cw.write_all(&frame)?;
        cw.write_all(&ct)?;

        plain_buf[..len].zeroize();
        hidden_total_bytes += len as u64;
        hidden_progress(hidden_total_bytes);

        chunk_idx = chunk_idx
            .checked_add(1)
            .ok_or_else(|| CryptoError::InvalidFormat("chunk counter overflow".into()))?;
        if is_final {
            break;
        }
    }

    let hidden_data_len = cw.written - hidden_data_offset;
    let trailing_pad = hidden_end_limit.saturating_sub(cw.written);
    write_random_padding(&mut cw, trailing_pad, cancel)?;

    let mut hidden_flags = 0u8;
    if opts.hidden_compressed {
        hidden_flags |= HIDDEN_FLAG_COMPRESSED;
    }
    if opts.hidden_keyfile_hash.is_some() {
        hidden_flags |= HIDDEN_FLAG_HAS_KEYFILE;
    }

    let mini_plain = encode_mini_header(
        hidden_flags,
        opts.chunk_size,
        enc_hidden_meta.len() as u32,
        hidden_data_offset,
        hidden_data_len,
        &hidden_dek,
        &hidden_meta_nonce,
    );
    let mini_kek = derive_hidden_kek(
        hidden_password,
        &container_salt,
        &opts.kdf,
        opts.hidden_keyfile_hash.as_ref(),
    )?;
    let mini_aad = mini_header_aad(
        opts.container_size_bytes,
        &container_salt,
        opts.hidden_keyfile_hash.is_some(),
    );
    let mut mini_nonce = [0u8; AES_NONCE_SIZE];
    OsRng.fill_bytes(&mut mini_nonce);
    let mini_cipher =
        Aes256Gcm::new_from_slice(mini_kek.as_bytes()).map_err(|_| CryptoError::CryptoFailure)?;
    let mini_ct = mini_cipher
        .encrypt(
            Nonce::from_slice(&mini_nonce),
            Payload {
                msg: mini_plain.as_ref(),
                aad: &mini_aad,
            },
        )
        .map_err(|_| CryptoError::CryptoFailure)?;

    cw.write_all(&mini_nonce)?;
    cw.write_all(&mini_ct)?;
    cw.flush()?;

    Ok(HiddenEncryptSummary {
        decoy: decoy_summary,
        hidden_bytes_encrypted: hidden_total_bytes,
        hidden_chunks_written: chunk_idx,
        container_size: opts.container_size_bytes,
    })
}

pub(crate) struct HiddenContainer<'a> {
    pub salt: [u8; SALT_SIZE],
    pub size: u64,
    pub kdf: KdfParams,
    /// The public vault ID is available only for ordinary v5 containers.
    pub public_id: Option<&'a str>,
    pub min_offset: u64,
}

pub(crate) fn try_unlock_hidden<R: Read + Seek>(
    reader: &mut R,
    container: HiddenContainer<'_>,
    password: &[u8],
    keyfile_hash: Option<&SecretKey>,
) -> Result<UnlockedVault, CryptoError> {
    let container_size = container.size;
    let hdr_len = container.min_offset;
    if password.is_empty() || container_size < hdr_len + HIDDEN_MINI_HEADER_WIRE_SIZE as u64 {
        return Err(CryptoError::AuthenticationFailed);
    }
    let container_salt = container.salt;

    let mini_offset = container_size - HIDDEN_MINI_HEADER_WIRE_SIZE as u64;
    reader.seek(SeekFrom::Start(mini_offset))?;
    let mut wire = [0u8; HIDDEN_MINI_HEADER_WIRE_SIZE];
    reader.read_exact(&mut wire).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            CryptoError::AuthenticationFailed
        } else {
            CryptoError::Io(e)
        }
    })?;

    let mini_kek = derive_hidden_kek(password, &container_salt, &container.kdf, keyfile_hash)?;
    let mini_aad = mini_header_aad(container_size, &container_salt, keyfile_hash.is_some());
    let mini_cipher =
        Aes256Gcm::new_from_slice(mini_kek.as_bytes()).map_err(|_| CryptoError::CryptoFailure)?;
    let mini_plain = Zeroizing::new(
        mini_cipher
            .decrypt(
                Nonce::from_slice(&wire[..AES_NONCE_SIZE]),
                Payload {
                    msg: &wire[AES_NONCE_SIZE..],
                    aad: &mini_aad,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?,
    );

    let decoded = decode_mini_header(&mini_plain)?;
    if decoded.has_keyfile != keyfile_hash.is_some() {
        return Err(CryptoError::AuthenticationFailed);
    }

    let hidden_end = decoded
        .hidden_data_offset
        .checked_add(decoded.hidden_data_len)
        .ok_or(CryptoError::AuthenticationFailed)?;
    let min_data_len = (decoded.encrypted_meta_len as u64) + 5 + (AES_TAG_SIZE as u64);
    if decoded.hidden_data_offset < hdr_len
        || decoded.hidden_data_len < min_data_len
        || hidden_end > mini_offset
    {
        return Err(CryptoError::AuthenticationFailed);
    }

    let hidden_ctx = hidden_payload_context(
        decoded.chunk_size,
        decoded.compressed,
        container_size,
        &container_salt,
        decoded.hidden_data_offset,
    );

    reader.seek(SeekFrom::Start(decoded.hidden_data_offset))?;
    let mut enc_meta = vec![0u8; decoded.encrypted_meta_len as usize];
    reader.read_exact(&mut enc_meta).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            CryptoError::AuthenticationFailed
        } else {
            CryptoError::Io(e)
        }
    })?;

    let cipher = Aes256Gcm::new_from_slice(decoded.hidden_dek.as_bytes())
        .map_err(|_| CryptoError::CryptoFailure)?;
    let meta_plain = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&decoded.hidden_meta_nonce),
                Payload {
                    msg: &enc_meta,
                    aad: &hidden_ctx,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?,
    );
    let metadata: VaultMetadata = serde_json::from_slice(&meta_plain)
        .map_err(|e| CryptoError::InvalidFormat(format!("invalid hidden metadata JSON: {e}")))?;

    Ok(UnlockedVault::Hidden {
        info: VaultInfo {
            has_reed_solomon: false,
            rs_repaired_bytes: 0,
            is_stealth: container.public_id.is_none(),
            version: VAULT_VERSION,
            vault_id: container.public_id.map_or_else(
                || crate::stealth::id_string(&hidden_ctx[..16]),
                str::to_owned,
            ),
            cipher: crate::constants::CHUNKED_CIPHER_NAME.into(),
            chunk_size: decoded.chunk_size,
            has_recovery: false,
            has_keyfile: decoded.has_keyfile,
            compressed: decoded.compressed,
            argon_memory_kib: container.kdf.memory_kib,
            argon_iterations: container.kdf.iterations,
            argon_parallelism: container.kdf.parallelism,
            container_size: Some(container_size),
            is_hidden_compartment: true,
            metadata,
        },

        hidden_dek: decoded.hidden_dek,
        hidden_ctx,
        chunk_size: decoded.chunk_size,
        hidden_data_offset: decoded.hidden_data_offset,
        hidden_data_len: decoded.hidden_data_len,
        encrypted_meta_len: decoded.encrypted_meta_len,
    })
}

/// Transparently unlock either the outer compartment or (on a padded container)
/// a hidden compartment using seekable I/O, revealing zero existence clues on failure.
pub fn unlock_seekable<R: Read + Seek>(
    reader: &mut R,
    auth: Auth<'_>,
) -> Result<UnlockedVault, CryptoError> {
    unlock_seekable_with_kdf(reader, auth, &crate::STEALTH_KDF_PARAMS)
}

pub fn unlock_seekable_with_kdf<R: Read + Seek>(
    reader: &mut R,
    auth: Auth<'_>,
    stealth_kdf: &KdfParams,
) -> Result<UnlockedVault, CryptoError> {
    if crate::rs::probe(reader)? {
        let mut rs = crate::RsSeekableReader::new(reader)?;
        let inner = unlock_inner(&mut rs, auth, stealth_kdf, true)?;
        Ok(UnlockedVault::ReedSolomon {
            inner: Box::new(inner),
            repaired: rs.repaired_bytes(),
        })
    } else {
        unlock_inner(reader, auth, stealth_kdf, false)
    }
}

fn unlock_inner<R: Read + Seek>(
    reader: &mut R,
    auth: Auth<'_>,
    stealth_kdf: &KdfParams,
    rs: bool,
) -> Result<UnlockedVault, CryptoError> {
    reader.seek(SeekFrom::Start(0))?;
    let mut magic = [0; 4];
    reader
        .read_exact(&mut magic)
        .map_err(crate::stealth::map_eof)?;
    reader.seek(SeekFrom::Start(0))?;
    if magic != crate::VAULT_MAGIC {
        if rs {
            return Err(CryptoError::InvalidFormat(
                "expected RPMV inside Reed-Solomon envelope".into(),
            ));
        }
        return crate::stealth::unlock(reader, auth, stealth_kdf);
    }
    let (header, enc_meta, hdr_len) = read_header_and_meta(reader)?;
    let stream_len = reader.seek(SeekFrom::End(0))?;
    if let Some(target_size) = header.container_size {
        if stream_len != target_size {
            return Err(CryptoError::AuthenticationFailed);
        }
    }
    reader.seek(SeekFrom::Start(hdr_len))?;

    let outer_err = match unlock_dek(&header, auth) {
        Ok(dek) => {
            let metadata = decrypt_metadata(&dek, &header, &enc_meta)?;
            return Ok(UnlockedVault::Outer {
                header,
                dek,
                metadata,
                hdr_len,
            });
        }
        Err(err) => err,
    };

    if let (
        Some(target_size),
        Auth::Password {
            password,
            keyfile_hash,
        },
    ) = (header.container_size, auth)
    {
        if let Ok(hidden) = try_unlock_hidden(
            reader,
            HiddenContainer {
                salt: header
                    .container_salt_bytes()?
                    .ok_or(CryptoError::AuthenticationFailed)?,
                size: target_size,
                kdf: header.kdf_params(),
                public_id: Some(&header.vault_id),
                min_offset: hdr_len,
            },
            password,
            keyfile_hash,
        ) {
            return Ok(hidden);
        }
    }

    Err(outer_err)
}

/// Inspect a vault header/metadata transparently across standard, padded, and hidden vaults.
pub fn inspect_header_seekable<R: Read + Seek>(
    reader: &mut R,
    auth: Auth<'_>,
) -> Result<VaultInfo, CryptoError> {
    inspect_header_seekable_with_kdf(reader, auth, &crate::STEALTH_KDF_PARAMS)
}

pub fn inspect_header_seekable_with_kdf<R: Read + Seek>(
    reader: &mut R,
    auth: Auth<'_>,
    stealth_kdf: &KdfParams,
) -> Result<VaultInfo, CryptoError> {
    Ok(unlock_seekable_with_kdf(reader, auth, stealth_kdf)?.vault_info())
}

/// Decrypt the chunked payload of an already-unlocked outer or hidden compartment.
pub fn decrypt_unlocked_stream<R: Read + Seek, W: Write>(
    reader: &mut R,
    writer: &mut W,
    unlocked: &UnlockedVault,
    progress_cb: impl FnMut(u64),
    cancel: Option<&AtomicBool>,
) -> Result<u64, CryptoError> {
    if let UnlockedVault::ReedSolomon { inner, .. } = unlocked {
        let mut rs = crate::RsSeekableReader::new(reader)?;
        decrypt_inner(&mut rs, writer, inner, progress_cb, cancel)
    } else {
        decrypt_inner(reader, writer, unlocked, progress_cb, cancel)
    }
}
fn decrypt_inner<R: Read + Seek, W: Write>(
    reader: &mut R,
    writer: &mut W,
    unlocked: &UnlockedVault,
    mut progress_cb: impl FnMut(u64),
    cancel: Option<&AtomicBool>,
) -> Result<u64, CryptoError> {
    match unlocked {
        UnlockedVault::ReedSolomon { .. } => Err(CryptoError::InvalidFormat(
            "nested Reed-Solomon envelope".into(),
        )),
        UnlockedVault::Outer {
            header,
            dek,
            hdr_len,
            ..
        } => {
            reader.seek(SeekFrom::Start(*hdr_len))?;
            decrypt_chunks_with_key_at(reader, writer, header, *hdr_len, dek, progress_cb, cancel)
        }
        UnlockedVault::Stealth {
            info,
            dek,
            ctx,
            payload_offset,
        } => {
            reader.seek(SeekFrom::Start(*payload_offset))?;
            crate::vault::decrypt_outer_chunks(
                reader,
                writer,
                info.chunk_size,
                info.container_size,
                *payload_offset,
                dek,
                *ctx,
                true,
                progress_cb,
                cancel,
            )
        }
        UnlockedVault::Hidden {
            hidden_dek,
            hidden_ctx,
            chunk_size,
            hidden_data_offset,
            hidden_data_len,
            encrypted_meta_len,
            ..
        } => {
            let meta_bytes = *encrypted_meta_len as u64;
            reader.seek(SeekFrom::Start(*hidden_data_offset + meta_bytes))?;
            let prefix = derive_stream_nonce_prefix(hidden_dek, hidden_ctx)?;
            let cipher = Aes256Gcm::new_from_slice(hidden_dek.as_bytes())
                .map_err(|_| CryptoError::CryptoFailure)?;

            let mut consumed = meta_bytes;
            let mut chunk_idx: u32 = 0;
            let mut total_bytes: u64 = 0;
            let mut ct_buf: Vec<u8> = Vec::new();

            loop {
                if is_cancelled(cancel) {
                    return Err(CryptoError::Cancelled);
                }
                if consumed.saturating_add(5) > *hidden_data_len {
                    return Err(CryptoError::AuthenticationFailed);
                }
                let mut frame = [0u8; 5];
                reader.read_exact(&mut frame).map_err(|e| {
                    if e.kind() == io::ErrorKind::UnexpectedEof {
                        CryptoError::AuthenticationFailed
                    } else {
                        CryptoError::Io(e)
                    }
                })?;

                let mask = derive_hidden_frame_mask(hidden_dek, hidden_ctx, chunk_idx)?;
                for i in 0..5 {
                    frame[i] ^= mask[i];
                }
                let plain_len = u32::from_be_bytes(frame[0..4].try_into().unwrap());
                let final_flag = frame[4];
                if plain_len > *chunk_size || final_flag > 1 || (plain_len == 0 && final_flag == 0)
                {
                    return Err(CryptoError::AuthenticationFailed);
                }

                let ct_len = (plain_len as usize) + AES_TAG_SIZE;
                let frame_total = 5u64
                    .checked_add(ct_len as u64)
                    .ok_or(CryptoError::AuthenticationFailed)?;
                if consumed.saturating_add(frame_total) > *hidden_data_len {
                    return Err(CryptoError::AuthenticationFailed);
                }
                consumed += frame_total;

                ct_buf.resize(ct_len, 0);
                reader.read_exact(&mut ct_buf).map_err(|e| {
                    if e.kind() == io::ErrorKind::UnexpectedEof {
                        CryptoError::AuthenticationFailed
                    } else {
                        CryptoError::Io(e)
                    }
                })?;

                let nonce_bytes = chunk_nonce(&prefix, chunk_idx, final_flag);
                let aad = chunk_aad(hidden_ctx, chunk_idx, final_flag, plain_len);
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
                    if consumed != *hidden_data_len {
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
    }
}

/// Transparently unlock and stream-decrypt a standard, padded, or hidden vault.
pub fn decrypt_stream_seekable<R: Read + Seek, W: Write>(
    reader: &mut R,
    writer: &mut W,
    auth: Auth<'_>,
    progress_cb: impl FnMut(u64),
    cancel: Option<&AtomicBool>,
) -> Result<VaultMetadata, CryptoError> {
    decrypt_stream_seekable_with_kdf(
        reader,
        writer,
        auth,
        &crate::STEALTH_KDF_PARAMS,
        progress_cb,
        cancel,
    )
}

pub fn decrypt_stream_seekable_with_kdf<R: Read + Seek, W: Write>(
    reader: &mut R,
    writer: &mut W,
    auth: Auth<'_>,
    stealth_kdf: &KdfParams,
    progress_cb: impl FnMut(u64),
    cancel: Option<&AtomicBool>,
) -> Result<VaultMetadata, CryptoError> {
    let unlocked = unlock_seekable_with_kdf(reader, auth, stealth_kdf)?;
    decrypt_unlocked_stream(reader, writer, &unlocked, progress_cb, cancel)?;
    Ok(unlocked.metadata().clone())
}
