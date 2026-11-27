//! Fixed-layout encrypted outer header. No unauthenticated length or KDF
//! setting from the file controls an allocation or a password derivation.
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::atomic::AtomicBool;

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::constants::*;
use crate::header::encrypt_metadata;
use crate::hidden::{try_unlock_hidden, HiddenContainer, UnlockedVault};
use crate::kdf::{derive_stealth_frame_mask, derive_stealth_kek, derive_stealth_recovery_kek};
use crate::{Auth, CryptoError, EncryptOptions, KdfParams, SecretKey, VaultInfo, VaultMetadata};

const SLOT_SIZE: usize = AES_NONCE_SIZE + 80 + AES_TAG_SIZE;
const META_OFFSET: u64 = (SALT_SIZE + 2 * SLOT_SIZE) as u64;
const PADDED: u8 = 1 << 3;
const PASSWORD_DOMAIN: &[u8] = b"RPMV5-STEALTH-PW-SLOT";
const RECOVERY_DOMAIN: &[u8] = b"RPMV5-STEALTH-REC-SLOT";

pub(crate) fn map_eof(err: io::Error) -> CryptoError {
    if err.kind() == io::ErrorKind::UnexpectedEof {
        CryptoError::AuthenticationFailed
    } else {
        err.into()
    }
}

pub(crate) fn id_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn context(salt: &[u8; 32], id: &[u8], chunk: u32, flags: u8, size: u64) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"RPMV5-STEALTH-CTX")
        .chain_update(salt)
        .chain_update(id)
        .chain_update(chunk.to_be_bytes())
        .chain_update([flags])
        .chain_update(size.to_be_bytes())
        .finalize()
        .into()
}

pub(crate) fn mask_frame(
    frame: &mut [u8; 5],
    dek: &SecretKey,
    ctx: &[u8; 32],
    idx: u32,
) -> Result<(), CryptoError> {
    for (byte, mask) in frame
        .iter_mut()
        .zip(derive_stealth_frame_mask(dek, ctx, idx)?)
    {
        *byte ^= mask;
    }
    Ok(())
}

fn write_slot(
    writer: &mut impl Write,
    key: &SecretKey,
    domain: &[u8],
    salt: &[u8; 32],
    plain: &[u8; 80],
) -> Result<(), CryptoError> {
    let mut nonce = [0; AES_NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);
    let cipher = Aes256Gcm::new(key.as_bytes().into());
    let ct = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: plain,
                aad: &[domain, salt].concat(),
            },
        )
        .map_err(|_| CryptoError::CryptoFailure)?;
    writer.write_all(&nonce)?;
    writer.write_all(&ct)?;
    Ok(())
}

pub(crate) fn write_header(
    writer: &mut impl Write,
    metadata: &VaultMetadata,
    password: &[u8],
    opts: &EncryptOptions,
    dek: &SecretKey,
) -> Result<crate::vault::OuterHeaderContext, CryptoError> {
    let mut salt = [0; SALT_SIZE];
    loop {
        OsRng.fill_bytes(&mut salt);
        if !salt.starts_with(&VAULT_MAGIC) && !salt.starts_with(b"RPMR") {
            break;
        }
    }
    let mut id = [0; 16];
    OsRng.fill_bytes(&mut id);
    let mut flags = 0;
    if opts.compressed {
        flags |= FLAG_COMPRESSED;
    }
    if opts.keyfile_hash.is_some() {
        flags |= FLAG_HAS_KEYFILE;
    }
    if opts.recovery_key.is_some() {
        flags |= FLAG_HAS_RECOVERY;
    }
    if opts.container_size_bytes.is_some() {
        flags |= PADDED;
    }
    let size = opts.container_size_bytes.unwrap_or(0);
    let ctx = context(&salt, &id, opts.chunk_size, flags, size);
    let (nonce, meta) = encrypt_metadata(dek, metadata, &ctx)?;
    let meta_len = nonce.len() + meta.len();
    if meta_len > MAX_HEADER_SIZE {
        return Err(CryptoError::InvalidFormat(
            "Stealth metadata exceeds header limit".into(),
        ));
    }

    let mut slot = Zeroizing::new([0; 80]);
    slot[..4].copy_from_slice(b"RPMS");
    slot[4] = VAULT_VERSION;
    slot[5] = flags;
    slot[8..12].copy_from_slice(&opts.chunk_size.to_be_bytes());
    slot[12..20].copy_from_slice(&size.to_be_bytes());
    slot[20..28].copy_from_slice(&META_OFFSET.to_be_bytes());
    slot[28..32].copy_from_slice(&(meta_len as u32).to_be_bytes());
    slot[32..64].copy_from_slice(dek.as_bytes());
    slot[64..].copy_from_slice(&id);

    let kek = derive_stealth_kek(password, &salt, &opts.kdf, opts.keyfile_hash.as_ref())?;
    writer.write_all(&salt)?;
    write_slot(writer, &kek, PASSWORD_DOMAIN, &salt, &slot)?;
    if let Some(entropy) = &opts.recovery_key {
        let key = derive_stealth_recovery_kek(entropy, &salt)?;
        write_slot(writer, &key, RECOVERY_DOMAIN, &salt, &slot)?;
    } else {
        let mut noise = [0; SLOT_SIZE];
        OsRng.fill_bytes(&mut noise);
        writer.write_all(&noise)?;
    }
    writer.write_all(&nonce)?;
    writer.write_all(&meta)?;
    Ok((id_string(&id), ctx, opts.container_size_bytes.map(|_| salt)))
}

pub(crate) fn unlock<R: Read + Seek>(
    reader: &mut R,
    auth: Auth<'_>,
    kdf: &KdfParams,
    cancel: Option<&AtomicBool>,
) -> Result<UnlockedVault, CryptoError> {
    if crate::vault::is_cancelled(cancel) {
        return Err(CryptoError::Cancelled);
    }
    let size = reader.seek(SeekFrom::End(0))?;
    if size < META_OFFSET {
        return Err(CryptoError::AuthenticationFailed);
    }
    reader.seek(SeekFrom::Start(0))?;
    let mut salt = [0; SALT_SIZE];
    reader.read_exact(&mut salt).map_err(|e| {
        if crate::vault::is_cancelled(cancel) {
            CryptoError::Cancelled
        } else {
            map_eof(e)
        }
    })?;

    let (key, domain) = match auth {
        Auth::Password {
            password,
            keyfile_hash,
        } => {
            if password.is_empty() {
                return Err(CryptoError::AuthenticationFailed);
            }
            (
                derive_stealth_kek(password, &salt, kdf, keyfile_hash)?,
                PASSWORD_DOMAIN,
            )
        }
        Auth::RecoveryKey(entropy) => {
            reader.seek(SeekFrom::Current(SLOT_SIZE as i64))?;
            (
                derive_stealth_recovery_kek(entropy, &salt)?,
                RECOVERY_DOMAIN,
            )
        }
    };
    if crate::vault::is_cancelled(cancel) {
        return Err(CryptoError::Cancelled);
    }
    let mut wire = [0; SLOT_SIZE];
    reader.read_exact(&mut wire).map_err(|e| {
        if crate::vault::is_cancelled(cancel) {
            CryptoError::Cancelled
        } else {
            map_eof(e)
        }
    })?;
    let cipher = Aes256Gcm::new(key.as_bytes().into());
    let plain = match cipher.decrypt(
        Nonce::from_slice(&wire[..AES_NONCE_SIZE]),
        Payload {
            msg: &wire[AES_NONCE_SIZE..],
            aad: &[domain, &salt].concat(),
        },
    ) {
        Ok(slot) => Zeroizing::new(slot),
        Err(_) => {
            if crate::vault::is_cancelled(cancel) {
                return Err(CryptoError::Cancelled);
            }
            if let Auth::Password {
                password,
                keyfile_hash,
            } = auth
            {
                if (MIN_CONTAINER_SIZE..=MAX_CONTAINER_SIZE).contains(&size) {
                    return try_unlock_hidden(
                        reader,
                        HiddenContainer {
                            salt,
                            size,
                            kdf: *kdf,
                            public_id: None,
                            min_offset: META_OFFSET,
                        },
                        password,
                        keyfile_hash,
                        cancel,
                    );
                }
            }
            return Err(CryptoError::AuthenticationFailed);
        }
    };
    let flags = plain[5];
    let chunk_size = u32::from_be_bytes(plain[8..12].try_into().unwrap());
    let container = u64::from_be_bytes(plain[12..20].try_into().unwrap());
    let meta_len = u32::from_be_bytes(plain[28..32].try_into().unwrap()) as usize;
    let padded = flags & PADDED != 0;
    let slot_matches_auth = match auth {
        Auth::Password { keyfile_hash, .. } => {
            keyfile_hash.is_some() == (flags & FLAG_HAS_KEYFILE != 0)
        }
        Auth::RecoveryKey(_) => flags & FLAG_HAS_RECOVERY != 0,
    };
    if !slot_matches_auth
        || &plain[..4] != b"RPMS"
        || plain[4] != VAULT_VERSION
        || plain[6..8] != [0; 2]
        || flags & !(ALL_KNOWN_FLAGS | PADDED) != 0
        || !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size)
        || plain[20..28] != META_OFFSET.to_be_bytes()
        || !(AES_TAG_SIZE + AES_NONCE_SIZE..=MAX_HEADER_SIZE).contains(&meta_len)
        || META_OFFSET + meta_len as u64 + 5 + AES_TAG_SIZE as u64 > size
        || (padded
            && (container != size
                || !(MIN_CONTAINER_SIZE..=MAX_CONTAINER_SIZE).contains(&container)))
        || (!padded && container != 0)
    {
        return Err(CryptoError::AuthenticationFailed);
    }
    let dek = SecretKey::from_slice(&plain[32..64]).ok_or(CryptoError::AuthenticationFailed)?;
    let id = &plain[64..80];
    let ctx = context(&salt, id, chunk_size, flags, container);
    reader.seek(SeekFrom::Start(META_OFFSET))?;
    let mut meta = vec![0; meta_len];
    reader.read_exact(&mut meta).map_err(|e| {
        if crate::vault::is_cancelled(cancel) {
            CryptoError::Cancelled
        } else {
            map_eof(e)
        }
    })?;
    if crate::vault::is_cancelled(cancel) {
        return Err(CryptoError::Cancelled);
    }
    let decrypted = Zeroizing::new(
        Aes256Gcm::new(dek.as_bytes().into())
            .decrypt(
                Nonce::from_slice(&meta[..AES_NONCE_SIZE]),
                Payload {
                    msg: &meta[AES_NONCE_SIZE..],
                    aad: &ctx,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?,
    );
    let metadata =
        serde_json::from_slice(&decrypted).map_err(|_| CryptoError::AuthenticationFailed)?;
    let info = VaultInfo {
        version: VAULT_VERSION,
        vault_id: id_string(id),
        cipher: CHUNKED_CIPHER_NAME.into(),
        chunk_size,
        has_keyfile: flags & FLAG_HAS_KEYFILE != 0,
        has_recovery: flags & FLAG_HAS_RECOVERY != 0,
        compressed: flags & FLAG_COMPRESSED != 0,
        argon_memory_kib: kdf.memory_kib,
        argon_iterations: kdf.iterations,
        argon_parallelism: kdf.parallelism,
        is_hidden_compartment: false,
        has_reed_solomon: false,
        rs_repaired_bytes: 0,
        is_stealth: true,
        container_size: padded.then_some(container),
        metadata,
    };
    Ok(UnlockedVault::Stealth {
        info,
        dek,
        ctx,
        payload_offset: META_OFFSET + meta_len as u64,
    })
}
