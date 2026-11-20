//! High-level zero-temp-plaintext workflows uniting `rpm-core` v5 and `rpm-storage`.

use std::fs::{self, File};
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

use rpm_core::header::read_header_and_meta;
use rpm_core::{
    decrypt_chunks_with_key, encrypt_stream, rekey_stream, Auth, EncryptOptions, EncryptSummary,
    KdfParams, RekeyOptions, SecretKey, VaultMetadata,
};

use crate::atomic::atomic_write;
use crate::error::StorageError;
use crate::packager::{collect_manifest, pack_sources, unpack_vault_stream};
use crate::pipe::bounded_pipe;

#[derive(Clone, Debug)]
pub struct DecryptSummary {
    pub metadata: VaultMetadata,
    pub files_extracted: u64,
}

/// Choose a collision-free output path (`name_1.ext`, `name_2.ext`, ...).
pub fn unique_path(base: &Path) -> PathBuf {
    let mut candidate = base.to_path_buf();
    let mut idx = 1usize;
    let stem = base
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "output".into());
    let ext = base
        .extension()
        .map(|s| format!(".{}", s.to_string_lossy()))
        .unwrap_or_default();

    while candidate.exists() {
        candidate = base.with_file_name(format!("{stem}_{idx}{ext}"));
        idx += 1;
    }
    candidate
}

/// Stream-pack `sources` directly into a Vault v5 archive via an in-memory bounded
/// pipe — zero plaintext temporary archive is ever written to disk.
pub fn encrypt_sources_v5(
    sources: &[PathBuf],
    out_vault: &Path,
    password: &[u8],
    opts: &EncryptOptions,
    progress: Arc<dyn Fn(u64, u64) + Send + Sync>,
    cancel: Arc<AtomicBool>,
    mut on_skip: impl FnMut(&str) + Send + 'static,
) -> Result<(EncryptSummary, VaultMetadata), StorageError> {
    let metadata = collect_manifest(sources, opts.compressed, Some(&cancel))?;
    let total_expected = metadata.original_size;
    let (writer, mut reader) = bounded_pipe(8);

    let sources_owned = sources.to_vec();
    let compress = opts.compressed;
    let cancel_pack = Arc::clone(&cancel);
    let packer_handle = thread::spawn(move || -> Result<(), StorageError> {
        pack_sources(
            &sources_owned,
            writer,
            compress,
            Some(&cancel_pack),
            |msg| {
                on_skip(msg);
            },
        )
    });

    let mut summary_out: Option<EncryptSummary> = None;
    let enc_res = atomic_write(out_vault, |vault_writer| {
        let s = encrypt_stream(
            &mut reader,
            vault_writer,
            &metadata,
            password,
            opts,
            |done| progress(done, total_expected),
            Some(&cancel),
        )?;
        summary_out = Some(s);
        Ok(())
    });

    // Drop reader before joining in case encryption failed early, unblocking packer.
    drop(reader);
    let pack_res = packer_handle
        .join()
        .map_err(|_| StorageError::Io(std::io::Error::other("packer thread panicked")))?;

    enc_res?;
    pack_res?;
    Ok((summary_out.expect("summary set on Ok"), metadata))
}

/// Stream-decrypt a Vault v5 file directly through AEAD chunk verification into
/// `dest_dir`. Every chunk is authenticated before any bytes enter the tar unpacker,
/// and any error removes partial outputs cleanly.
pub fn decrypt_vault_v5(
    vault_path: &Path,
    dest_dir: &Path,
    auth: Auth<'_>,
    progress: Arc<dyn Fn(u64, u64) + Send + Sync>,
    cancel: Arc<AtomicBool>,
) -> Result<DecryptSummary, StorageError> {
    let mut reader = BufReader::with_capacity(256 * 1024, File::open(vault_path)?);
    let (header, enc_meta, _hdr_len) = read_header_and_meta(&mut reader)?;
    let dek = rpm_core::header::unlock_dek(&header, auth)?;
    let metadata = rpm_core::header::decrypt_metadata(&dek, &header, &enc_meta)?;

    let total_expected = metadata.original_size;
    let compressed = (header.flags & rpm_core::constants::FLAG_COMPRESSED) != 0;
    let (mut pipe_tx, pipe_rx) = bounded_pipe(8);

    let dest_owned = dest_dir.to_path_buf();
    let cancel_unpack = Arc::clone(&cancel);
    let unpack_handle = thread::spawn(move || -> Result<u64, StorageError> {
        unpack_vault_stream(pipe_rx, &dest_owned, compressed, Some(&cancel_unpack))
    });

    let dec_res = decrypt_chunks_with_key(
        &mut reader,
        &mut pipe_tx,
        &header,
        &dek,
        |done| progress(done, total_expected),
        Some(&cancel),
    );
    drop(pipe_tx);

    let unpack_res = unpack_handle
        .join()
        .map_err(|_| StorageError::Io(std::io::Error::other("unpacker thread panicked")))?;

    let final_res = match (dec_res, unpack_res) {
        (Err(e), _) => Err(StorageError::Crypto(e)),
        (Ok(_), Err(e)) => Err(e),
        (Ok(_), Ok(count)) => Ok(DecryptSummary {
            metadata,
            files_extracted: count,
        }),
    };

    if final_res.is_err() || cancel.load(Ordering::Relaxed) {
        let _ = fs::remove_dir_all(dest_dir);
    }
    final_res
}

/// Atomically re-key `vault_path` in place using a sibling temp file (payload is
/// never decrypted).
pub fn rekey_vault_v5(
    vault_path: &Path,
    old_password: &[u8],
    new_password: &[u8],
    old_keyfile: Option<&SecretKey>,
    new_keyfile: Option<&SecretKey>,
    new_kdf: Option<KdfParams>,
    cancel: Option<&AtomicBool>,
) -> Result<(), StorageError> {
    // Stage into a sibling temp file, close the source handle first, then rename.
    // (`atomic_write` runs the closure and drops handles cleanly only if we open
    // `vault_path` inside the closure AND drop `src_reader` before `atomic_write` renames!)
    atomic_write(vault_path, |out_writer| {
        let mut src_reader = BufReader::with_capacity(256 * 1024, File::open(vault_path)?);
        rekey_stream(
            &mut src_reader,
            out_writer,
            &RekeyOptions {
                old_password,
                new_password,
                old_keyfile_hash: old_keyfile,
                new_keyfile_hash: new_keyfile,
                new_kdf,
            },
            cancel,
        )?;
        drop(src_reader); // Crucial on Windows before `atomic_write` renames over `vault_path`.
        Ok(())
    })
}
