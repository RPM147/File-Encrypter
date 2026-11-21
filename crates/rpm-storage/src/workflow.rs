//! High-level zero-temp-plaintext workflows uniting `rpm-core` v5 and `rpm-storage`.

use std::fs::{self, File};
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use rand::rngs::OsRng;
use rand::RngCore;
use rpm_core::{
    decrypt_unlocked_stream, encrypt_hidden_stream, encrypt_stream, rekey_stream,
    unlock_seekable_with_kdf, Auth, EncryptOptions, EncryptSummary, HiddenEncryptOptions,
    HiddenEncryptSummary, KdfParams, RekeyOptions, SecretKey, VaultMetadata,
};

use crate::atomic::{atomic_write, write_vault};
use crate::error::StorageError;
use crate::packager::{
    collect_manifest, normalize_archive_selector, pack_sources_excluding, unpack_vault_stream,
    unpack_vault_stream_selected, UnpackLimits,
};
use crate::pipe::bounded_pipe;

#[derive(Clone, Debug)]
pub struct DecryptSummary {
    pub metadata: VaultMetadata,
    pub files_extracted: u64,
    pub output_path: PathBuf,
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

fn random_hex_6() -> String {
    let mut rand_bytes = [0u8; 6];
    OsRng.fill_bytes(&mut rand_bytes);
    let mut hex = String::with_capacity(12);
    for b in rand_bytes {
        hex.push_str(&format!("{b:02x}"));
    }
    hex
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
    let (writer, reader) = bounded_pipe(8);

    let sources_owned = sources.to_vec();
    let compress = opts.compressed;
    let cancel_pack = Arc::clone(&cancel);
    let output = opts.stealth.then(|| out_vault.to_path_buf());
    let packer_handle = thread::spawn(move || -> Result<(), StorageError> {
        pack_sources_excluding(
            &sources_owned,
            writer,
            compress,
            Some(&cancel_pack),
            output.as_deref(),
            |msg| {
                on_skip(msg);
            },
        )
    });

    let mut reader_opt = Some(reader);
    let mut packer_opt = Some(packer_handle);
    let mut summary_out: Option<EncryptSummary> = None;

    let enc_res = write_vault(out_vault, opts.stealth, |vault_writer| {
        let mut reader = reader_opt.take().expect("reader taken once");
        let enc_attempt = encrypt_stream(
            &mut reader,
            vault_writer,
            &metadata,
            password,
            opts,
            |done| progress(done, total_expected),
            Some(&cancel),
        );
        // Drop reader BEFORE joining so early encryption/cancel errors unblock packer cleanly.
        drop(reader);
        let pack_attempt = packer_opt
            .take()
            .expect("packer taken once")
            .join()
            .map_err(|_| StorageError::Io(std::io::Error::other("packer thread panicked")))?;
        let summary = enc_attempt?;
        pack_attempt?;
        summary_out = Some(summary);
        Ok(())
    });

    // Clean up if `atomic_write` failed before entering its closure.
    drop(reader_opt.take());
    if let Some(handle) = packer_opt.take() {
        let _ = handle.join();
    }

    enc_res?;
    Ok((summary_out.expect("summary set on Ok"), metadata))
}

/// Stream-pack decoy and hidden sources directly into a single fixed-size padded
/// Vault v5 container with plausible deniability (zero temporary plaintext files).
#[allow(clippy::too_many_arguments)]
pub fn encrypt_hidden_sources_v5(
    decoy_sources: &[PathBuf],
    hidden_sources: &[PathBuf],
    out_vault: &Path,
    decoy_password: &[u8],
    hidden_password: &[u8],
    opts: &HiddenEncryptOptions,
    progress: Arc<dyn Fn(u64, u64) + Send + Sync>,
    cancel: Arc<AtomicBool>,
    on_skip: impl FnMut(&str) + Send + 'static,
) -> Result<(HiddenEncryptSummary, VaultMetadata, VaultMetadata), StorageError> {
    let decoy_meta = collect_manifest(decoy_sources, opts.decoy_compressed, Some(&cancel))?;
    let hidden_meta = collect_manifest(hidden_sources, opts.hidden_compressed, Some(&cancel))?;
    let total_expected = decoy_meta
        .original_size
        .saturating_add(hidden_meta.original_size);

    let on_skip = Arc::new(Mutex::new(on_skip));
    let (decoy_writer, decoy_reader) = bounded_pipe(8);
    let (hidden_writer, hidden_reader) = bounded_pipe(8);

    let decoy_owned = decoy_sources.to_vec();
    let decoy_compress = opts.decoy_compressed;
    let cancel_decoy = Arc::clone(&cancel);
    let skip_decoy = Arc::clone(&on_skip);
    let output = opts.stealth.then(|| out_vault.to_path_buf());
    let decoy_handle = thread::spawn(move || -> Result<(), StorageError> {
        pack_sources_excluding(
            &decoy_owned,
            decoy_writer,
            decoy_compress,
            Some(&cancel_decoy),
            output.as_deref(),
            |msg| {
                if let Ok(mut cb) = skip_decoy.lock() {
                    cb(msg);
                }
            },
        )
    });

    let hidden_owned = hidden_sources.to_vec();
    let hidden_compress = opts.hidden_compressed;
    let cancel_hidden = Arc::clone(&cancel);
    let skip_hidden = Arc::clone(&on_skip);
    let output = opts.stealth.then(|| out_vault.to_path_buf());
    let hidden_handle = thread::spawn(move || -> Result<(), StorageError> {
        pack_sources_excluding(
            &hidden_owned,
            hidden_writer,
            hidden_compress,
            Some(&cancel_hidden),
            output.as_deref(),
            |msg| {
                if let Ok(mut cb) = skip_hidden.lock() {
                    cb(msg);
                }
            },
        )
    });

    let mut decoy_reader_opt = Some(decoy_reader);
    let mut hidden_reader_opt = Some(hidden_reader);
    let mut decoy_handle_opt = Some(decoy_handle);
    let mut hidden_handle_opt = Some(hidden_handle);
    let mut summary_out: Option<HiddenEncryptSummary> = None;

    let decoy_done = Arc::new(AtomicU64::new(0));
    let hidden_done = Arc::new(AtomicU64::new(0));

    let enc_res = write_vault(out_vault, opts.stealth, |vault_writer| {
        let mut d_reader = decoy_reader_opt.take().expect("decoy reader taken once");
        let mut h_reader = hidden_reader_opt.take().expect("hidden reader taken once");

        let d1 = Arc::clone(&decoy_done);
        let h1 = Arc::clone(&hidden_done);
        let p1 = Arc::clone(&progress);
        let decoy_cb = move |done: u64| {
            d1.store(done, Ordering::Relaxed);
            p1(
                done.saturating_add(h1.load(Ordering::Relaxed)),
                total_expected,
            );
        };

        let d2 = Arc::clone(&decoy_done);
        let h2 = Arc::clone(&hidden_done);
        let p2 = Arc::clone(&progress);
        let hidden_cb = move |done: u64| {
            h2.store(done, Ordering::Relaxed);
            p2(
                d2.load(Ordering::Relaxed).saturating_add(done),
                total_expected,
            );
        };

        let enc_attempt = encrypt_hidden_stream(
            &mut d_reader,
            &mut h_reader,
            vault_writer,
            &decoy_meta,
            &hidden_meta,
            decoy_password,
            hidden_password,
            opts,
            decoy_cb,
            hidden_cb,
            Some(&cancel),
        );
        // Drop both readers BEFORE joining so early errors unblock either packer cleanly.
        drop(d_reader);
        drop(h_reader);

        let decoy_pack = decoy_handle_opt
            .take()
            .expect("decoy packer taken once")
            .join()
            .map_err(|_| StorageError::Io(std::io::Error::other("decoy packer panicked")))?;
        let hidden_pack = hidden_handle_opt
            .take()
            .expect("hidden packer taken once")
            .join()
            .map_err(|_| StorageError::Io(std::io::Error::other("hidden packer panicked")))?;

        let summary = enc_attempt?;
        decoy_pack?;
        hidden_pack?;
        summary_out = Some(summary);
        Ok(())
    });

    drop(decoy_reader_opt.take());
    drop(hidden_reader_opt.take());
    if let Some(h) = decoy_handle_opt.take() {
        let _ = h.join();
    }
    if let Some(h) = hidden_handle_opt.take() {
        let _ = h.join();
    }

    enc_res?;
    Ok((
        summary_out.expect("summary set on Ok"),
        decoy_meta,
        hidden_meta,
    ))
}

/// Stream-decrypt a Vault v5 file directly through AEAD chunk verification into an
/// isolated staging directory inside `output_root`, then atomically promote the
/// verified payload only after all chunks succeed.
pub fn decrypt_vault_v5(
    vault_path: &Path,
    output_root: &Path,
    auth: Auth<'_>,
    progress: Arc<dyn Fn(u64, u64) + Send + Sync>,
    cancel: Arc<AtomicBool>,
) -> Result<DecryptSummary, StorageError> {
    decrypt_vault_v5_with_stealth_kdf(
        vault_path,
        output_root,
        auth,
        None,
        &rpm_core::STEALTH_KDF_PARAMS,
        progress,
        cancel,
    )
}

/// Stream-decrypt an entire Vault v5 archive (authenticating every AEAD chunk through EOF)
/// while writing only entries matching `selected_paths` into `output_root`.
pub fn decrypt_vault_selected_v5(
    vault_path: &Path,
    output_root: &Path,
    auth: Auth<'_>,
    selected_paths: &[String],
    progress: Arc<dyn Fn(u64, u64) + Send + Sync>,
    cancel: Arc<AtomicBool>,
) -> Result<DecryptSummary, StorageError> {
    decrypt_vault_v5_with_stealth_kdf(
        vault_path,
        output_root,
        auth,
        Some(selected_paths),
        &rpm_core::STEALTH_KDF_PARAMS,
        progress,
        cancel,
    )
}

pub fn decrypt_vault_v5_with_stealth_kdf(
    vault_path: &Path,
    output_root: &Path,
    auth: Auth<'_>,
    selected_paths: Option<&[String]>,
    stealth_kdf: &KdfParams,
    progress: Arc<dyn Fn(u64, u64) + Send + Sync>,
    cancel: Arc<AtomicBool>,
) -> Result<DecryptSummary, StorageError> {
    let selected_owned = match selected_paths {
        Some(paths) => {
            let cleaned: Vec<String> = paths
                .iter()
                .map(|p| normalize_archive_selector(p))
                .filter(|p| !p.is_empty())
                .collect();
            if cleaned.is_empty() {
                return Err(StorageError::InvalidPath(
                    "no files selected for extraction".into(),
                ));
            }
            Some(cleaned)
        }
        None => None,
    };

    let mut reader = BufReader::with_capacity(256 * 1024, File::open(vault_path)?);
    let unlocked = unlock_seekable_with_kdf(&mut reader, auth, stealth_kdf)?;
    let metadata = unlocked.metadata().clone();

    let total_expected = metadata.original_size;
    let compressed = unlocked.is_compressed();

    let created_root = !output_root.exists();
    fs::create_dir_all(output_root)?;

    let staging_dir = output_root.join(format!(".rpm_unpack_{}.part", random_hex_6()));
    fs::create_dir(&staging_dir)?;

    let (mut pipe_tx, pipe_rx) = bounded_pipe(8);
    let staging_owned = staging_dir.clone();
    let cancel_unpack = Arc::clone(&cancel);
    let is_selective = selected_owned.is_some();
    let unpack_handle = thread::spawn(move || -> Result<u64, StorageError> {
        if let Some(paths) = selected_owned {
            unpack_vault_stream_selected(
                pipe_rx,
                &staging_owned,
                compressed,
                &paths,
                UnpackLimits::default(),
                Some(&cancel_unpack),
            )
        } else {
            unpack_vault_stream(pipe_rx, &staging_owned, compressed, Some(&cancel_unpack))
        }
    });

    let dec_res = decrypt_unlocked_stream(
        &mut reader,
        &mut pipe_tx,
        &unlocked,
        |done| progress(done, total_expected),
        Some(&cancel),
    );
    drop(pipe_tx);

    let unpack_res = unpack_handle
        .join()
        .map_err(|_| StorageError::Io(std::io::Error::other("unpacker thread panicked")))?;

    let verified_count = match (dec_res, unpack_res) {
        (Err(e), _) => {
            let _ = fs::remove_dir_all(&staging_dir);
            if created_root {
                let _ = fs::remove_dir(output_root);
            }
            return Err(StorageError::Crypto(e));
        }
        (Ok(_), Err(e)) => {
            let _ = fs::remove_dir_all(&staging_dir);
            if created_root {
                let _ = fs::remove_dir(output_root);
            }
            return Err(e);
        }
        (Ok(_), Ok(count)) => count,
    };

    if cancel.load(Ordering::Relaxed) {
        let _ = fs::remove_dir_all(&staging_dir);
        if created_root {
            let _ = fs::remove_dir(output_root);
        }
        return Err(StorageError::Cancelled);
    }

    let promote = (|| -> Result<PathBuf, StorageError> {
        let mut top_entries = Vec::new();
        for entry in fs::read_dir(&staging_dir)? {
            top_entries.push(entry?.path());
        }
        if is_selective && verified_count == 0 && top_entries.is_empty() {
            return Err(StorageError::InvalidPath(
                "no matching files found in vault".into(),
            ));
        }
        if top_entries.len() == 1 {
            let single = &top_entries[0];
            let name = single
                .file_name()
                .map(|n| n.to_os_string())
                .unwrap_or_else(|| std::ffi::OsString::from("restored"));
            let target = unique_path(&output_root.join(name));
            fs::rename(single, &target)?;
            let _ = fs::remove_dir(&staging_dir);
            Ok(target)
        } else {
            let stem = vault_path
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "restored".into());
            let target = unique_path(&output_root.join(stem));
            fs::rename(&staging_dir, &target)?;
            Ok(target)
        }
    })();

    match promote {
        Ok(output_path) => Ok(DecryptSummary {
            metadata,
            files_extracted: verified_count,
            output_path,
        }),
        Err(err) => {
            let _ = fs::remove_dir_all(&staging_dir);
            if created_root {
                let _ = fs::remove_dir(output_root);
            }
            Err(err)
        }
    }
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
