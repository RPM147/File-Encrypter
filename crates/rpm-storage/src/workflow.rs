//! High-level zero-temp-plaintext workflows uniting `rpm-core` v5 and `rpm-storage`.

use std::fs::{self, File};
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use rand::rngs::OsRng;
use rand::RngCore;
use rpm_core::{
    decrypt_unlocked_stream_with_threads, encrypt_hidden_stream_with_threads,
    encrypt_stream_with_threads, rekey_stream, unlock_seekable_with_kdf_and_threads, Auth,
    CryptoError, EncryptOptions, EncryptSummary, HiddenEncryptOptions, HiddenEncryptSummary,
    KdfParams, RekeyOptions, SecretKey, VaultMetadata,
};
use zeroize::Zeroizing;

use crate::atomic::{atomic_write, write_vault};
use crate::error::StorageError;
use crate::packager::{
    collect_manifest, normalize_archive_selector, pack_sources_excluding, unpack_vault_stream,
    unpack_vault_stream_selected, OutputExclusion, UnpackLimits,
};
use crate::pipe::bounded_pipe;
use crate::split::{
    discover_split_parts, open_vault_reader, path_conflicts_with_split_set, validate_split_bounds,
    vault_display_stem, write_split_vault, write_split_vault_replacing, SplitVolumeReader,
};

#[derive(Clone, Debug)]
pub struct DecryptSummary {
    pub metadata: VaultMetadata,
    pub files_extracted: u64,
    pub output_path: PathBuf,
}

/// Reject overlapping outer/decoy and hidden compartment source trees so hidden
/// files can never leak into the outer vault or conflict during secure wiping.
pub fn check_compartment_sources(
    outer: &[PathBuf],
    hidden: &[PathBuf],
) -> Result<(), StorageError> {
    let mut first_io_err: Option<io::Error> = None;
    let mut outer_canon = Vec::with_capacity(outer.len());
    for p in outer {
        match fs::canonicalize(p) {
            Ok(c) => outer_canon.push(c),
            Err(e) if first_io_err.is_none() => first_io_err = Some(e),
            Err(_) => {}
        }
    }
    for source in hidden {
        match fs::canonicalize(source) {
            Ok(source) => {
                if outer_canon
                    .iter()
                    .any(|path| path.starts_with(&source) || source.starts_with(path))
                {
                    return Err(StorageError::InvalidPath(
                        "outer and hidden source paths overlap; select separate files or directories"
                            .into(),
                    ));
                }
            }
            Err(e) if first_io_err.is_none() => first_io_err = Some(e),
            Err(_) => {}
        }
    }
    if let Some(err) = first_io_err {
        return Err(StorageError::Io(err));
    }
    Ok(())
}

/// Reject secure-wipe configurations where any source path is an ancestor of (or identical to)
/// the vault output directory or a required keyfile.
pub fn check_wipe_targets<'a>(
    sources: impl Iterator<Item = &'a PathBuf>,
    output_dir: &Path,
    keyfiles: impl Iterator<Item = &'a PathBuf>,
) -> Result<(), StorageError> {
    let mut first_io_err: Option<io::Error> = None;
    let mut protected = Vec::new();
    match fs::canonicalize(output_dir) {
        Ok(c) => protected.push(c),
        Err(e) => first_io_err = Some(e),
    }
    for keyfile in keyfiles {
        match fs::canonicalize(keyfile) {
            Ok(c) => protected.push(c),
            Err(e) if first_io_err.is_none() => first_io_err = Some(e),
            Err(_) => {}
        }
    }
    for source in sources {
        match fs::canonicalize(source) {
            Ok(source) => {
                if protected.iter().any(|path| path.starts_with(&source)) {
                    return Err(StorageError::InvalidPath(
                        "--wipe would remove the output directory or a required keyfile".into(),
                    ));
                }
            }
            Err(e) if first_io_err.is_none() => first_io_err = Some(e),
            Err(_) => {}
        }
    }
    if let Some(err) = first_io_err {
        return Err(StorageError::Io(err));
    }
    Ok(())
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

    while fs::symlink_metadata(&candidate).is_ok() {
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

#[allow(clippy::too_many_arguments)]
fn encrypt_sources_v5_with_sink<F>(
    sources: &[PathBuf],
    split_part_bytes: Option<u64>,
    password: &[u8],
    opts: &EncryptOptions,
    threads: usize,
    progress: Arc<dyn Fn(u64, u64) + Send + Sync>,
    cancel: Arc<AtomicBool>,
    on_skip: impl FnMut(&str) + Send + 'static,
    write_sink: F,
) -> Result<(EncryptSummary, VaultMetadata), StorageError>
where
    F: FnOnce(
        Arc<OutputExclusion>,
        &mut dyn FnMut(&mut dyn Write) -> Result<(), StorageError>,
    ) -> Result<(), StorageError>,
{
    if let Some(part_size) = split_part_bytes {
        validate_split_bounds(part_size, opts.container_size_bytes, opts.reed_solomon)?;
    }

    let metadata = collect_manifest(sources, opts.compressed, Some(&cancel))?;
    if let Some(part_size) = split_part_bytes {
        if !opts.compressed {
            let min_inner = metadata
                .original_size
                .max(opts.container_size_bytes.unwrap_or(0));
            validate_split_bounds(part_size, Some(min_inner), opts.reed_solomon)?;
        }
    }

    let total_expected = metadata.original_size;
    let exclusion = Arc::new(OutputExclusion::new());
    let exclusion_pack = Arc::clone(&exclusion);
    let mut on_skip_opt = Some(on_skip);
    let mut summary_out: Option<EncryptSummary> = None;

    let mut run_enc = |mut vault_writer: &mut dyn Write| -> Result<(), StorageError> {
        let (writer, mut reader) = bounded_pipe(8);
        let sources_owned = sources.to_vec();
        let compress = opts.compressed;
        let cancel_pack = Arc::clone(&cancel);
        let exclusion_pack = Arc::clone(&exclusion_pack);
        let mut on_skip = on_skip_opt.take().expect("on_skip taken once");
        let packer_handle = thread::spawn(move || -> Result<(), StorageError> {
            pack_sources_excluding(
                &sources_owned,
                writer,
                compress,
                Some(&cancel_pack),
                Some(&exclusion_pack),
                |msg| {
                    on_skip(msg);
                },
            )
        });

        let enc_attempt = encrypt_stream_with_threads(
            &mut reader,
            &mut vault_writer,
            &metadata,
            password,
            opts,
            threads,
            |done| progress(done, total_expected),
            Some(&cancel),
        );
        // Drop reader BEFORE joining so early encryption/cancel errors unblock packer cleanly.
        drop(reader);
        let pack_attempt = packer_handle
            .join()
            .map_err(|_| StorageError::Io(std::io::Error::other("packer thread panicked")))?;
        let summary = enc_attempt?;
        pack_attempt?;
        summary_out = Some(summary);
        Ok(())
    };

    write_sink(exclusion, &mut run_enc)?;
    Ok((summary_out.expect("summary set on Ok"), metadata))
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
    on_skip: impl FnMut(&str) + Send + 'static,
) -> Result<(EncryptSummary, VaultMetadata), StorageError> {
    encrypt_sources_v5_with_threads(
        sources, out_vault, password, opts, 0, progress, cancel, on_skip,
    )
}

/// Stream-pack `sources` into a Vault v5 archive using `threads` pipeline workers (`0` = auto).
#[allow(clippy::too_many_arguments)]
pub fn encrypt_sources_v5_with_threads(
    sources: &[PathBuf],
    out_vault: &Path,
    password: &[u8],
    opts: &EncryptOptions,
    threads: usize,
    progress: Arc<dyn Fn(u64, u64) + Send + Sync>,
    cancel: Arc<AtomicBool>,
    on_skip: impl FnMut(&str) + Send + 'static,
) -> Result<(EncryptSummary, VaultMetadata), StorageError> {
    encrypt_sources_v5_with_sink(
        sources,
        None,
        password,
        opts,
        threads,
        progress,
        cancel,
        on_skip,
        |exclusion, run| write_vault(out_vault, opts.stealth, Some(&exclusion), |w| run(w)),
    )
}

/// Stream-pack `sources` directly into a multi-part split Vault v5 volume
/// (`<out_vault_base>.001`, `.002`, ...) with zero temporary merged files on disk.
#[allow(clippy::too_many_arguments)]
pub fn encrypt_sources_v5_split(
    sources: &[PathBuf],
    out_vault_base: &Path,
    part_size_bytes: u64,
    password: &[u8],
    opts: &EncryptOptions,
    progress: Arc<dyn Fn(u64, u64) + Send + Sync>,
    cancel: Arc<AtomicBool>,
    on_skip: impl FnMut(&str) + Send + 'static,
) -> Result<(EncryptSummary, VaultMetadata, Vec<PathBuf>), StorageError> {
    encrypt_sources_v5_split_with_threads(
        sources,
        out_vault_base,
        part_size_bytes,
        password,
        opts,
        0,
        progress,
        cancel,
        on_skip,
    )
}

/// Stream-pack `sources` into a split Vault v5 volume using `threads` pipeline workers (`0` = auto).
#[allow(clippy::too_many_arguments)]
pub fn encrypt_sources_v5_split_with_threads(
    sources: &[PathBuf],
    out_vault_base: &Path,
    part_size_bytes: u64,
    password: &[u8],
    opts: &EncryptOptions,
    threads: usize,
    progress: Arc<dyn Fn(u64, u64) + Send + Sync>,
    cancel: Arc<AtomicBool>,
    on_skip: impl FnMut(&str) + Send + 'static,
) -> Result<(EncryptSummary, VaultMetadata, Vec<PathBuf>), StorageError> {
    let mut created_parts = Vec::new();
    let (summary, meta) = encrypt_sources_v5_with_sink(
        sources,
        Some(part_size_bytes),
        password,
        opts,
        threads,
        progress,
        cancel,
        on_skip,
        |exclusion, run| {
            created_parts = write_split_vault(
                out_vault_base,
                part_size_bytes,
                opts.stealth,
                Some(exclusion),
                |w| run(w),
            )?;
            Ok(())
        },
    )?;
    Ok((summary, meta, created_parts))
}

#[allow(clippy::too_many_arguments)]
fn encrypt_hidden_sources_v5_with_sink<F>(
    decoy_sources: &[PathBuf],
    hidden_sources: &[PathBuf],
    split_part_bytes: Option<u64>,
    decoy_password: &[u8],
    hidden_password: &[u8],
    opts: &HiddenEncryptOptions,
    threads: usize,
    progress: Arc<dyn Fn(u64, u64) + Send + Sync>,
    cancel: Arc<AtomicBool>,
    on_skip: impl FnMut(&str) + Send + 'static,
    write_sink: F,
) -> Result<(HiddenEncryptSummary, VaultMetadata, VaultMetadata), StorageError>
where
    F: FnOnce(
        Arc<OutputExclusion>,
        &mut dyn FnMut(&mut dyn Write) -> Result<(), StorageError>,
    ) -> Result<(), StorageError>,
{
    if let Some(part_size) = split_part_bytes {
        validate_split_bounds(
            part_size,
            Some(opts.container_size_bytes),
            opts.reed_solomon,
        )?;
    }

    let decoy_meta = collect_manifest(decoy_sources, opts.decoy_compressed, Some(&cancel))?;
    let hidden_meta = collect_manifest(hidden_sources, opts.hidden_compressed, Some(&cancel))?;
    let total_expected = decoy_meta
        .original_size
        .saturating_add(hidden_meta.original_size);

    let on_skip = Arc::new(Mutex::new(on_skip));
    let exclusion = Arc::new(OutputExclusion::new());
    let exclusion_for_packers = Arc::clone(&exclusion);
    let mut summary_out: Option<HiddenEncryptSummary> = None;

    let decoy_done = Arc::new(AtomicU64::new(0));
    let hidden_done = Arc::new(AtomicU64::new(0));

    let mut run_enc = |mut vault_writer: &mut dyn Write| -> Result<(), StorageError> {
        let (decoy_writer, mut d_reader) = bounded_pipe(8);
        let (hidden_writer, mut h_reader) = bounded_pipe(8);

        let decoy_owned = decoy_sources.to_vec();
        let decoy_compress = opts.decoy_compressed;
        let cancel_decoy = Arc::clone(&cancel);
        let skip_decoy = Arc::clone(&on_skip);
        let exclusion_decoy = Arc::clone(&exclusion_for_packers);
        let decoy_handle = thread::spawn(move || -> Result<(), StorageError> {
            pack_sources_excluding(
                &decoy_owned,
                decoy_writer,
                decoy_compress,
                Some(&cancel_decoy),
                Some(&exclusion_decoy),
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
        let exclusion_hidden = Arc::clone(&exclusion_for_packers);
        let hidden_handle = thread::spawn(move || -> Result<(), StorageError> {
            pack_sources_excluding(
                &hidden_owned,
                hidden_writer,
                hidden_compress,
                Some(&cancel_hidden),
                Some(&exclusion_hidden),
                |msg| {
                    if let Ok(mut cb) = skip_hidden.lock() {
                        cb(msg);
                    }
                },
            )
        });

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

        let enc_attempt = encrypt_hidden_stream_with_threads(
            &mut d_reader,
            &mut h_reader,
            &mut vault_writer,
            &decoy_meta,
            &hidden_meta,
            decoy_password,
            hidden_password,
            opts,
            threads,
            decoy_cb,
            hidden_cb,
            Some(&cancel),
        );
        // Drop both readers BEFORE joining so early errors unblock either packer cleanly.
        drop(d_reader);
        drop(h_reader);

        let decoy_pack = decoy_handle
            .join()
            .map_err(|_| StorageError::Io(std::io::Error::other("decoy packer panicked")))?;
        let hidden_pack = hidden_handle
            .join()
            .map_err(|_| StorageError::Io(std::io::Error::other("hidden packer panicked")))?;

        let summary = enc_attempt?;
        decoy_pack?;
        hidden_pack?;
        summary_out = Some(summary);
        Ok(())
    };

    write_sink(exclusion, &mut run_enc)?;
    Ok((
        summary_out.expect("summary set on Ok"),
        decoy_meta,
        hidden_meta,
    ))
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
    encrypt_hidden_sources_v5_with_threads(
        decoy_sources,
        hidden_sources,
        out_vault,
        decoy_password,
        hidden_password,
        opts,
        0,
        progress,
        cancel,
        on_skip,
    )
}

/// Stream-pack decoy and hidden sources using `threads` pipeline workers (`0` = auto).
#[allow(clippy::too_many_arguments)]
pub fn encrypt_hidden_sources_v5_with_threads(
    decoy_sources: &[PathBuf],
    hidden_sources: &[PathBuf],
    out_vault: &Path,
    decoy_password: &[u8],
    hidden_password: &[u8],
    opts: &HiddenEncryptOptions,
    threads: usize,
    progress: Arc<dyn Fn(u64, u64) + Send + Sync>,
    cancel: Arc<AtomicBool>,
    on_skip: impl FnMut(&str) + Send + 'static,
) -> Result<(HiddenEncryptSummary, VaultMetadata, VaultMetadata), StorageError> {
    encrypt_hidden_sources_v5_with_sink(
        decoy_sources,
        hidden_sources,
        None,
        decoy_password,
        hidden_password,
        opts,
        threads,
        progress,
        cancel,
        on_skip,
        |exclusion, run| write_vault(out_vault, opts.stealth, Some(&exclusion), |w| run(w)),
    )
}

/// Stream-pack decoy and hidden sources directly into a multi-part split Vault v5 container.
#[allow(clippy::too_many_arguments)]
pub fn encrypt_hidden_sources_v5_split(
    decoy_sources: &[PathBuf],
    hidden_sources: &[PathBuf],
    out_vault_base: &Path,
    part_size_bytes: u64,
    decoy_password: &[u8],
    hidden_password: &[u8],
    opts: &HiddenEncryptOptions,
    progress: Arc<dyn Fn(u64, u64) + Send + Sync>,
    cancel: Arc<AtomicBool>,
    on_skip: impl FnMut(&str) + Send + 'static,
) -> Result<
    (
        HiddenEncryptSummary,
        VaultMetadata,
        VaultMetadata,
        Vec<PathBuf>,
    ),
    StorageError,
> {
    encrypt_hidden_sources_v5_split_with_threads(
        decoy_sources,
        hidden_sources,
        out_vault_base,
        part_size_bytes,
        decoy_password,
        hidden_password,
        opts,
        0,
        progress,
        cancel,
        on_skip,
    )
}

/// Stream-pack decoy and hidden sources into a split Vault v5 container using `threads` workers.
#[allow(clippy::too_many_arguments)]
pub fn encrypt_hidden_sources_v5_split_with_threads(
    decoy_sources: &[PathBuf],
    hidden_sources: &[PathBuf],
    out_vault_base: &Path,
    part_size_bytes: u64,
    decoy_password: &[u8],
    hidden_password: &[u8],
    opts: &HiddenEncryptOptions,
    threads: usize,
    progress: Arc<dyn Fn(u64, u64) + Send + Sync>,
    cancel: Arc<AtomicBool>,
    on_skip: impl FnMut(&str) + Send + 'static,
) -> Result<
    (
        HiddenEncryptSummary,
        VaultMetadata,
        VaultMetadata,
        Vec<PathBuf>,
    ),
    StorageError,
> {
    let mut created_parts = Vec::new();
    let (summary, decoy_meta, hidden_meta) = encrypt_hidden_sources_v5_with_sink(
        decoy_sources,
        hidden_sources,
        Some(part_size_bytes),
        decoy_password,
        hidden_password,
        opts,
        threads,
        progress,
        cancel,
        on_skip,
        |exclusion, run| {
            created_parts = write_split_vault(
                out_vault_base,
                part_size_bytes,
                opts.stealth,
                Some(exclusion),
                |w| run(w),
            )?;
            Ok(())
        },
    )?;
    Ok((summary, decoy_meta, hidden_meta, created_parts))
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
    decrypt_vault_v5_with_stealth_kdf_and_threads(
        vault_path,
        output_root,
        auth,
        selected_paths,
        stealth_kdf,
        0,
        progress,
        cancel,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn decrypt_vault_v5_with_stealth_kdf_and_threads(
    vault_path: &Path,
    output_root: &Path,
    auth: Auth<'_>,
    selected_paths: Option<&[String]>,
    stealth_kdf: &KdfParams,
    threads: usize,
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

    let mut reader = open_vault_reader(vault_path)?;
    let unlocked = unlock_seekable_with_kdf_and_threads(&mut reader, auth, stealth_kdf, threads)?;
    let metadata = unlocked.metadata().clone();

    let total_expected = metadata.original_size;
    let compressed = unlocked.is_compressed();

    let created_root = !output_root.exists();
    fs::create_dir_all(output_root)?;

    let staging_dir = output_root.join(format!(".rpm_unpack_{}.part", random_hex_6()));
    fs::create_dir(&staging_dir)?;

    let (mut pipe_tx, mut pipe_rx) = bounded_pipe(8);
    let staging_owned = staging_dir.clone();
    let cancel_unpack = Arc::clone(&cancel);
    let is_selective = selected_owned.is_some();
    let unpack_handle = thread::spawn(move || -> Result<u64, StorageError> {
        let count = if let Some(paths) = selected_owned {
            unpack_vault_stream_selected(
                &mut pipe_rx,
                &staging_owned,
                compressed,
                &paths,
                UnpackLimits::default(),
                Some(&cancel_unpack),
            )?
        } else {
            unpack_vault_stream(
                &mut pipe_rx,
                &staging_owned,
                compressed,
                Some(&cancel_unpack),
            )?
        };
        // A tar end marker can precede the final authenticated chunk frame.
        let mut scratch = Zeroizing::new([0u8; 8192]);
        loop {
            if cancel_unpack.load(Ordering::Relaxed) {
                return Err(StorageError::Cancelled);
            }
            if pipe_rx.read(&mut *scratch)? == 0 {
                break;
            }
        }
        Ok(count)
    });

    let dec_res = decrypt_unlocked_stream_with_threads(
        &mut reader,
        &mut pipe_tx,
        &unlocked,
        threads,
        |done| progress(done, total_expected),
        Some(&cancel),
    );
    drop(pipe_tx);

    let unpack_res = unpack_handle
        .join()
        .map_err(|_| StorageError::Io(io::Error::other("unpacker thread panicked")))?;

    let verified_count = match (dec_res, unpack_res) {
        // Early archive/path/limit rejection closes the pipe while the decryptor is writing.
        (Err(CryptoError::Io(io_err)), Err(unpack_err))
            if io_err.kind() == io::ErrorKind::BrokenPipe =>
        {
            let _ = fs::remove_dir_all(&staging_dir);
            if created_root {
                let _ = fs::remove_dir(output_root);
            }
            return Err(unpack_err);
        }
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
            let stem = vault_display_stem(vault_path);
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

/// Atomically re-key `vault_path` in place using sibling temp file(s) (payload is
/// never decrypted). Works transparently on both single `.vault` files and split volumes.
pub fn rekey_vault_v5(
    vault_path: &Path,
    old_password: &[u8],
    new_password: &[u8],
    old_keyfile: Option<&SecretKey>,
    new_keyfile: Option<&SecretKey>,
    new_kdf: Option<KdfParams>,
    cancel: Option<&AtomicBool>,
) -> Result<(), StorageError> {
    if !vault_path.is_file() {
        return Err(StorageError::InvalidPath(format!(
            "vault file not found: {}",
            vault_path.display()
        )));
    }
    let rekey_opts = RekeyOptions {
        old_password,
        new_password,
        old_keyfile_hash: old_keyfile,
        new_keyfile_hash: new_keyfile,
        new_kdf,
    };
    if let Some(set) = discover_split_parts(vault_path)? {
        if set.part_count() > 1 {
            let old_parts = set.part_paths();
            let part_size = set.part_size_hint();
            let base = set.base.clone();
            write_split_vault_replacing(&base, &old_parts, part_size, false, None, |out_writer| {
                let mut src_reader = SplitVolumeReader::new(set.clone());
                rekey_stream(&mut src_reader, out_writer, &rekey_opts, cancel)?;
                drop(src_reader); // Crucial on Windows before promoting over existing part files.
                Ok(())
            })?;
            return Ok(());
        }
        // Single-part `.vault.001` has no established split boundary; rewrite in place
        // atomically so a larger KDF header never splits it into a spurious `.002`.
        let single_part = set.first_part().to_path_buf();
        return atomic_write(&single_part, |out_writer| {
            let mut src_reader = BufReader::with_capacity(256 * 1024, File::open(&single_part)?);
            rekey_stream(&mut src_reader, out_writer, &rekey_opts, cancel)?;
            drop(src_reader);
            Ok(())
        });
    }
    atomic_write(vault_path, |out_writer| {
        let mut src_reader = BufReader::with_capacity(256 * 1024, File::open(vault_path)?);
        rekey_stream(&mut src_reader, out_writer, &rekey_opts, cancel)?;
        drop(src_reader); // Crucial on Windows before `atomic_write` renames over `vault_path`.
        Ok(())
    })
}

/// Repair ciphertext into sibling staging file(s), promoting only after the entire envelope
/// succeeds. Supports single vaults and multi-part split volumes (preserving split layout in place).
pub fn repair_vault_v5(
    vault_path: &Path,
    output_path: Option<&Path>,
    cancel: Arc<AtomicBool>,
) -> Result<rpm_core::RepairReport, StorageError> {
    repair_vault_v5_with_threads(vault_path, output_path, 0, cancel)
}

/// Repair ciphertext using `threads` Reed-Solomon workers (`0` = auto).
pub fn repair_vault_v5_with_threads(
    vault_path: &Path,
    output_path: Option<&Path>,
    threads: usize,
    cancel: Arc<AtomicBool>,
) -> Result<rpm_core::RepairReport, StorageError> {
    if !vault_path.is_file() {
        return Err(StorageError::InvalidPath(format!(
            "vault file not found: {}",
            vault_path.display()
        )));
    }
    if let Some(out) = output_path {
        if out.is_dir() {
            return Err(StorageError::InvalidPath(format!(
                "repair output path is a directory: {}",
                out.display()
            )));
        }
    }

    let split_set = discover_split_parts(vault_path)?;
    let mut report = None;

    if let Some(out) = output_path {
        if let Some(set) = split_set {
            if path_conflicts_with_split_set(out, &set) {
                return Err(StorageError::InvalidPath(
                    "repair output path cannot overwrite or extend the input split volume set"
                        .into(),
                ));
            }
            atomic_write(out, |writer| {
                let mut input = SplitVolumeReader::new(set.clone());
                report = Some(rpm_core::repair_vault_stream_with_threads(
                    &mut input,
                    writer,
                    Some(&cancel),
                    threads,
                )?);
                drop(input);
                Ok(())
            })?;
            return Ok(report.expect("atomic write completed"));
        }

        atomic_write(out, |writer| {
            let mut input = BufReader::with_capacity(256 * 1024, File::open(vault_path)?);
            report = Some(rpm_core::repair_vault_stream_with_threads(
                &mut input,
                writer,
                Some(&cancel),
                threads,
            )?);
            drop(input);
            Ok(())
        })?;
        return Ok(report.expect("atomic write completed"));
    }

    if let Some(set) = split_set {
        if set.part_count() > 1 {
            let old_parts = set.part_paths();
            let part_size = set.part_size_hint();
            let base = set.base.clone();
            write_split_vault_replacing(&base, &old_parts, part_size, false, None, |writer| {
                let mut input = SplitVolumeReader::new(set.clone());
                report = Some(rpm_core::repair_vault_stream_with_threads(
                    &mut input,
                    writer,
                    Some(&cancel),
                    threads,
                )?);
                drop(input);
                Ok(())
            })?;
            return Ok(report.expect("split write completed"));
        }
        let single_part = set.first_part().to_path_buf();
        atomic_write(&single_part, |writer| {
            let mut input = BufReader::with_capacity(256 * 1024, File::open(&single_part)?);
            report = Some(rpm_core::repair_vault_stream_with_threads(
                &mut input,
                writer,
                Some(&cancel),
                threads,
            )?);
            drop(input);
            Ok(())
        })?;
        return Ok(report.expect("atomic write completed"));
    }

    atomic_write(vault_path, |writer| {
        let mut input = BufReader::with_capacity(256 * 1024, File::open(vault_path)?);
        report = Some(rpm_core::repair_vault_stream_with_threads(
            &mut input,
            writer,
            Some(&cancel),
            threads,
        )?);
        drop(input);
        Ok(())
    })?;
    Ok(report.expect("atomic write completed"))
}
