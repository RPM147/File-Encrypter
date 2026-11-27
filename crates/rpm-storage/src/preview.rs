use rpm_core::{
    decrypt_unlocked_stream_with_threads, unlock_seekable_with_kdf_threads_and_cancel, Auth,
    CryptoError,
};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use zeroize::Zeroizing;

use crate::packager::{sanitize_archive_path, visit_tar_entries};
use crate::split::open_vault_reader;
use crate::{pipe::bounded_pipe, StorageError, UnpackLimits};

pub const DEFAULT_PREVIEW_MAX_BYTES: usize = 16 * 1024 * 1024;

fn relative_path(raw: &str, depth: usize) -> Result<PathBuf, StorageError> {
    let normalized = raw.replace('\\', "/");
    if normalized.as_bytes().get(1) == Some(&b':') {
        return Err(StorageError::InvalidPath(
            "drive-qualified archive path".into(),
        ));
    }
    sanitize_archive_path(Path::new(&normalized), depth)
}

fn read_member(
    reader: impl Read,
    target: &Path,
    max: usize,
    cancel: &AtomicBool,
) -> Result<Zeroizing<Vec<u8>>, StorageError> {
    let limits = UnpackLimits::default();
    let mut found = None;
    visit_tar_entries(reader, limits, Some(cancel), |rel, entry| {
        let raw = rel
            .to_str()
            .ok_or_else(|| StorageError::InvalidPath("non-UTF-8 archive path".into()))?;
        if relative_path(raw, limits.max_path_depth)? == target {
            if !entry.header().entry_type().is_file() || found.is_some() {
                return Err(StorageError::InvalidPath(
                    "expected one regular file".into(),
                ));
            }
            if entry.size() > max as u64 {
                return Err(StorageError::LimitExceeded(
                    "preview byte limit exceeded".into(),
                ));
            }
            let total_len = entry.size() as usize;
            let mut bytes = Zeroizing::new(vec![0; total_len]);
            let mut filled = 0usize;
            while filled < total_len {
                if cancel.load(Ordering::Relaxed) {
                    return Err(StorageError::Cancelled);
                }
                let end = (filled + 64 * 1024).min(total_len);
                match entry.read(&mut bytes[filled..end]) {
                    Ok(0) => {
                        return Err(StorageError::Io(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "unexpected EOF reading preview entry",
                        )));
                    }
                    Ok(n) => filled += n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(StorageError::Io(e)),
                }
            }
            if cancel.load(Ordering::Relaxed) {
                return Err(StorageError::Cancelled);
            }
            found = Some(bytes);
        }
        Ok(())
    })?;
    found.ok_or_else(|| StorageError::InvalidPath("preview file not found".into()))
}

/// Read one file in RAM, returning its bytes only after compartment authentication completes.
pub fn extract_entry_to_memory_v5(
    vault_path: &Path,
    auth: Auth<'_>,
    target_path: &str,
    max_bytes: usize,
    progress: Arc<dyn Fn(u64, u64) + Send + Sync>,
    cancel: Arc<AtomicBool>,
) -> Result<Zeroizing<Vec<u8>>, StorageError> {
    extract_entry_to_memory_v5_with_stealth_kdf(
        vault_path,
        auth,
        target_path,
        max_bytes,
        &rpm_core::STEALTH_KDF_PARAMS,
        progress,
        cancel,
    )
}

pub fn extract_entry_to_memory_v5_with_stealth_kdf(
    vault_path: &Path,
    auth: Auth<'_>,
    target_path: &str,
    max_bytes: usize,
    stealth_kdf: &rpm_core::KdfParams,
    progress: Arc<dyn Fn(u64, u64) + Send + Sync>,
    cancel: Arc<AtomicBool>,
) -> Result<Zeroizing<Vec<u8>>, StorageError> {
    extract_entry_to_memory_v5_with_stealth_kdf_and_threads(
        vault_path,
        auth,
        target_path,
        max_bytes,
        stealth_kdf,
        0,
        progress,
        cancel,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn extract_entry_to_memory_v5_with_stealth_kdf_and_threads(
    vault_path: &Path,
    auth: Auth<'_>,
    target_path: &str,
    max_bytes: usize,
    stealth_kdf: &rpm_core::KdfParams,
    threads: usize,
    progress: Arc<dyn Fn(u64, u64) + Send + Sync>,
    cancel: Arc<AtomicBool>,
) -> Result<Zeroizing<Vec<u8>>, StorageError> {
    let target = relative_path(target_path, UnpackLimits::default().max_path_depth)?;
    if cancel.load(Ordering::Relaxed) {
        return Err(StorageError::Cancelled);
    }
    let mut vault = open_vault_reader(vault_path)?;
    let unlocked = unlock_seekable_with_kdf_threads_and_cancel(
        &mut vault,
        auth,
        stealth_kdf,
        threads,
        Some(&cancel),
    )?;
    if cancel.load(Ordering::Relaxed) {
        return Err(StorageError::Cancelled);
    }
    let compressed = unlocked.is_compressed();
    let total = unlocked.metadata().original_size;
    let (mut writer, mut reader) = bounded_pipe(2);
    let stop = Arc::clone(&cancel);
    let worker = std::thread::spawn(move || {
        let bytes = crate::packager::with_tar_reader(
            &mut reader,
            compressed,
            UnpackLimits::default(),
            Some(&stop),
            |tar| read_member(tar, &target, max_bytes, &stop),
        )?;
        // A tar end marker can precede the final authenticated frame.
        let mut scratch = Zeroizing::new([0u8; 8192]);
        loop {
            if stop.load(Ordering::Relaxed) {
                return Err(StorageError::Cancelled);
            }
            if reader.read(&mut *scratch)? == 0 {
                break;
            }
        }
        Ok(bytes)
    });
    let verified = decrypt_unlocked_stream_with_threads(
        &mut vault,
        &mut writer,
        &unlocked,
        threads,
        |n| progress(n, total),
        Some(&cancel),
    );
    drop(writer);
    let extracted = worker
        .join()
        .map_err(|_| io::Error::other("preview worker panicked"))?;
    if cancel.load(Ordering::Relaxed) {
        return Err(StorageError::Cancelled);
    }
    // Early parser rejection can close the pipe while the verifier is writing.
    if matches!(&verified, Err(CryptoError::Io(e)) if e.kind() == io::ErrorKind::BrokenPipe) {
        if let Err(err) = extracted {
            return Err(err);
        }
    }
    verified?;
    extracted
}
