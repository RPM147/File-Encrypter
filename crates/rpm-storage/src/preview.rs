use rpm_core::{decrypt_unlocked_stream, unlock_seekable_with_kdf, Auth, CryptoError};
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
            let mut bytes = Zeroizing::new(vec![0; entry.size() as usize]);
            entry.read_exact(&mut bytes)?;
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
    let target = relative_path(target_path, UnpackLimits::default().max_path_depth)?;
    let mut vault = open_vault_reader(vault_path)?;
    let unlocked = unlock_seekable_with_kdf(&mut vault, auth, stealth_kdf)?;
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
        while reader.read(&mut *scratch)? != 0 {}
        Ok(bytes)
    });
    let verified = decrypt_unlocked_stream(
        &mut vault,
        &mut writer,
        &unlocked,
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
