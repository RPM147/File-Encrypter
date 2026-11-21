//! Crash-safe atomic file replacement via sibling temp file + sync_all + rename.

use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;

use rand::rngs::OsRng;
use rand::RngCore;

use crate::error::StorageError;

/// Write `target` via a sibling `.rpm_tmp_<hex>.part` file, flush + `sync_all`,
/// close the handle, and atomically rename into place.
pub fn atomic_write<F>(target: &Path, write_fn: F) -> Result<(), StorageError>
where
    F: FnOnce(&mut BufWriter<File>) -> Result<(), StorageError>,
{
    let parent = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;

    let mut rand_bytes = [0u8; 6];
    OsRng.fill_bytes(&mut rand_bytes);
    let mut hex = String::with_capacity(12);
    for b in rand_bytes {
        hex.push_str(&format!("{b:02x}"));
    }
    let stem = target
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "vault".into());
    let temp_path = parent.join(format!(".rpm_tmp_{stem}_{hex}.part"));

    let res = (|| -> Result<(), StorageError> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)?;
        let mut writer = BufWriter::with_capacity(256 * 1024, file);
        write_fn(&mut writer)?;
        writer.flush()?;
        let inner = writer.into_inner().map_err(|e| e.into_error())?;
        inner.sync_all()?;
        drop(inner); // Must drop before rename on Windows.
        fs::rename(&temp_path, target)?;
        Ok(())
    })();

    if res.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    res
}

/// Stealth encryption streams directly to a fresh destination. Exclusive creation
/// preserves existing files, including a destination claimed by another writer.
pub(crate) fn write_vault(
    target: &Path,
    stealth: bool,
    write_fn: impl FnOnce(&mut BufWriter<File>) -> Result<(), StorageError>,
) -> Result<(), StorageError> {
    if !stealth {
        return atomic_write(target, write_fn);
    }
    if let Some(parent) = target.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    let file = File::create_new(target)?;
    let mut writer = BufWriter::with_capacity(256 * 1024, file);
    let result = write_fn(&mut writer).and_then(|()| {
        writer.flush()?;
        writer.get_ref().sync_all()?;
        Ok(())
    });
    drop(writer);
    if result.is_err() {
        let _ = fs::remove_file(target);
    }
    result
}
