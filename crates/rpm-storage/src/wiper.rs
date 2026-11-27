//! Best-effort secure file and directory wiping (never follows symlinks).

use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use rand::rngs::OsRng;
use rand::RngCore;

use crate::error::StorageError;

const WIPE_CHUNK: usize = 256 * 1024;

fn is_cancelled(cancel: Option<&AtomicBool>) -> bool {
    cancel.is_some_and(|c| c.load(Ordering::Relaxed))
}

pub struct SecureWiper {
    pub passes: u8,
}

impl Default for SecureWiper {
    fn default() -> Self {
        Self { passes: 1 }
    }
}

impl SecureWiper {
    pub fn new(passes: u8) -> Self {
        Self {
            passes: passes.max(1),
        }
    }

    pub fn wipe_file(&self, path: &Path) -> Result<(), StorageError> {
        self.wipe_file_cancellable(path, None)
    }

    pub fn wipe_file_cancellable(
        &self,
        path: &Path,
        cancel: Option<&AtomicBool>,
    ) -> Result<(), StorageError> {
        if is_cancelled(cancel) {
            return Err(StorageError::Cancelled);
        }
        let meta = fs::symlink_metadata(path)?;
        if meta.file_type().is_symlink() {
            fs::remove_file(path)?;
            return Ok(());
        }
        if !meta.is_file() {
            return Ok(());
        }

        let len = meta.len();
        if len > 0 {
            let mut f = OpenOptions::new().write(true).open(path)?;
            let mut buf = vec![0u8; WIPE_CHUNK.min(len as usize)];
            for _pass in 0..self.passes {
                if is_cancelled(cancel) {
                    return Err(StorageError::Cancelled);
                }
                f.seek(SeekFrom::Start(0))?;
                let mut remaining = len;
                while remaining > 0 {
                    if is_cancelled(cancel) {
                        return Err(StorageError::Cancelled);
                    }
                    let step = buf.len().min(remaining as usize);
                    OsRng.fill_bytes(&mut buf[..step]);
                    f.write_all(&buf[..step])?;
                    remaining -= step as u64;
                }
                f.sync_all()?;
            }
        }
        if is_cancelled(cancel) {
            return Err(StorageError::Cancelled);
        }
        fs::remove_file(path)?;
        Ok(())
    }

    pub fn wipe_folder(&self, dir: &Path) -> Result<(), StorageError> {
        self.wipe_folder_cancellable(dir, None)
    }

    pub fn wipe_folder_cancellable(
        &self,
        dir: &Path,
        cancel: Option<&AtomicBool>,
    ) -> Result<(), StorageError> {
        if is_cancelled(cancel) {
            return Err(StorageError::Cancelled);
        }
        let meta = fs::symlink_metadata(dir)?;
        if meta.file_type().is_symlink() {
            fs::remove_file(dir)?;
            return Ok(());
        }
        if !meta.is_dir() {
            return Ok(());
        }

        for entry in fs::read_dir(dir)? {
            if is_cancelled(cancel) {
                return Err(StorageError::Cancelled);
            }
            let entry = entry?;
            let p = entry.path();
            let cmeta = fs::symlink_metadata(&p)?;
            if cmeta.file_type().is_symlink() {
                let _ = fs::remove_file(&p);
            } else if cmeta.is_dir() {
                self.wipe_folder_cancellable(&p, cancel)?;
            } else if cmeta.is_file() {
                self.wipe_file_cancellable(&p, cancel)?;
            }
        }
        if is_cancelled(cancel) {
            return Err(StorageError::Cancelled);
        }
        fs::remove_dir(dir)?;
        Ok(())
    }
}
