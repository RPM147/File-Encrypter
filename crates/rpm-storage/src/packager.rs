//! Pure-Rust streaming tar (+ optional deflate/gzip) packager with symlink & Tar-Slip guards.

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::UNIX_EPOCH;

use chrono::Utc;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use rpm_core::{FileManifestEntry, VaultMetadata};
use tar::{Archive, Builder, EntryType};

use crate::error::StorageError;

fn check_cancelled(cancel: Option<&AtomicBool>) -> Result<(), StorageError> {
    if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
        return Err(StorageError::Cancelled);
    }
    Ok(())
}

/// Assign collision-free top-level archive names when packing multiple inputs
/// whose basenames might collide (e.g. `a/report.txt` + `b/report.txt`).
pub fn assign_unique_roots(paths: &[PathBuf]) -> Vec<(PathBuf, String)> {
    let mut used: HashSet<String> = HashSet::new();
    let mut out = Vec::with_capacity(paths.len());

    for p in paths {
        let base_name = p
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "item".to_string());

        let candidate_stem = Path::new(&base_name)
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| base_name.clone());
        let candidate_ext = Path::new(&base_name)
            .extension()
            .map(|s| format!(".{}", s.to_string_lossy()))
            .unwrap_or_default();

        let is_dir = fs::symlink_metadata(p).map(|m| m.is_dir()).unwrap_or(false);
        let mut chosen = base_name.clone();
        let mut idx = 2usize;
        while used.contains(&chosen.to_lowercase()) {
            chosen = if is_dir || candidate_ext.is_empty() {
                format!("{base_name}_{idx}")
            } else {
                format!("{candidate_stem}_{idx}{candidate_ext}")
            };
            idx += 1;
        }
        used.insert(chosen.to_lowercase());
        out.push((p.clone(), chosen));
    }

    out
}

fn collect_recursive(
    fs_path: &Path,
    arc_path: &str,
    entries: &mut Vec<FileManifestEntry>,
    total_bytes: &mut u64,
    cancel: Option<&AtomicBool>,
) -> Result<(), StorageError> {
    check_cancelled(cancel)?;
    let meta = fs::symlink_metadata(fs_path)?;
    if meta.file_type().is_symlink() {
        return Ok(());
    }
    if meta.is_file() {
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        *total_bytes = total_bytes.saturating_add(meta.len());
        entries.push(FileManifestEntry {
            path: arc_path.replace('\\', "/"),
            size: meta.len(),
            modified_unix: mtime,
        });
        return Ok(());
    }
    if meta.is_dir() {
        let mut children: Vec<_> = fs::read_dir(fs_path)?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .collect();
        children.sort();
        for child in children {
            let name = child.file_name().unwrap_or_default().to_string_lossy();
            let next_arc = if arc_path.is_empty() {
                name.into_owned()
            } else {
                format!("{arc_path}/{name}")
            };
            collect_recursive(&child, &next_arc, entries, total_bytes, cancel)?;
        }
    }
    Ok(())
}

/// Inspect `sources` without following symlinks and build authenticated metadata.
pub fn collect_manifest(
    sources: &[PathBuf],
    compressed: bool,
    cancel: Option<&AtomicBool>,
) -> Result<VaultMetadata, StorageError> {
    if sources.is_empty() {
        return Err(StorageError::InvalidPath("no sources provided".into()));
    }
    for s in sources {
        if fs::symlink_metadata(s).is_err() {
            return Err(StorageError::InvalidPath(format!(
                "source does not exist: {}",
                s.display()
            )));
        }
    }

    let roots = assign_unique_roots(sources);
    let mut entries = Vec::new();
    let mut total_bytes = 0u64;
    for (fs_path, arc_root) in &roots {
        collect_recursive(fs_path, arc_root, &mut entries, &mut total_bytes, cancel)?;
    }

    let (filename, source_type) = if sources.len() == 1 {
        let meta = fs::symlink_metadata(&sources[0])?;
        let name = sources[0]
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "VaultPayload".into());
        (
            name,
            if meta.is_dir() {
                "folder".into()
            } else {
                "file".into()
            },
        )
    } else {
        ("Archive".into(), "batch".into())
    };

    Ok(VaultMetadata {
        filename,
        source_type,
        original_size: total_bytes,
        file_count: entries.len() as u64,
        created_at: Utc::now().to_rfc3339(),
        compressed,
        files: entries,
    })
}

fn append_recursive<W: Write>(
    builder: &mut Builder<W>,
    fs_path: &Path,
    arc_path: &str,
    cancel: Option<&AtomicBool>,
    on_skip: &mut dyn FnMut(&str),
) -> Result<(), StorageError> {
    check_cancelled(cancel)?;
    let meta = match fs::symlink_metadata(fs_path) {
        Ok(m) => m,
        Err(err) => {
            on_skip(&format!("{} ({err})", fs_path.display()));
            return Ok(());
        }
    };

    if meta.file_type().is_symlink() {
        on_skip(&format!("symlink skipped: {arc_path}"));
        return Ok(());
    }

    if meta.is_file() {
        let mut f = File::open(fs_path)?;
        builder.append_file(arc_path, &mut f)?;
        return Ok(());
    }

    if meta.is_dir() {
        builder.append_dir(arc_path, fs_path)?;
        let mut children: Vec<_> = fs::read_dir(fs_path)?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .collect();
        children.sort();
        for child in children {
            let name = child.file_name().unwrap_or_default().to_string_lossy();
            let next_arc = format!("{arc_path}/{name}");
            append_recursive(builder, &child, &next_arc, cancel, on_skip)?;
        }
    }
    Ok(())
}

/// Stream `sources` into a tar (optionally gzip-compressed) writer. Drops `writer`
/// after finalizing so channel pipes receive EOF cleanly.
pub fn pack_sources<W: Write>(
    sources: &[PathBuf],
    writer: W,
    compress: bool,
    cancel: Option<&AtomicBool>,
    mut on_skip: impl FnMut(&str),
) -> Result<(), StorageError> {
    let roots = assign_unique_roots(sources);
    if compress {
        let enc = GzEncoder::new(writer, Compression::default());
        let mut builder = Builder::new(enc);
        for (fs_path, arc_root) in roots {
            append_recursive(&mut builder, &fs_path, &arc_root, cancel, &mut on_skip)?;
        }
        let enc = builder.into_inner()?;
        let inner = enc.finish()?;
        drop(inner);
    } else {
        let mut builder = Builder::new(writer);
        for (fs_path, arc_root) in roots {
            append_recursive(&mut builder, &fs_path, &arc_root, cancel, &mut on_skip)?;
        }
        let inner = builder.into_inner()?;
        drop(inner);
    }
    Ok(())
}

fn sanitize_archive_path(entry_path: &Path, max_depth: usize) -> Result<PathBuf, StorageError> {
    let raw = entry_path.to_string_lossy();
    if raw.contains('\0') {
        return Err(StorageError::InvalidPath(
            "archive entry path contains NUL byte".into(),
        ));
    }

    let mut clean = PathBuf::new();
    let mut depth = 0usize;
    for comp in entry_path.components() {
        match comp {
            Component::Normal(part) => {
                depth += 1;
                if depth > max_depth {
                    return Err(StorageError::LimitExceeded(format!(
                        "archive entry exceeds maximum path depth {max_depth}"
                    )));
                }
                clean.push(part);
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(StorageError::InvalidPath(format!(
                    "unsafe archive entry path: {}",
                    entry_path.display()
                )));
            }
        }
    }
    if clean.as_os_str().is_empty() {
        return Err(StorageError::InvalidPath("empty archive entry path".into()));
    }
    Ok(clean)
}

/// Hard upper bounds enforced while unpacking decrypted tar streams (tar-bomb defense).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnpackLimits {
    pub max_total_bytes: u64,
    pub max_file_count: u64,
    pub max_path_depth: usize,
}

impl Default for UnpackLimits {
    fn default() -> Self {
        Self {
            max_total_bytes: 64 * 1024 * 1024 * 1024, // 64 GiB
            max_file_count: 500_000,
            max_path_depth: 128,
        }
    }
}

fn unpack_tar_stream<R: Read>(
    reader: R,
    dest_dir: &Path,
    limits: UnpackLimits,
    cancel: Option<&AtomicBool>,
) -> Result<u64, StorageError> {
    fs::create_dir_all(dest_dir)?;
    let mut archive = Archive::new(reader);
    let mut file_count = 0u64;
    let mut entries_seen = 0u64;
    let mut total_bytes = 0u64;
    let mut buf = [0u8; 64 * 1024];

    for entry_res in archive.entries()? {
        check_cancelled(cancel)?;
        let mut entry = entry_res?;
        let etype = entry.header().entry_type();
        if etype != EntryType::Regular && etype != EntryType::Directory {
            return Err(StorageError::InvalidPath(format!(
                "unsupported/unsafe entry type {etype:?}"
            )));
        }

        entries_seen += 1;
        if entries_seen > limits.max_file_count {
            return Err(StorageError::LimitExceeded(format!(
                "archive exceeds maximum entry count {}",
                limits.max_file_count
            )));
        }

        let raw_path = entry.path()?.into_owned();
        let rel = sanitize_archive_path(&raw_path, limits.max_path_depth)?;
        let out_path = dest_dir.join(&rel);

        if etype == EntryType::Directory {
            fs::create_dir_all(&out_path)?;
        } else {
            let declared_size = entry.header().size()?;
            if total_bytes.saturating_add(declared_size) > limits.max_total_bytes {
                return Err(StorageError::LimitExceeded(format!(
                    "archive exceeds maximum unpacked size {} bytes",
                    limits.max_total_bytes
                )));
            }
            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut out_file = File::create(&out_path)?;
            loop {
                check_cancelled(cancel)?;
                let n = entry.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                total_bytes = total_bytes
                    .checked_add(n as u64)
                    .ok_or_else(|| StorageError::LimitExceeded("unpacked size overflow".into()))?;
                if total_bytes > limits.max_total_bytes {
                    return Err(StorageError::LimitExceeded(format!(
                        "archive exceeds maximum unpacked size {} bytes",
                        limits.max_total_bytes
                    )));
                }
                out_file.write_all(&buf[..n])?;
            }
            out_file.flush()?;
            file_count += 1;
        }
    }
    Ok(file_count)
}

/// Safely unpack a tar (or tar.gz) stream into `dest_dir` with explicit safety bounds.
pub fn unpack_vault_stream_with_limits<R: Read>(
    reader: R,
    dest_dir: &Path,
    compressed: bool,
    limits: UnpackLimits,
    cancel: Option<&AtomicBool>,
) -> Result<u64, StorageError> {
    if compressed {
        unpack_tar_stream(GzDecoder::new(reader), dest_dir, limits, cancel)
    } else {
        unpack_tar_stream(reader, dest_dir, limits, cancel)
    }
}

/// Safely unpack a tar (or tar.gz) stream into `dest_dir`, blocking symlinks, Tar-Slip paths, and tar bombs.
pub fn unpack_vault_stream<R: Read>(
    reader: R,
    dest_dir: &Path,
    compressed: bool,
    cancel: Option<&AtomicBool>,
) -> Result<u64, StorageError> {
    unpack_vault_stream_with_limits(
        reader,
        dest_dir,
        compressed,
        UnpackLimits::default(),
        cancel,
    )
}
