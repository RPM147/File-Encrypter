//! Pure-Rust streaming tar (+ optional deflate/gzip) packager with symlink & Tar-Slip guards.

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

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

/// Format Unix epoch seconds as an ISO-8601 / RFC-3339 UTC timestamp (`YYYY-MM-DDTHH:MM:SSZ`).
pub fn format_unix_rfc3339(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let hour = rem / 3600;
    let min = (rem % 3600) / 60;
    let sec = rem % 60;

    // Howard Hinnant's proleptic Gregorian civil_from_days algorithm (epoch 1970-01-01).
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + if m <= 2 { 1 } else { 0 };

    format!("{year:04}-{m:02}-{d:02}T{hour:02}:{min:02}:{sec:02}Z")
}

fn utc_now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_unix_rfc3339(secs)
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
        created_at: utc_now_rfc3339(),
        compressed,
        files: entries,
    })
}

fn append_recursive<W: Write>(
    builder: &mut Builder<W>,
    fs_path: &Path,
    arc_path: &str,
    cancel: Option<&AtomicBool>,
    excluded: Option<&Path>,
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
        // A destination inside a selected directory may appear after manifest collection
        // (including multi-part Stealth outputs `<base>.001`, `<base>.002`, ...).
        if let Some(path) = excluded {
            let exact_match = path.file_name() == fs_path.file_name()
                && fs::canonicalize(path)
                    .is_ok_and(|out| fs::canonicalize(fs_path).is_ok_and(|input| input == out));
            let split_part_match =
                crate::split::parse_split_part_path(fs_path).is_some_and(|(cand_base, _)| {
                    cand_base.file_name() == path.file_name()
                        && match (path.parent(), cand_base.parent()) {
                            (Some(p1), Some(p2)) => {
                                let d1 = if p1.as_os_str().is_empty() {
                                    Path::new(".")
                                } else {
                                    p1
                                };
                                let d2 = if p2.as_os_str().is_empty() {
                                    Path::new(".")
                                } else {
                                    p2
                                };
                                fs::canonicalize(d1).ok() == fs::canonicalize(d2).ok()
                            }
                            _ => cand_base == path,
                        }
                });
            if exact_match || split_part_match {
                return Ok(());
            }
        }
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
            append_recursive(builder, &child, &next_arc, cancel, excluded, on_skip)?;
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
    on_skip: impl FnMut(&str),
) -> Result<(), StorageError> {
    pack_sources_excluding(sources, writer, compress, cancel, None, on_skip)
}

pub(crate) fn pack_sources_excluding<W: Write>(
    sources: &[PathBuf],
    writer: W,
    compress: bool,
    cancel: Option<&AtomicBool>,
    excluded: Option<&Path>,
    mut on_skip: impl FnMut(&str),
) -> Result<(), StorageError> {
    let roots = assign_unique_roots(sources);
    if compress {
        let enc = GzEncoder::new(writer, Compression::default());
        let mut builder = Builder::new(enc);
        for (fs_path, arc_root) in roots {
            append_recursive(
                &mut builder,
                &fs_path,
                &arc_root,
                cancel,
                excluded,
                &mut on_skip,
            )?;
        }
        let enc = builder.into_inner()?;
        let inner = enc.finish()?;
        drop(inner);
    } else {
        let mut builder = Builder::new(writer);
        for (fs_path, arc_root) in roots {
            append_recursive(
                &mut builder,
                &fs_path,
                &arc_root,
                cancel,
                excluded,
                &mut on_skip,
            )?;
        }
        let inner = builder.into_inner()?;
        drop(inner);
    }
    Ok(())
}

pub(crate) fn sanitize_archive_path(
    entry_path: &Path,
    max_depth: usize,
) -> Result<PathBuf, StorageError> {
    let raw = entry_path.to_string_lossy();
    // Apply portable archive path rules even when host Path::components
    // would treat a Windows prefix or backslash as ordinary filename bytes.
    if raw.starts_with('\\')
        || (raw.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
            && raw.as_bytes().get(1) == Some(&b':'))
        || raw.split(['/', '\\']).any(|part| part == "..")
    {
        return Err(StorageError::InvalidPath(format!(
            "unsafe archive entry path: {raw}"
        )));
    }
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

/// Normalize an archive member selector path to canonical forward-slash form (`a/b/c`).
pub fn normalize_archive_selector(raw: &str) -> String {
    let mut s = raw.trim().replace('\\', "/");
    while let Some(rest) = s.strip_prefix("./") {
        s = rest.to_string();
    }
    s.trim_matches('/').to_string()
}

fn build_selector_set(selected_paths: &[String]) -> Result<HashSet<String>, StorageError> {
    let set: HashSet<String> = selected_paths
        .iter()
        .map(|s| normalize_archive_selector(s))
        .filter(|s| !s.is_empty())
        .collect();
    if set.is_empty() {
        return Err(StorageError::InvalidPath(
            "no valid archive paths selected for extraction".into(),
        ));
    }
    Ok(set)
}

fn matches_selector(rel_unix: &str, selected: &HashSet<String>) -> bool {
    if selected.contains(rel_unix) {
        return true;
    }
    selected.iter().any(|sel| {
        rel_unix
            .strip_prefix(sel.as_str())
            .is_some_and(|rest| rest.starts_with('/'))
    })
}

fn unpack_tar_stream<R: Read>(
    reader: R,
    dest_dir: &Path,
    limits: UnpackLimits,
    filter: Option<&HashSet<String>>,
    cancel: Option<&AtomicBool>,
) -> Result<u64, StorageError> {
    fs::create_dir_all(dest_dir)?;
    let mut file_count = 0u64;
    let mut buf = [0u8; 64 * 1024];
    visit_tar_entries(reader, limits, cancel, |rel, entry| {
        if let Some(selected) = filter {
            let rel_unix = rel.to_string_lossy().replace('\\', "/");
            if !matches_selector(&rel_unix, selected) {
                return Ok(());
            }
        }
        let out_path = dest_dir.join(rel);

        if entry.header().entry_type() == EntryType::Directory {
            fs::create_dir_all(&out_path)?;
        } else {
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
                out_file.write_all(&buf[..n])?;
            }
            out_file.flush()?;
            file_count += 1;
        }
        Ok(())
    })?;
    Ok(file_count)
}

pub(crate) fn visit_tar_entries<R: Read>(
    reader: R,
    limits: UnpackLimits,
    cancel: Option<&AtomicBool>,
    mut visit: impl FnMut(&Path, &mut tar::Entry<'_, R>) -> Result<(), StorageError>,
) -> Result<(), StorageError> {
    let mut archive = Archive::new(reader);
    let mut entries_seen = 0u64;
    let mut total_bytes = 0u64;

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
        // The tar reader consumes skipped entries too. Charge their effective
        // size (including PAX size overrides) before applying the selection.
        total_bytes = total_bytes
            .checked_add(entry.size())
            .ok_or_else(|| StorageError::LimitExceeded("unpacked size overflow".into()))?;
        if total_bytes > limits.max_total_bytes {
            return Err(StorageError::LimitExceeded(format!(
                "archive exceeds maximum unpacked size {} bytes",
                limits.max_total_bytes
            )));
        }
        visit(&rel, &mut entry)?;
    }
    Ok(())
}

/// Tar iteration stops at its first end marker. Finish reading the gzip member
/// before publishing the result, so its CRC32 and original length are checked.
pub(crate) fn with_tar_reader<R: Read, T>(
    mut input: R,
    compressed: bool,
    limits: UnpackLimits,
    cancel: Option<&AtomicBool>,
    parse: impl FnOnce(&mut dyn Read) -> Result<T, StorageError>,
) -> Result<T, StorageError> {
    if !compressed {
        return parse(&mut input);
    }
    let mut gzip = GzDecoder::new(input);
    let result = parse(&mut gzip)?;
    let mut buf = zeroize::Zeroizing::new([0; 8192]);
    // Permit tar record padding even with tiny caller-supplied file limits.
    let mut remaining = limits.max_total_bytes.max(10 * 1024);
    loop {
        check_cancelled(cancel)?;
        let n = gzip.read(&mut buf[..])?;
        if n == 0 {
            break;
        }
        remaining = remaining.checked_sub(n as u64).ok_or_else(|| {
            StorageError::LimitExceeded("excessive data after tar end marker".into())
        })?;
    }
    Ok(result)
}

/// Safely unpack only the entries matching `selected_paths` (exact file or folder prefix)
/// while still validating every entry header for Tar-Slip, symlinks, and bomb limits.
pub fn unpack_vault_stream_selected<R: Read>(
    reader: R,
    dest_dir: &Path,
    compressed: bool,
    selected_paths: &[String],
    limits: UnpackLimits,
    cancel: Option<&AtomicBool>,
) -> Result<u64, StorageError> {
    let filter = build_selector_set(selected_paths)?;
    with_tar_reader(reader, compressed, limits, cancel, |tar| {
        unpack_tar_stream(tar, dest_dir, limits, Some(&filter), cancel)
    })
}

/// Safely unpack a tar (or tar.gz) stream into `dest_dir` with explicit safety bounds.
pub fn unpack_vault_stream_with_limits<R: Read>(
    reader: R,
    dest_dir: &Path,
    compressed: bool,
    limits: UnpackLimits,
    cancel: Option<&AtomicBool>,
) -> Result<u64, StorageError> {
    with_tar_reader(reader, compressed, limits, cancel, |tar| {
        unpack_tar_stream(tar, dest_dir, limits, None, cancel)
    })
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

#[cfg(test)]
mod tests {
    use super::format_unix_rfc3339;

    #[test]
    fn utc_rfc3339_formatting_handles_epoch_and_leap_day() {
        assert_eq!(format_unix_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_unix_rfc3339(1_709_251_199), "2024-02-29T23:59:59Z");
        assert_eq!(format_unix_rfc3339(1_709_251_200), "2024-03-01T00:00:00Z");
        assert_eq!(format_unix_rfc3339(1_767_225_600), "2026-01-01T00:00:00Z");
    }
}
