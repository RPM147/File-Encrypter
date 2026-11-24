//! Streaming multi-part volume splitting, discovery, and zero-temp-merge virtual `Read + Seek`.
//!
//! Split volumes use canonical numeric part suffixes appended to the vault base name:
//! `<base>.001`, `<base>.002`, ..., `<base>.999`, `<base>.1000`, etc.
//! No Vault Format v5 changes are required: the logical byte stream of concatenated parts
//! is byte-for-byte identical to a single `.vault` file.

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use rand::rngs::OsRng;
use rand::RngCore;
use rpm_core::IntegrityReport;

use crate::atomic::atomic_write;
use crate::error::StorageError;
use crate::workflow::unique_path;

/// Minimum allowed split part size at the storage layer (64 KiB).
pub const MIN_SPLIT_PART_SIZE: u64 = 64 * 1024;
/// Maximum number of parts in a single split volume to prevent runaway file creation.
pub const MAX_SPLIT_PARTS: usize = 9999;

const IO_BUF_CAPACITY: usize = 256 * 1024;

/// Format a 1-based part path `<base>.001`, `<base>.002`, ..., `<base>.1000`.
pub fn split_part_path(base: &Path, part_index_1based: usize) -> PathBuf {
    let mut os = OsString::from(base.as_os_str());
    os.push(format!(".{part_index_1based:03}"));
    PathBuf::from(os)
}

/// Parse a trailing canonical numeric part suffix (`.001`..`.999`, `.1000`, ...).
/// Returns `(base_path, 1_based_index)` if `path` matches the canonical split suffix format.
pub fn parse_split_part_path(path: &Path) -> Option<(PathBuf, usize)> {
    let file_name = path.file_name()?.to_str()?;
    let (base_name, suffix) = file_name.rsplit_once('.')?;
    if base_name.is_empty() || suffix.len() < 3 || !suffix.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let idx: usize = suffix.parse().ok()?;
    if idx == 0 || format!("{idx:03}") != suffix {
        return None;
    }
    let base = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(base_name),
        _ => PathBuf::from(base_name),
    };
    Some((base, idx))
}

/// Returns `true` if `path` looks like a `.vault` file or a split `.vault.NNN` part purely by name.
pub fn is_vault_or_split_filename(path: &Path) -> bool {
    if path
        .extension()
        .is_some_and(|e| e.to_string_lossy().eq_ignore_ascii_case("vault"))
    {
        return true;
    }
    if let Some((base, _)) = parse_split_part_path(path) {
        if base
            .extension()
            .is_some_and(|e| e.to_string_lossy().eq_ignore_ascii_case("vault"))
        {
            return true;
        }
    }
    false
}

/// Extract a clean display/folder stem for single or split vault paths
/// (`Archive.vault` -> `Archive`, `Archive.vault.001` -> `Archive`, `opaque.bin.001` -> `opaque`).
pub fn vault_display_stem(path: &Path) -> String {
    let unwrapped = parse_split_part_path(path)
        .map(|(base, _)| base)
        .unwrap_or_else(|| path.to_path_buf());
    unwrapped
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "restored".into())
}

/// Choose a collision-free base path for a split volume so `<candidate>.001` does not exist.
pub fn unique_split_base(base: &Path) -> PathBuf {
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

    while split_part_path(&candidate, 1).exists() {
        candidate = base.with_file_name(format!("{stem}_{idx}{ext}"));
        idx += 1;
    }
    candidate
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitVolumePart {
    pub path: PathBuf,
    pub len: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitVolumeSet {
    pub base: PathBuf,
    pub parts: Vec<SplitVolumePart>,
    pub total_len: u64,
}

impl SplitVolumeSet {
    pub fn first_part(&self) -> &Path {
        &self.parts[0].path
    }

    pub fn part_count(&self) -> usize {
        self.parts.len()
    }

    pub fn part_paths(&self) -> Vec<PathBuf> {
        self.parts.iter().map(|p| p.path.clone()).collect()
    }

    /// Infer the nominal split part size from the first part (bounded below by `MIN_SPLIT_PART_SIZE`).
    pub fn part_size_hint(&self) -> u64 {
        self.parts
            .first()
            .map(|p| p.len)
            .unwrap_or(MIN_SPLIT_PART_SIZE)
            .max(MIN_SPLIT_PART_SIZE)
    }
}

fn os_name_matches(a: &OsStr, b: &OsStr) -> bool {
    #[cfg(windows)]
    {
        a.to_string_lossy()
            .eq_ignore_ascii_case(&b.to_string_lossy())
    }
    #[cfg(not(windows))]
    {
        a == b
    }
}

/// Discover whether `path` is part of a split volume (`<base>.001`, `.002`, ...).
///
/// - Returns `Ok(None)` when `path` is an ordinary single file (including numeric extensions
///   like `report.2026` that have no `.001` companion and are not `.vault.NNN`).
/// - Returns `Ok(Some(set))` when all contiguous parts `1..=N` exist with no gaps.
/// - Returns `Err(StorageError::InvalidPath(_))` when a split volume is incomplete (e.g. `.001`
///   or a middle part `.002` is missing while higher parts exist).
pub fn discover_split_parts(path: &Path) -> Result<Option<SplitVolumeSet>, StorageError> {
    let Some((base, clicked_idx)) = parse_split_part_path(path) else {
        return Ok(None);
    };

    let parent = base
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let base_name = base.file_name().unwrap_or_else(|| OsStr::new(""));

    let mut found_indices = BTreeSet::new();
    let entries = fs::read_dir(parent)?;
    for entry in entries {
        let entry = entry?;
        let candidate = entry.path();
        if let Some((cand_base, idx)) = parse_split_part_path(&candidate) {
            if cand_base
                .file_name()
                .is_some_and(|n| os_name_matches(n, base_name))
                && candidate.is_file()
            {
                found_indices.insert(idx);
            }
        }
    }

    let base_is_vault = base
        .extension()
        .is_some_and(|e| e.to_string_lossy().eq_ignore_ascii_case("vault"));

    if !found_indices.contains(&1) {
        let has_neighbor = found_indices.contains(&clicked_idx.saturating_add(1))
            || (clicked_idx > 1 && found_indices.contains(&(clicked_idx - 1)));
        if base_is_vault || has_neighbor {
            return Err(StorageError::InvalidPath(format!(
                "missing split volume part: {}",
                split_part_path(&base, 1).display()
            )));
        }
        return Ok(None);
    }

    let max_idx = *found_indices.iter().next_back().unwrap_or(&1);
    if max_idx > MAX_SPLIT_PARTS {
        return Err(StorageError::LimitExceeded(format!(
            "split volume exceeds maximum part count ({MAX_SPLIT_PARTS})"
        )));
    }

    for expected in 1..=max_idx {
        if !found_indices.contains(&expected) {
            return Err(StorageError::InvalidPath(format!(
                "missing split volume part: {}",
                split_part_path(&base, expected).display()
            )));
        }
    }

    if !found_indices.contains(&clicked_idx) {
        return Err(StorageError::InvalidPath(format!(
            "missing split volume part: {}",
            split_part_path(&base, clicked_idx).display()
        )));
    }

    let mut parts = Vec::with_capacity(max_idx);
    let mut total_len = 0u64;
    for idx in 1..=max_idx {
        let part_p = split_part_path(&base, idx);
        let meta = fs::metadata(&part_p)?;
        if !meta.is_file() {
            return Err(StorageError::InvalidPath(format!(
                "split volume part is not a regular file: {}",
                part_p.display()
            )));
        }
        let len = meta.len();
        total_len = total_len
            .checked_add(len)
            .ok_or_else(|| StorageError::LimitExceeded("split volume size overflow".into()))?;
        parts.push(SplitVolumePart { path: part_p, len });
    }

    Ok(Some(SplitVolumeSet {
        base,
        parts,
        total_len,
    }))
}

/// Virtual `Read + Seek` view over a contiguous split volume with at most 1 open file handle
/// at a time and zero temporary merged files written to disk.
pub struct SplitVolumeReader {
    set: SplitVolumeSet,
    cum_ends: Vec<u64>,
    pos: u64,
    active_idx: Option<usize>,
    active_file: Option<BufReader<File>>,
    active_file_pos: u64,
}

impl SplitVolumeReader {
    pub fn new(set: SplitVolumeSet) -> Self {
        let mut cum_ends = Vec::with_capacity(set.parts.len());
        let mut acc = 0u64;
        for part in &set.parts {
            acc = acc.saturating_add(part.len);
            cum_ends.push(acc);
        }
        Self {
            set,
            cum_ends,
            pos: 0,
            active_idx: None,
            active_file: None,
            active_file_pos: 0,
        }
    }

    pub fn volume_set(&self) -> &SplitVolumeSet {
        &self.set
    }

    pub fn total_len(&self) -> u64 {
        self.set.total_len
    }

    pub fn part_count(&self) -> usize {
        self.set.parts.len()
    }

    fn ensure_active(
        &mut self,
        idx: usize,
        offset_in_part: u64,
    ) -> io::Result<&mut BufReader<File>> {
        if self.active_idx != Some(idx) {
            self.active_file = None;
            self.active_idx = None;
            let file = File::open(&self.set.parts[idx].path)?;
            let mut reader = BufReader::with_capacity(IO_BUF_CAPACITY, file);
            if offset_in_part > 0 {
                reader.seek(SeekFrom::Start(offset_in_part))?;
            }
            self.active_idx = Some(idx);
            self.active_file = Some(reader);
            self.active_file_pos = offset_in_part;
        } else if self.active_file_pos != offset_in_part {
            let reader = self.active_file.as_mut().expect("active file present");
            reader.seek(SeekFrom::Start(offset_in_part))?;
            self.active_file_pos = offset_in_part;
        }
        Ok(self.active_file.as_mut().expect("active file present"))
    }
}

impl Read for SplitVolumeReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.pos >= self.set.total_len {
            return Ok(0);
        }
        let idx = self.cum_ends.partition_point(|&end| end <= self.pos);
        if idx >= self.set.parts.len() {
            return Ok(0);
        }
        let part_start = if idx == 0 { 0 } else { self.cum_ends[idx - 1] };
        let offset_in_part = self.pos - part_start;
        let remaining_in_part = self.cum_ends[idx] - self.pos;
        let to_read = (buf.len() as u64).min(remaining_in_part) as usize;

        let reader = self.ensure_active(idx, offset_in_part)?;
        let n = reader.read(&mut buf[..to_read])?;
        if n == 0 && remaining_in_part > 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "split volume part truncated unexpectedly: {}",
                    self.set.parts[idx].path.display()
                ),
            ));
        }
        self.pos += n as u64;
        self.active_file_pos += n as u64;
        Ok(n)
    }
}

impl Seek for SplitVolumeReader {
    fn seek(&mut self, style: SeekFrom) -> io::Result<u64> {
        let target: i128 = match style {
            SeekFrom::Start(n) => i128::from(n),
            SeekFrom::End(delta) => i128::from(self.set.total_len) + i128::from(delta),
            SeekFrom::Current(delta) => i128::from(self.pos) + i128::from(delta),
        };
        if target < 0 || target > i128::from(u64::MAX) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid seek to negative or overflowing position",
            ));
        }
        self.pos = target as u64;
        Ok(self.pos)
    }
}

/// Unified `Read + Seek` reader for either a single `.vault` file or a multi-part split volume.
pub enum VaultReader {
    Single(BufReader<File>),
    Split(SplitVolumeReader),
}

impl VaultReader {
    pub fn is_split(&self) -> bool {
        matches!(self, Self::Split(_))
    }

    pub fn part_count(&self) -> usize {
        match self {
            Self::Single(_) => 1,
            Self::Split(s) => s.part_count(),
        }
    }
}

impl Read for VaultReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Single(f) => f.read(buf),
            Self::Split(s) => s.read(buf),
        }
    }
}

impl Seek for VaultReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match self {
            Self::Single(f) => f.seek(pos),
            Self::Split(s) => s.seek(pos),
        }
    }
}

/// Open either a single vault file or a multi-part split volume as a virtual `Read + Seek` stream.
pub fn open_vault_reader(path: &Path) -> Result<VaultReader, StorageError> {
    if let Some(set) = discover_split_parts(path)? {
        return Ok(VaultReader::Split(SplitVolumeReader::new(set)));
    }
    let file = File::open(path)?;
    Ok(VaultReader::Single(BufReader::with_capacity(
        IO_BUF_CAPACITY,
        file,
    )))
}

/// Passwordless structural integrity check (or Stealth SHA-256) working transparently
/// across both single files and multi-part split volumes.
pub fn check_vault_integrity(path: &Path) -> Result<IntegrityReport, StorageError> {
    let mut reader = open_vault_reader(path)?;
    Ok(rpm_core::check_integrity_reader(&mut reader)?)
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

/// Streaming writer that splits an outgoing vault byte stream into bounded parts
/// (`<base>.001`, `.002`, ...) with atomic temp-file staging (or direct `create_new` in Stealth mode).
pub struct SplitVolumeWriter {
    base_target: PathBuf,
    parent: PathBuf,
    base_name: String,
    part_size_bytes: u64,
    stealth: bool,
    run_hex: String,
    next_part_idx: usize,
    written_in_current: u64,
    total_written: u64,
    current_writer: Option<BufWriter<File>>,
    staged_parts: Vec<(PathBuf, PathBuf)>,
}

impl SplitVolumeWriter {
    fn new(base_target: &Path, part_size_bytes: u64, stealth: bool) -> Result<Self, StorageError> {
        if part_size_bytes < MIN_SPLIT_PART_SIZE {
            return Err(StorageError::InvalidPath(format!(
                "split part size must be at least {} bytes",
                MIN_SPLIT_PART_SIZE
            )));
        }
        let parent = base_target
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        fs::create_dir_all(&parent)?;
        let base_name = base_target
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "vault".into());

        Ok(Self {
            base_target: base_target.to_path_buf(),
            parent,
            base_name,
            part_size_bytes,
            stealth,
            run_hex: random_hex_6(),
            next_part_idx: 1,
            written_in_current: 0,
            total_written: 0,
            current_writer: None,
            staged_parts: Vec::new(),
        })
    }

    pub fn total_written(&self) -> u64 {
        self.total_written
    }

    fn close_current_part(&mut self) -> io::Result<()> {
        if let Some(mut writer) = self.current_writer.take() {
            writer.flush()?;
            let file = writer.into_inner().map_err(|e| e.into_error())?;
            file.sync_all()?;
            drop(file);
        }
        self.written_in_current = 0;
        Ok(())
    }

    fn open_next_part(&mut self) -> io::Result<()> {
        if self.next_part_idx > MAX_SPLIT_PARTS {
            return Err(io::Error::other(format!(
                "split volume exceeds maximum part count ({MAX_SPLIT_PARTS})"
            )));
        }
        let idx = self.next_part_idx;
        let final_path = split_part_path(&self.base_target, idx);
        let staging_path = if self.stealth {
            final_path.clone()
        } else {
            self.parent.join(format!(
                ".rpm_tmp_{}_{}.{idx:03}.part",
                self.base_name, self.run_hex
            ))
        };

        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staging_path)?;
        self.staged_parts.push((staging_path, final_path));
        self.current_writer = Some(BufWriter::with_capacity(IO_BUF_CAPACITY, file));
        self.written_in_current = 0;
        self.next_part_idx += 1;
        Ok(())
    }

    fn cleanup_staged(&mut self) {
        self.current_writer = None;
        for (staging, _) in self.staged_parts.drain(..) {
            let _ = fs::remove_file(staging);
        }
    }

    fn commit(mut self, obsolete_old_parts: &[PathBuf]) -> Result<Vec<PathBuf>, StorageError> {
        self.close_current_part()?;
        if self.staged_parts.is_empty() {
            return Err(StorageError::InvalidPath(
                "split volume produced zero bytes".into(),
            ));
        }

        let mut finals = Vec::with_capacity(self.staged_parts.len());
        if self.stealth {
            for (_, final_path) in self.staged_parts.drain(..) {
                finals.push(final_path);
            }
            return Ok(finals);
        }

        let staged = std::mem::take(&mut self.staged_parts);
        let mut iter = staged.into_iter();
        while let Some((staging, final_path)) = iter.next() {
            if let Err(err) = fs::rename(&staging, &final_path) {
                let _ = fs::remove_file(&staging);
                for (rem_staging, _) in iter {
                    let _ = fs::remove_file(rem_staging);
                }
                return Err(StorageError::Io(err));
            }
            finals.push(final_path);
        }

        if obsolete_old_parts.len() > finals.len() {
            for old_extra in &obsolete_old_parts[finals.len()..] {
                let _ = fs::remove_file(old_extra);
            }
        }
        Ok(finals)
    }
}

impl Drop for SplitVolumeWriter {
    fn drop(&mut self) {
        self.cleanup_staged();
    }
}

impl Write for SplitVolumeWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.current_writer.is_none() || self.written_in_current >= self.part_size_bytes {
            self.close_current_part()?;
            self.open_next_part()?;
        }
        let room = (self.part_size_bytes - self.written_in_current) as usize;
        let chunk = buf.len().min(room);
        let writer = self.current_writer.as_mut().expect("active part writer");
        let n = writer.write(&buf[..chunk])?;
        self.written_in_current += n as u64;
        self.total_written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(writer) = self.current_writer.as_mut() {
            writer.flush()?;
        }
        Ok(())
    }
}

/// Stream a vault directly into `<base>.001`, `.002`, ... parts with full rollback on error.
pub(crate) fn write_split_vault<F>(
    base_target: &Path,
    part_size_bytes: u64,
    stealth: bool,
    write_fn: F,
) -> Result<Vec<PathBuf>, StorageError>
where
    F: FnOnce(&mut SplitVolumeWriter) -> Result<(), StorageError>,
{
    write_split_vault_replacing(base_target, &[], part_size_bytes, stealth, write_fn)
}

/// Atomically write and promote split volume parts, removing any trailing obsolete old parts
/// after all new parts succeed.
pub(crate) fn write_split_vault_replacing<F>(
    base_target: &Path,
    obsolete_old_parts: &[PathBuf],
    part_size_bytes: u64,
    stealth: bool,
    write_fn: F,
) -> Result<Vec<PathBuf>, StorageError>
where
    F: FnOnce(&mut SplitVolumeWriter) -> Result<(), StorageError>,
{
    let mut writer = SplitVolumeWriter::new(base_target, part_size_bytes, stealth)?;
    if let Err(err) = write_fn(&mut writer) {
        writer.cleanup_staged();
        return Err(err);
    }
    writer.commit(obsolete_old_parts)
}

/// Split an existing single `.vault` file into `<name>.001`, `<name>.002`, ... parts atomically.
pub fn split_vault_file(
    src_vault: &Path,
    output_dir: Option<&Path>,
    part_size_bytes: u64,
    progress: Arc<dyn Fn(u64, u64) + Send + Sync>,
    cancel: Arc<AtomicBool>,
) -> Result<Vec<PathBuf>, StorageError> {
    if !src_vault.is_file() {
        return Err(StorageError::InvalidPath(format!(
            "vault file not found: {}",
            src_vault.display()
        )));
    }
    if discover_split_parts(src_vault)?.is_some() {
        return Err(StorageError::InvalidPath(
            "input is already part of a split volume".into(),
        ));
    }
    if part_size_bytes < MIN_SPLIT_PART_SIZE {
        return Err(StorageError::InvalidPath(format!(
            "split part size must be at least {} bytes",
            MIN_SPLIT_PART_SIZE
        )));
    }
    let total_len = fs::metadata(src_vault)?.len();
    if total_len == 0 {
        return Err(StorageError::InvalidPath(
            "cannot split an empty file".into(),
        ));
    }
    let expected_parts = total_len.div_ceil(part_size_bytes);
    if expected_parts > MAX_SPLIT_PARTS as u64 {
        return Err(StorageError::LimitExceeded(format!(
            "split would create {expected_parts} parts (max {MAX_SPLIT_PARTS}); choose a larger part size"
        )));
    }

    let out_parent = match output_dir {
        Some(dir) => {
            if !dir.is_dir() {
                return Err(StorageError::InvalidPath(format!(
                    "output directory not found: {}",
                    dir.display()
                )));
            }
            dir
        }
        None => src_vault
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new(".")),
    };
    let file_name = src_vault
        .file_name()
        .ok_or_else(|| StorageError::InvalidPath("invalid source vault filename".into()))?;
    let base_target = unique_split_base(&out_parent.join(file_name));

    write_split_vault(&base_target, part_size_bytes, false, |writer| {
        let mut src = BufReader::with_capacity(IO_BUF_CAPACITY, File::open(src_vault)?);
        let mut buf = vec![0u8; IO_BUF_CAPACITY];
        let mut done = 0u64;
        loop {
            if cancel.load(Ordering::Relaxed) {
                return Err(StorageError::Cancelled);
            }
            let n = src.read(&mut buf)?;
            if n == 0 {
                break;
            }
            writer.write_all(&buf[..n])?;
            done += n as u64;
            progress(done, total_len);
        }
        Ok(())
    })
}

/// Join a contiguous multi-part split volume (passing any part, typically `.001`) into a single
/// vault file atomically.
pub fn join_vault_parts(
    any_part_path: &Path,
    output_path: Option<&Path>,
    progress: Arc<dyn Fn(u64, u64) + Send + Sync>,
    cancel: Arc<AtomicBool>,
) -> Result<(PathBuf, u64), StorageError> {
    if !any_part_path.is_file() {
        return Err(StorageError::InvalidPath(format!(
            "split part not found: {}",
            any_part_path.display()
        )));
    }
    let set = discover_split_parts(any_part_path)?.ok_or_else(|| {
        StorageError::InvalidPath(format!(
            "not a split vault volume: {}",
            any_part_path.display()
        ))
    })?;

    let target = match output_path {
        Some(p) => {
            if p.is_dir() {
                let name = set
                    .base
                    .file_name()
                    .unwrap_or_else(|| OsStr::new("joined.vault"));
                unique_path(&p.join(name))
            } else {
                p.to_path_buf()
            }
        }
        None => unique_path(&set.base),
    };

    let target_canon = fs::canonicalize(&target).ok();
    if set.parts.iter().any(|part| {
        part.path == target
            || target_canon
                .as_ref()
                .is_some_and(|tc| fs::canonicalize(&part.path).ok().as_ref() == Some(tc))
    }) {
        return Err(StorageError::InvalidPath(
            "join output path cannot overwrite one of the input split parts".into(),
        ));
    }

    let total_len = set.total_len;
    let mut reader = SplitVolumeReader::new(set);
    let mut written = 0u64;

    atomic_write(&target, |writer| {
        let mut buf = vec![0u8; IO_BUF_CAPACITY];
        loop {
            if cancel.load(Ordering::Relaxed) {
                return Err(StorageError::Cancelled);
            }
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            writer.write_all(&buf[..n])?;
            written += n as u64;
            progress(written, total_len);
        }
        Ok(())
    })?;

    Ok((target, written))
}
