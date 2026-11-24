//! Streaming multi-part volume splitting, discovery, and zero-temp-merge virtual `Read + Seek`.
//!
//! Split volumes use canonical numeric part suffixes appended to the vault base name:
//! `<base>.001`, `<base>.002`, ..., `<base>.999`, `<base>.1000`, etc.
//! No Vault Format v5 changes are required: the logical byte stream of concatenated parts
//! is byte-for-byte identical to a single `.vault` file.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use rand::rngs::OsRng;
use rand::RngCore;
use rpm_core::IntegrityReport;

use crate::atomic::atomic_write;
use crate::error::StorageError;
use crate::packager::{create_dir_all_tracked, OutputExclusion};
use crate::workflow::unique_path;

/// Minimum allowed split part size at the storage layer (64 KiB).
pub const MIN_SPLIT_PART_SIZE: u64 = 64 * 1024;
/// Maximum number of parts in a single split volume to prevent runaway file creation.
pub const MAX_SPLIT_PARTS: usize = 9999;

const IO_BUF_CAPACITY: usize = 256 * 1024;
const RS_HEADER_BYTES: u64 = 48;

#[cfg(windows)]
pub(crate) type OsNameKey = Vec<u16>;
#[cfg(not(windows))]
pub(crate) type OsNameKey = OsString;

#[cfg(windows)]
fn single_char(mut iter: impl Iterator<Item = char>) -> Option<char> {
    match (iter.next(), iter.next()) {
        (Some(c), None) => Some(c),
        _ => None,
    }
}

#[cfg(windows)]
fn fold_windows_char(c: char) -> char {
    match single_char(c.to_lowercase()) {
        Some(low) if low != c && single_char(low.to_uppercase()) == Some(c) => low,
        _ => c,
    }
}

/// Lossless platform-native filename comparison key.
///
/// On Windows, folds reflexive single-character Unicode case pairs matching NTFS `$UpCase`
/// semantics (including Turkish `Ş/ş`, `Ö/ö`, `Ü/ü`, `Ç/ç`, `Ğ/ğ`, `I/i` while keeping
/// distinct NTFS entries such as `İ` vs `i`, `I` vs `ı`, `K` vs `k`, and `Å` vs `å` separate).
/// On Unix, preserves exact `OsString` bytes.
pub(crate) fn os_name_key(name: &OsStr) -> OsNameKey {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let mut out = Vec::new();
        let mut buf = [0u16; 2];
        for decoded in char::decode_utf16(name.encode_wide()) {
            match decoded {
                Ok(c) => out.extend_from_slice(fold_windows_char(c).encode_utf16(&mut buf)),
                Err(surrogate) => out.push(surrogate.unpaired_surrogate()),
            }
        }
        out
    }
    #[cfg(not(windows))]
    {
        name.to_os_string()
    }
}

/// Canonical, platform-appropriate deduplication key for filesystem paths
/// (Unicode case-insensitive on Windows, exact canonical path on Unix).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PathDedupKey(OsNameKey);

fn parent_or_dot(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(out.components().next_back(), Some(Component::Normal(_))) {
                    out.pop();
                } else if !matches!(
                    out.components().next_back(),
                    Some(Component::RootDir | Component::Prefix(_))
                ) {
                    out.push(comp);
                }
            }
            other => out.push(other),
        }
    }
    if out.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        out
    }
}

fn canonicalize_best_effort(path: &Path) -> PathBuf {
    if let Ok(canon) = fs::canonicalize(path) {
        return canon;
    }
    let normalized = lexical_normalize(path);
    if let Ok(canon) = fs::canonicalize(&normalized) {
        return canon;
    }
    let mut tail: Vec<OsString> = Vec::new();
    let mut cur = normalized.as_path();
    while let Some(name) = cur.file_name() {
        tail.push(name.to_os_string());
        let parent = parent_or_dot(cur);
        if parent == cur {
            break;
        }
        if let Ok(canon_parent) = fs::canonicalize(parent) {
            let mut res = canon_parent;
            for part in tail.into_iter().rev() {
                res.push(part);
            }
            return res;
        }
        cur = parent;
    }
    normalized
}

/// Build a canonical deduplication key for `path`, falling back to lexical normalization
/// joined onto the deepest canonical existing ancestor when `path` does not exist yet
/// (or is a dangling symlink).
pub fn path_dedup_key(path: &Path) -> PathDedupKey {
    PathDedupKey(os_name_key(canonicalize_best_effort(path).as_os_str()))
}

pub(crate) fn paths_refer_to_same_target(a: &Path, b: &Path) -> bool {
    a == b || path_dedup_key(a) == path_dedup_key(b)
}

/// Returns `true` if `target` overwrites an existing part of `set` or would create
/// another `<base>.NNN` part belonging to the same split volume set.
pub(crate) fn path_conflicts_with_split_set(target: &Path, set: &SplitVolumeSet) -> bool {
    let target_key = path_dedup_key(target);
    if set
        .parts
        .iter()
        .any(|part| path_dedup_key(&part.path) == target_key)
    {
        return true;
    }
    if let Some((target_base, _)) = parse_split_part_path(target) {
        if paths_refer_to_same_target(&target_base, &set.base) {
            return true;
        }
    }
    false
}

/// Exact Reed-Solomon wire size in bytes for an inner Vault v5 byte stream of `inner_bytes`.
pub(crate) fn rs_wire_size(inner_bytes: u64) -> u64 {
    let blocks = inner_bytes
        .max(1)
        .div_ceil(rpm_core::rs::RS_BLOCK_DATA_CAP as u64);
    RS_HEADER_BYTES.saturating_add(blocks.saturating_mul(rpm_core::rs::RS_BLOCK_WIRE_SIZE as u64))
}

/// Pre-flight validation for split part size and maximum part count bounds.
pub fn validate_split_bounds(
    part_size_bytes: u64,
    min_inner_bytes: Option<u64>,
    reed_solomon: bool,
) -> Result<(), StorageError> {
    if part_size_bytes < MIN_SPLIT_PART_SIZE {
        return Err(StorageError::InvalidPath(format!(
            "split part size must be at least {MIN_SPLIT_PART_SIZE} bytes"
        )));
    }
    if let Some(inner) = min_inner_bytes {
        let min_disk = if reed_solomon {
            rs_wire_size(inner)
        } else {
            inner
        };
        if min_disk > 0 {
            let min_parts = min_disk.div_ceil(part_size_bytes);
            if min_parts > MAX_SPLIT_PARTS as u64 {
                return Err(StorageError::LimitExceeded(format!(
                    "split would create at least {min_parts} parts (max {MAX_SPLIT_PARTS}); choose a larger part size"
                )));
            }
        }
    }
    Ok(())
}

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
    if base_name.is_empty()
        || base_name.bytes().all(|b| b == b'.')
        || suffix.len() < 3
        || !suffix.bytes().all(|b| b.is_ascii_digit())
    {
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

/// Choose a collision-free base path for a split volume so no `<candidate>.NNN` part
/// (including orphan `.002`/`.003` files, directories, or dangling symlinks) exists in the
/// destination directory.
pub fn unique_split_base(base: &Path) -> PathBuf {
    let parent = parent_or_dot(base);
    let mut occupied_bases: HashSet<OsNameKey> = HashSet::new();
    if let Ok(entries) = fs::read_dir(parent) {
        for entry in entries.flatten() {
            let entry_path = entry.path();
            if let Some((cand_base, _)) = parse_split_part_path(&entry_path) {
                if let Some(name) = cand_base.file_name() {
                    occupied_bases.insert(os_name_key(name));
                }
            }
        }
    }

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

    let has_collision = |cand: &Path| -> bool {
        if fs::symlink_metadata(split_part_path(cand, 1)).is_ok() {
            return true;
        }
        cand.file_name()
            .is_some_and(|name| occupied_bases.contains(&os_name_key(name)))
    };

    while has_collision(&candidate) {
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

fn entry_is_regular_file(entry: &fs::DirEntry) -> bool {
    match entry.file_type() {
        Ok(ft) if ft.is_file() => true,
        Ok(ft) if ft.is_symlink() => entry.path().is_file(),
        Ok(_) => false,
        Err(_) => entry.path().is_file(),
    }
}

fn join_like_base(base: &Path, actual_file_name: &OsStr) -> PathBuf {
    match base.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(actual_file_name),
        _ => PathBuf::from(actual_file_name),
    }
}

fn active_non_vault_is_split(found: &BTreeMap<usize, OsString>) -> bool {
    found.len() >= 2
        && (found.contains_key(&1) || (found.contains_key(&2) && found.contains_key(&3)))
}

fn resolve_split_from_entries(
    path: &Path,
    base: PathBuf,
    clicked_idx: usize,
    found: &BTreeMap<usize, OsString>,
) -> Result<Option<SplitVolumeSet>, StorageError> {
    let base_is_vault = base
        .extension()
        .is_some_and(|e| e.to_string_lossy().eq_ignore_ascii_case("vault"));

    if fs::metadata(path).is_ok_and(|m| !m.is_file()) {
        return if base_is_vault {
            Err(StorageError::InvalidPath(format!(
                "split volume part is not a regular file: {}",
                path.display()
            )))
        } else {
            Ok(None)
        };
    }

    // For non-`.vault` files (Stealth split volumes vs ordinary numeric extensions such as
    // `photo.001`, `report.2025`+`report.2026`, or `report.001`+`report.002` alongside an
    // unrelated `report.2026`), only include 4+-digit suffixes (`>= 1000`) when the numbered
    // sequence reaches the `.999`/`.1000` boundary, and require either `.001` with at least one
    // companion (catching missing `.002` in `.001`+`.003`) or `.002`+`.003` (catching missing `.001`).
    let filtered: BTreeMap<usize, OsString>;
    let active: &BTreeMap<usize, OsString> = if base_is_vault {
        found
    } else {
        let reaches_1000 =
            found.contains_key(&999) || (found.contains_key(&998) && found.contains_key(&1000));
        if clicked_idx >= 1000 && !reaches_1000 {
            return Ok(None);
        }
        filtered = found
            .iter()
            .filter(|(&idx, _)| idx < 1000 || reaches_1000)
            .map(|(&idx, name)| (idx, name.clone()))
            .collect();
        if !active_non_vault_is_split(&filtered) {
            return Ok(None);
        }
        &filtered
    };

    if !active.contains_key(&1) {
        return Err(StorageError::InvalidPath(format!(
            "missing split volume part: {}",
            split_part_path(&base, 1).display()
        )));
    }

    let max_idx = *active.keys().next_back().unwrap_or(&1);
    if max_idx > MAX_SPLIT_PARTS {
        return Err(StorageError::LimitExceeded(format!(
            "split volume exceeds maximum part count ({MAX_SPLIT_PARTS})"
        )));
    }

    for expected in 1..=max_idx {
        if !active.contains_key(&expected) {
            return Err(StorageError::InvalidPath(format!(
                "missing split volume part: {}",
                split_part_path(&base, expected).display()
            )));
        }
    }

    if !active.contains_key(&clicked_idx) {
        return Err(StorageError::InvalidPath(format!(
            "missing split volume part: {}",
            split_part_path(&base, clicked_idx).display()
        )));
    }

    let mut parts = Vec::with_capacity(max_idx);
    let mut total_len = 0u64;
    for idx in 1..=max_idx {
        let actual_name = &active[&idx];
        let part_p = join_like_base(&base, actual_name);
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

    let resolved_base = parse_split_part_path(&parts[0].path)
        .map(|(b, _)| b)
        .unwrap_or(base);

    Ok(Some(SplitVolumeSet {
        base: resolved_base,
        parts,
        total_len,
    }))
}

/// Directory-cached split volume discovery to keep batch normalization (e.g. CLI globs
/// or GUI multi-part drag-and-drop) strictly `O(D + N)` instead of `O(N^2)`.
#[derive(Default)]
pub struct SplitDiscoveryCache {
    dirs: HashMap<PathDedupKey, HashMap<OsNameKey, BTreeMap<usize, OsString>>>,
    resolved_sets: HashMap<(PathDedupKey, OsNameKey), SplitVolumeSet>,
}

impl SplitDiscoveryCache {
    pub fn discover(&mut self, path: &Path) -> Result<Option<SplitVolumeSet>, StorageError> {
        let Some((base, clicked_idx)) = parse_split_part_path(path) else {
            return Ok(None);
        };

        let parent = parent_or_dot(&base);
        let parent_key = path_dedup_key(parent);
        let base_name = base.file_name().unwrap_or_else(|| OsStr::new(""));
        let base_key = os_name_key(base_name);

        if let Some(set) = self
            .resolved_sets
            .get(&(parent_key.clone(), base_key.clone()))
        {
            if clicked_idx >= 1 && clicked_idx <= set.part_count() {
                return Ok(Some(set.clone()));
            }
        }

        if !self.dirs.contains_key(&parent_key) {
            let mut dir_index: HashMap<OsNameKey, BTreeMap<usize, OsString>> = HashMap::new();
            for entry in fs::read_dir(parent)? {
                let entry = entry?;
                let file_name = entry.file_name();
                if let Some((cand_base, idx)) = parse_split_part_path(Path::new(&file_name)) {
                    if let Some(cand_name) = cand_base.file_name() {
                        if entry_is_regular_file(&entry) {
                            dir_index
                                .entry(os_name_key(cand_name))
                                .or_default()
                                .entry(idx)
                                .or_insert(file_name);
                        }
                    }
                }
            }
            self.dirs.insert(parent_key.clone(), dir_index);
        }

        let empty = BTreeMap::new();
        let found = self
            .dirs
            .get(&parent_key)
            .and_then(|d| d.get(&base_key))
            .unwrap_or(&empty);

        let result = resolve_split_from_entries(path, base, clicked_idx, found)?;
        if let Some(ref set) = result {
            self.resolved_sets
                .insert((parent_key, base_key), set.clone());
        }
        Ok(result)
    }
}

/// Discover whether `path` is part of a split volume (`<base>.001`, `.002`, ...).
///
/// - Returns `Ok(None)` when `path` is an ordinary single file (including single non-`.vault`
///   files like `photo.001` or `report.2026` without an adjacent numbered companion).
/// - Returns `Ok(Some(set))` when all contiguous parts `1..=N` exist with no gaps.
/// - Returns `Err(StorageError::InvalidPath(_))` when a split volume is incomplete (e.g. `.001`
///   or a middle part `.002` is missing while higher parts exist).
pub fn discover_split_parts(path: &Path) -> Result<Option<SplitVolumeSet>, StorageError> {
    let Some((base, clicked_idx)) = parse_split_part_path(path) else {
        return Ok(None);
    };

    let parent = parent_or_dot(&base);
    let base_name = base.file_name().unwrap_or_else(|| OsStr::new(""));
    let base_key = os_name_key(base_name);

    let mut found: BTreeMap<usize, OsString> = BTreeMap::new();
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        let file_name = entry.file_name();
        if let Some((cand_base, idx)) = parse_split_part_path(Path::new(&file_name)) {
            if cand_base
                .file_name()
                .is_some_and(|n| os_name_key(n) == base_key)
                && entry_is_regular_file(&entry)
            {
                found.entry(idx).or_insert(file_name);
            }
        }
    }

    resolve_split_from_entries(path, base, clicked_idx, &found)
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
    pub fn new(mut set: SplitVolumeSet) -> Self {
        let mut cum_ends = Vec::with_capacity(set.parts.len());
        let mut acc = 0u64;
        for part in &set.parts {
            acc = acc.saturating_add(part.len);
            cum_ends.push(acc);
        }
        // Keep `set.total_len` strictly consistent with the summed part lengths.
        set.total_len = acc;
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
/// across both single files and multi-part split volumes, also returning the discovered
/// split part count without a second directory scan.
pub fn check_vault_integrity_with_parts(
    path: &Path,
) -> Result<(IntegrityReport, Option<usize>), StorageError> {
    let mut reader = open_vault_reader(path)?;
    let split_parts = reader.is_split().then_some(reader.part_count());
    let report = rpm_core::check_integrity_reader(&mut reader)?;
    Ok((report, split_parts))
}

/// Passwordless structural integrity check (or Stealth SHA-256) working transparently
/// across both single files and multi-part split volumes.
pub fn check_vault_integrity(path: &Path) -> Result<IntegrityReport, StorageError> {
    let (report, _) = check_vault_integrity_with_parts(path)?;
    Ok(report)
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
    part_size_bytes: u64,
    stealth: bool,
    run_hex: String,
    next_part_idx: usize,
    written_in_current: u64,
    total_written: u64,
    current_writer: Option<BufWriter<File>>,
    staged_parts: Vec<(PathBuf, PathBuf)>,
    exclusion: Option<Arc<OutputExclusion>>,
}

impl SplitVolumeWriter {
    fn new(
        base_target: &Path,
        part_size_bytes: u64,
        stealth: bool,
        exclusion: Option<Arc<OutputExclusion>>,
    ) -> Result<Self, StorageError> {
        if part_size_bytes < MIN_SPLIT_PART_SIZE {
            return Err(StorageError::InvalidPath(format!(
                "split part size must be at least {} bytes",
                MIN_SPLIT_PART_SIZE
            )));
        }
        let parent = parent_or_dot(base_target).to_path_buf();
        create_dir_all_tracked(&parent, exclusion.as_deref())?;

        Ok(Self {
            base_target: base_target.to_path_buf(),
            parent,
            part_size_bytes,
            stealth,
            run_hex: random_hex_6(),
            next_part_idx: 1,
            written_in_current: 0,
            total_written: 0,
            current_writer: None,
            staged_parts: Vec::new(),
            exclusion,
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
            // Short staging filename (30-31 bytes) avoids breaching 255-byte component limits.
            self.parent
                .join(format!(".rpm_tmp_{}.{idx:03}.part", self.run_hex))
        };

        if let Some(ex) = &self.exclusion {
            ex.register_path(&staging_path);
        }

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

    fn commit(self, obsolete_old_parts: &[PathBuf]) -> Result<Vec<PathBuf>, StorageError> {
        self.commit_with_ops(
            obsolete_old_parts,
            |from, to| fs::rename(from, to),
            |p| fs::remove_file(p),
        )
    }

    fn commit_with_ops<FRename, FRemove>(
        mut self,
        obsolete_old_parts: &[PathBuf],
        mut rename_fn: FRename,
        mut remove_fn: FRemove,
    ) -> Result<Vec<PathBuf>, StorageError>
    where
        FRename: FnMut(&Path, &Path) -> io::Result<()>,
        FRemove: FnMut(&Path) -> io::Result<()>,
    {
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

        let cleanup_all_staged = |items: Vec<(PathBuf, PathBuf)>| {
            for (s, _) in items {
                let _ = fs::remove_file(s);
            }
        };

        // Step A: Collect every existing file that will be replaced or removed in O(N) using
        // canonical deduplication keys, and verify none is a directory or marked read-only
        // before mutating any target on disk.
        let mut to_backup_keys: HashSet<PathDedupKey> =
            HashSet::with_capacity(obsolete_old_parts.len() + staged.len());
        let mut to_backup: Vec<PathBuf> = Vec::with_capacity(obsolete_old_parts.len());
        for old in obsolete_old_parts {
            if to_backup_keys.insert(path_dedup_key(old)) {
                to_backup.push(old.clone());
            }
        }
        for (_, final_path) in &staged {
            if fs::symlink_metadata(final_path).is_ok()
                && to_backup_keys.insert(path_dedup_key(final_path))
            {
                to_backup.push(final_path.clone());
            }
        }

        for target in &to_backup {
            match fs::symlink_metadata(target) {
                Ok(meta) => {
                    if meta.is_dir() {
                        cleanup_all_staged(staged);
                        return Err(StorageError::Io(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            format!("split target path is a directory: {}", target.display()),
                        )));
                    }
                    if meta.permissions().readonly() {
                        cleanup_all_staged(staged);
                        return Err(StorageError::Io(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            format!("split volume part is read-only: {}", target.display()),
                        )));
                    }
                }
                Err(err) => {
                    cleanup_all_staged(staged);
                    return Err(StorageError::Io(err));
                }
            }
        }

        // Step B: Move all existing parts aside to sibling backups BEFORE promoting any new part.
        // If any existing part is locked (e.g. open without share-delete on Windows), restore all
        // previously moved parts cleanly so the original volume stays intact.
        let mut backed_up: Vec<(PathBuf, PathBuf)> = Vec::with_capacity(to_backup.len());
        for (i, orig) in to_backup.iter().enumerate() {
            let bak_parent = parent_or_dot(orig);
            let bak = bak_parent.join(format!(".rpm_bak_{}.{:03}.part", self.run_hex, i + 1));
            if let Err(err) = rename_fn(orig, &bak) {
                for (prev_orig, prev_bak) in backed_up.into_iter().rev() {
                    let _ = fs::rename(prev_bak, prev_orig);
                }
                cleanup_all_staged(staged);
                return Err(StorageError::Io(err));
            }
            backed_up.push((orig.clone(), bak));
        }

        // Step C: Promote every new staged part into its final destination; on any failure,
        // remove already-promoted new parts and restore every backed-up original part.
        let mut iter = staged.into_iter();
        while let Some((staging, final_path)) = iter.next() {
            if let Err(err) = rename_fn(&staging, &final_path) {
                let _ = fs::remove_file(&staging);
                for (rem_staging, _) in iter {
                    let _ = fs::remove_file(rem_staging);
                }
                for promoted in finals.into_iter().rev() {
                    let _ = fs::remove_file(promoted);
                }
                for (orig, bak) in backed_up.into_iter().rev() {
                    let _ = fs::rename(bak, orig);
                }
                return Err(StorageError::Io(err));
            }
            finals.push(final_path);
        }

        // Step D: Remove temporary backups of old/obsolete parts; propagate any removal failure
        // rather than silently swallowing it.
        let mut remove_err: Option<io::Error> = None;
        for (_, bak) in backed_up {
            if let Err(err) = remove_fn(&bak) {
                if remove_err.is_none() {
                    remove_err = Some(err);
                }
            }
        }
        if let Some(err) = remove_err {
            return Err(StorageError::Io(err));
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
        let remaining_in_part = self.part_size_bytes - self.written_in_current;
        let chunk = (buf.len() as u64).min(remaining_in_part) as usize;
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
    exclusion: Option<Arc<OutputExclusion>>,
    write_fn: F,
) -> Result<Vec<PathBuf>, StorageError>
where
    F: FnOnce(&mut SplitVolumeWriter) -> Result<(), StorageError>,
{
    write_split_vault_replacing(
        base_target,
        &[],
        part_size_bytes,
        stealth,
        exclusion,
        write_fn,
    )
}

/// Atomically write and promote split volume parts, removing any trailing obsolete old parts
/// after all new parts succeed.
pub(crate) fn write_split_vault_replacing<F>(
    base_target: &Path,
    obsolete_old_parts: &[PathBuf],
    part_size_bytes: u64,
    stealth: bool,
    exclusion: Option<Arc<OutputExclusion>>,
    write_fn: F,
) -> Result<Vec<PathBuf>, StorageError>
where
    F: FnOnce(&mut SplitVolumeWriter) -> Result<(), StorageError>,
{
    let mut writer = SplitVolumeWriter::new(base_target, part_size_bytes, stealth, exclusion)?;
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
        None => parent_or_dot(src_vault),
    };
    let file_name = src_vault
        .file_name()
        .ok_or_else(|| StorageError::InvalidPath("invalid source vault filename".into()))?;
    let base_target = unique_split_base(&out_parent.join(file_name));

    write_split_vault(&base_target, part_size_bytes, false, None, |writer| {
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
    if set.total_len == 0 {
        return Err(StorageError::InvalidPath(
            "cannot join an empty split volume".into(),
        ));
    }

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

    if path_conflicts_with_split_set(&target, &set) {
        return Err(StorageError::InvalidPath(
            "join output path cannot overwrite or extend the input split volume set".into(),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn has_temp_or_bak(dir: &Path) -> bool {
        fs::read_dir(dir).unwrap().any(|entry| {
            let name = entry.unwrap().file_name().to_string_lossy().into_owned();
            name.starts_with(".rpm_tmp_")
                || name.starts_with(".rpm_bak_")
                || name.ends_with(".part")
        })
    }

    #[test]
    fn commit_step_b_c_d_fault_injection_rollback_and_error_propagation() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("fault.vault");
        let p1 = split_part_path(&base, 1);
        let p2 = split_part_path(&base, 2);
        let p3 = split_part_path(&base, 3);

        // 1) Step C failure during a FRESH split (part 1 promoted, part 2 rename fails)
        //    MUST delete already-promoted `.001` and all staged files.
        let mut w_fresh = SplitVolumeWriter::new(&base, MIN_SPLIT_PART_SIZE, false, None).unwrap();
        w_fresh
            .write_all(&vec![0xAA; (MIN_SPLIT_PART_SIZE as usize) + 128])
            .unwrap();
        let mut rename_calls = 0usize;
        let err = w_fresh
            .commit_with_ops(
                &[],
                |from, to| {
                    rename_calls += 1;
                    if rename_calls == 2 {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "injected Step C part 2 failure",
                        ));
                    }
                    fs::rename(from, to)
                },
                |p| fs::remove_file(p),
            )
            .unwrap_err();
        assert!(matches!(err, StorageError::Io(_)));
        assert!(!p1.exists(), "fresh Step C rollback must remove .001");
        assert!(!p2.exists());
        assert!(!has_temp_or_bak(dir.path()));

        // Seed an existing 3-part volume on disk for overwrite fault injection.
        fs::write(&p1, b"OLD_PART_1").unwrap();
        fs::write(&p2, b"OLD_PART_2").unwrap();
        fs::write(&p3, b"OLD_PART_3").unwrap();
        let old_parts = vec![p1.clone(), p2.clone(), p3.clone()];

        // 2) Step B failure on backup #2 (after backup #1 moved `.001` aside)
        //    MUST restore `.001` and leave all 3 original parts intact.
        let mut w_b = SplitVolumeWriter::new(&base, MIN_SPLIT_PART_SIZE, false, None).unwrap();
        w_b.write_all(&vec![0xBB; (MIN_SPLIT_PART_SIZE as usize) + 64])
            .unwrap();
        let mut step_b_calls = 0usize;
        let err = w_b
            .commit_with_ops(
                &old_parts,
                |from, to| {
                    step_b_calls += 1;
                    if step_b_calls == 2 {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "injected Step B lock on .002",
                        ));
                    }
                    fs::rename(from, to)
                },
                |p| fs::remove_file(p),
            )
            .unwrap_err();
        assert!(matches!(err, StorageError::Io(_)));
        assert_eq!(fs::read(&p1).unwrap(), b"OLD_PART_1");
        assert_eq!(fs::read(&p2).unwrap(), b"OLD_PART_2");
        assert_eq!(fs::read(&p3).unwrap(), b"OLD_PART_3");
        assert!(!has_temp_or_bak(dir.path()));

        // 3) Step C failure on promotion #2 (after all 3 old parts backed up and new `.001` promoted)
        //    MUST delete new `.001` and restore all 3 old parts from backups.
        let mut w_c = SplitVolumeWriter::new(&base, MIN_SPLIT_PART_SIZE, false, None).unwrap();
        w_c.write_all(&vec![0xCC; (MIN_SPLIT_PART_SIZE as usize) + 64])
            .unwrap();
        let mut step_c_calls = 0usize;
        let err = w_c
            .commit_with_ops(
                &old_parts,
                |from, to| {
                    step_c_calls += 1;
                    // Calls 1..=3 are Step B backups; call 4 promotes new .001; call 5 fails on new .002.
                    if step_c_calls == 5 {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "injected Step C promote failure on .002",
                        ));
                    }
                    fs::rename(from, to)
                },
                |p| fs::remove_file(p),
            )
            .unwrap_err();
        assert!(matches!(err, StorageError::Io(_)));
        assert_eq!(fs::read(&p1).unwrap(), b"OLD_PART_1");
        assert_eq!(fs::read(&p2).unwrap(), b"OLD_PART_2");
        assert_eq!(fs::read(&p3).unwrap(), b"OLD_PART_3");
        assert!(!has_temp_or_bak(dir.path()));

        // 4) Step D failure removing backup #1 MUST still delete remaining backups AND propagate error.
        let mut w_d = SplitVolumeWriter::new(&base, MIN_SPLIT_PART_SIZE, false, None).unwrap();
        let new_bytes = vec![0xDD; (MIN_SPLIT_PART_SIZE as usize) + 64];
        w_d.write_all(&new_bytes).unwrap();
        let mut remove_calls = 0usize;
        let mut skipped_bak: Option<PathBuf> = None;
        let err = w_d
            .commit_with_ops(
                &old_parts,
                |from, to| fs::rename(from, to),
                |bak| {
                    remove_calls += 1;
                    if remove_calls == 1 {
                        skipped_bak = Some(bak.to_path_buf());
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "injected Step D remove failure",
                        ));
                    }
                    fs::remove_file(bak)
                },
            )
            .unwrap_err();
        assert!(matches!(err, StorageError::Io(_)));
        assert_eq!(remove_calls, 3, "Step D must attempt all backups");
        assert_eq!(fs::read(&p1).unwrap().len(), MIN_SPLIT_PART_SIZE as usize);
        assert_eq!(fs::read(&p2).unwrap().len(), 64);
        assert!(!p3.exists());
        // Clean up the single intentionally retained backup and verify no others leaked.
        fs::remove_file(skipped_bak.unwrap()).unwrap();
        assert!(!has_temp_or_bak(dir.path()));
    }

    #[cfg(windows)]
    #[test]
    fn windows_os_name_key_matches_ntfs_reflexive_case_pairs() {
        assert_eq!(
            os_name_key(OsStr::new("ŞifreÖzelÜÇĞ.vault")),
            os_name_key(OsStr::new("şifreözelüçğ.vault"))
        );
        // NTFS keeps İ/i, I/ı, K/k, Å/å, ς/Σ as distinct entries.
        assert_ne!(os_name_key(OsStr::new("İ")), os_name_key(OsStr::new("i")));
        assert_ne!(os_name_key(OsStr::new("I")), os_name_key(OsStr::new("ı")));
        assert_ne!(
            os_name_key(OsStr::new("\u{212A}")),
            os_name_key(OsStr::new("k"))
        );
        assert_ne!(
            os_name_key(OsStr::new("\u{212B}")),
            os_name_key(OsStr::new("å"))
        );
        assert_ne!(
            os_name_key(OsStr::new("\u{03C2}")),
            os_name_key(OsStr::new("\u{03A3}"))
        );
        assert_eq!(
            os_name_key(OsStr::new("\u{03C3}")),
            os_name_key(OsStr::new("\u{03A3}"))
        );
    }
}
