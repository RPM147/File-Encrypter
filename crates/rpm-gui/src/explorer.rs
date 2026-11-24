//! Pure Vault Explorer model: file category classification, filters, and folder tree aggregation.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use rpm_core::FileManifestEntry;
use rpm_storage::DEFAULT_PREVIEW_MAX_BYTES;

use crate::i18n::Strings;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum ManifestViewMode {
    #[default]
    Tree,
    Flat,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FileCategory {
    Text,
    Image,
    Archive,
    Media,
    Other,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum FileCategoryFilter {
    #[default]
    All,
    Text,
    Image,
    Archive,
    Media,
    Other,
}

impl FileCategoryFilter {
    pub const ALL: [Self; 6] = [
        Self::All,
        Self::Text,
        Self::Image,
        Self::Archive,
        Self::Media,
        Self::Other,
    ];

    pub fn localized_label(self, s: &'static Strings) -> &'static str {
        match self {
            Self::All => s.cat_all,
            Self::Text => s.cat_text,
            Self::Image => s.cat_image,
            Self::Archive => s.cat_archive,
            Self::Media => s.cat_media,
            Self::Other => s.cat_other,
        }
    }

    pub fn matches(self, cat: FileCategory) -> bool {
        match self {
            Self::All => true,
            Self::Text => cat == FileCategory::Text,
            Self::Image => cat == FileCategory::Image,
            Self::Archive => cat == FileCategory::Archive,
            Self::Media => cat == FileCategory::Media,
            Self::Other => cat == FileCategory::Other,
        }
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum SizeFilter {
    #[default]
    All,
    PreviewableOnly,
    Under1MiB,
    From1To16MiB,
    Over16MiB,
}

impl SizeFilter {
    pub const ALL: [Self; 5] = [
        Self::All,
        Self::PreviewableOnly,
        Self::Under1MiB,
        Self::From1To16MiB,
        Self::Over16MiB,
    ];

    pub fn localized_label(self, s: &'static Strings) -> &'static str {
        match self {
            Self::All => s.size_all,
            Self::PreviewableOnly => s.size_previewable,
            Self::Under1MiB => s.size_under_1m,
            Self::From1To16MiB => s.size_1_to_16m,
            Self::Over16MiB => s.size_over_16m,
        }
    }

    pub fn matches(self, bytes: u64) -> bool {
        const ONE_MIB: u64 = 1024 * 1024;
        const SIXTEEN_MIB: u64 = 16 * ONE_MIB;
        match self {
            Self::All => true,
            Self::PreviewableOnly => bytes <= DEFAULT_PREVIEW_MAX_BYTES as u64,
            Self::Under1MiB => bytes < ONE_MIB,
            Self::From1To16MiB => (ONE_MIB..=SIXTEEN_MIB).contains(&bytes),
            Self::Over16MiB => bytes > SIXTEEN_MIB,
        }
    }
}

pub fn classify_file_category(path: &str) -> FileCategory {
    let ext = Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase());
    match ext.as_deref() {
        Some(
            "txt" | "md" | "json" | "toml" | "yaml" | "yml" | "xml" | "csv" | "log" | "rs" | "py"
            | "js" | "ts" | "tsx" | "jsx" | "c" | "h" | "cpp" | "hpp" | "java" | "go" | "html"
            | "css" | "sql" | "sh" | "ps1" | "bat" | "ini" | "cfg" | "conf" | "env",
        ) => FileCategory::Text,
        Some("png" | "jpg" | "jpeg" | "webp" | "gif" | "bmp" | "svg" | "ico" | "tif" | "tiff") => {
            FileCategory::Image
        }
        Some("zip" | "tar" | "gz" | "tgz" | "bz2" | "xz" | "7z" | "rar" | "vault") => {
            FileCategory::Archive
        }
        Some(
            "mp3" | "wav" | "flac" | "ogg" | "m4a" | "mp4" | "mkv" | "mov" | "avi" | "webm" | "pdf",
        ) => FileCategory::Media,
        _ => FileCategory::Other,
    }
}

pub fn category_badge(cat: FileCategory) -> &'static str {
    match cat {
        FileCategory::Text => "[TXT]",
        FileCategory::Image => "[IMG]",
        FileCategory::Archive => "[ARC]",
        FileCategory::Media => "[MED]",
        FileCategory::Other => "[BIN]",
    }
}

pub fn file_basename(path: &str) -> &str {
    path.rsplit(['/', '\\'])
        .find(|seg| !seg.is_empty())
        .unwrap_or(path)
}

pub fn matches_filters(
    entry: &FileManifestEntry,
    query_lower: &str,
    category: FileCategoryFilter,
    size: SizeFilter,
) -> bool {
    if !query_lower.is_empty() {
        let norm = entry.path.replace('\\', "/").to_ascii_lowercase();
        if !norm.contains(query_lower) {
            return false;
        }
    }
    if !category.matches(classify_file_category(&entry.path)) {
        return false;
    }
    size.matches(entry.size)
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FolderSelectionState {
    None,
    Partial,
    All,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ManifestTreeNode {
    pub name: String,
    pub full_path: String,
    pub dirs: BTreeMap<String, ManifestTreeNode>,
    pub files: Vec<usize>,
    pub total_files: usize,
    pub total_bytes: u64,
}

impl ManifestTreeNode {
    fn sort_and_aggregate(&mut self, manifest: &[FileManifestEntry]) {
        self.files.sort_by(|&a, &b| {
            let pa = &manifest[a].path;
            let pb = &manifest[b].path;
            let ba = file_basename(pa).to_ascii_lowercase();
            let bb = file_basename(pb).to_ascii_lowercase();
            ba.cmp(&bb).then_with(|| pa.cmp(pb))
        });

        let mut total_files = self.files.len();
        let mut total_bytes: u64 = self
            .files
            .iter()
            .map(|&idx| manifest[idx].size)
            .fold(0u64, u64::saturating_add);

        for child in self.dirs.values_mut() {
            child.sort_and_aggregate(manifest);
            total_files = total_files.saturating_add(child.total_files);
            total_bytes = total_bytes.saturating_add(child.total_bytes);
        }

        self.total_files = total_files;
        self.total_bytes = total_bytes;
    }
}

pub fn build_manifest_tree(manifest: &[FileManifestEntry], indices: &[usize]) -> ManifestTreeNode {
    let mut root = ManifestTreeNode::default();
    for &idx in indices {
        let Some(entry) = manifest.get(idx) else {
            continue;
        };
        let segments: Vec<&str> = entry
            .path
            .split(['/', '\\'])
            .filter(|s| !s.is_empty())
            .collect();
        if segments.is_empty() {
            continue;
        }
        let mut node = &mut root;
        for &dir_seg in &segments[..segments.len() - 1] {
            let next_path = if node.full_path.is_empty() {
                dir_seg.to_owned()
            } else {
                format!("{}/{dir_seg}", node.full_path)
            };
            node = node
                .dirs
                .entry(dir_seg.to_owned())
                .or_insert_with(|| ManifestTreeNode {
                    name: dir_seg.to_owned(),
                    full_path: next_path,
                    ..Default::default()
                });
        }
        node.files.push(idx);
    }
    root.sort_and_aggregate(manifest);
    root
}

fn count_selected_in_subtree(
    node: &ManifestTreeNode,
    manifest: &[FileManifestEntry],
    selected: &HashSet<String>,
) -> (usize, usize) {
    let mut sel_count = 0usize;
    let mut tot_count = 0usize;
    for &idx in &node.files {
        if let Some(entry) = manifest.get(idx) {
            tot_count += 1;
            if selected.contains(&entry.path) {
                sel_count += 1;
            }
        }
    }
    for child in node.dirs.values() {
        let (cs, ct) = count_selected_in_subtree(child, manifest, selected);
        sel_count += cs;
        tot_count += ct;
    }
    (sel_count, tot_count)
}

pub fn folder_selection_state(
    node: &ManifestTreeNode,
    manifest: &[FileManifestEntry],
    selected: &HashSet<String>,
) -> FolderSelectionState {
    let (sel_count, tot_count) = count_selected_in_subtree(node, manifest, selected);
    if sel_count == 0 || tot_count == 0 {
        FolderSelectionState::None
    } else if sel_count == tot_count {
        FolderSelectionState::All
    } else {
        FolderSelectionState::Partial
    }
}

pub fn set_folder_selection(
    node: &ManifestTreeNode,
    manifest: &[FileManifestEntry],
    selected: &mut HashSet<String>,
    select: bool,
) {
    for &idx in &node.files {
        if let Some(entry) = manifest.get(idx) {
            if select {
                selected.insert(entry.path.clone());
            } else {
                selected.remove(&entry.path);
            }
        }
    }
    for child in node.dirs.values() {
        set_folder_selection(child, manifest, selected, select);
    }
}
