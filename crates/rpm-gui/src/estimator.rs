//! Pre-flight source scanning, Vault v5 size/RS overhead math, and container fit estimation.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use rpm_core::constants::{DEFAULT_CHUNK_SIZE, HIDDEN_MINI_HEADER_WIRE_SIZE};
use rpm_core::rs::{RS_BLOCK_DATA_CAP, RS_BLOCK_WIRE_SIZE};

use crate::state::{
    ContainerSizeError, ContainerSizePreset, SplitSizeError, SplitSizePreset, CONTAINER_MAX_MIB,
    CONTAINER_MIB,
};

pub const MAX_SCAN_ENTRIES: u64 = 250_000;
pub const RS_HEADER_BYTES: u64 = 48;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SourceSizeSummary {
    pub file_count: u64,
    pub dir_count: u64,
    pub raw_bytes: u64,
    pub skipped_symlinks: u64,
    pub unreadable_entries: u64,
    pub truncated: bool,
}

impl SourceSizeSummary {
    pub fn total_entries(&self) -> u64 {
        self.file_count.saturating_add(self.dir_count)
    }
}

fn scan_path_recursive(
    path: &std::path::Path,
    summary: &mut SourceSizeSummary,
    cancel: &AtomicBool,
) -> Option<()> {
    if cancel.load(Ordering::Relaxed) {
        return None;
    }
    if summary.total_entries() >= MAX_SCAN_ENTRIES {
        summary.truncated = true;
        return Some(());
    }
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => {
            summary.unreadable_entries = summary.unreadable_entries.saturating_add(1);
            return Some(());
        }
    };
    if meta.file_type().is_symlink() {
        summary.skipped_symlinks = summary.skipped_symlinks.saturating_add(1);
        return Some(());
    }
    if meta.is_file() {
        summary.file_count = summary.file_count.saturating_add(1);
        summary.raw_bytes = summary.raw_bytes.saturating_add(meta.len());
        return Some(());
    }
    if meta.is_dir() {
        summary.dir_count = summary.dir_count.saturating_add(1);
        let entries = match fs::read_dir(path) {
            Ok(iter) => iter,
            Err(_) => {
                summary.unreadable_entries = summary.unreadable_entries.saturating_add(1);
                return Some(());
            }
        };
        for entry in entries {
            if cancel.load(Ordering::Relaxed) {
                return None;
            }
            if summary.total_entries() >= MAX_SCAN_ENTRIES {
                summary.truncated = true;
                break;
            }
            match entry {
                Ok(dir_entry) => scan_path_recursive(&dir_entry.path(), summary, cancel)?,
                Err(_) => {
                    summary.unreadable_entries = summary.unreadable_entries.saturating_add(1);
                }
            }
        }
    }
    Some(())
}

/// Recursively measure files and directories without following symlinks (matching `packager.rs`).
/// Returns `None` if cancelled before completion.
pub fn scan_sources_sync(paths: &[PathBuf], cancel: &AtomicBool) -> Option<SourceSizeSummary> {
    let mut summary = SourceSizeSummary::default();
    for path in paths {
        scan_path_recursive(path, &mut summary, cancel)?;
        if summary.truncated {
            break;
        }
    }
    Some(summary)
}

/// Exact Reed-Solomon envelope size in bytes for an inner Vault v5 byte stream of `inner_bytes`.
pub fn rs_wire_size(inner_bytes: u64) -> u64 {
    let blocks = inner_bytes.max(1).div_ceil(RS_BLOCK_DATA_CAP as u64);
    RS_HEADER_BYTES.saturating_add(blocks.saturating_mul(RS_BLOCK_WIRE_SIZE as u64))
}

fn estimate_compartment_bytes(summary: &SourceSizeSummary, include_outer_header: bool) -> u64 {
    let tar_bytes = summary
        .raw_bytes
        .saturating_add(summary.file_count.saturating_mul(1024))
        .saturating_add(summary.dir_count.saturating_mul(512))
        .saturating_add(1024);
    let meta_base: u64 = if include_outer_header { 4096 } else { 2048 };
    let meta_bytes = meta_base.saturating_add(summary.file_count.saturating_mul(96));
    let chunks = tar_bytes.max(1).div_ceil(u64::from(DEFAULT_CHUNK_SIZE));
    let chunk_overhead = chunks.saturating_mul(20);
    meta_bytes
        .saturating_add(tar_bytes)
        .saturating_add(chunk_overhead)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContainerFitStatus {
    NoContainer,
    InvalidContainer(ContainerSizeError),
    Fits {
        used_bytes: u64,
        container_bytes: u64,
        free_bytes: u64,
    },
    CompressionDependent {
        required_uncompressed: u64,
        container_bytes: u64,
        suggested_mib: u64,
    },
    ExceedsContainer {
        required_bytes: u64,
        container_bytes: u64,
        suggested_mib: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SplitEstimateStatus {
    Off,
    Invalid(SplitSizeError),
    TooManyParts {
        part_bytes: u64,
        estimated_parts: u64,
    },
    Parts {
        part_bytes: u64,
        estimated_parts: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptPreflightEstimate {
    pub outer: SourceSizeSummary,
    pub hidden: SourceSizeSummary,
    pub outer_estimated_bytes: u64,
    pub hidden_estimated_bytes: u64,
    pub total_inner_required_bytes: u64,
    pub estimated_disk_bytes: u64,
    pub rs_overhead_bytes: u64,
    pub fit: ContainerFitStatus,
    pub split: SplitEstimateStatus,
}

#[allow(clippy::too_many_arguments)]
pub fn estimate_encrypt_preflight(
    outer: &SourceSizeSummary,
    hidden: &SourceSizeSummary,
    enable_hidden: bool,
    compress: bool,
    hidden_compress: bool,
    reed_solomon: bool,
    container_preset: ContainerSizePreset,
    container_custom_mb: &str,
) -> EncryptPreflightEstimate {
    estimate_encrypt_preflight_with_split(
        outer,
        hidden,
        enable_hidden,
        compress,
        hidden_compress,
        reed_solomon,
        container_preset,
        container_custom_mb,
        SplitSizePreset::None,
        "",
    )
}

#[allow(clippy::too_many_arguments)]
pub fn estimate_encrypt_preflight_with_split(
    outer: &SourceSizeSummary,
    hidden: &SourceSizeSummary,
    enable_hidden: bool,
    compress: bool,
    hidden_compress: bool,
    reed_solomon: bool,
    container_preset: ContainerSizePreset,
    container_custom_mb: &str,
    split_preset: SplitSizePreset,
    split_custom_mb: &str,
) -> EncryptPreflightEstimate {
    let outer_estimated_bytes = estimate_compartment_bytes(outer, true);
    let hidden_estimated_bytes = if enable_hidden {
        estimate_compartment_bytes(hidden, false)
    } else {
        0
    };
    let mut total_inner_required_bytes = outer_estimated_bytes;
    if enable_hidden {
        total_inner_required_bytes = total_inner_required_bytes
            .saturating_add(hidden_estimated_bytes)
            .saturating_add(HIDDEN_MINI_HEADER_WIRE_SIZE as u64);
    }

    let resolved_container = match container_preset.resolve_bytes(container_custom_mb) {
        Ok(Some(bytes)) => Ok(Some(bytes)),
        Ok(None) if enable_hidden => Err(ContainerSizeError::RequiredForHidden),
        Ok(None) => Ok(None),
        Err(err) => Err(err),
    };

    let (inner_base, fit) = match resolved_container {
        Err(err) => (
            total_inner_required_bytes,
            ContainerFitStatus::InvalidContainer(err),
        ),
        Ok(None) => (total_inner_required_bytes, ContainerFitStatus::NoContainer),
        Ok(Some(container_bytes)) => {
            let any_compressed = compress || (enable_hidden && hidden_compress);
            if total_inner_required_bytes <= container_bytes {
                (
                    container_bytes,
                    ContainerFitStatus::Fits {
                        used_bytes: total_inner_required_bytes,
                        container_bytes,
                        free_bytes: container_bytes - total_inner_required_bytes,
                    },
                )
            } else {
                let mut suggested_mib = total_inner_required_bytes
                    .div_ceil(CONTAINER_MIB)
                    .clamp(1, CONTAINER_MAX_MIB);
                let near_full = total_inner_required_bytes.saturating_mul(20)
                    >= suggested_mib
                        .saturating_mul(CONTAINER_MIB)
                        .saturating_mul(19);
                if (enable_hidden || near_full) && suggested_mib < CONTAINER_MAX_MIB {
                    suggested_mib += 1;
                }
                let status = if any_compressed {
                    ContainerFitStatus::CompressionDependent {
                        required_uncompressed: total_inner_required_bytes,
                        container_bytes,
                        suggested_mib,
                    }
                } else {
                    ContainerFitStatus::ExceedsContainer {
                        required_bytes: total_inner_required_bytes,
                        container_bytes,
                        suggested_mib,
                    }
                };
                (container_bytes, status)
            }
        }
    };

    let estimated_disk_bytes = if reed_solomon {
        rs_wire_size(inner_base)
    } else {
        inner_base
    };
    let rs_overhead_bytes = if reed_solomon {
        estimated_disk_bytes.saturating_sub(inner_base)
    } else {
        0
    };

    let split = match split_preset.resolve_bytes(split_custom_mb) {
        Ok(None) => SplitEstimateStatus::Off,
        Ok(Some(part_bytes)) => {
            let estimated_parts = estimated_disk_bytes.max(1).div_ceil(part_bytes);
            if estimated_parts > rpm_storage::MAX_SPLIT_PARTS as u64 {
                SplitEstimateStatus::TooManyParts {
                    part_bytes,
                    estimated_parts,
                }
            } else {
                SplitEstimateStatus::Parts {
                    part_bytes,
                    estimated_parts,
                }
            }
        }
        Err(err) => SplitEstimateStatus::Invalid(err),
    };

    EncryptPreflightEstimate {
        outer: outer.clone(),
        hidden: hidden.clone(),
        outer_estimated_bytes,
        hidden_estimated_bytes,
        total_inner_required_bytes,
        estimated_disk_bytes,
        rs_overhead_bytes,
        fit,
        split,
    }
}
