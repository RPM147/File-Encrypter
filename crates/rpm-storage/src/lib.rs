//! Streaming archive packaging, atomic I/O, wiping, config, and Windows shell integration.

pub mod atomic;
pub mod config;
pub mod error;
pub mod launch;
pub mod packager;
pub mod pipe;
mod preview;
pub use preview::{
    extract_entry_to_memory_v5, extract_entry_to_memory_v5_with_stealth_kdf,
    extract_entry_to_memory_v5_with_stealth_kdf_and_threads, DEFAULT_PREVIEW_MAX_BYTES,
};
pub mod recovery_sheet;
pub mod shell_integration;
pub mod split;
pub mod wiper;
pub mod workflow;

pub use atomic::atomic_write;
pub use config::{load_config_from, save_config_to, AppConfig, EncryptProfile, ThemeMode};
pub use error::StorageError;
pub use launch::{parse_gui_launch_args, GuiLaunchIntent, LaunchTab};
pub use packager::UnpackLimits;
pub use recovery_sheet::{
    render_recovery_sheet_html, suggested_recovery_sheet_filename, write_recovery_sheet_html,
    RecoverySheetInfo,
};
pub use split::{
    check_vault_integrity, check_vault_integrity_with_parts,
    check_vault_integrity_with_parts_and_threads,
    check_vault_integrity_with_parts_threads_and_cancel, discover_split_parts,
    is_vault_or_split_filename, join_vault_parts, open_vault_reader, parse_split_part_path,
    path_dedup_key, split_part_path, split_vault_file, unique_split_base, validate_split_bounds,
    vault_display_stem, PathDedupKey, SplitDiscoveryCache, SplitVolumePart, SplitVolumeReader,
    SplitVolumeSet, VaultReader, MAX_SPLIT_PARTS, MIN_SPLIT_PART_SIZE,
};
pub use wiper::SecureWiper;
pub use workflow::{
    check_compartment_sources, check_wipe_targets, decrypt_vault_selected_v5, decrypt_vault_v5,
    decrypt_vault_v5_with_stealth_kdf, decrypt_vault_v5_with_stealth_kdf_and_threads,
    encrypt_hidden_sources_v5, encrypt_hidden_sources_v5_split,
    encrypt_hidden_sources_v5_split_with_threads, encrypt_hidden_sources_v5_with_threads,
    encrypt_sources_v5, encrypt_sources_v5_split, encrypt_sources_v5_split_with_threads,
    encrypt_sources_v5_with_threads, rekey_vault_v5, repair_vault_v5, repair_vault_v5_with_threads,
    unique_path, DecryptSummary,
};
