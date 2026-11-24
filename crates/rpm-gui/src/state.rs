//! GUI state, launch routing, drag-and-drop triage, and zeroizing field management.

use std::collections::{HashSet, VecDeque};
use std::ops::RangeInclusive;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use eframe::egui;
use rand::rngs::OsRng;
use rand::Rng;
use rpm_core::constants::{MAX_CONTAINER_SIZE, MIN_CONTAINER_SIZE};
use rpm_core::{CryptoError, FileManifestEntry, KdfParams, SecretKey};
use rpm_storage::config::{
    default_config_path, load_config_from, save_config_to, AppConfig, AppLanguage, EncryptProfile,
    ThemeMode, MAX_ENCRYPT_PROFILES, MAX_IDLE_CLEAR_MINUTES,
};
use rpm_storage::shell_integration::{self, ShellIntegrationStatus};
use rpm_storage::{
    is_vault_or_split_filename, path_dedup_key, GuiLaunchIntent, LaunchTab, PathDedupKey,
    SplitDiscoveryCache, MAX_SPLIT_PARTS,
};
use zeroize::Zeroize;

use crate::estimator::{
    estimate_encrypt_preflight_with_split, rs_wire_size, EncryptPreflightEstimate,
    SourceSizeSummary,
};
use crate::explorer::{matches_filters, FileCategoryFilter, ManifestViewMode, SizeFilter};
use crate::i18n::{self, Strings};
use crate::progress::TransferSnapshot;
use crate::queue::{format_job_label, QueuedJob, QueuedJobKind};

pub const CONTAINER_MIB: u64 = 1024 * 1024;
pub const CONTAINER_MAX_MIB: u64 = MAX_CONTAINER_SIZE / CONTAINER_MIB;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ContainerSizePreset {
    Auto,
    MiB10,
    MiB50,
    MiB100,
    MiB500,
    Custom,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ContainerSizeError {
    InvalidCustomValue,
    OutOfRange,
    RequiredForHidden,
}

impl ContainerSizePreset {
    pub const ALL: [ContainerSizePreset; 6] = [
        ContainerSizePreset::Auto,
        ContainerSizePreset::MiB10,
        ContainerSizePreset::MiB50,
        ContainerSizePreset::MiB100,
        ContainerSizePreset::MiB500,
        ContainerSizePreset::Custom,
    ];

    pub fn localized_label(self, s: &'static Strings) -> &'static str {
        match self {
            Self::Auto => s.container_auto,
            Self::MiB10 => s.container_10_mib,
            Self::MiB50 => s.container_50_mib,
            Self::MiB100 => s.container_100_mib,
            Self::MiB500 => s.container_500_mib,
            Self::Custom => s.container_custom,
        }
    }

    pub fn resolve_bytes(self, custom_mb: &str) -> Result<Option<u64>, ContainerSizeError> {
        let bytes = match self {
            Self::Auto => return Ok(None),
            Self::MiB10 => 10 * CONTAINER_MIB,
            Self::MiB50 => 50 * CONTAINER_MIB,
            Self::MiB100 => 100 * CONTAINER_MIB,
            Self::MiB500 => 500 * CONTAINER_MIB,
            Self::Custom => {
                let parsed: u64 = custom_mb
                    .trim()
                    .parse()
                    .map_err(|_| ContainerSizeError::InvalidCustomValue)?;
                if parsed == 0 {
                    return Err(ContainerSizeError::InvalidCustomValue);
                }
                parsed
                    .checked_mul(CONTAINER_MIB)
                    .ok_or(ContainerSizeError::OutOfRange)?
            }
        };
        if !(MIN_CONTAINER_SIZE..=MAX_CONTAINER_SIZE).contains(&bytes) {
            return Err(ContainerSizeError::OutOfRange);
        }
        Ok(Some(bytes))
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SplitSizePreset {
    None,
    MiB25,
    MiB100,
    MiB500,
    MiB2000,
    MiB4000Fat32,
    Custom,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SplitSizeError {
    InvalidCustomValue,
    OutOfRange,
    TooManyParts,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProfileSnapshotError {
    Container(ContainerSizeError),
    Split(SplitSizeError),
}

impl SplitSizePreset {
    pub const ALL: [SplitSizePreset; 7] = [
        SplitSizePreset::None,
        SplitSizePreset::MiB25,
        SplitSizePreset::MiB100,
        SplitSizePreset::MiB500,
        SplitSizePreset::MiB2000,
        SplitSizePreset::MiB4000Fat32,
        SplitSizePreset::Custom,
    ];

    pub const STANDALONE_ALL: [SplitSizePreset; 6] = [
        SplitSizePreset::MiB25,
        SplitSizePreset::MiB100,
        SplitSizePreset::MiB500,
        SplitSizePreset::MiB2000,
        SplitSizePreset::MiB4000Fat32,
        SplitSizePreset::Custom,
    ];

    pub fn localized_label(self, s: &'static Strings) -> &'static str {
        match self {
            Self::None => s.split_none,
            Self::MiB25 => s.split_25_mib,
            Self::MiB100 => s.split_100_mib,
            Self::MiB500 => s.split_500_mib,
            Self::MiB2000 => s.split_2000_mib,
            Self::MiB4000Fat32 => s.split_4000_fat32,
            Self::Custom => s.split_custom,
        }
    }

    pub fn from_mib(mib: Option<u64>) -> (Self, Option<String>) {
        match mib {
            None => (Self::None, None),
            Some(25) => (Self::MiB25, None),
            Some(100) => (Self::MiB100, None),
            Some(500) => (Self::MiB500, None),
            Some(2000) => (Self::MiB2000, None),
            Some(4000) => (Self::MiB4000Fat32, None),
            Some(other) => (Self::Custom, Some(other.to_string())),
        }
    }

    pub fn resolve_bytes(self, custom_mb: &str) -> Result<Option<u64>, SplitSizeError> {
        let bytes = match self {
            Self::None => return Ok(None),
            Self::MiB25 => 25 * CONTAINER_MIB,
            Self::MiB100 => 100 * CONTAINER_MIB,
            Self::MiB500 => 500 * CONTAINER_MIB,
            Self::MiB2000 => 2000 * CONTAINER_MIB,
            Self::MiB4000Fat32 => 4000 * CONTAINER_MIB,
            Self::Custom => {
                let parsed: u64 = custom_mb
                    .trim()
                    .parse()
                    .map_err(|_| SplitSizeError::InvalidCustomValue)?;
                if parsed == 0 {
                    return Err(SplitSizeError::InvalidCustomValue);
                }
                parsed
                    .checked_mul(CONTAINER_MIB)
                    .ok_or(SplitSizeError::OutOfRange)?
            }
        };
        if !(MIN_CONTAINER_SIZE..=MAX_CONTAINER_SIZE).contains(&bytes) {
            return Err(SplitSizeError::OutOfRange);
        }
        Ok(Some(bytes))
    }
}

pub const UI_SCALE_PRESETS: [u16; 7] = [80, 90, 100, 110, 120, 130, 150];
pub const UI_SCALE_MIN: u16 = 80;
pub const UI_SCALE_MAX: u16 = 150;
pub const UI_SCALE_DEFAULT: u16 = 100;

pub const IDLE_CLEAR_PRESET_MINUTES: [u16; 5] = [0, 1, 5, 15, 30];

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SessionClearReason {
    ManualPanic,
    IdleTimeout,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LastCompletedAction {
    pub summary: String,
    pub reveal_path: PathBuf,
    pub verify_vault: Option<PathBuf>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BuiltinEncryptPreset {
    DailyBackup,
    LongTermArchiveRs,
    MaximumPrivacyStealth,
}

impl BuiltinEncryptPreset {
    pub const ALL: [BuiltinEncryptPreset; 3] = [
        Self::DailyBackup,
        Self::LongTermArchiveRs,
        Self::MaximumPrivacyStealth,
    ];

    pub fn localized_label(self, s: &'static Strings) -> &'static str {
        match self {
            Self::DailyBackup => s.profile_builtin_daily,
            Self::LongTermArchiveRs => s.profile_builtin_archive_rs,
            Self::MaximumPrivacyStealth => s.profile_builtin_stealth,
        }
    }

    pub fn to_profile(self, s: &'static Strings) -> EncryptProfile {
        match self {
            Self::DailyBackup => EncryptProfile {
                name: self.localized_label(s).to_owned(),
                compress: true,
                stealth: false,
                reed_solomon: false,
                secure_wipe: false,
                container_size_mib: None,
                split_part_mib: None,
                save_next_to_source: true,
                output_dir: String::new(),
                keyfile_path: None,
            },
            Self::LongTermArchiveRs => EncryptProfile {
                name: self.localized_label(s).to_owned(),
                compress: true,
                stealth: false,
                reed_solomon: true,
                secure_wipe: false,
                container_size_mib: None,
                split_part_mib: None,
                save_next_to_source: true,
                output_dir: String::new(),
                keyfile_path: None,
            },
            Self::MaximumPrivacyStealth => EncryptProfile {
                name: self.localized_label(s).to_owned(),
                compress: true,
                stealth: true,
                reed_solomon: false,
                secure_wipe: false,
                container_size_mib: Some(100),
                split_part_mib: None,
                save_next_to_source: true,
                output_dir: String::new(),
                keyfile_path: None,
            },
        }
    }
}

pub const ARGON_ITERATIONS_RANGE: RangeInclusive<u32> = 1..=10;
pub const ARGON_PARALLELISM_RANGE: RangeInclusive<u32> = 1..=16;

pub const PWGEN_UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
pub const PWGEN_LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
pub const PWGEN_DIGITS: &[u8] = b"0123456789";
pub const PWGEN_SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{}";
pub const PWGEN_AMBIGUOUS: &[u8] = b"0O1lI";

pub fn clamp_ui_scale_percent(percent: u16) -> u16 {
    percent.clamp(UI_SCALE_MIN, UI_SCALE_MAX)
}

pub fn ui_scale_zoom_factor(percent: u16) -> f32 {
    f32::from(clamp_ui_scale_percent(percent)) / 100.0
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Tab {
    Encrypt,
    Decrypt,
    Inspect,
    Rekey,
    Password,
    Settings,
}

impl Tab {
    pub const ALL: [Tab; 6] = [
        Tab::Encrypt,
        Tab::Decrypt,
        Tab::Inspect,
        Tab::Rekey,
        Tab::Password,
        Tab::Settings,
    ];

    pub fn label(self) -> &'static str {
        self.localized_label(&i18n::EN)
    }

    pub fn localized_label(self, s: &'static Strings) -> &'static str {
        match self {
            Tab::Encrypt => s.tab_encrypt,
            Tab::Decrypt => s.tab_decrypt,
            Tab::Inspect => s.tab_inspect,
            Tab::Rekey => s.tab_rekey,
            Tab::Password => s.tab_password,
            Tab::Settings => s.tab_settings,
        }
    }
}

#[derive(Debug)]
pub enum WorkerUpdate {
    PreviewDone {
        gen: u64,
        path: String,
        bytes: zeroize::Zeroizing<Vec<u8>>,
        status: String,
    },
    PreviewError {
        gen: u64,
        message: String,
        cancelled: bool,
    },
    Progress(TransferSnapshot),
    Log(String),
    EncryptDone {
        status: String,
        output_path: PathBuf,
    },
    DecryptDone {
        status: String,
        output_path: Option<PathBuf>,
    },
    InspectDone {
        text: String,
        status: String,
        manifest: Vec<FileManifestEntry>,
        vault_path: PathBuf,
    },
    RepairDone {
        text: String,
        vault_path: PathBuf,
    },
    IntegrityDone {
        sha256_only: bool,
        text: String,
        ok: bool,
    },
    DiffDone {
        text: String,
        status: String,
    },
    RekeyDone {
        status: String,
        vault_path: PathBuf,
    },
    SplitDone {
        status: String,
        first_part: PathBuf,
    },
    JoinDone {
        status: String,
        output_path: PathBuf,
    },
    SourceScanDone {
        gen: u64,
        outer: SourceSizeSummary,
        hidden: SourceSizeSummary,
    },
    Error(String),
}

pub struct RecoveryPrompt {
    pub phrase: String,
    pub entropy: SecretKey,
    pub confirmed: bool,
    pub queue_after_confirm: bool,
}

impl Drop for RecoveryPrompt {
    fn drop(&mut self) {
        self.phrase.zeroize();
    }
}

pub struct EncryptFields {
    pub reed_solomon: bool,
    pub stealth: bool,
    pub sources: Vec<PathBuf>,
    pub keyfile: Option<PathBuf>,
    pub password: String,
    pub confirm_password: String,
    pub show_password: bool,
    pub compress: bool,
    pub secure_wipe: bool,
    pub save_next_to_source: bool,
    pub output_dir: String,
    pub recovery_prompt: Option<RecoveryPrompt>,
    pub container_preset: ContainerSizePreset,
    pub container_custom_mb: String,
    pub split_preset: SplitSizePreset,
    pub split_custom_mb: String,
    pub enable_hidden: bool,
    pub hidden_sources: Vec<PathBuf>,
    pub hidden_keyfile: Option<PathBuf>,
    pub hidden_password: String,
    pub hidden_confirm_password: String,
    pub show_hidden_password: bool,
    pub hidden_compress: bool,
    pub profile_name_input: String,
    pub selected_profile_name: Option<String>,
    pub preflight_outer: SourceSizeSummary,
    pub preflight_hidden: SourceSizeSummary,
    pub preflight_scanning: bool,
    pub(crate) preflight_scan_gen: u64,
    pub(crate) preflight_scan_cancel: Option<Arc<AtomicBool>>,
    pub(crate) preflight_scanned_key: (Vec<PathBuf>, Vec<PathBuf>),
}

impl EncryptFields {
    pub fn set_stealth(&mut self, on: bool) {
        self.stealth = on;
        if on {
            self.reed_solomon = false;
        }
    }
    pub fn set_reed_solomon(&mut self, on: bool) {
        self.reed_solomon = on;
        if on {
            self.stealth = false;
        }
    }

    pub fn resolve_container_size(&self) -> Result<Option<u64>, ContainerSizeError> {
        let resolved = self
            .container_preset
            .resolve_bytes(&self.container_custom_mb)?;
        if self.enable_hidden && resolved.is_none() {
            return Err(ContainerSizeError::RequiredForHidden);
        }
        Ok(resolved)
    }

    pub fn resolve_split_size(&self) -> Result<Option<u64>, SplitSizeError> {
        self.split_preset.resolve_bytes(&self.split_custom_mb)
    }

    pub fn set_hidden_enabled(&mut self, enabled: bool) {
        self.enable_hidden = enabled;
        if enabled && self.container_preset == ContainerSizePreset::Auto {
            self.container_preset = ContainerSizePreset::MiB50;
        }
    }

    pub fn add_hidden_sources(&mut self, paths: Vec<PathBuf>) -> usize {
        let mut seen: HashSet<PathDedupKey> = self
            .hidden_sources
            .iter()
            .map(|p| path_dedup_key(p))
            .collect();
        let mut added = 0usize;
        for p in paths {
            if seen.insert(path_dedup_key(&p)) {
                self.hidden_sources.push(p);
                added += 1;
            }
        }
        added
    }

    pub fn current_profile_snapshot(
        &self,
        name: String,
    ) -> Result<EncryptProfile, ProfileSnapshotError> {
        let container_bytes = self
            .container_preset
            .resolve_bytes(&self.container_custom_mb)
            .map_err(ProfileSnapshotError::Container)?;
        let split_bytes = self
            .split_preset
            .resolve_bytes(&self.split_custom_mb)
            .map_err(ProfileSnapshotError::Split)?;
        if let (Some(c_bytes), Some(s_bytes)) = (container_bytes, split_bytes) {
            let disk_bytes = if self.reed_solomon {
                rs_wire_size(c_bytes)
            } else {
                c_bytes
            };
            if disk_bytes.div_ceil(s_bytes) > MAX_SPLIT_PARTS as u64 {
                return Err(ProfileSnapshotError::Split(SplitSizeError::TooManyParts));
            }
        }
        let container_size_mib = container_bytes.map(|bytes| bytes / CONTAINER_MIB);
        let split_part_mib = split_bytes.map(|bytes| bytes / CONTAINER_MIB);
        Ok(EncryptProfile {
            name,
            compress: self.compress,
            stealth: self.stealth,
            reed_solomon: self.reed_solomon,
            secure_wipe: self.secure_wipe,
            container_size_mib,
            split_part_mib,
            save_next_to_source: self.save_next_to_source,
            output_dir: self.output_dir.clone(),
            keyfile_path: self.keyfile.clone(),
        })
    }

    pub fn preflight_estimate(&self) -> EncryptPreflightEstimate {
        estimate_encrypt_preflight_with_split(
            &self.preflight_outer,
            &self.preflight_hidden,
            self.enable_hidden,
            self.compress,
            self.hidden_compress,
            self.reed_solomon,
            self.container_preset,
            &self.container_custom_mb,
            self.split_preset,
            &self.split_custom_mb,
        )
    }

    pub fn cancel_preflight_scan(&mut self) {
        if let Some(flag) = self.preflight_scan_cancel.take() {
            flag.store(true, Ordering::Relaxed);
        }
        self.preflight_scanning = false;
    }
}

impl Drop for EncryptFields {
    fn drop(&mut self) {
        self.cancel_preflight_scan();
        self.password.zeroize();
        self.confirm_password.zeroize();
        self.hidden_password.zeroize();
        self.hidden_confirm_password.zeroize();
    }
}

pub struct DecryptFields {
    pub vaults: Vec<PathBuf>,
    pub keyfile: Option<PathBuf>,
    pub use_recovery: bool,
    pub password: String,
    pub show_password: bool,
    pub recovery_phrase: String,
    pub output_dir: String,
}

impl Drop for DecryptFields {
    fn drop(&mut self) {
        self.password.zeroize();
        self.recovery_phrase.zeroize();
    }
}

pub struct InspectFields {
    pub preview: Option<crate::preview::PreviewState>,
    pub(crate) preview_gen: u64,
    pub(crate) preview_pending: Option<(u64, std::sync::Arc<std::sync::atomic::AtomicBool>)>,
    pub vault_path: String,
    pub keyfile: Option<PathBuf>,
    pub use_recovery: bool,
    pub password: String,
    pub show_password: bool,
    pub recovery_phrase: String,
    pub results: String,
    pub manifest: Vec<FileManifestEntry>,
    pub manifest_vault: Option<PathBuf>,
    pub selected_paths: HashSet<String>,
    pub filter_query: String,
    pub view_mode: ManifestViewMode,
    pub category_filter: FileCategoryFilter,
    pub size_filter: SizeFilter,
    pub tree_default_open: bool,
    pub tree_id_epoch: u64,
    pub extract_output_dir: String,
}

impl InspectFields {
    pub fn clear_preview(&mut self) {
        self.preview = None;
        if let Some((_, cancel)) = self.preview_pending.take() {
            cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }

    pub(crate) fn begin_preview(&mut self) -> (u64, std::sync::Arc<std::sync::atomic::AtomicBool>) {
        self.clear_preview();
        self.preview_gen = self.preview_gen.wrapping_add(1);
        let gen = self.preview_gen;
        let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        self.preview_pending = Some((gen, std::sync::Arc::clone(&cancel)));
        (gen, cancel)
    }
    pub fn set_manifest(&mut self, vault: PathBuf, entries: Vec<FileManifestEntry>) {
        self.clear_preview();
        if self.extract_output_dir.trim().is_empty() {
            if let Some(parent) = vault.parent().filter(|p| !p.as_os_str().is_empty()) {
                self.extract_output_dir = parent.display().to_string();
            }
        }
        self.tree_default_open = entries.len() <= 200;
        self.tree_id_epoch = self.tree_id_epoch.wrapping_add(1);
        self.manifest = entries;
        self.manifest_vault = Some(vault);
        self.selected_paths.clear();
        self.reset_filters();
    }

    pub fn reset_manifest(&mut self) {
        self.clear_preview();
        self.manifest.clear();
        self.manifest_vault = None;
        self.selected_paths.clear();
        self.tree_default_open = true;
        self.tree_id_epoch = self.tree_id_epoch.wrapping_add(1);
        self.reset_filters();
    }

    pub fn expand_all_tree(&mut self) {
        self.tree_default_open = true;
        self.tree_id_epoch = self.tree_id_epoch.wrapping_add(1);
    }

    pub fn collapse_all_tree(&mut self) {
        self.tree_default_open = false;
        self.tree_id_epoch = self.tree_id_epoch.wrapping_add(1);
    }

    pub fn has_active_filters(&self) -> bool {
        !self.filter_query.trim().is_empty()
            || self.category_filter != FileCategoryFilter::All
            || self.size_filter != SizeFilter::All
    }

    pub fn reset_filters(&mut self) {
        self.filter_query.clear();
        self.category_filter = FileCategoryFilter::All;
        self.size_filter = SizeFilter::All;
    }

    pub fn filtered_indices(&self) -> Vec<usize> {
        let q = self
            .filter_query
            .trim()
            .replace('\\', "/")
            .to_ascii_lowercase();
        if q.is_empty()
            && self.category_filter == FileCategoryFilter::All
            && self.size_filter == SizeFilter::All
        {
            return (0..self.manifest.len()).collect();
        }
        self.manifest
            .iter()
            .enumerate()
            .filter(|(_, e)| matches_filters(e, &q, self.category_filter, self.size_filter))
            .map(|(i, _)| i)
            .collect()
    }

    pub fn selected_total_bytes(&self) -> u64 {
        self.manifest
            .iter()
            .filter(|e| self.selected_paths.contains(&e.path))
            .map(|e| e.size)
            .fold(0u64, u64::saturating_add)
    }

    pub fn select_all_filtered(&mut self) {
        for idx in self.filtered_indices() {
            if let Some(entry) = self.manifest.get(idx) {
                self.selected_paths.insert(entry.path.clone());
            }
        }
    }

    pub fn clear_selection(&mut self) {
        self.selected_paths.clear();
    }
}

impl Drop for InspectFields {
    fn drop(&mut self) {
        self.clear_preview();
        self.password.zeroize();
        self.recovery_phrase.zeroize();
    }
}

pub struct DiffFields {
    pub vault_a_path: String,
    pub keyfile_a: Option<PathBuf>,
    pub use_recovery_a: bool,
    pub password_a: String,
    pub show_password_a: bool,
    pub recovery_phrase_a: String,
    pub vault_b_path: String,
    pub keyfile_b: Option<PathBuf>,
    pub use_recovery_b: bool,
    pub password_b: String,
    pub show_password_b: bool,
    pub recovery_phrase_b: String,
    pub results: String,
}

impl Drop for DiffFields {
    fn drop(&mut self) {
        self.password_a.zeroize();
        self.recovery_phrase_a.zeroize();
        self.password_b.zeroize();
        self.recovery_phrase_b.zeroize();
    }
}

pub struct RekeyFields {
    pub vault_path: String,
    pub current_keyfile: Option<PathBuf>,
    pub new_keyfile: Option<PathBuf>,
    pub keep_same_keyfile: bool,
    pub current_password: String,
    pub new_password: String,
    pub confirm_password: String,
    pub show_password: bool,
}

impl Drop for RekeyFields {
    fn drop(&mut self) {
        self.current_password.zeroize();
        self.new_password.zeroize();
        self.confirm_password.zeroize();
    }
}

pub struct PasswordGenFields {
    pub length: usize,
    pub include_uppercase: bool,
    pub include_lowercase: bool,
    pub include_digits: bool,
    pub include_symbols: bool,
    pub exclude_ambiguous: bool,
    pub generated: String,
}

impl Default for PasswordGenFields {
    fn default() -> Self {
        Self {
            length: 24,
            include_uppercase: true,
            include_lowercase: true,
            include_digits: true,
            include_symbols: true,
            exclude_ambiguous: true,
            generated: String::new(),
        }
    }
}

impl PasswordGenFields {
    pub fn enabled_class_count(&self) -> usize {
        usize::from(self.include_uppercase)
            + usize::from(self.include_lowercase)
            + usize::from(self.include_digits)
            + usize::from(self.include_symbols)
    }

    pub fn has_any_class(&self) -> bool {
        self.enabled_class_count() > 0
    }

    /// Build the active ASCII character pool from selected classes and ambiguity filter.
    pub fn build_alphabet(&self) -> Vec<u8> {
        let mut alphabet = Vec::with_capacity(80);
        if self.include_lowercase {
            alphabet.extend_from_slice(PWGEN_LOWERCASE);
        }
        if self.include_uppercase {
            alphabet.extend_from_slice(PWGEN_UPPERCASE);
        }
        if self.include_digits {
            alphabet.extend_from_slice(PWGEN_DIGITS);
        }
        if self.include_symbols {
            alphabet.extend_from_slice(PWGEN_SYMBOLS);
        }
        if self.exclude_ambiguous {
            alphabet.retain(|b| !PWGEN_AMBIGUOUS.contains(b));
        }
        alphabet
    }
}

impl Drop for PasswordGenFields {
    fn drop(&mut self) {
        self.generated.zeroize();
    }
}

pub struct SplitJoinFields {
    pub split_source_path: String,
    pub split_preset: SplitSizePreset,
    pub split_custom_mb: String,
    pub split_output_dir: String,
    pub join_part_path: String,
    pub join_output_path: String,
}

impl Default for SplitJoinFields {
    fn default() -> Self {
        Self {
            split_source_path: String::new(),
            split_preset: SplitSizePreset::MiB100,
            split_custom_mb: "100".into(),
            split_output_dir: String::new(),
            join_part_path: String::new(),
            join_output_path: String::new(),
        }
    }
}

pub struct AppState {
    pub active_tab: Tab,
    pub busy: bool,
    pub progress: f32,
    pub transfer: Option<TransferSnapshot>,
    pub status: String,
    pub is_error: bool,
    pub logs: Vec<String>,
    pub config: AppConfig,
    pub config_path: Option<PathBuf>,
    pub shell_status: ShellIntegrationStatus,
    pub show_shell_install_modal: bool,
    pub clipboard_deadline: Option<Instant>,
    pub last_activity: Instant,
    pub last_action: Option<LastCompletedAction>,
    pub job_queue: VecDeque<QueuedJob>,
    pub queue_paused: bool,
    pub active_queue_job: Option<String>,
    pub queue_completed: usize,
    pub queue_failed: usize,
    next_queue_id: u64,
    pub encrypt: EncryptFields,
    pub decrypt: DecryptFields,
    pub inspect: InspectFields,
    pub diff: DiffFields,
    pub split_join: SplitJoinFields,
    pub rekey: RekeyFields,
    pub pwgen: PasswordGenFields,
}

impl Default for AppState {
    fn default() -> Self {
        let cfg_path = default_config_path();
        let config = cfg_path
            .as_deref()
            .map(load_config_from)
            .unwrap_or_default();
        let mut state = Self::from_config(config, cfg_path);
        state.shell_status = shell_integration::get_status();
        state
    }
}

impl AppState {
    /// Construct an `AppState` directly from an in-memory `AppConfig` and optional
    /// config path without reading host `%APPDATA%` preferences or querying the OS registry.
    pub fn from_config(mut config: AppConfig, config_path: Option<PathBuf>) -> Self {
        config.ui_scale_percent = clamp_ui_scale_percent(config.ui_scale_percent);
        config.idle_clear_minutes = config.idle_clear_minutes.min(MAX_IDLE_CLEAR_MINUTES);
        if config.kdf_params().validate().is_err() {
            let defaults = KdfParams::owasp_default();
            config.argon_memory_kib = defaults.memory_kib;
            config.argon_iterations = defaults.iterations;
            config.argon_parallelism = defaults.parallelism;
        }
        let compress = config.compress_by_default;
        let s = i18n::strings(config.language);

        Self {
            active_tab: Tab::Encrypt,
            busy: false,
            progress: 0.0,
            transfer: None,
            status: s.status_ready.into(),
            is_error: false,
            logs: Vec::new(),
            config,
            config_path,
            shell_status: ShellIntegrationStatus {
                supported: cfg!(windows),
                installed: false,
                context_menu_installed: false,
                vault_association_installed: false,
                command_preview: String::new(),
            },
            show_shell_install_modal: false,
            clipboard_deadline: None,
            last_activity: Instant::now(),
            last_action: None,
            job_queue: VecDeque::new(),
            queue_paused: false,
            active_queue_job: None,
            queue_completed: 0,
            queue_failed: 0,
            next_queue_id: 1,
            encrypt: EncryptFields {
                reed_solomon: false,
                stealth: false,
                sources: Vec::new(),
                keyfile: None,
                password: String::new(),
                confirm_password: String::new(),
                show_password: false,
                compress,
                secure_wipe: false,
                save_next_to_source: true,
                output_dir: String::new(),
                recovery_prompt: None,
                container_preset: ContainerSizePreset::Auto,
                container_custom_mb: "100".into(),
                split_preset: SplitSizePreset::None,
                split_custom_mb: "100".into(),
                enable_hidden: false,
                hidden_sources: Vec::new(),
                hidden_keyfile: None,
                hidden_password: String::new(),
                hidden_confirm_password: String::new(),
                show_hidden_password: false,
                hidden_compress: compress,
                profile_name_input: String::new(),
                selected_profile_name: None,
                preflight_outer: SourceSizeSummary::default(),
                preflight_hidden: SourceSizeSummary::default(),
                preflight_scanning: false,
                preflight_scan_gen: 0,
                preflight_scan_cancel: None,
                preflight_scanned_key: (Vec::new(), Vec::new()),
            },
            decrypt: DecryptFields {
                vaults: Vec::new(),
                keyfile: None,
                use_recovery: false,
                password: String::new(),
                show_password: false,
                recovery_phrase: String::new(),
                output_dir: String::new(),
            },
            inspect: InspectFields {
                preview: None,
                preview_gen: 0,
                preview_pending: None,
                vault_path: String::new(),
                keyfile: None,
                use_recovery: false,
                password: String::new(),
                show_password: false,
                recovery_phrase: String::new(),
                results: s.ins_default_results.into(),
                manifest: Vec::new(),
                manifest_vault: None,
                selected_paths: HashSet::new(),
                filter_query: String::new(),
                view_mode: ManifestViewMode::default(),
                category_filter: FileCategoryFilter::default(),
                size_filter: SizeFilter::default(),
                tree_default_open: true,
                tree_id_epoch: 0,
                extract_output_dir: String::new(),
            },
            diff: DiffFields {
                vault_a_path: String::new(),
                keyfile_a: None,
                use_recovery_a: false,
                password_a: String::new(),
                show_password_a: false,
                recovery_phrase_a: String::new(),
                vault_b_path: String::new(),
                keyfile_b: None,
                use_recovery_b: false,
                password_b: String::new(),
                show_password_b: false,
                recovery_phrase_b: String::new(),
                results: s.diff_default_results.into(),
            },
            split_join: SplitJoinFields::default(),
            rekey: RekeyFields {
                vault_path: String::new(),
                current_keyfile: None,
                new_keyfile: None,
                keep_same_keyfile: true,
                current_password: String::new(),
                new_password: String::new(),
                confirm_password: String::new(),
                show_password: false,
            },
            pwgen: PasswordGenFields::default(),
        }
    }

    pub fn strings(&self) -> &'static Strings {
        i18n::strings(self.config.language)
    }

    pub fn set_status(&mut self, msg: impl Into<String>, error: bool) {
        self.status = msg.into();
        self.is_error = error;
    }

    pub fn begin_transfer(&mut self, status: impl Into<String>) {
        self.busy = true;
        self.progress = 0.0;
        self.transfer = None;
        self.set_status(status, false);
    }

    pub fn push_log(&mut self, line: impl Into<String>) {
        self.logs.push(line.into());
        if self.logs.len() > 200 {
            let overflow = self.logs.len() - 200;
            self.logs.drain(0..overflow);
        }
    }

    pub fn copy_secret_with_autoclear(
        &mut self,
        ctx: &egui::Context,
        secret: String,
        status_msg: &str,
    ) {
        ctx.copy_text(secret);
        self.clipboard_deadline = Some(Instant::now() + Duration::from_secs(30));
        self.set_status(status_msg, false);
    }

    pub fn persist_config_best_effort(&self) {
        if self.validate_kdf_params().is_err() {
            return;
        }
        if let Some(ref path) = self.config_path {
            let mut cfg = self.config.clone();
            cfg.ui_scale_percent = clamp_ui_scale_percent(cfg.ui_scale_percent);
            let _ = save_config_to(path, &cfg);
        }
    }

    pub fn validate_kdf_params(&self) -> Result<KdfParams, CryptoError> {
        let params = self.config.kdf_params();
        params.validate()?;
        Ok(params)
    }

    pub fn set_argon_params(
        &mut self,
        memory_kib: u32,
        iterations: u32,
        parallelism: u32,
    ) -> Result<KdfParams, CryptoError> {
        let candidate = KdfParams {
            memory_kib,
            iterations,
            parallelism,
        };
        candidate.validate()?;
        self.config.argon_memory_kib = candidate.memory_kib;
        self.config.argon_iterations = candidate.iterations;
        self.config.argon_parallelism = candidate.parallelism;
        Ok(candidate)
    }

    pub fn save_preferences(&mut self) -> Result<(), String> {
        let s = self.strings();
        if let Err(e) = self.validate_kdf_params() {
            let msg = format!("{}: {e}", s.err_invalid_kdf);
            self.set_status(msg.clone(), true);
            return Err(msg);
        }
        self.config.ui_scale_percent = clamp_ui_scale_percent(self.config.ui_scale_percent);
        self.config.idle_clear_minutes = self.config.idle_clear_minutes.min(MAX_IDLE_CLEAR_MINUTES);
        if let Some(ref p) = self.config_path {
            match save_config_to(p, &self.config) {
                Ok(()) => self.set_status(s.status_prefs_saved, false),
                Err(e) => {
                    let msg = format!("{}: {e}", s.err_save_prefs);
                    self.set_status(msg.clone(), true);
                    return Err(msg);
                }
            }
        }
        Ok(())
    }

    pub fn clear_encrypt_secrets(&mut self) {
        self.encrypt.password.zeroize();
        self.encrypt.confirm_password.zeroize();
        self.encrypt.hidden_password.zeroize();
        self.encrypt.hidden_confirm_password.zeroize();
        self.encrypt.recovery_prompt = None;
    }

    pub fn clear_decrypt_secrets(&mut self) {
        self.decrypt.password.zeroize();
        self.decrypt.recovery_phrase.zeroize();
    }

    pub fn clear_diff_secrets(&mut self) {
        self.diff.password_a.zeroize();
        self.diff.recovery_phrase_a.zeroize();
        self.diff.password_b.zeroize();
        self.diff.recovery_phrase_b.zeroize();
    }

    pub fn clear_rekey_secrets(&mut self) {
        self.rekey.current_password.zeroize();
        self.rekey.new_password.zeroize();
        self.rekey.confirm_password.zeroize();
    }

    pub fn clear_inspect_secrets(&mut self) {
        self.inspect.password.zeroize();
        self.inspect.recovery_phrase.zeroize();
    }

    pub fn has_sensitive_session_data(&self) -> bool {
        let inspect_non_default = !self.inspect.results.is_empty()
            && self.inspect.results != i18n::TR.ins_default_results
            && self.inspect.results != i18n::EN.ins_default_results;
        let diff_non_default = !self.diff.results.is_empty()
            && self.diff.results != i18n::TR.diff_default_results
            && self.diff.results != i18n::EN.diff_default_results;

        !self.encrypt.password.is_empty()
            || !self.encrypt.confirm_password.is_empty()
            || !self.encrypt.hidden_password.is_empty()
            || !self.encrypt.hidden_confirm_password.is_empty()
            || self.encrypt.recovery_prompt.is_some()
            || !self.decrypt.password.is_empty()
            || !self.decrypt.recovery_phrase.is_empty()
            || !self.inspect.password.is_empty()
            || !self.inspect.recovery_phrase.is_empty()
            || self.inspect.preview.is_some()
            || self.inspect.preview_pending.is_some()
            || !self.inspect.manifest.is_empty()
            || self.inspect.manifest_vault.is_some()
            || inspect_non_default
            || !self.diff.password_a.is_empty()
            || !self.diff.recovery_phrase_a.is_empty()
            || !self.diff.password_b.is_empty()
            || !self.diff.recovery_phrase_b.is_empty()
            || diff_non_default
            || !self.rekey.current_password.is_empty()
            || !self.rekey.new_password.is_empty()
            || !self.rekey.confirm_password.is_empty()
            || !self.pwgen.generated.is_empty()
            || !self.logs.is_empty()
            || !self.job_queue.is_empty()
            || self.last_action.is_some()
    }

    /// Clear all in-app secrets, previews, loaded manifests, logs, pending queue, and quick action
    /// banners. Never alters `clipboard_deadline` or overwrites the OS clipboard.
    pub fn clear_sensitive_session(&mut self, reason: SessionClearReason) {
        self.clear_encrypt_secrets();
        self.clear_decrypt_secrets();
        self.clear_inspect_secrets();
        self.clear_diff_secrets();
        self.clear_rekey_secrets();
        self.pwgen.generated.zeroize();
        self.clear_preview_and_busy();
        self.show_shell_install_modal = false;
        let s = self.strings();
        self.inspect.reset_manifest();
        self.inspect.results = s.ins_default_results.into();
        self.diff.results = s.diff_default_results.into();
        self.logs.clear();
        self.job_queue.clear();
        self.queue_paused = false;
        self.queue_completed = 0;
        self.queue_failed = 0;
        self.last_action = None;
        self.last_activity = Instant::now();
        let msg = match reason {
            SessionClearReason::ManualPanic => s.status_session_cleared_panic,
            SessionClearReason::IdleTimeout => s.status_session_cleared_idle,
        };
        self.set_status(msg, false);
    }

    pub fn note_activity(&mut self, now: Instant) {
        self.last_activity = now;
    }

    pub fn check_idle_timeout(&mut self, now: Instant) -> bool {
        if self.config.idle_clear_minutes == 0 {
            return false;
        }
        if self.busy && self.inspect.preview_pending.is_none() {
            self.last_activity = now;
            return false;
        }
        if !self.has_sensitive_session_data() {
            return false;
        }
        let limit = Duration::from_secs(u64::from(self.config.idle_clear_minutes) * 60);
        if now.saturating_duration_since(self.last_activity) >= limit {
            self.clear_sensitive_session(SessionClearReason::IdleTimeout);
            return true;
        }
        false
    }

    pub fn apply_encrypt_profile(&mut self, profile: &EncryptProfile) {
        self.encrypt.compress = profile.compress;
        if profile.stealth {
            self.encrypt.set_stealth(true);
        } else if profile.reed_solomon {
            self.encrypt.set_reed_solomon(true);
        } else {
            self.encrypt.stealth = false;
            self.encrypt.reed_solomon = false;
        }
        self.encrypt.secure_wipe = profile.secure_wipe;
        self.encrypt.save_next_to_source = profile.save_next_to_source;
        self.encrypt.output_dir = profile.output_dir.clone();
        self.encrypt.keyfile = profile.keyfile_path.clone();

        match profile.container_size_mib {
            None => {
                if self.encrypt.enable_hidden {
                    self.encrypt.container_preset = ContainerSizePreset::MiB50;
                } else {
                    self.encrypt.container_preset = ContainerSizePreset::Auto;
                }
            }
            Some(10) => self.encrypt.container_preset = ContainerSizePreset::MiB10,
            Some(50) => self.encrypt.container_preset = ContainerSizePreset::MiB50,
            Some(100) => self.encrypt.container_preset = ContainerSizePreset::MiB100,
            Some(500) => self.encrypt.container_preset = ContainerSizePreset::MiB500,
            Some(mib) => {
                self.encrypt.container_preset = ContainerSizePreset::Custom;
                self.encrypt.container_custom_mb = mib.to_string();
            }
        }

        let (split_preset, split_custom) = SplitSizePreset::from_mib(profile.split_part_mib);
        self.encrypt.split_preset = split_preset;
        if let Some(custom) = split_custom {
            self.encrypt.split_custom_mb = custom;
        }

        self.encrypt.selected_profile_name = Some(profile.name.clone());
        let msg = self.strings().status_profile_applied;
        self.set_status(msg, false);
    }

    pub fn save_current_encrypt_profile(&mut self, name: &str) -> Result<(), &'static str> {
        let s = self.strings();
        let trimmed = name.trim();
        if trimmed.is_empty() {
            self.set_status(s.err_profile_empty_name, true);
            return Err(s.err_profile_empty_name);
        }
        let mut profile = self
            .encrypt
            .current_profile_snapshot(trimmed.to_owned())
            .map_err(|err| {
                let msg = match err {
                    ProfileSnapshotError::Container(ContainerSizeError::InvalidCustomValue) => {
                        s.err_container_invalid_mb
                    }
                    ProfileSnapshotError::Container(ContainerSizeError::OutOfRange) => {
                        s.err_container_out_of_range
                    }
                    ProfileSnapshotError::Container(ContainerSizeError::RequiredForHidden) => {
                        s.err_hidden_requires_container
                    }
                    ProfileSnapshotError::Split(SplitSizeError::InvalidCustomValue) => {
                        s.err_split_invalid_mb
                    }
                    ProfileSnapshotError::Split(SplitSizeError::OutOfRange) => {
                        s.err_split_out_of_range
                    }
                    ProfileSnapshotError::Split(SplitSizeError::TooManyParts) => {
                        s.err_split_too_many_parts
                    }
                };
                self.set_status(msg, true);
                msg
            })?;
        profile.sanitize();

        if let Some(pos) = self
            .config
            .encrypt_profiles
            .iter()
            .position(|p| p.name.eq_ignore_ascii_case(trimmed))
        {
            self.config.encrypt_profiles[pos] = profile;
        } else if self.config.encrypt_profiles.len() >= MAX_ENCRYPT_PROFILES {
            self.set_status(s.err_profile_limit, true);
            return Err(s.err_profile_limit);
        } else {
            self.config.encrypt_profiles.push(profile);
        }

        self.encrypt.selected_profile_name = Some(trimmed.to_owned());
        self.encrypt.profile_name_input.clear();
        self.persist_config_best_effort();
        self.set_status(s.status_profile_saved, false);
        Ok(())
    }

    pub fn delete_encrypt_profile(&mut self, name: &str) -> bool {
        let before = self.config.encrypt_profiles.len();
        self.config
            .encrypt_profiles
            .retain(|p| !p.name.eq_ignore_ascii_case(name));
        if self.config.encrypt_profiles.len() == before {
            return false;
        }
        if self
            .encrypt
            .selected_profile_name
            .as_deref()
            .is_some_and(|n| n.eq_ignore_ascii_case(name))
        {
            self.encrypt.selected_profile_name = None;
        }
        self.persist_config_best_effort();
        let msg = self.strings().status_profile_deleted;
        self.set_status(msg, false);
        true
    }

    pub fn enqueue_job(&mut self, kind: QueuedJobKind) -> u64 {
        if self.job_queue.is_empty() && self.active_queue_job.is_none() {
            self.queue_completed = 0;
            self.queue_failed = 0;
        }
        let id = self.next_queue_id;
        self.next_queue_id = self.next_queue_id.wrapping_add(1).max(1);
        let label = format_job_label(&kind, self.config.language);
        self.job_queue.push_back(QueuedJob {
            id,
            label: label.clone(),
            kind,
        });
        let s = self.strings();
        self.push_log(format!("{}: {label}", s.status_job_enqueued));
        self.set_status(s.status_job_enqueued, false);
        id
    }

    pub fn pop_next_queued_job(&mut self) -> Option<QueuedJob> {
        self.job_queue.pop_front()
    }

    pub fn remove_queued_job(&mut self, id: u64) -> bool {
        let Some(pos) = self.job_queue.iter().position(|j| j.id == id) else {
            return false;
        };
        self.job_queue.remove(pos);
        true
    }

    pub fn move_queued_job_up(&mut self, idx: usize) -> bool {
        if idx == 0 || idx >= self.job_queue.len() {
            return false;
        }
        self.job_queue.swap(idx - 1, idx);
        true
    }

    pub fn move_queued_job_down(&mut self, idx: usize) -> bool {
        if idx + 1 >= self.job_queue.len() {
            return false;
        }
        self.job_queue.swap(idx, idx + 1);
        true
    }

    pub fn clear_pending_queue(&mut self) -> usize {
        let n = self.job_queue.len();
        self.job_queue.clear();
        if self.active_queue_job.is_none() {
            self.queue_paused = false;
        }
        n
    }

    pub fn trigger_preflight_scan_if_needed(
        &mut self,
        ctx: &egui::Context,
        tx: &mpsc::Sender<WorkerUpdate>,
    ) {
        let current_key = (
            self.encrypt.sources.clone(),
            self.encrypt.hidden_sources.clone(),
        );
        if current_key == self.encrypt.preflight_scanned_key {
            return;
        }
        self.encrypt.preflight_scanned_key = current_key.clone();
        self.encrypt.cancel_preflight_scan();
        self.encrypt.preflight_scan_gen = self.encrypt.preflight_scan_gen.wrapping_add(1);

        if current_key.0.is_empty() && current_key.1.is_empty() {
            self.encrypt.preflight_outer = SourceSizeSummary::default();
            self.encrypt.preflight_hidden = SourceSizeSummary::default();
            self.encrypt.preflight_scanning = false;
            return;
        }

        let gen = self.encrypt.preflight_scan_gen;
        let cancel = Arc::new(AtomicBool::new(false));
        self.encrypt.preflight_scan_cancel = Some(Arc::clone(&cancel));
        self.encrypt.preflight_scanning = true;
        crate::worker::spawn_source_scan(
            ctx.clone(),
            tx.clone(),
            cancel,
            gen,
            current_key.0,
            current_key.1,
        );
    }

    pub fn clear_preview_and_busy(&mut self) -> bool {
        let had_pending = self.inspect.preview_pending.is_some();
        let had_any = had_pending || self.inspect.preview.is_some();
        self.inspect.clear_preview();
        if had_pending {
            self.busy = false;
            self.transfer = None;
            self.progress = 0.0;
        }
        had_any
    }

    pub fn select_tab(&mut self, tab: Tab) {
        if tab != Tab::Inspect {
            self.clear_preview_and_busy();
        }
        self.active_tab = tab;
    }

    pub fn handle_shortcut_tab(&mut self, digit: u8) -> bool {
        if let Some(&tab) = digit
            .checked_sub(1)
            .and_then(|idx| Tab::ALL.get(idx as usize))
        {
            self.select_tab(tab);
            true
        } else {
            false
        }
    }

    pub fn dismiss_modals(&mut self) -> bool {
        let had_pending = self.inspect.preview_pending.is_some();
        let mut closed = self.clear_preview_and_busy();
        if had_pending {
            let msg = self.strings().preview_cancelled;
            self.set_status(msg, false);
        }
        if self.show_shell_install_modal {
            self.show_shell_install_modal = false;
            closed = true;
        }
        if self.encrypt.recovery_prompt.take().is_some() {
            let msg = self.strings().status_enc_cancelled;
            self.set_status(msg, false);
            closed = true;
        }
        closed
    }

    /// Add external paths (from OS drag-and-drop or Explorer/CLI args), switching tabs smartly.
    pub fn add_dropped_paths(&mut self, paths: Vec<PathBuf>, forced_tab: Option<Tab>) {
        if paths.is_empty() {
            return;
        }
        let mut split_cache = SplitDiscoveryCache::default();
        let all_vaults = paths.iter().all(|p| {
            if p.is_dir() {
                return false;
            }
            is_vault_or_split_filename(p)
                || (p.is_file() && matches!(split_cache.discover(p), Ok(Some(_)) | Err(_)))
        });

        let target = forced_tab.unwrap_or(if all_vaults {
            Tab::Decrypt
        } else {
            Tab::Encrypt
        });
        let lang = self.config.language;

        match target {
            Tab::Decrypt => {
                self.select_tab(Tab::Decrypt);
                let mut seen: HashSet<PathDedupKey> = self
                    .decrypt
                    .vaults
                    .iter()
                    .map(|v| path_dedup_key(v))
                    .collect();
                let mut added = 0usize;
                let mut skipped = 0usize;
                let mut first_split_err: Option<String> = None;
                for p in paths {
                    if p.is_dir() {
                        skipped += 1;
                        continue;
                    }
                    let is_vault = is_vault_or_split_filename(&p);
                    if !is_vault && !p.is_file() {
                        skipped += 1;
                        continue;
                    }
                    // Deduplicate multiple dropped parts of the same split volume to its `.001` part
                    // in O(D + N) without swallowing incomplete split volume errors.
                    let canonical = if p.is_file() {
                        match split_cache.discover(&p) {
                            Ok(Some(set)) => set.first_part().to_path_buf(),
                            Ok(None) => p,
                            Err(err) => {
                                if first_split_err.is_none() {
                                    first_split_err = Some(err.to_string());
                                }
                                skipped += 1;
                                continue;
                            }
                        }
                    } else {
                        p
                    };
                    if seen.insert(path_dedup_key(&canonical)) {
                        self.decrypt.vaults.push(canonical);
                        added += 1;
                    }
                }
                if self.decrypt.output_dir.trim().is_empty() {
                    if let Some(parent) = self.decrypt.vaults.first().and_then(|v| v.parent()) {
                        self.decrypt.output_dir = parent.display().to_string();
                    }
                }
                if let Some(err_msg) = first_split_err {
                    let msg = if added > 0 {
                        match lang {
                            AppLanguage::Tr => {
                                format!("Çözme için {added} dosya eklendi; hata: {err_msg}")
                            }
                            AppLanguage::En => {
                                format!("Loaded {added} vault(s); error: {err_msg}")
                            }
                        }
                    } else {
                        err_msg
                    };
                    self.set_status(msg, true);
                } else if added > 0 {
                    let msg = match lang {
                        AppLanguage::Tr => format!("Çözme için {added} dosya eklendi"),
                        AppLanguage::En => format!("Loaded {added} vault(s) for decryption"),
                    };
                    self.set_status(msg, false);
                } else if skipped > 0 {
                    let msg = match lang {
                        AppLanguage::Tr => "Çözmek için mevcut bir dosya seçin",
                        AppLanguage::En => "Select an existing file to decrypt",
                    };
                    self.set_status(msg, true);
                }
            }
            Tab::Inspect => {
                if let Some(first) = paths.into_iter().next() {
                    self.select_tab(Tab::Inspect);
                    self.inspect.vault_path = first.display().to_string();
                    self.clear_preview_and_busy();
                    self.inspect.reset_manifest();
                }
            }
            Tab::Rekey => {
                if let Some(first) = paths.into_iter().next() {
                    self.select_tab(Tab::Rekey);
                    self.rekey.vault_path = first.display().to_string();
                }
            }
            _ => {
                self.select_tab(Tab::Encrypt);
                let mut seen: HashSet<PathDedupKey> = self
                    .encrypt
                    .sources
                    .iter()
                    .map(|v| path_dedup_key(v))
                    .collect();
                let mut added = 0usize;
                for p in paths {
                    if seen.insert(path_dedup_key(&p)) {
                        self.encrypt.sources.push(p);
                        added += 1;
                    }
                }
                if added > 0 {
                    let msg = match lang {
                        AppLanguage::Tr => format!("Şifreleme listesine {added} öğe eklendi"),
                        AppLanguage::En => format!("Added {added} item(s) to Encrypt"),
                    };
                    self.set_status(msg, false);
                }
            }
        }
    }

    pub fn apply_launch_intent(&mut self, intent: GuiLaunchIntent) {
        let paths: Vec<PathBuf> = intent.paths.into_iter().map(PathBuf::from).collect();
        let tab = intent.tab.map(|t| match t {
            LaunchTab::Encrypt => Tab::Encrypt,
            LaunchTab::Decrypt => Tab::Decrypt,
        });
        if !paths.is_empty() {
            self.add_dropped_paths(paths, tab);
        } else if let Some(t) = tab {
            self.select_tab(t);
        }
    }

    pub fn generate_password(&mut self) {
        let alphabet = self.pwgen.build_alphabet();
        if alphabet.is_empty() {
            self.pwgen.generated.zeroize();
            let msg = self.strings().err_pw_no_class;
            self.set_status(msg, true);
            return;
        }
        let len = self.pwgen.length.clamp(12, 64);
        self.pwgen.generated.zeroize();
        let mut out = String::with_capacity(len);
        let mut rng = OsRng;
        for _ in 0..len {
            let idx = rng.gen_range(0..alphabet.len());
            out.push(alphabet[idx] as char);
        }
        self.pwgen.generated = out;
        let msg = self.strings().status_pw_generated;
        self.set_status(msg, false);
    }

    pub fn toggle_language(&mut self) {
        self.config.language = match self.config.language {
            AppLanguage::Tr => AppLanguage::En,
            AppLanguage::En => AppLanguage::Tr,
        };
        self.set_status(self.strings().status_ready, false);
    }

    pub fn toggle_theme(&mut self, ctx: &egui::Context) {
        self.config.theme = match self.config.theme {
            ThemeMode::Dark => ThemeMode::Light,
            ThemeMode::Light => ThemeMode::Dark,
        };
        self.apply_theme_visuals(ctx);
    }

    pub fn apply_theme_visuals(&self, ctx: &egui::Context) {
        crate::theme::apply_theme(ctx, self.config.theme);
    }

    pub fn ui_scale_zoom_factor(&self) -> f32 {
        ui_scale_zoom_factor(self.config.ui_scale_percent)
    }

    pub fn set_ui_scale_percent(&mut self, percent: u16, ctx: &egui::Context) {
        self.config.ui_scale_percent = clamp_ui_scale_percent(percent);
        self.apply_ui_scale(ctx);
    }

    pub fn apply_ui_scale(&self, ctx: &egui::Context) {
        ctx.set_zoom_factor(self.ui_scale_zoom_factor());
    }
}

pub fn strength_label_and_color(pw: &str) -> (&'static str, egui::Color32) {
    let (lbl, _frac, color) = strength_label_and_color_for(pw, AppLanguage::En);
    (lbl, color)
}

pub fn strength_label_and_color_for(
    pw: &str,
    lang: AppLanguage,
) -> (&'static str, f32, egui::Color32) {
    let s = i18n::strings(lang);
    if pw.is_empty() {
        return (s.str_empty, 0.0, egui::Color32::GRAY);
    }
    let est = zxcvbn::zxcvbn(pw, &[]);
    match u8::from(est.score()) {
        0 => (s.str_very_weak, 0.15, egui::Color32::from_rgb(220, 65, 65)),
        1 => (s.str_weak, 0.35, egui::Color32::from_rgb(230, 120, 50)),
        2 => (s.str_fair, 0.58, egui::Color32::from_rgb(225, 185, 50)),
        3 => (s.str_good, 0.80, egui::Color32::from_rgb(95, 190, 95)),
        _ => (s.str_strong, 1.0, egui::Color32::from_rgb(20, 184, 166)),
    }
}
