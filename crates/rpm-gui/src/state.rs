//! GUI state, launch routing, drag-and-drop triage, and zeroizing field management.

use std::collections::HashSet;
use std::ops::RangeInclusive;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use eframe::egui;
use rand::rngs::OsRng;
use rand::Rng;
use rpm_core::constants::{MAX_CONTAINER_SIZE, MIN_CONTAINER_SIZE};
use rpm_core::{CryptoError, FileManifestEntry, KdfParams, SecretKey};
use rpm_storage::config::{
    default_config_path, load_config_from, save_config_to, AppConfig, AppLanguage, ThemeMode,
};
use rpm_storage::shell_integration::{self, ShellIntegrationStatus};
use rpm_storage::{GuiLaunchIntent, LaunchTab};
use zeroize::Zeroize;

use crate::i18n::{self, Strings};
use crate::progress::TransferSnapshot;

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

pub const UI_SCALE_PRESETS: [u16; 7] = [80, 90, 100, 110, 120, 130, 150];
pub const UI_SCALE_MIN: u16 = 80;
pub const UI_SCALE_MAX: u16 = 150;
pub const UI_SCALE_DEFAULT: u16 = 100;

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
    },
    DecryptDone {
        status: String,
    },
    InspectDone {
        text: String,
        status: String,
        manifest: Vec<FileManifestEntry>,
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
    },
    Error(String),
}

pub struct RecoveryPrompt {
    pub phrase: String,
    pub entropy: SecretKey,
    pub confirmed: bool,
}

impl Drop for RecoveryPrompt {
    fn drop(&mut self) {
        self.phrase.zeroize();
    }
}

pub struct EncryptFields {
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
    pub enable_hidden: bool,
    pub hidden_sources: Vec<PathBuf>,
    pub hidden_keyfile: Option<PathBuf>,
    pub hidden_password: String,
    pub hidden_confirm_password: String,
    pub show_hidden_password: bool,
    pub hidden_compress: bool,
}

impl EncryptFields {
    pub fn resolve_container_size(&self) -> Result<Option<u64>, ContainerSizeError> {
        let resolved = self
            .container_preset
            .resolve_bytes(&self.container_custom_mb)?;
        if self.enable_hidden && resolved.is_none() {
            return Err(ContainerSizeError::RequiredForHidden);
        }
        Ok(resolved)
    }

    pub fn set_hidden_enabled(&mut self, enabled: bool) {
        self.enable_hidden = enabled;
        if enabled && self.container_preset == ContainerSizePreset::Auto {
            self.container_preset = ContainerSizePreset::MiB50;
        }
    }

    pub fn add_hidden_sources(&mut self, paths: Vec<PathBuf>) -> usize {
        let mut added = 0usize;
        for p in paths {
            if !self.hidden_sources.contains(&p) {
                self.hidden_sources.push(p);
                added += 1;
            }
        }
        added
    }
}

impl Drop for EncryptFields {
    fn drop(&mut self) {
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
        self.manifest = entries;
        self.manifest_vault = Some(vault);
        self.selected_paths.clear();
        self.filter_query.clear();
    }

    pub fn reset_manifest(&mut self) {
        self.clear_preview();
        self.manifest.clear();
        self.manifest_vault = None;
        self.selected_paths.clear();
        self.filter_query.clear();
    }

    pub fn filtered_indices(&self) -> Vec<usize> {
        let q = self.filter_query.trim().to_ascii_lowercase();
        if q.is_empty() {
            return (0..self.manifest.len()).collect();
        }
        self.manifest
            .iter()
            .enumerate()
            .filter(|(_, e)| e.path.to_ascii_lowercase().contains(&q))
            .map(|(i, _)| i)
            .collect()
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
    pub encrypt: EncryptFields,
    pub decrypt: DecryptFields,
    pub inspect: InspectFields,
    pub diff: DiffFields,
    pub rekey: RekeyFields,
    pub pwgen: PasswordGenFields,
}

impl Default for AppState {
    fn default() -> Self {
        let cfg_path = default_config_path();
        let mut config = cfg_path
            .as_deref()
            .map(load_config_from)
            .unwrap_or_default();
        config.ui_scale_percent = clamp_ui_scale_percent(config.ui_scale_percent);
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
            config_path: cfg_path,
            shell_status: shell_integration::get_status(),
            show_shell_install_modal: false,
            clipboard_deadline: None,
            encrypt: EncryptFields {
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
                enable_hidden: false,
                hidden_sources: Vec::new(),
                hidden_keyfile: None,
                hidden_password: String::new(),
                hidden_confirm_password: String::new(),
                show_hidden_password: false,
                hidden_compress: compress,
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
}

impl AppState {
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

    pub fn select_tab(&mut self, tab: Tab) {
        if tab != Tab::Inspect {
            self.inspect.clear_preview();
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
        let mut closed = self.inspect.preview.is_some() || self.inspect.preview_pending.is_some();
        self.inspect.clear_preview();
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
        let all_vaults = paths.iter().all(|p| {
            p.extension()
                .is_some_and(|e| e.to_string_lossy().eq_ignore_ascii_case("vault"))
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
                let mut added = 0usize;
                let mut skipped = 0usize;
                for p in paths {
                    let is_vault = p
                        .extension()
                        .is_some_and(|e| e.to_string_lossy().eq_ignore_ascii_case("vault"));
                    if !is_vault && !p.is_file() {
                        skipped += 1;
                        continue;
                    }
                    if !self.decrypt.vaults.contains(&p) {
                        self.decrypt.vaults.push(p);
                        added += 1;
                    }
                }
                if self.decrypt.output_dir.trim().is_empty() {
                    if let Some(parent) = self.decrypt.vaults.first().and_then(|v| v.parent()) {
                        self.decrypt.output_dir = parent.display().to_string();
                    }
                }
                if added > 0 {
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
                let mut added = 0usize;
                for p in paths {
                    if !self.encrypt.sources.contains(&p) {
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
