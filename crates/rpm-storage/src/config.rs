//! User-local JSON application preferences (no secrets persisted).

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use directories::ProjectDirs;
use rpm_core::constants::MAX_CONTAINER_SIZE;
use rpm_core::{KdfParams, MAX_PIPELINE_THREADS};
use serde::{Deserialize, Serialize};

use crate::error::StorageError;

pub const MAX_IDLE_CLEAR_MINUTES: u16 = 120;
pub const DEFAULT_IDLE_CLEAR_MINUTES: u16 = 5;
pub const MAX_ENCRYPT_PROFILES: usize = 32;
const CONTAINER_MIB: u64 = 1024 * 1024;
const MAX_CONTAINER_MIB: u64 = MAX_CONTAINER_SIZE / CONTAINER_MIB;

const fn default_idle_clear_minutes() -> u16 {
    DEFAULT_IDLE_CLEAR_MINUTES
}

const fn default_notify_on_complete() -> bool {
    true
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThemeMode {
    Dark,
    Light,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppLanguage {
    #[default]
    Tr,
    En,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct EncryptProfile {
    pub name: String,
    pub compress: bool,
    pub stealth: bool,
    pub reed_solomon: bool,
    pub secure_wipe: bool,
    pub container_size_mib: Option<u64>,
    pub split_part_mib: Option<u64>,
    pub save_next_to_source: bool,
    pub output_dir: String,
    pub keyfile_path: Option<PathBuf>,
}

impl Default for EncryptProfile {
    fn default() -> Self {
        Self {
            name: String::new(),
            compress: true,
            stealth: false,
            reed_solomon: false,
            secure_wipe: false,
            container_size_mib: None,
            split_part_mib: None,
            save_next_to_source: true,
            output_dir: String::new(),
            keyfile_path: None,
        }
    }
}

impl EncryptProfile {
    /// Normalize profile settings, returning `false` if the profile has no valid name.
    pub fn sanitize(&mut self) -> bool {
        let trimmed = self.name.trim();
        if trimmed.is_empty() {
            return false;
        }
        if trimmed.len() != self.name.len() {
            self.name = trimmed.to_owned();
        }
        if self.stealth && self.reed_solomon {
            self.reed_solomon = false;
        }
        if let Some(mib) = self.container_size_mib {
            if mib == 0 || mib > MAX_CONTAINER_MIB {
                self.container_size_mib = None;
            }
        }
        if let Some(mib) = self.split_part_mib {
            let part_bytes = mib.saturating_mul(CONTAINER_MIB);
            if mib == 0 || mib > MAX_CONTAINER_MIB || part_bytes < crate::split::MIN_SPLIT_PART_SIZE
            {
                self.split_part_mib = None;
            }
        }
        if let (Some(container_mib), Some(split_mib)) =
            (self.container_size_mib, self.split_part_mib)
        {
            let container_bytes = container_mib.saturating_mul(CONTAINER_MIB);
            let split_bytes = split_mib.saturating_mul(CONTAINER_MIB);
            if crate::split::validate_split_bounds(
                split_bytes,
                Some(container_bytes),
                self.reed_solomon,
            )
            .is_err()
            {
                self.split_part_mib = None;
            }
        }
        true
    }
}

fn sanitize_profiles(profiles: &mut Vec<EncryptProfile>) {
    let mut seen = HashSet::new();
    let mut cleaned = Vec::with_capacity(profiles.len().min(MAX_ENCRYPT_PROFILES));
    for mut profile in profiles.drain(..) {
        if !profile.sanitize() {
            continue;
        }
        let key = profile.name.to_lowercase();
        if seen.insert(key) {
            cleaned.push(profile);
            if cleaned.len() >= MAX_ENCRYPT_PROFILES {
                break;
            }
        }
    }
    *profiles = cleaned;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub ui_scale_percent: u16,
    pub theme: ThemeMode,
    #[serde(default)]
    pub language: AppLanguage,
    pub wipe_passes: u8,
    pub argon_memory_kib: u32,
    pub argon_iterations: u32,
    pub argon_parallelism: u32,
    pub compress_by_default: bool,
    /// Multi-core AEAD & Reed-Solomon pipeline worker count (`0` = auto-detect logical CPUs).
    #[serde(default)]
    pub pipeline_threads: u16,
    #[serde(default = "default_idle_clear_minutes")]
    pub idle_clear_minutes: u16,
    #[serde(default = "default_notify_on_complete")]
    pub notify_on_complete: bool,
    #[serde(default)]
    pub encrypt_profiles: Vec<EncryptProfile>,
}

impl Default for AppConfig {
    fn default() -> Self {
        let kdf = KdfParams::owasp_default();
        Self {
            ui_scale_percent: 100,
            theme: ThemeMode::Dark,
            language: AppLanguage::Tr,
            wipe_passes: 1,
            argon_memory_kib: kdf.memory_kib,
            argon_iterations: kdf.iterations,
            argon_parallelism: kdf.parallelism,
            compress_by_default: true,
            pipeline_threads: 0,
            idle_clear_minutes: default_idle_clear_minutes(),
            notify_on_complete: default_notify_on_complete(),
            encrypt_profiles: Vec::new(),
        }
    }
}

impl AppConfig {
    pub fn kdf_params(&self) -> KdfParams {
        KdfParams {
            memory_kib: self.argon_memory_kib,
            iterations: self.argon_iterations,
            parallelism: self.argon_parallelism,
        }
    }
}

pub fn default_config_path() -> Option<PathBuf> {
    ProjectDirs::from("com", "RPMEncrypter", "RPMEncrypter")
        .map(|dirs| dirs.config_dir().join("config.json"))
}

pub fn load_config_from(path: &Path) -> AppConfig {
    match fs::read(path) {
        Ok(bytes) => {
            let mut cfg: AppConfig = serde_json::from_slice(&bytes).unwrap_or_default();
            cfg.ui_scale_percent = cfg.ui_scale_percent.clamp(80, 150);
            cfg.wipe_passes = cfg.wipe_passes.clamp(1, 5);
            cfg.pipeline_threads = cfg.pipeline_threads.min(MAX_PIPELINE_THREADS as u16);
            cfg.idle_clear_minutes = cfg.idle_clear_minutes.min(MAX_IDLE_CLEAR_MINUTES);
            sanitize_profiles(&mut cfg.encrypt_profiles);
            if cfg.kdf_params().validate().is_err() {
                let defaults = KdfParams::owasp_default();
                cfg.argon_memory_kib = defaults.memory_kib;
                cfg.argon_iterations = defaults.iterations;
                cfg.argon_parallelism = defaults.parallelism;
            }
            cfg
        }
        Err(_) => AppConfig::default(),
    }
}

fn ensure_parent_dir(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

pub fn save_config_to(path: &Path, cfg: &AppConfig) -> Result<(), StorageError> {
    ensure_parent_dir(path)?;
    let data = serde_json::to_vec_pretty(cfg)?;
    crate::atomic::atomic_write(path, |w| {
        std::io::Write::write_all(w, &data)?;
        Ok(())
    })
}

#[cfg(test)]
mod config_loading_tests {
    use super::*;

    #[test]
    fn ensure_parent_dir_accepts_bare_relative_filename() {
        ensure_parent_dir(Path::new("config.json")).unwrap();
    }

    #[test]
    fn legacy_preferences_and_invalid_numeric_values() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        fs::write(&path, r#"{"theme":"Light","compress_by_default":false}"#).unwrap();
        let legacy = load_config_from(&path);
        assert_eq!(legacy.ui_scale_percent, 100);
        assert_eq!(legacy.theme, ThemeMode::Light);
        assert!(!legacy.compress_by_default);
        assert_eq!(legacy.idle_clear_minutes, DEFAULT_IDLE_CLEAR_MINUTES);
        assert!(legacy.notify_on_complete);
        assert!(legacy.encrypt_profiles.is_empty());
        for (scale, expected) in [(0, 80), (80, 80), (125, 125), (150, 150), (151, 150)] {
            let config = AppConfig {
                ui_scale_percent: scale,
                wipe_passes: 250,
                argon_iterations: 0,
                ..legacy.clone()
            };
            save_config_to(&path, &config).unwrap();
            let loaded = load_config_from(&path);
            assert_eq!(loaded.ui_scale_percent, expected);
            assert_eq!(loaded.wipe_passes, 5);
            assert_eq!(loaded.kdf_params(), KdfParams::owasp_default());
            assert_eq!(loaded.theme, ThemeMode::Light);
        }
    }

    #[test]
    fn sanitize_idle_clear_and_encrypt_profiles_bounds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");

        let mut profiles = vec![
            EncryptProfile {
                name: "   ".into(),
                ..EncryptProfile::default()
            },
            EncryptProfile {
                name: " Work Backup ".into(),
                stealth: true,
                reed_solomon: true,
                container_size_mib: Some(0),
                ..EncryptProfile::default()
            },
            EncryptProfile {
                name: "work backup".into(),
                compress: false,
                ..EncryptProfile::default()
            },
            EncryptProfile {
                name: "TooLarge".into(),
                container_size_mib: Some(999_999),
                ..EncryptProfile::default()
            },
        ];
        for i in 0..40 {
            profiles.push(EncryptProfile {
                name: format!("Extra-{i}"),
                ..EncryptProfile::default()
            });
        }

        let cfg = AppConfig {
            idle_clear_minutes: 999,
            notify_on_complete: false,
            encrypt_profiles: profiles,
            ..AppConfig::default()
        };
        save_config_to(&path, &cfg).unwrap();

        let loaded = load_config_from(&path);
        assert_eq!(loaded.idle_clear_minutes, MAX_IDLE_CLEAR_MINUTES);
        assert!(!loaded.notify_on_complete);
        assert_eq!(loaded.encrypt_profiles.len(), MAX_ENCRYPT_PROFILES);
        assert_eq!(loaded.encrypt_profiles[0].name, "Work Backup");
        assert!(loaded.encrypt_profiles[0].stealth);
        assert!(!loaded.encrypt_profiles[0].reed_solomon);
        assert_eq!(loaded.encrypt_profiles[0].container_size_mib, None);
        assert_eq!(loaded.encrypt_profiles[1].name, "TooLarge");
        assert_eq!(loaded.encrypt_profiles[1].container_size_mib, None);
    }

    #[test]
    fn pipeline_threads_defaults_to_auto_and_clamps_upper_bound() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        fs::write(&path, r#"{"theme":"Dark"}"#).unwrap();
        assert_eq!(load_config_from(&path).pipeline_threads, 0);

        let cfg = AppConfig {
            pipeline_threads: 999,
            ..AppConfig::default()
        };
        save_config_to(&path, &cfg).unwrap();
        assert_eq!(
            load_config_from(&path).pipeline_threads,
            MAX_PIPELINE_THREADS as u16
        );

        let explicit = AppConfig {
            pipeline_threads: 4,
            ..AppConfig::default()
        };
        save_config_to(&path, &explicit).unwrap();
        assert_eq!(load_config_from(&path).pipeline_threads, 4);
    }
}
