//! User-local JSON application preferences (no secrets persisted).

use std::fs;
use std::path::{Path, PathBuf};

use directories::ProjectDirs;
use rpm_core::KdfParams;
use serde::{Deserialize, Serialize};

use crate::error::StorageError;

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

pub fn save_config_to(path: &Path, cfg: &AppConfig) -> Result<(), StorageError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
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
    fn legacy_preferences_and_invalid_numeric_values() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        fs::write(&path, r#"{"theme":"Light","compress_by_default":false}"#).unwrap();
        let legacy = load_config_from(&path);
        assert_eq!(legacy.ui_scale_percent, 100);
        assert_eq!(legacy.theme, ThemeMode::Light);
        assert!(!legacy.compress_by_default);
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
}
