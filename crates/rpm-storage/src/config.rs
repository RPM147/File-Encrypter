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
pub struct AppConfig {
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
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
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
