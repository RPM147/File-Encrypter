//! Streaming archive packaging, atomic I/O, wiping, config, and Windows shell integration.

pub mod atomic;
pub mod config;
pub mod error;
pub mod launch;
pub mod packager;
pub mod pipe;
pub mod shell_integration;
pub mod wiper;
pub mod workflow;

pub use atomic::atomic_write;
pub use config::{load_config_from, save_config_to, AppConfig, ThemeMode};
pub use error::StorageError;
pub use launch::{parse_gui_launch_args, GuiLaunchIntent, LaunchTab};
pub use packager::UnpackLimits;
pub use wiper::SecureWiper;
pub use workflow::{
    decrypt_vault_selected_v5, decrypt_vault_v5, encrypt_sources_v5, rekey_vault_v5, unique_path,
    DecryptSummary,
};
