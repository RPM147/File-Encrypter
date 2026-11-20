//! GUI state, launch routing, drag-and-drop triage, and zeroizing field management.

use std::path::PathBuf;
use std::time::Instant;

use eframe::egui;
use rand::rngs::OsRng;
use rand::Rng;
use rpm_core::SecretKey;
use rpm_storage::config::{default_config_path, load_config_from, AppConfig, ThemeMode};
use rpm_storage::shell_integration::{self, ShellIntegrationStatus};
use rpm_storage::{GuiLaunchIntent, LaunchTab};
use zeroize::Zeroize;

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
        match self {
            Tab::Encrypt => "Encrypt",
            Tab::Decrypt => "Decrypt",
            Tab::Inspect => "Inspect",
            Tab::Rekey => "Re-Key",
            Tab::Password => "Password Gen",
            Tab::Settings => "Settings",
        }
    }
}

#[derive(Debug)]
pub enum WorkerUpdate {
    Progress(f32),
    Log(String),
    EncryptDone { status: String },
    DecryptDone { status: String },
    InspectDone { text: String, status: String },
    IntegrityDone { text: String, ok: bool },
    RekeyDone { status: String },
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
    pub sources: Vec<PathBuf>,
    pub keyfile: Option<PathBuf>,
    pub password: String,
    pub confirm_password: String,
    pub compress: bool,
    pub secure_wipe: bool,
    pub save_next_to_source: bool,
    pub output_dir: String,
    pub recovery_prompt: Option<RecoveryPrompt>,
}

impl Drop for EncryptFields {
    fn drop(&mut self) {
        self.password.zeroize();
        self.confirm_password.zeroize();
    }
}

pub struct DecryptFields {
    pub vaults: Vec<PathBuf>,
    pub keyfile: Option<PathBuf>,
    pub use_recovery: bool,
    pub password: String,
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
    pub vault_path: String,
    pub keyfile: Option<PathBuf>,
    pub use_recovery: bool,
    pub password: String,
    pub recovery_phrase: String,
    pub results: String,
}

impl Drop for InspectFields {
    fn drop(&mut self) {
        self.password.zeroize();
        self.recovery_phrase.zeroize();
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
    pub include_symbols: bool,
    pub generated: String,
    pub clipboard_deadline: Option<Instant>,
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
    pub status: String,
    pub is_error: bool,
    pub logs: Vec<String>,
    pub config: AppConfig,
    pub config_path: Option<PathBuf>,
    pub shell_status: ShellIntegrationStatus,
    pub show_shell_install_modal: bool,
    pub encrypt: EncryptFields,
    pub decrypt: DecryptFields,
    pub inspect: InspectFields,
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
        let compress = config.compress_by_default;

        Self {
            active_tab: Tab::Encrypt,
            busy: false,
            progress: 0.0,
            status: "Ready — drag files or folders onto the window anytime".into(),
            is_error: false,
            logs: Vec::new(),
            config,
            config_path: cfg_path,
            shell_status: shell_integration::get_status(),
            show_shell_install_modal: false,
            encrypt: EncryptFields {
                sources: Vec::new(),
                keyfile: None,
                password: String::new(),
                confirm_password: String::new(),
                compress,
                secure_wipe: false,
                save_next_to_source: true,
                output_dir: String::new(),
                recovery_prompt: None,
            },
            decrypt: DecryptFields {
                vaults: Vec::new(),
                keyfile: None,
                use_recovery: false,
                password: String::new(),
                recovery_phrase: String::new(),
                output_dir: String::new(),
            },
            inspect: InspectFields {
                vault_path: String::new(),
                keyfile: None,
                use_recovery: false,
                password: String::new(),
                recovery_phrase: String::new(),
                results: "Select a .vault file and click Integrity Check or Inspect Metadata."
                    .into(),
            },
            rekey: RekeyFields {
                vault_path: String::new(),
                current_keyfile: None,
                new_keyfile: None,
                keep_same_keyfile: true,
                current_password: String::new(),
                new_password: String::new(),
                confirm_password: String::new(),
            },
            pwgen: PasswordGenFields {
                length: 24,
                include_symbols: true,
                generated: String::new(),
                clipboard_deadline: None,
            },
        }
    }
}

impl AppState {
    pub fn set_status(&mut self, msg: impl Into<String>, error: bool) {
        self.status = msg.into();
        self.is_error = error;
    }

    pub fn push_log(&mut self, line: impl Into<String>) {
        self.logs.push(line.into());
        if self.logs.len() > 200 {
            let overflow = self.logs.len() - 200;
            self.logs.drain(0..overflow);
        }
    }

    pub fn clear_encrypt_secrets(&mut self) {
        self.encrypt.password.zeroize();
        self.encrypt.confirm_password.zeroize();
        self.encrypt.recovery_prompt = None;
    }

    pub fn clear_decrypt_secrets(&mut self) {
        self.decrypt.password.zeroize();
        self.decrypt.recovery_phrase.zeroize();
    }

    pub fn clear_rekey_secrets(&mut self) {
        self.rekey.current_password.zeroize();
        self.rekey.new_password.zeroize();
        self.rekey.confirm_password.zeroize();
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

        match target {
            Tab::Decrypt => {
                self.active_tab = Tab::Decrypt;
                let mut added = 0usize;
                let mut skipped = 0usize;
                for p in paths {
                    let is_vault = p
                        .extension()
                        .is_some_and(|e| e.to_string_lossy().eq_ignore_ascii_case("vault"));
                    if !is_vault {
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
                    self.set_status(format!("Loaded {added} vault(s) for decryption"), false);
                } else if skipped > 0 {
                    self.set_status("Only .vault files can be decrypted", true);
                }
            }
            Tab::Inspect => {
                if let Some(first) = paths.into_iter().next() {
                    self.active_tab = Tab::Inspect;
                    self.inspect.vault_path = first.display().to_string();
                }
            }
            Tab::Rekey => {
                if let Some(first) = paths.into_iter().next() {
                    self.active_tab = Tab::Rekey;
                    self.rekey.vault_path = first.display().to_string();
                }
            }
            _ => {
                self.active_tab = Tab::Encrypt;
                let mut added = 0usize;
                for p in paths {
                    if !self.encrypt.sources.contains(&p) {
                        self.encrypt.sources.push(p);
                        added += 1;
                    }
                }
                if added > 0 {
                    self.set_status(format!("Added {added} item(s) to Encrypt"), false);
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
            self.active_tab = t;
        }
    }

    pub fn generate_password(&mut self) {
        let mut alphabet: Vec<u8> =
            b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789".to_vec();
        if self.pwgen.include_symbols {
            alphabet.extend_from_slice(b"!@#$%^&*()-_=+[]{}");
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
        self.set_status("Generated new random password", false);
    }

    pub fn apply_theme_visuals(&self, ctx: &egui::Context) {
        let visuals = match self.config.theme {
            ThemeMode::Dark => egui::Visuals::dark(),
            ThemeMode::Light => egui::Visuals::light(),
        };
        ctx.set_visuals(visuals);
    }
}

pub fn strength_label_and_color(pw: &str) -> (&'static str, egui::Color32) {
    if pw.is_empty() {
        return ("-", egui::Color32::GRAY);
    }
    let est = zxcvbn::zxcvbn(pw, &[]);
    match u8::from(est.score()) {
        0 => ("Very Weak", egui::Color32::from_rgb(220, 65, 65)),
        1 => ("Weak", egui::Color32::from_rgb(230, 120, 50)),
        2 => ("Fair", egui::Color32::from_rgb(225, 185, 50)),
        3 => ("Good", egui::Color32::from_rgb(95, 190, 95)),
        _ => ("Strong", egui::Color32::from_rgb(50, 200, 140)),
    }
}
