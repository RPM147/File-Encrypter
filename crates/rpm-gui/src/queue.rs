//! Zeroizing sequential batch job queue for background vault operations.

use std::fmt;
use std::path::{Path, PathBuf};

use rpm_core::{KdfParams, SecretKey};
use rpm_storage::config::AppLanguage;
use zeroize::Zeroizing;

#[derive(Clone)]
pub enum QueuedJobKind {
    Encrypt {
        sources: Vec<PathBuf>,
        password: Zeroizing<String>,
        recovery_entropy: SecretKey,
        keyfile: Option<PathBuf>,
        output_dir: Option<PathBuf>,
        compress: bool,
        container_size_bytes: Option<u64>,
        split_part_bytes: Option<u64>,
        stealth: bool,
        reed_solomon: bool,
        secure_wipe: bool,
        wipe_passes: u8,
        kdf: KdfParams,
    },
    EncryptHidden {
        decoy_sources: Vec<PathBuf>,
        hidden_sources: Vec<PathBuf>,
        decoy_password: Zeroizing<String>,
        hidden_password: Zeroizing<String>,
        decoy_recovery_entropy: SecretKey,
        decoy_keyfile: Option<PathBuf>,
        hidden_keyfile: Option<PathBuf>,
        output_dir: Option<PathBuf>,
        decoy_compressed: bool,
        hidden_compressed: bool,
        container_size_bytes: u64,
        split_part_bytes: Option<u64>,
        stealth: bool,
        reed_solomon: bool,
        secure_wipe: bool,
        wipe_passes: u8,
        kdf: KdfParams,
    },
    Decrypt {
        vaults: Vec<PathBuf>,
        use_recovery: bool,
        secret: Zeroizing<String>,
        keyfile: Option<PathBuf>,
        output_dir: Option<PathBuf>,
    },
    Repair {
        path: PathBuf,
    },
    IntegrityCheck {
        path: PathBuf,
    },
}

impl fmt::Debug for QueuedJobKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encrypt {
                sources,
                keyfile,
                output_dir,
                compress,
                container_size_bytes,
                split_part_bytes,
                stealth,
                reed_solomon,
                secure_wipe,
                wipe_passes,
                kdf,
                ..
            } => f
                .debug_struct("Encrypt")
                .field("sources", sources)
                .field("password", &"[REDACTED]")
                .field("recovery_entropy", &"[REDACTED]")
                .field("keyfile", keyfile)
                .field("output_dir", output_dir)
                .field("compress", compress)
                .field("container_size_bytes", container_size_bytes)
                .field("split_part_bytes", split_part_bytes)
                .field("stealth", stealth)
                .field("reed_solomon", reed_solomon)
                .field("secure_wipe", secure_wipe)
                .field("wipe_passes", wipe_passes)
                .field("kdf", kdf)
                .finish(),
            Self::EncryptHidden {
                decoy_sources,
                hidden_sources,
                decoy_keyfile,
                hidden_keyfile,
                output_dir,
                decoy_compressed,
                hidden_compressed,
                container_size_bytes,
                split_part_bytes,
                stealth,
                reed_solomon,
                secure_wipe,
                wipe_passes,
                kdf,
                ..
            } => f
                .debug_struct("EncryptHidden")
                .field("decoy_sources", decoy_sources)
                .field("hidden_sources", hidden_sources)
                .field("decoy_password", &"[REDACTED]")
                .field("hidden_password", &"[REDACTED]")
                .field("decoy_recovery_entropy", &"[REDACTED]")
                .field("decoy_keyfile", decoy_keyfile)
                .field("hidden_keyfile", hidden_keyfile)
                .field("output_dir", output_dir)
                .field("decoy_compressed", decoy_compressed)
                .field("hidden_compressed", hidden_compressed)
                .field("container_size_bytes", container_size_bytes)
                .field("split_part_bytes", split_part_bytes)
                .field("stealth", stealth)
                .field("reed_solomon", reed_solomon)
                .field("secure_wipe", secure_wipe)
                .field("wipe_passes", wipe_passes)
                .field("kdf", kdf)
                .finish(),
            Self::Decrypt {
                vaults,
                use_recovery,
                keyfile,
                output_dir,
                ..
            } => f
                .debug_struct("Decrypt")
                .field("vaults", vaults)
                .field("use_recovery", use_recovery)
                .field("secret", &"[REDACTED]")
                .field("keyfile", keyfile)
                .field("output_dir", output_dir)
                .finish(),
            Self::Repair { path } => f.debug_struct("Repair").field("path", path).finish(),
            Self::IntegrityCheck { path } => f
                .debug_struct("IntegrityCheck")
                .field("path", path)
                .finish(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct QueuedJob {
    pub id: u64,
    pub label: String,
    pub kind: QueuedJobKind,
}

fn short_name(path: &Path) -> String {
    path.file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| path.display().to_string())
}

fn summarize_paths(paths: &[PathBuf]) -> String {
    match paths.first() {
        None => "?".into(),
        Some(first) if paths.len() == 1 => short_name(first),
        Some(first) => format!("{} (+{})", short_name(first), paths.len() - 1),
    }
}

pub fn format_job_label(kind: &QueuedJobKind, lang: AppLanguage) -> String {
    match (kind, lang) {
        (QueuedJobKind::Encrypt { sources, .. }, AppLanguage::Tr) => {
            format!("Şifrele: {}", summarize_paths(sources))
        }
        (QueuedJobKind::Encrypt { sources, .. }, AppLanguage::En) => {
            format!("Encrypt: {}", summarize_paths(sources))
        }
        (QueuedJobKind::EncryptHidden { decoy_sources, .. }, AppLanguage::Tr) => {
            format!("Gizli Kasa: {}", summarize_paths(decoy_sources))
        }
        (QueuedJobKind::EncryptHidden { decoy_sources, .. }, AppLanguage::En) => {
            format!("Hidden Vault: {}", summarize_paths(decoy_sources))
        }
        (QueuedJobKind::Decrypt { vaults, .. }, AppLanguage::Tr) => {
            format!("Çöz: {}", summarize_paths(vaults))
        }
        (QueuedJobKind::Decrypt { vaults, .. }, AppLanguage::En) => {
            format!("Decrypt: {}", summarize_paths(vaults))
        }
        (QueuedJobKind::Repair { path }, AppLanguage::Tr) => {
            format!("Onar (RS): {}", short_name(path))
        }
        (QueuedJobKind::Repair { path }, AppLanguage::En) => {
            format!("Repair (RS): {}", short_name(path))
        }
        (QueuedJobKind::IntegrityCheck { path }, AppLanguage::Tr) => {
            format!("Doğrula: {}", short_name(path))
        }
        (QueuedJobKind::IntegrityCheck { path }, AppLanguage::En) => {
            format!("Verify: {}", short_name(path))
        }
    }
}
