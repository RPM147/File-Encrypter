//! Background worker thread launchers bridging `rpm-core`/`rpm-storage` to `egui`.

use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use eframe::egui;
use rpm_core::{
    check_integrity, diff_metadata, hash_keyfile_reader, inspect_header_seekable,
    mnemonic_to_entropy, Auth, CryptoError, EncryptOptions, HiddenEncryptOptions, IntegrityReport,
    KdfParams, SecretKey, VaultDiff, VaultInfo,
};
use rpm_storage::config::AppLanguage;
use rpm_storage::{
    decrypt_vault_selected_v5, decrypt_vault_v5, encrypt_hidden_sources_v5, encrypt_sources_v5,
    rekey_vault_v5, unique_path, SecureWiper, StorageError,
};
use zeroize::Zeroizing;

use crate::progress::{TransferMeter, TransferSnapshot};
use crate::state::WorkerUpdate;

const PROGRESS_INTERVAL: Duration = Duration::from_millis(80);
const MAX_REPORT_ENTRIES: usize = 150;

fn send(tx: &mpsc::Sender<WorkerUpdate>, ctx: &egui::Context, msg: WorkerUpdate) {
    let _ = tx.send(msg);
    ctx.request_repaint();
}

fn make_progress_cb(
    tx: mpsc::Sender<WorkerUpdate>,
    ctx: egui::Context,
    item_index: Option<(usize, usize)>,
) -> Arc<dyn Fn(u64, u64) + Send + Sync> {
    let meter = match item_index {
        Some((cur, tot)) => TransferMeter::with_item(Instant::now(), cur, tot),
        None => TransferMeter::new(Instant::now()),
    };
    let shared = Mutex::new((meter, Option::<Instant>::None));
    Arc::new(move |done: u64, total: u64| {
        let now = Instant::now();
        let Ok(mut guard) = shared.lock() else {
            return;
        };
        let snap: TransferSnapshot = guard.0.update_at(now, done, total);
        let is_final = total > 0 && done >= total;
        let should_send = is_final
            || match guard.1 {
                None => true,
                Some(last) => now.saturating_duration_since(last) >= PROGRESS_INTERVAL,
            };
        if should_send {
            guard.1 = Some(now);
            drop(guard);
            send(&tx, &ctx, WorkerUpdate::Progress(snap));
        }
    })
}

fn load_optional_keyfile(path: Option<&Path>) -> Result<Option<SecretKey>, StorageError> {
    let Some(p) = path else {
        return Ok(None);
    };
    let mut f = File::open(p)?;
    Ok(Some(hash_keyfile_reader(&mut f)?))
}

fn keyfile_error_msg(err: &StorageError, lang: AppLanguage) -> String {
    match lang {
        AppLanguage::Tr => format!("Anahtar dosyası hatası: {err}"),
        AppLanguage::En => format!("Keyfile error: {err}"),
    }
}

/// Format a re-key failure cleanly without exposing padded/hidden container structure.
pub fn format_rekey_error(err: &StorageError, lang: AppLanguage) -> String {
    if matches!(
        err,
        StorageError::Crypto(CryptoError::UnsupportedOperation(_))
    ) {
        return match lang {
            AppLanguage::Tr => "Bu kasa için yerinde anahtar değiştirme kullanılamıyor; kimlik bilgilerini değiştirmek için kasayı çözüp yeniden şifreleyin.".to_string(),
            AppLanguage::En => "In-place re-key is not available for this vault; decrypt and re-encrypt to change credentials.".to_string(),
        };
    }
    err.to_string()
}

fn yes_no(flag: bool, lang: AppLanguage) -> &'static str {
    match (lang, flag) {
        (AppLanguage::Tr, true) => "Evet",
        (AppLanguage::Tr, false) => "Hayır",
        (AppLanguage::En, true) => "Yes",
        (AppLanguage::En, false) => "No",
    }
}

/// Format a passwordless structural integrity report for localized GUI display.
pub fn format_integrity_report(rep: &IntegrityReport, lang: AppLanguage) -> String {
    if rep.sha256_only {
        let size_label = match lang {
            AppLanguage::Tr => "Dosya boyutu",
            AppLanguage::En => "File size",
        };
        return format!(
            "{size_label}: {} B\nSHA-256: {}\n{}",
            rep.file_size,
            rep.sha256_hex,
            crate::i18n::strings(lang).digest_computed
        );
    }
    let s = crate::i18n::strings(lang);
    let rs = yes_no(rep.has_reed_solomon, lang);
    let kf = yes_no(rep.has_keyfile, lang);
    let rec = yes_no(rep.has_recovery, lang);
    match lang {
        AppLanguage::Tr => {
            let extra = if rep.has_reed_solomon {
                format!("\n{:<17} : {}", s.rs_bytes, rep.rs_repaired_bytes)
            } else {
                String::new()
            };
            format!(
                "BÜTÜNLÜK KONTROLÜ\nDosya Boyutu      : {} bayt\nSürüm             : v{}\nParça Sayısı      : {}\nAnahtar Dosyası   : {kf}\nKurtarma Slotu    : {rec}\nReed-Solomon      : {rs}{extra}\n\n{}",
                rep.file_size, rep.version, rep.chunk_count, rep.message
            )
        }
        AppLanguage::En => {
            let extra = if rep.has_reed_solomon {
                format!("\n{:<16} : {}", s.rs_bytes, rep.rs_repaired_bytes)
            } else {
                String::new()
            };
            format!(
                "INTEGRITY CHECK\nFile Size        : {} bytes\nVersion          : v{}\nChunks           : {}\nKeyfile Slot     : {kf}\nRecovery Slot    : {rec}\nReed-Solomon     : {rs}{extra}\n\n{}",
                rep.file_size, rep.version, rep.chunk_count, rep.message
            )
        }
    }
}

/// Format unlocked Vault v5 metadata & file manifest summary for localized GUI display.
pub fn format_inspect_report(info: &VaultInfo, lang: AppLanguage) -> String {
    let m = &info.metadata;
    let mib = (m.original_size as f64) / (1024.0 * 1024.0);
    let kf = yes_no(info.has_keyfile, lang);
    let rec = yes_no(info.has_recovery, lang);
    let mut lines = match lang {
        AppLanguage::Tr => vec![
            "KASA META VERİSİ (v5 Parçalı AEAD)".to_string(),
            format!("Özgün Ad        : {}", m.filename),
            format!("Özgün Boyut     : {} bayt ({mib:.2} MiB)", m.original_size),
            format!("Dosya Sayısı    : {}", m.file_count),
            format!("Oluşturulma     : {}", m.created_at),
            format!(
                "Şifreleme       : {} ({} KiB parça)",
                info.cipher,
                info.chunk_size / 1024
            ),
            format!(
                "Argon2id        : bellek={} KiB, tekrar={}, paralel={}",
                info.argon_memory_kib, info.argon_iterations, info.argon_parallelism
            ),
            format!("Anahtar Dosyası : {kf}"),
            format!("Kurtarma Slotu  : {rec}"),
        ],
        AppLanguage::En => vec![
            "VAULT METADATA (v5 Chunked AEAD)".to_string(),
            format!("Original Name  : {}", m.filename),
            format!("Original Size  : {} bytes ({mib:.2} MiB)", m.original_size),
            format!("File Count     : {}", m.file_count),
            format!("Created        : {}", m.created_at),
            format!(
                "Cipher         : {} ({} KiB chunks)",
                info.cipher,
                info.chunk_size / 1024
            ),
            format!(
                "Argon2id       : mem={} KiB, iters={}, par={}",
                info.argon_memory_kib, info.argon_iterations, info.argon_parallelism
            ),
            format!("Keyfile Bound  : {kf}"),
            format!("Recovery Slot  : {rec}"),
        ],
    };

    match lang {
        AppLanguage::Tr => {
            lines.push(format!(
                "Reed-Solomon    : {}",
                yes_no(info.has_reed_solomon, lang)
            ));
            if info.has_reed_solomon {
                lines.push(format!(
                    "{:<15} : {}",
                    crate::i18n::strings(lang).rs_seen,
                    info.rs_repaired_bytes
                ));
            }
        }
        AppLanguage::En => {
            lines.push(format!(
                "Reed-Solomon   : {}",
                yes_no(info.has_reed_solomon, lang)
            ));
            if info.has_reed_solomon {
                lines.push(format!(
                    "{:<14} : {}",
                    crate::i18n::strings(lang).rs_seen,
                    info.rs_repaired_bytes
                ));
            }
        }
    }
    if info.is_stealth {
        lines.push(match lang {
            AppLanguage::Tr => {
                format!(
                    "Başlık Modu     : {}",
                    crate::i18n::strings(lang).stealth_mode
                )
            }
            AppLanguage::En => {
                format!(
                    "Header Mode    : {}",
                    crate::i18n::strings(lang).stealth_mode
                )
            }
        });
    }
    if let Some(container_size) = info.container_size {
        let container_mib = (container_size as f64) / (1024.0 * 1024.0);
        lines.push(match lang {
            AppLanguage::Tr => {
                format!("Konteyner Boyutu: {container_size} bayt ({container_mib:.2} MiB)")
            }
            AppLanguage::En => {
                format!("Container Size : {container_size} bytes ({container_mib:.2} MiB)")
            }
        });
    }
    if info.is_hidden_compartment {
        lines.push(match lang {
            AppLanguage::Tr => {
                "Bölme           : Gizli Kasa (Makul İnkâr Edilebilirlik)".to_string()
            }
            AppLanguage::En => "Compartment    : Hidden Vault (Plausible Deniability)".to_string(),
        });
    }

    if !m.files.is_empty() {
        lines.push(String::new());
        match lang {
            AppLanguage::Tr => {
                lines.push(format!("DOSYA LİSTESİ ({} girdi):", m.files.len()));
                for entry in m.files.iter().take(MAX_REPORT_ENTRIES) {
                    lines.push(format!("  - {} ({} bayt)", entry.path, entry.size));
                }
                if m.files.len() > MAX_REPORT_ENTRIES {
                    lines.push(format!(
                        "  ... ve {} girdi daha",
                        m.files.len() - MAX_REPORT_ENTRIES
                    ));
                }
            }
            AppLanguage::En => {
                lines.push(format!("FILE MANIFEST ({} entries):", m.files.len()));
                for entry in m.files.iter().take(MAX_REPORT_ENTRIES) {
                    lines.push(format!("  - {} ({} bytes)", entry.path, entry.size));
                }
                if m.files.len() > MAX_REPORT_ENTRIES {
                    lines.push(format!(
                        "  ... and {} more",
                        m.files.len() - MAX_REPORT_ENTRIES
                    ));
                }
            }
        }
    }
    lines.join("\n")
}

fn format_signed_delta(delta: i128) -> String {
    if delta > 0 {
        format!("+{delta}")
    } else {
        delta.to_string()
    }
}

/// Format a header-only Vault Diff (A -> B) summary & categorized entries for localized GUI display.
pub fn format_diff_report(diff: &VaultDiff, lang: AppLanguage) -> String {
    let mut lines = match lang {
        AppLanguage::Tr => vec![
            "KASA KARŞILAŞTIRMA (A -> B, Yalnızca Başlık)".to_string(),
            format!(
                "Özet: +{} eklenen, -{} silinen, ~{} değişen, ={} değişmeyen",
                diff.added.len(),
                diff.removed.len(),
                diff.changed.len(),
                diff.unchanged.len()
            ),
        ],
        AppLanguage::En => vec![
            "VAULT DIFF (A -> B, Header-Only)".to_string(),
            format!(
                "Summary: +{} added, -{} removed, ~{} changed, ={} unchanged",
                diff.added.len(),
                diff.removed.len(),
                diff.changed.len(),
                diff.unchanged.len()
            ),
        ],
    };

    if diff.added.is_empty() && diff.removed.is_empty() && diff.changed.is_empty() {
        lines.push(match lang {
            AppLanguage::Tr => {
                "Fark bulunamadı — her iki kasa dosya listesi birebir aynı.".to_string()
            }
            AppLanguage::En => {
                "No differences found — both vault manifests are identical.".to_string()
            }
        });
    }

    let push_simple_section =
        |lines: &mut Vec<String>,
         heading_tr: &str,
         heading_en: &str,
         prefix: char,
         entries: &[rpm_core::FileManifestEntry]| {
            if entries.is_empty() {
                return;
            }
            lines.push(String::new());
            match lang {
                AppLanguage::Tr => {
                    lines.push(format!("{heading_tr} ({}):", entries.len()));
                    for entry in entries.iter().take(MAX_REPORT_ENTRIES) {
                        lines.push(format!("  {prefix} {} ({} bayt)", entry.path, entry.size));
                    }
                    if entries.len() > MAX_REPORT_ENTRIES {
                        lines.push(format!(
                            "  ... ve {} girdi daha",
                            entries.len() - MAX_REPORT_ENTRIES
                        ));
                    }
                }
                AppLanguage::En => {
                    lines.push(format!("{heading_en} ({}):", entries.len()));
                    for entry in entries.iter().take(MAX_REPORT_ENTRIES) {
                        lines.push(format!("  {prefix} {} ({} bytes)", entry.path, entry.size));
                    }
                    if entries.len() > MAX_REPORT_ENTRIES {
                        lines.push(format!(
                            "  ... and {} more",
                            entries.len() - MAX_REPORT_ENTRIES
                        ));
                    }
                }
            }
        };

    push_simple_section(&mut lines, "EKLENEN", "ADDED", '+', &diff.added);
    push_simple_section(&mut lines, "SİLİNEN", "REMOVED", '-', &diff.removed);

    if !diff.changed.is_empty() {
        lines.push(String::new());
        match lang {
            AppLanguage::Tr => {
                lines.push(format!("DEĞİŞEN ({}):", diff.changed.len()));
                for entry in diff.changed.iter().take(MAX_REPORT_ENTRIES) {
                    let size_delta = i128::from(entry.after.size) - i128::from(entry.before.size);
                    let mtime_delta = i128::from(entry.after.modified_unix)
                        - i128::from(entry.before.modified_unix);
                    lines.push(format!(
                        "  ~ {} (boyut: {} -> {} bayt [{}], mtime: {} -> {} [{} sn])",
                        entry.after.path,
                        entry.before.size,
                        entry.after.size,
                        format_signed_delta(size_delta),
                        entry.before.modified_unix,
                        entry.after.modified_unix,
                        format_signed_delta(mtime_delta),
                    ));
                }
                if diff.changed.len() > MAX_REPORT_ENTRIES {
                    lines.push(format!(
                        "  ... ve {} girdi daha",
                        diff.changed.len() - MAX_REPORT_ENTRIES
                    ));
                }
            }
            AppLanguage::En => {
                lines.push(format!("CHANGED ({}):", diff.changed.len()));
                for entry in diff.changed.iter().take(MAX_REPORT_ENTRIES) {
                    let size_delta = i128::from(entry.after.size) - i128::from(entry.before.size);
                    let mtime_delta = i128::from(entry.after.modified_unix)
                        - i128::from(entry.before.modified_unix);
                    lines.push(format!(
                        "  ~ {} (size: {} -> {} bytes [{}], mtime: {} -> {} [{}s])",
                        entry.after.path,
                        entry.before.size,
                        entry.after.size,
                        format_signed_delta(size_delta),
                        entry.before.modified_unix,
                        entry.after.modified_unix,
                        format_signed_delta(mtime_delta),
                    ));
                }
                if diff.changed.len() > MAX_REPORT_ENTRIES {
                    lines.push(format!(
                        "  ... and {} more",
                        diff.changed.len() - MAX_REPORT_ENTRIES
                    ));
                }
            }
        }
    }

    push_simple_section(&mut lines, "DEĞİŞMEYEN", "UNCHANGED", '=', &diff.unchanged);

    lines.join("\n")
}

fn resolve_output_vault_path(sources: &[PathBuf], output_dir: Option<PathBuf>) -> PathBuf {
    let base_dir = output_dir.unwrap_or_else(|| {
        sources
            .first()
            .and_then(|s| s.parent())
            .filter(|p| !p.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
    });
    let base_name = if sources.len() == 1 {
        sources[0]
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "Archive".into())
    } else {
        "Archive".into()
    };
    unique_path(&base_dir.join(format!("{base_name}.vault")))
}

fn wipe_sources(
    sources: &[PathBuf],
    wipe_passes: u8,
    tx: &mpsc::Sender<WorkerUpdate>,
    ctx: &egui::Context,
    lang: AppLanguage,
) {
    let wiper = SecureWiper::new(wipe_passes);
    for s in sources {
        let wres = if s.is_dir() {
            wiper.wipe_folder(s)
        } else {
            wiper.wipe_file(s)
        };
        if let Err(err) = wres {
            let warn = match lang {
                AppLanguage::Tr => format!("Güvenli silme uyarısı: {err}"),
                AppLanguage::En => format!("Wipe warning: {err}"),
            };
            send(tx, ctx, WorkerUpdate::Log(warn));
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn spawn_encrypt(
    ctx: egui::Context,
    tx: mpsc::Sender<WorkerUpdate>,
    cancel: Arc<AtomicBool>,
    sources: Vec<PathBuf>,
    password: Zeroizing<String>,
    recovery_entropy: SecretKey,
    keyfile: Option<PathBuf>,
    output_dir: Option<PathBuf>,
    compress: bool,
    container_size_bytes: Option<u64>,
    stealth: bool,
    reed_solomon: bool,
    secure_wipe: bool,
    wipe_passes: u8,
    kdf: KdfParams,
    lang: AppLanguage,
) {
    thread::spawn(move || {
        let keyfile_hash = match load_optional_keyfile(keyfile.as_deref()) {
            Ok(k) => k,
            Err(e) => {
                send(&tx, &ctx, WorkerUpdate::Error(keyfile_error_msg(&e, lang)));
                return;
            }
        };

        let opts = EncryptOptions {
            stealth,
            reed_solomon,
            kdf: if stealth {
                rpm_core::STEALTH_KDF_PARAMS
            } else {
                kdf
            },
            chunk_size: rpm_core::constants::DEFAULT_CHUNK_SIZE,
            recovery_key: Some(recovery_entropy),
            keyfile_hash,
            compressed: compress,
            container_size_bytes,
        };

        let out_vault = resolve_output_vault_path(&sources, output_dir);
        let start_log = match lang {
            AppLanguage::Tr => format!("Şifreleniyor -> {}", out_vault.display()),
            AppLanguage::En => format!("Encrypting -> {}", out_vault.display()),
        };
        send(&tx, &ctx, WorkerUpdate::Log(start_log));

        let progress = make_progress_cb(tx.clone(), ctx.clone(), None);

        let tx_skip = tx.clone();
        let ctx_skip = ctx.clone();
        let res = encrypt_sources_v5(
            &sources,
            &out_vault,
            password.as_bytes(),
            &opts,
            progress,
            cancel,
            move |msg| {
                let line = match lang {
                    AppLanguage::Tr => format!("Atlandı: {msg}"),
                    AppLanguage::En => format!("Skipped: {msg}"),
                };
                send(&tx_skip, &ctx_skip, WorkerUpdate::Log(line));
            },
        );

        match res {
            Ok((_summary, meta)) => {
                if secure_wipe {
                    wipe_sources(&sources, wipe_passes, &tx, &ctx, lang);
                }
                let vault_name = out_vault
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "vault".into());
                let status = match lang {
                    AppLanguage::Tr => {
                        format!("{} dosya şifrelendi -> {vault_name}", meta.file_count)
                    }
                    AppLanguage::En => {
                        format!("Encrypted {} file(s) -> {vault_name}", meta.file_count)
                    }
                };
                send(&tx, &ctx, WorkerUpdate::EncryptDone { status });
            }
            Err(e) => send(&tx, &ctx, WorkerUpdate::Error(e.to_string())),
        }
    });
}

#[allow(clippy::too_many_arguments)]
pub fn spawn_encrypt_hidden(
    ctx: egui::Context,
    tx: mpsc::Sender<WorkerUpdate>,
    cancel: Arc<AtomicBool>,
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
    stealth: bool,
    reed_solomon: bool,
    secure_wipe: bool,
    wipe_passes: u8,
    kdf: KdfParams,
    lang: AppLanguage,
) {
    thread::spawn(move || {
        let decoy_keyfile_hash = match load_optional_keyfile(decoy_keyfile.as_deref()) {
            Ok(k) => k,
            Err(e) => {
                send(&tx, &ctx, WorkerUpdate::Error(keyfile_error_msg(&e, lang)));
                return;
            }
        };
        let hidden_keyfile_hash = match load_optional_keyfile(hidden_keyfile.as_deref()) {
            Ok(k) => k,
            Err(e) => {
                let msg = match lang {
                    AppLanguage::Tr => format!("Gizli anahtar dosyası hatası: {e}"),
                    AppLanguage::En => format!("Hidden keyfile error: {e}"),
                };
                send(&tx, &ctx, WorkerUpdate::Error(msg));
                return;
            }
        };

        let opts = HiddenEncryptOptions {
            stealth,
            reed_solomon,
            kdf: if stealth {
                rpm_core::STEALTH_KDF_PARAMS
            } else {
                kdf
            },
            chunk_size: rpm_core::constants::DEFAULT_CHUNK_SIZE,
            container_size_bytes,
            decoy_recovery_key: Some(decoy_recovery_entropy),
            decoy_keyfile_hash,
            decoy_compressed,
            hidden_keyfile_hash,
            hidden_compressed,
        };

        let out_vault = resolve_output_vault_path(&decoy_sources, output_dir);
        let start_log = match lang {
            AppLanguage::Tr => {
                format!("Gizli kasa konteyneri yazılıyor -> {}", out_vault.display())
            }
            AppLanguage::En => format!("Writing hidden vault container -> {}", out_vault.display()),
        };
        send(&tx, &ctx, WorkerUpdate::Log(start_log));

        let progress = make_progress_cb(tx.clone(), ctx.clone(), None);
        let tx_skip = tx.clone();
        let ctx_skip = ctx.clone();

        let res = encrypt_hidden_sources_v5(
            &decoy_sources,
            &hidden_sources,
            &out_vault,
            decoy_password.as_bytes(),
            hidden_password.as_bytes(),
            &opts,
            progress,
            cancel,
            move |msg| {
                let line = match lang {
                    AppLanguage::Tr => format!("Atlandı: {msg}"),
                    AppLanguage::En => format!("Skipped: {msg}"),
                };
                send(&tx_skip, &ctx_skip, WorkerUpdate::Log(line));
            },
        );

        match res {
            Ok((summary, decoy_meta, hidden_meta)) => {
                if secure_wipe {
                    wipe_sources(&decoy_sources, wipe_passes, &tx, &ctx, lang);
                    wipe_sources(&hidden_sources, wipe_passes, &tx, &ctx, lang);
                }
                let vault_name = out_vault
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "vault".into());
                let container_mib = (summary.container_size as f64) / (1024.0 * 1024.0);
                let status = match lang {
                    AppLanguage::Tr => format!(
                        "{} dış + {} gizli dosya şifrelendi ({container_mib:.1} MiB) -> {vault_name}",
                        decoy_meta.file_count, hidden_meta.file_count
                    ),
                    AppLanguage::En => format!(
                        "Encrypted {} decoy + {} hidden file(s) ({container_mib:.1} MiB) -> {vault_name}",
                        decoy_meta.file_count, hidden_meta.file_count
                    ),
                };
                send(&tx, &ctx, WorkerUpdate::EncryptDone { status });
            }
            Err(e) => send(&tx, &ctx, WorkerUpdate::Error(e.to_string())),
        }
    });
}

#[allow(clippy::too_many_arguments)]
pub fn spawn_decrypt(
    ctx: egui::Context,
    tx: mpsc::Sender<WorkerUpdate>,
    cancel: Arc<AtomicBool>,
    vaults: Vec<PathBuf>,
    use_recovery: bool,
    secret: Zeroizing<String>,
    keyfile: Option<PathBuf>,
    output_dir: Option<PathBuf>,
    lang: AppLanguage,
) {
    thread::spawn(move || {
        let keyfile_hash = match load_optional_keyfile(keyfile.as_deref()) {
            Ok(k) => k,
            Err(e) => {
                send(&tx, &ctx, WorkerUpdate::Error(keyfile_error_msg(&e, lang)));
                return;
            }
        };

        let recovery_key = if use_recovery {
            match mnemonic_to_entropy(&secret) {
                Ok(k) => Some(k),
                Err(e) => {
                    send(&tx, &ctx, WorkerUpdate::Error(e.to_string()));
                    return;
                }
            }
        } else {
            None
        };

        let mut ok_count = 0usize;
        for (idx, vault) in vaults.iter().enumerate() {
            let root_out = output_dir.clone().unwrap_or_else(|| {
                vault
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| PathBuf::from("."))
            });

            let auth = if let Some(ref rk) = recovery_key {
                Auth::RecoveryKey(rk)
            } else {
                Auth::Password {
                    password: secret.as_bytes(),
                    keyfile_hash: keyfile_hash.as_ref(),
                }
            };

            let item = (vaults.len() > 1).then_some((idx + 1, vaults.len()));
            let progress = make_progress_cb(tx.clone(), ctx.clone(), item);

            match decrypt_vault_v5(vault, &root_out, auth, progress, Arc::clone(&cancel)) {
                Ok(summary) => {
                    ok_count += 1;
                    let line = match lang {
                        AppLanguage::Tr => format!(
                            "Çözüldü: {} ({} dosya) -> {}",
                            vault.display(),
                            summary.files_extracted,
                            summary.output_path.display()
                        ),
                        AppLanguage::En => format!(
                            "Decrypted {} ({} file(s)) -> {}",
                            vault.display(),
                            summary.files_extracted,
                            summary.output_path.display()
                        ),
                    };
                    send(&tx, &ctx, WorkerUpdate::Log(line));
                }
                Err(e) => {
                    send(&tx, &ctx, WorkerUpdate::Error(e.to_string()));
                    return;
                }
            }
        }

        let status = match lang {
            AppLanguage::Tr => format!("{ok_count}/{} kasa çözüldü", vaults.len()),
            AppLanguage::En => format!("Decrypted {ok_count}/{} vault(s)", vaults.len()),
        };
        send(&tx, &ctx, WorkerUpdate::DecryptDone { status });
    });
}

pub fn spawn_integrity_check(
    ctx: egui::Context,
    tx: mpsc::Sender<WorkerUpdate>,
    vault: PathBuf,
    lang: AppLanguage,
) {
    thread::spawn(move || match check_integrity(&vault) {
        Ok(rep) => {
            let text = format_integrity_report(&rep, lang);
            send(
                &tx,
                &ctx,
                WorkerUpdate::IntegrityDone {
                    text,
                    ok: rep.ok,
                    sha256_only: rep.sha256_only,
                },
            );
        }
        Err(e) => send(&tx, &ctx, WorkerUpdate::Error(e.to_string())),
    });
}

pub fn spawn_inspect(
    ctx: egui::Context,
    tx: mpsc::Sender<WorkerUpdate>,
    vault: PathBuf,
    use_recovery: bool,
    secret: Zeroizing<String>,
    keyfile: Option<PathBuf>,
    lang: AppLanguage,
) {
    thread::spawn(move || {
        let keyfile_hash = match load_optional_keyfile(keyfile.as_deref()) {
            Ok(k) => k,
            Err(e) => {
                send(&tx, &ctx, WorkerUpdate::Error(keyfile_error_msg(&e, lang)));
                return;
            }
        };
        let recovery_key = if use_recovery {
            match mnemonic_to_entropy(&secret) {
                Ok(k) => Some(k),
                Err(e) => {
                    send(&tx, &ctx, WorkerUpdate::Error(e.to_string()));
                    return;
                }
            }
        } else {
            None
        };

        let mut reader = match File::open(&vault).map(BufReader::new) {
            Ok(r) => r,
            Err(e) => {
                send(&tx, &ctx, WorkerUpdate::Error(e.to_string()));
                return;
            }
        };
        let auth = if let Some(ref rk) = recovery_key {
            Auth::RecoveryKey(rk)
        } else {
            Auth::Password {
                password: secret.as_bytes(),
                keyfile_hash: keyfile_hash.as_ref(),
            }
        };

        match inspect_header_seekable(&mut reader, auth) {
            Ok(info) => {
                let text = format_inspect_report(&info, lang);
                let status = match (lang, info.is_hidden_compartment) {
                    (AppLanguage::Tr, true) => "Gizli kasa meta verisi açıldı",
                    (AppLanguage::Tr, false) => "Kasa meta verisi açıldı",
                    (AppLanguage::En, true) => "Hidden vault metadata unlocked",
                    (AppLanguage::En, false) => "Vault metadata unlocked",
                };
                let manifest = info.metadata.files.clone();
                send(
                    &tx,
                    &ctx,
                    WorkerUpdate::InspectDone {
                        text,
                        status: status.into(),
                        manifest,
                        vault_path: vault.clone(),
                    },
                );
            }
            Err(e) => send(&tx, &ctx, WorkerUpdate::Error(e.to_string())),
        }
    });
}

pub struct VaultDiffTarget {
    pub path: PathBuf,
    pub use_recovery: bool,
    pub secret: Zeroizing<String>,
    pub keyfile: Option<PathBuf>,
}

fn unlock_vault_header_for_diff(
    label: &str,
    target: &VaultDiffTarget,
    lang: AppLanguage,
) -> Result<VaultInfo, String> {
    let prefix = match lang {
        AppLanguage::Tr => format!("Kasa {label}"),
        AppLanguage::En => format!("Vault {label}"),
    };
    if !target.path.is_file() {
        return Err(match lang {
            AppLanguage::Tr => format!("{prefix}: dosya bulunamadı: {}", target.path.display()),
            AppLanguage::En => format!("{prefix}: vault not found: {}", target.path.display()),
        });
    }
    let keyfile_hash = if target.use_recovery {
        None
    } else {
        load_optional_keyfile(target.keyfile.as_deref())
            .map_err(|e| format!("{prefix}: {}", keyfile_error_msg(&e, lang)))?
    };
    let recovery_key = if target.use_recovery {
        Some(mnemonic_to_entropy(&target.secret).map_err(|e| format!("{prefix}: {e}"))?)
    } else {
        None
    };

    let mut reader = File::open(&target.path)
        .map(BufReader::new)
        .map_err(|e| format!("{prefix}: {e}"))?;
    let auth = if let Some(ref rk) = recovery_key {
        Auth::RecoveryKey(rk)
    } else {
        Auth::Password {
            password: target.secret.as_bytes(),
            keyfile_hash: keyfile_hash.as_ref(),
        }
    };
    inspect_header_seekable(&mut reader, auth).map_err(|e| format!("{prefix}: {e}"))
}

pub fn spawn_vault_diff(
    ctx: egui::Context,
    tx: mpsc::Sender<WorkerUpdate>,
    vault_a: VaultDiffTarget,
    vault_b: VaultDiffTarget,
    lang: AppLanguage,
) {
    thread::spawn(move || {
        let info_a = match unlock_vault_header_for_diff("A", &vault_a, lang) {
            Ok(info) => info,
            Err(err) => {
                send(&tx, &ctx, WorkerUpdate::Error(err));
                return;
            }
        };
        let info_b = match unlock_vault_header_for_diff("B", &vault_b, lang) {
            Ok(info) => info,
            Err(err) => {
                send(&tx, &ctx, WorkerUpdate::Error(err));
                return;
            }
        };

        match diff_metadata(&info_a.metadata, &info_b.metadata) {
            Ok(diff) => {
                let text = format_diff_report(&diff, lang);
                let status = match lang {
                    AppLanguage::Tr => format!(
                        "Karşılaştırma tamamlandı: +{} -{} ~{} ={}",
                        diff.added.len(),
                        diff.removed.len(),
                        diff.changed.len(),
                        diff.unchanged.len()
                    ),
                    AppLanguage::En => format!(
                        "Comparison complete: +{} -{} ~{} ={}",
                        diff.added.len(),
                        diff.removed.len(),
                        diff.changed.len(),
                        diff.unchanged.len()
                    ),
                };
                send(&tx, &ctx, WorkerUpdate::DiffDone { text, status });
            }
            Err(e) => send(&tx, &ctx, WorkerUpdate::Error(e.to_string())),
        }
    });
}

#[allow(clippy::too_many_arguments)]
pub fn spawn_selective_extract(
    ctx: egui::Context,
    tx: mpsc::Sender<WorkerUpdate>,
    cancel: Arc<AtomicBool>,
    vault: PathBuf,
    use_recovery: bool,
    secret: Zeroizing<String>,
    keyfile: Option<PathBuf>,
    selected_paths: Vec<String>,
    output_dir: Option<PathBuf>,
    lang: AppLanguage,
) {
    thread::spawn(move || {
        let keyfile_hash = match load_optional_keyfile(keyfile.as_deref()) {
            Ok(k) => k,
            Err(e) => {
                send(&tx, &ctx, WorkerUpdate::Error(keyfile_error_msg(&e, lang)));
                return;
            }
        };
        let recovery_key = if use_recovery {
            match mnemonic_to_entropy(&secret) {
                Ok(k) => Some(k),
                Err(e) => {
                    send(&tx, &ctx, WorkerUpdate::Error(e.to_string()));
                    return;
                }
            }
        } else {
            None
        };

        let root_out = output_dir.unwrap_or_else(|| {
            vault
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("."))
        });

        let auth = if let Some(ref rk) = recovery_key {
            Auth::RecoveryKey(rk)
        } else {
            Auth::Password {
                password: secret.as_bytes(),
                keyfile_hash: keyfile_hash.as_ref(),
            }
        };

        let progress = make_progress_cb(tx.clone(), ctx.clone(), None);

        match decrypt_vault_selected_v5(
            &vault,
            &root_out,
            auth,
            &selected_paths,
            progress,
            Arc::clone(&cancel),
        ) {
            Ok(summary) => {
                let msg = match lang {
                    AppLanguage::Tr => format!(
                        "{} seçili dosya çıkarıldı -> {}",
                        summary.files_extracted,
                        summary.output_path.display()
                    ),
                    AppLanguage::En => format!(
                        "Extracted {} selected file(s) -> {}",
                        summary.files_extracted,
                        summary.output_path.display()
                    ),
                };
                send(&tx, &ctx, WorkerUpdate::Log(msg.clone()));
                send(&tx, &ctx, WorkerUpdate::DecryptDone { status: msg });
            }
            Err(e) => send(&tx, &ctx, WorkerUpdate::Error(e.to_string())),
        }
    });
}

#[allow(clippy::too_many_arguments)]
pub fn spawn_rekey(
    ctx: egui::Context,
    tx: mpsc::Sender<WorkerUpdate>,
    cancel: Arc<AtomicBool>,
    vault: PathBuf,
    old_password: Zeroizing<String>,
    new_password: Zeroizing<String>,
    old_keyfile: Option<PathBuf>,
    new_keyfile: Option<PathBuf>,
    new_kdf: KdfParams,
    lang: AppLanguage,
) {
    thread::spawn(move || {
        let old_kf = match load_optional_keyfile(old_keyfile.as_deref()) {
            Ok(k) => k,
            Err(e) => {
                send(&tx, &ctx, WorkerUpdate::Error(keyfile_error_msg(&e, lang)));
                return;
            }
        };
        let new_kf = match load_optional_keyfile(new_keyfile.as_deref()) {
            Ok(k) => k,
            Err(e) => {
                let msg = match lang {
                    AppLanguage::Tr => format!("Yeni anahtar dosyası hatası: {e}"),
                    AppLanguage::En => format!("New keyfile error: {e}"),
                };
                send(&tx, &ctx, WorkerUpdate::Error(msg));
                return;
            }
        };

        match rekey_vault_v5(
            &vault,
            old_password.as_bytes(),
            new_password.as_bytes(),
            old_kf.as_ref(),
            new_kf.as_ref(),
            Some(new_kdf),
            Some(&cancel),
        ) {
            Ok(()) => {
                let status = match lang {
                    AppLanguage::Tr => {
                        format!("Anahtar güncelleme tamamlandı: {}", vault.display())
                    }
                    AppLanguage::En => format!("Re-key complete: {}", vault.display()),
                };
                send(&tx, &ctx, WorkerUpdate::RekeyDone { status });
            }
            Err(e) => send(&tx, &ctx, WorkerUpdate::Error(format_rekey_error(&e, lang))),
        }
    });
}

#[allow(clippy::too_many_arguments)]
pub fn spawn_preview(
    ctx: egui::Context,
    tx: mpsc::Sender<WorkerUpdate>,
    cancel: Arc<AtomicBool>,
    gen: u64,
    target: VaultDiffTarget,
    path: String,
    lang: AppLanguage,
) {
    thread::spawn(move || {
        let s = crate::i18n::strings(lang);
        let result = (|| {
            let recovery = target
                .use_recovery
                .then(|| mnemonic_to_entropy(&target.secret))
                .transpose()
                .map_err(StorageError::from)?;
            let key = if recovery.is_none() {
                load_optional_keyfile(target.keyfile.as_deref())?
            } else {
                None
            };
            let auth = match recovery.as_ref() {
                Some(key) => Auth::RecoveryKey(key),
                None => Auth::Password {
                    password: target.secret.as_bytes(),
                    keyfile_hash: key.as_ref(),
                },
            };
            rpm_storage::extract_entry_to_memory_v5(
                &target.path,
                auth,
                &path,
                rpm_storage::DEFAULT_PREVIEW_MAX_BYTES,
                make_progress_cb(tx.clone(), ctx.clone(), None),
                cancel,
            )
        })();
        let msg = match result {
            Ok(bytes) => WorkerUpdate::PreviewDone {
                gen,
                path,
                bytes,
                status: s.preview_ready.into(),
            },
            Err(StorageError::Cancelled | StorageError::Crypto(CryptoError::Cancelled)) => {
                WorkerUpdate::PreviewError {
                    gen,
                    message: s.preview_cancelled.into(),
                    cancelled: true,
                }
            }
            Err(StorageError::LimitExceeded(_)) => WorkerUpdate::PreviewError {
                gen,
                message: s.preview_limit.into(),
                cancelled: false,
            },
            Err(err) => WorkerUpdate::PreviewError {
                gen,
                message: format!("{} ({err})", s.preview_failed),
                cancelled: false,
            },
        };
        send(&tx, &ctx, msg);
    });
}

pub fn spawn_repair(
    ctx: egui::Context,
    tx: mpsc::Sender<WorkerUpdate>,
    path: PathBuf,
    cancel: Arc<AtomicBool>,
    lang: AppLanguage,
) {
    thread::spawn(move || {
        let s = crate::i18n::strings(lang);
        let msg = match rpm_storage::repair_vault_v5(&path, None, cancel) {
            Ok(r) => WorkerUpdate::RepairDone(match lang {
                AppLanguage::Tr => format!(
                    "{}: {} ({} blok kontrol edildi)",
                    s.repair_done, r.repaired_bytes, r.blocks_checked
                ),
                AppLanguage::En => format!(
                    "{}: {} ({} blocks checked)",
                    s.repair_done, r.repaired_bytes, r.blocks_checked
                ),
            }),
            Err(StorageError::Crypto(CryptoError::UnsupportedOperation(_))) => {
                WorkerUpdate::Error(s.repair_requires_rs.into())
            }
            Err(StorageError::Crypto(CryptoError::Cancelled)) => {
                WorkerUpdate::Error(s.repair_cancelled.into())
            }
            Err(StorageError::Crypto(CryptoError::InvalidFormat(_))) => {
                WorkerUpdate::Error(s.repair_invalid.into())
            }
            Err(StorageError::Crypto(CryptoError::Io(e)))
                if e.kind() == std::io::ErrorKind::InvalidData =>
            {
                WorkerUpdate::Error(s.repair_invalid.into())
            }
            Err(e) => WorkerUpdate::Error(format!("{}: {e}", s.repair_error)),
        };
        send(&tx, &ctx, msg);
    });
}
