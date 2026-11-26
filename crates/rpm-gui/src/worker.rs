//! Background worker thread launchers bridging `rpm-core`/`rpm-storage` to `egui`.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use eframe::egui;
use rpm_core::{
    diff_metadata, hash_keyfile_reader, inspect_header_seekable_with_kdf_and_threads,
    mnemonic_to_entropy, Auth, CryptoError, EncryptOptions, HiddenEncryptOptions, IntegrityReport,
    KdfParams, SecretKey, VaultDiff, VaultInfo, STEALTH_KDF_PARAMS,
};
use rpm_storage::config::AppLanguage;
use rpm_storage::{
    check_compartment_sources, check_vault_integrity_with_parts_and_threads, check_wipe_targets,
    decrypt_vault_v5_with_stealth_kdf_and_threads, discover_split_parts,
    encrypt_hidden_sources_v5_split_with_threads, encrypt_hidden_sources_v5_with_threads,
    encrypt_sources_v5_split_with_threads, encrypt_sources_v5_with_threads,
    extract_entry_to_memory_v5_with_stealth_kdf_and_threads, join_vault_parts, open_vault_reader,
    rekey_vault_v5, repair_vault_v5_with_threads, split_vault_file, unique_path, unique_split_base,
    SecureWiper, StorageError,
};
use zeroize::Zeroizing;

use crate::estimator::{scan_sources_sync, SourceSizeSummary};
use crate::progress::{TransferMeter, TransferSnapshot};
use crate::queue::{QueuedJob, QueuedJobKind};
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
    format_integrity_report_with_split(rep, None, lang)
}

/// Format a passwordless structural integrity report with optional split volume part count
/// aligned inside the header summary block.
pub fn format_integrity_report_with_split(
    rep: &IntegrityReport,
    split_parts: Option<usize>,
    lang: AppLanguage,
) -> String {
    if rep.sha256_only {
        let size_label = match lang {
            AppLanguage::Tr => "Dosya boyutu",
            AppLanguage::En => "File size",
        };
        let split_line = match (split_parts, lang) {
            (Some(parts), AppLanguage::Tr) => format!("\nBölünmüş parça: {parts}"),
            (Some(parts), AppLanguage::En) => format!("\nSplit Parts: {parts}"),
            (None, _) => String::new(),
        };
        return format!(
            "{size_label}: {} B{split_line}\nSHA-256: {}\n{}",
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
            let mut extra = if rep.has_reed_solomon {
                format!("\n{:<17} : {}", s.rs_bytes, rep.rs_repaired_bytes)
            } else {
                String::new()
            };
            if let Some(parts) = split_parts {
                extra.push_str(&format!("\nBölünmüş Parça    : {parts}"));
            }
            format!(
                "BÜTÜNLÜK KONTROLÜ\nDosya Boyutu      : {} bayt\nSürüm             : v{}\nAEAD Blok Sayısı  : {}\nAnahtar Dosyası   : {kf}\nKurtarma Slotu    : {rec}\nReed-Solomon      : {rs}{extra}\n\n{}",
                rep.file_size, rep.version, rep.chunk_count, rep.message
            )
        }
        AppLanguage::En => {
            let mut extra = if rep.has_reed_solomon {
                format!("\n{:<16} : {}", s.rs_bytes, rep.rs_repaired_bytes)
            } else {
                String::new()
            };
            if let Some(parts) = split_parts {
                extra.push_str(&format!("\nSplit Parts      : {parts}"));
            }
            format!(
                "INTEGRITY CHECK\nFile Size        : {} bytes\nVersion          : v{}\nChunks           : {}\nKeyfile Slot     : {kf}\nRecovery Slot    : {rec}\nReed-Solomon     : {rs}{extra}\n\n{}",
                rep.file_size, rep.version, rep.chunk_count, rep.message
            )
        }
    }
}

/// Format unlocked Vault v5 metadata & file manifest summary for localized GUI display.
pub fn format_inspect_report(info: &VaultInfo, lang: AppLanguage) -> String {
    format_inspect_report_with_split(info, None, lang)
}

/// Format unlocked Vault v5 metadata & file manifest summary with optional split part count
/// aligned inside the header block (before the file manifest listing).
pub fn format_inspect_report_with_split(
    info: &VaultInfo,
    split_parts: Option<usize>,
    lang: AppLanguage,
) -> String {
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
    if let Some(parts) = split_parts {
        lines.push(match lang {
            AppLanguage::Tr => format!("Bölünmüş Parça  : {parts}"),
            AppLanguage::En => format!("Split Parts    : {parts}"),
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

fn resolve_output_dir(sources: &[PathBuf], output_dir: Option<PathBuf>) -> PathBuf {
    output_dir.unwrap_or_else(|| {
        sources
            .first()
            .and_then(|s| s.parent())
            .filter(|p| !p.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
    })
}

fn resolve_output_vault_path(
    sources: &[PathBuf],
    output_dir: Option<PathBuf>,
    split_mode: bool,
) -> PathBuf {
    let base_dir = resolve_output_dir(sources, output_dir);
    let base_name = if sources.len() == 1 {
        sources[0]
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "Archive".into())
    } else {
        "Archive".into()
    };
    let candidate = base_dir.join(format!("{base_name}.vault"));
    if split_mode {
        unique_split_base(&candidate)
    } else {
        unique_path(&candidate)
    }
}

fn format_safety_error(err: StorageError, overlap: bool, lang: AppLanguage) -> String {
    if matches!(err, StorageError::InvalidPath(_)) {
        let s = crate::i18n::strings(lang);
        return if overlap {
            s.err_compartment_overlap.to_string()
        } else {
            s.err_wipe_protected_target.to_string()
        };
    }
    err.to_string()
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
    spawn_encrypt_with_split(
        ctx,
        tx,
        cancel,
        sources,
        password,
        recovery_entropy,
        keyfile,
        output_dir,
        compress,
        container_size_bytes,
        None,
        stealth,
        reed_solomon,
        secure_wipe,
        wipe_passes,
        kdf,
        lang,
    );
}

#[allow(clippy::too_many_arguments)]
pub fn spawn_encrypt_with_split(
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
    split_part_bytes: Option<u64>,
    stealth: bool,
    reed_solomon: bool,
    secure_wipe: bool,
    wipe_passes: u8,
    kdf: KdfParams,
    lang: AppLanguage,
) {
    spawn_encrypt_with_split_and_threads(
        ctx,
        tx,
        cancel,
        sources,
        password,
        recovery_entropy,
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
        0,
        lang,
    );
}

#[allow(clippy::too_many_arguments)]
pub fn spawn_encrypt_with_split_and_threads(
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
    split_part_bytes: Option<u64>,
    stealth: bool,
    reed_solomon: bool,
    secure_wipe: bool,
    wipe_passes: u8,
    kdf: KdfParams,
    threads: usize,
    lang: AppLanguage,
) {
    thread::spawn(move || {
        let base_dir = resolve_output_dir(&sources, output_dir.clone());
        if secure_wipe {
            if let Err(e) = check_wipe_targets(sources.iter(), &base_dir, keyfile.iter()) {
                send(
                    &tx,
                    &ctx,
                    WorkerUpdate::Error(format_safety_error(e, false, lang)),
                );
                return;
            }
        }

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

        let out_vault = resolve_output_vault_path(&sources, output_dir, split_part_bytes.is_some());
        let start_log = match (lang, split_part_bytes.is_some()) {
            (AppLanguage::Tr, true) => {
                format!("Parçalı şifreleniyor -> {}.001...", out_vault.display())
            }
            (AppLanguage::Tr, false) => format!("Şifreleniyor -> {}", out_vault.display()),
            (AppLanguage::En, true) => {
                format!("Encrypting (split) -> {}.001...", out_vault.display())
            }
            (AppLanguage::En, false) => format!("Encrypting -> {}", out_vault.display()),
        };
        send(&tx, &ctx, WorkerUpdate::Log(start_log));

        let progress = make_progress_cb(tx.clone(), ctx.clone(), None);

        let tx_skip = tx.clone();
        let ctx_skip = ctx.clone();
        let on_skip = move |msg: &str| {
            let line = match lang {
                AppLanguage::Tr => format!("Atlandı: {msg}"),
                AppLanguage::En => format!("Skipped: {msg}"),
            };
            send(&tx_skip, &ctx_skip, WorkerUpdate::Log(line));
        };

        let res = if let Some(part_bytes) = split_part_bytes {
            encrypt_sources_v5_split_with_threads(
                &sources,
                &out_vault,
                part_bytes,
                password.as_bytes(),
                &opts,
                threads,
                progress,
                cancel,
                on_skip,
            )
            .map(|(_summary, meta, parts)| (meta, parts))
        } else {
            encrypt_sources_v5_with_threads(
                &sources,
                &out_vault,
                password.as_bytes(),
                &opts,
                threads,
                progress,
                cancel,
                on_skip,
            )
            .map(|(_summary, meta)| (meta, vec![out_vault.clone()]))
        };

        match res {
            Ok((meta, outputs)) => {
                if secure_wipe {
                    wipe_sources(&sources, wipe_passes, &tx, &ctx, lang);
                }
                let primary_out = outputs.first().cloned().unwrap_or(out_vault);
                let vault_name = primary_out
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "vault".into());
                let status = if split_part_bytes.is_some() {
                    match lang {
                        AppLanguage::Tr => format!(
                            "{} dosya şifrelendi ({} parça) -> {vault_name}",
                            meta.file_count,
                            outputs.len()
                        ),
                        AppLanguage::En => format!(
                            "Encrypted {} file(s) ({} part(s)) -> {vault_name}",
                            meta.file_count,
                            outputs.len()
                        ),
                    }
                } else {
                    match lang {
                        AppLanguage::Tr => {
                            format!("{} dosya şifrelendi -> {vault_name}", meta.file_count)
                        }
                        AppLanguage::En => {
                            format!("Encrypted {} file(s) -> {vault_name}", meta.file_count)
                        }
                    }
                };
                send(
                    &tx,
                    &ctx,
                    WorkerUpdate::EncryptDone {
                        status,
                        output_path: primary_out,
                    },
                );
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
    spawn_encrypt_hidden_with_split(
        ctx,
        tx,
        cancel,
        decoy_sources,
        hidden_sources,
        decoy_password,
        hidden_password,
        decoy_recovery_entropy,
        decoy_keyfile,
        hidden_keyfile,
        output_dir,
        decoy_compressed,
        hidden_compressed,
        container_size_bytes,
        None,
        stealth,
        reed_solomon,
        secure_wipe,
        wipe_passes,
        kdf,
        lang,
    );
}

#[allow(clippy::too_many_arguments)]
pub fn spawn_encrypt_hidden_with_split(
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
    split_part_bytes: Option<u64>,
    stealth: bool,
    reed_solomon: bool,
    secure_wipe: bool,
    wipe_passes: u8,
    kdf: KdfParams,
    lang: AppLanguage,
) {
    spawn_encrypt_hidden_with_split_and_threads(
        ctx,
        tx,
        cancel,
        decoy_sources,
        hidden_sources,
        decoy_password,
        hidden_password,
        decoy_recovery_entropy,
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
        0,
        lang,
    );
}

#[allow(clippy::too_many_arguments)]
pub fn spawn_encrypt_hidden_with_split_and_threads(
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
    split_part_bytes: Option<u64>,
    stealth: bool,
    reed_solomon: bool,
    secure_wipe: bool,
    wipe_passes: u8,
    kdf: KdfParams,
    threads: usize,
    lang: AppLanguage,
) {
    thread::spawn(move || {
        if let Err(e) = check_compartment_sources(&decoy_sources, &hidden_sources) {
            send(
                &tx,
                &ctx,
                WorkerUpdate::Error(format_safety_error(e, true, lang)),
            );
            return;
        }
        let base_dir = resolve_output_dir(&decoy_sources, output_dir.clone());
        if secure_wipe {
            if let Err(e) = check_wipe_targets(
                decoy_sources.iter().chain(&hidden_sources),
                &base_dir,
                decoy_keyfile.iter().chain(&hidden_keyfile),
            ) {
                send(
                    &tx,
                    &ctx,
                    WorkerUpdate::Error(format_safety_error(e, false, lang)),
                );
                return;
            }
        }

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

        let out_vault =
            resolve_output_vault_path(&decoy_sources, output_dir, split_part_bytes.is_some());
        let start_log = match (lang, split_part_bytes.is_some()) {
            (AppLanguage::Tr, true) => format!(
                "Parçalı gizli kasa konteyneri yazılıyor -> {}.001...",
                out_vault.display()
            ),
            (AppLanguage::Tr, false) => {
                format!("Gizli kasa konteyneri yazılıyor -> {}", out_vault.display())
            }
            (AppLanguage::En, true) => format!(
                "Writing split hidden vault container -> {}.001...",
                out_vault.display()
            ),
            (AppLanguage::En, false) => {
                format!("Writing hidden vault container -> {}", out_vault.display())
            }
        };
        send(&tx, &ctx, WorkerUpdate::Log(start_log));

        let progress = make_progress_cb(tx.clone(), ctx.clone(), None);
        let tx_skip = tx.clone();
        let ctx_skip = ctx.clone();
        let on_skip = move |msg: &str| {
            let line = match lang {
                AppLanguage::Tr => format!("Atlandı: {msg}"),
                AppLanguage::En => format!("Skipped: {msg}"),
            };
            send(&tx_skip, &ctx_skip, WorkerUpdate::Log(line));
        };

        let res = if let Some(part_bytes) = split_part_bytes {
            encrypt_hidden_sources_v5_split_with_threads(
                &decoy_sources,
                &hidden_sources,
                &out_vault,
                part_bytes,
                decoy_password.as_bytes(),
                hidden_password.as_bytes(),
                &opts,
                threads,
                progress,
                cancel,
                on_skip,
            )
        } else {
            encrypt_hidden_sources_v5_with_threads(
                &decoy_sources,
                &hidden_sources,
                &out_vault,
                decoy_password.as_bytes(),
                hidden_password.as_bytes(),
                &opts,
                threads,
                progress,
                cancel,
                on_skip,
            )
            .map(|(summary, d, h)| (summary, d, h, vec![out_vault.clone()]))
        };

        match res {
            Ok((summary, decoy_meta, hidden_meta, outputs)) => {
                if secure_wipe {
                    wipe_sources(&decoy_sources, wipe_passes, &tx, &ctx, lang);
                    wipe_sources(&hidden_sources, wipe_passes, &tx, &ctx, lang);
                }
                let primary_out = outputs.first().cloned().unwrap_or(out_vault);
                let vault_name = primary_out
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "vault".into());
                let container_mib = (summary.container_size as f64) / (1024.0 * 1024.0);
                let status = if split_part_bytes.is_some() {
                    match lang {
                        AppLanguage::Tr => format!(
                            "{} dış + {} gizli dosya şifrelendi ({container_mib:.1} MiB, {} parça) -> {vault_name}",
                            decoy_meta.file_count,
                            hidden_meta.file_count,
                            outputs.len()
                        ),
                        AppLanguage::En => format!(
                            "Encrypted {} decoy + {} hidden file(s) ({container_mib:.1} MiB, {} part(s)) -> {vault_name}",
                            decoy_meta.file_count,
                            hidden_meta.file_count,
                            outputs.len()
                        ),
                    }
                } else {
                    match lang {
                        AppLanguage::Tr => format!(
                            "{} dış + {} gizli dosya şifrelendi ({container_mib:.1} MiB) -> {vault_name}",
                            decoy_meta.file_count, hidden_meta.file_count
                        ),
                        AppLanguage::En => format!(
                            "Encrypted {} decoy + {} hidden file(s) ({container_mib:.1} MiB) -> {vault_name}",
                            decoy_meta.file_count, hidden_meta.file_count
                        ),
                    }
                };
                send(
                    &tx,
                    &ctx,
                    WorkerUpdate::EncryptDone {
                        status,
                        output_path: primary_out,
                    },
                );
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
    spawn_decrypt_with_threads(
        ctx,
        tx,
        cancel,
        vaults,
        use_recovery,
        secret,
        keyfile,
        output_dir,
        0,
        lang,
    );
}

#[allow(clippy::too_many_arguments)]
pub fn spawn_decrypt_with_threads(
    ctx: egui::Context,
    tx: mpsc::Sender<WorkerUpdate>,
    cancel: Arc<AtomicBool>,
    vaults: Vec<PathBuf>,
    use_recovery: bool,
    secret: Zeroizing<String>,
    keyfile: Option<PathBuf>,
    output_dir: Option<PathBuf>,
    threads: usize,
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
        let mut first_output: Option<PathBuf> = None;
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

            match decrypt_vault_v5_with_stealth_kdf_and_threads(
                vault,
                &root_out,
                auth,
                None,
                &rpm_core::STEALTH_KDF_PARAMS,
                threads,
                progress,
                Arc::clone(&cancel),
            ) {
                Ok(summary) => {
                    ok_count += 1;
                    if first_output.is_none() {
                        first_output = Some(summary.output_path.clone());
                    }
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

        let reveal_target = if vaults.len() > 1 {
            output_dir.or_else(|| {
                vaults
                    .first()
                    .and_then(|v| {
                        v.parent()
                            .filter(|p| !p.as_os_str().is_empty())
                            .map(Path::to_path_buf)
                    })
                    .or_else(|| Some(PathBuf::from(".")))
            })
        } else {
            first_output.or(output_dir)
        };
        let status = match lang {
            AppLanguage::Tr => format!("{ok_count}/{} kasa çözüldü", vaults.len()),
            AppLanguage::En => format!("Decrypted {ok_count}/{} vault(s)", vaults.len()),
        };
        send(
            &tx,
            &ctx,
            WorkerUpdate::DecryptDone {
                status,
                output_path: reveal_target,
            },
        );
    });
}

pub fn spawn_integrity_check(
    ctx: egui::Context,
    tx: mpsc::Sender<WorkerUpdate>,
    vault: PathBuf,
    lang: AppLanguage,
) {
    spawn_integrity_check_with_threads(ctx, tx, vault, 0, lang);
}

pub fn spawn_integrity_check_with_threads(
    ctx: egui::Context,
    tx: mpsc::Sender<WorkerUpdate>,
    vault: PathBuf,
    threads: usize,
    lang: AppLanguage,
) {
    thread::spawn(
        move || match check_vault_integrity_with_parts_and_threads(&vault, threads) {
            Ok((rep, split_parts)) => {
                let text = format_integrity_report_with_split(&rep, split_parts, lang);
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
        },
    );
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
    spawn_inspect_with_threads(ctx, tx, vault, use_recovery, secret, keyfile, 0, lang);
}

#[allow(clippy::too_many_arguments)]
pub fn spawn_inspect_with_threads(
    ctx: egui::Context,
    tx: mpsc::Sender<WorkerUpdate>,
    vault: PathBuf,
    use_recovery: bool,
    secret: Zeroizing<String>,
    keyfile: Option<PathBuf>,
    threads: usize,
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

        let mut reader = match open_vault_reader(&vault) {
            Ok(r) => r,
            Err(e) => {
                send(&tx, &ctx, WorkerUpdate::Error(e.to_string()));
                return;
            }
        };
        let split_parts = reader.is_split().then_some(reader.part_count());
        let auth = if let Some(ref rk) = recovery_key {
            Auth::RecoveryKey(rk)
        } else {
            Auth::Password {
                password: secret.as_bytes(),
                keyfile_hash: keyfile_hash.as_ref(),
            }
        };

        match inspect_header_seekable_with_kdf_and_threads(
            &mut reader,
            auth,
            &STEALTH_KDF_PARAMS,
            threads,
        ) {
            Ok(info) => {
                let text = format_inspect_report_with_split(&info, split_parts, lang);
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
    threads: usize,
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

    let mut reader = open_vault_reader(&target.path).map_err(|e| format!("{prefix}: {e}"))?;
    let auth = if let Some(ref rk) = recovery_key {
        Auth::RecoveryKey(rk)
    } else {
        Auth::Password {
            password: target.secret.as_bytes(),
            keyfile_hash: keyfile_hash.as_ref(),
        }
    };
    inspect_header_seekable_with_kdf_and_threads(&mut reader, auth, &STEALTH_KDF_PARAMS, threads)
        .map_err(|e| format!("{prefix}: {e}"))
}

pub fn spawn_vault_diff(
    ctx: egui::Context,
    tx: mpsc::Sender<WorkerUpdate>,
    vault_a: VaultDiffTarget,
    vault_b: VaultDiffTarget,
    lang: AppLanguage,
) {
    spawn_vault_diff_with_threads(ctx, tx, vault_a, vault_b, 0, lang);
}

pub fn spawn_vault_diff_with_threads(
    ctx: egui::Context,
    tx: mpsc::Sender<WorkerUpdate>,
    vault_a: VaultDiffTarget,
    vault_b: VaultDiffTarget,
    threads: usize,
    lang: AppLanguage,
) {
    thread::spawn(move || {
        let info_a = match unlock_vault_header_for_diff("A", &vault_a, threads, lang) {
            Ok(info) => info,
            Err(err) => {
                send(&tx, &ctx, WorkerUpdate::Error(err));
                return;
            }
        };
        let info_b = match unlock_vault_header_for_diff("B", &vault_b, threads, lang) {
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
    spawn_selective_extract_with_threads(
        ctx,
        tx,
        cancel,
        vault,
        use_recovery,
        secret,
        keyfile,
        selected_paths,
        output_dir,
        0,
        lang,
    );
}

#[allow(clippy::too_many_arguments)]
pub fn spawn_selective_extract_with_threads(
    ctx: egui::Context,
    tx: mpsc::Sender<WorkerUpdate>,
    cancel: Arc<AtomicBool>,
    vault: PathBuf,
    use_recovery: bool,
    secret: Zeroizing<String>,
    keyfile: Option<PathBuf>,
    selected_paths: Vec<String>,
    output_dir: Option<PathBuf>,
    threads: usize,
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

        match decrypt_vault_v5_with_stealth_kdf_and_threads(
            &vault,
            &root_out,
            auth,
            Some(&selected_paths),
            &rpm_core::STEALTH_KDF_PARAMS,
            threads,
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
                send(
                    &tx,
                    &ctx,
                    WorkerUpdate::DecryptDone {
                        status: msg,
                        output_path: Some(summary.output_path),
                    },
                );
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

        let primary_vault = match discover_split_parts(&vault) {
            Ok(Some(set)) => set.first_part().to_path_buf(),
            Ok(None) => vault,
            Err(e) => {
                send(&tx, &ctx, WorkerUpdate::Error(format_rekey_error(&e, lang)));
                return;
            }
        };

        match rekey_vault_v5(
            &primary_vault,
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
                        format!("Anahtar güncelleme tamamlandı: {}", primary_vault.display())
                    }
                    AppLanguage::En => format!("Re-key complete: {}", primary_vault.display()),
                };
                send(
                    &tx,
                    &ctx,
                    WorkerUpdate::RekeyDone {
                        status,
                        vault_path: primary_vault,
                    },
                );
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
    spawn_preview_with_threads(ctx, tx, cancel, gen, target, path, 0, lang);
}

#[allow(clippy::too_many_arguments)]
pub fn spawn_preview_with_threads(
    ctx: egui::Context,
    tx: mpsc::Sender<WorkerUpdate>,
    cancel: Arc<AtomicBool>,
    gen: u64,
    target: VaultDiffTarget,
    path: String,
    threads: usize,
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
            extract_entry_to_memory_v5_with_stealth_kdf_and_threads(
                &target.path,
                auth,
                &path,
                rpm_storage::DEFAULT_PREVIEW_MAX_BYTES,
                &rpm_core::STEALTH_KDF_PARAMS,
                threads,
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
    spawn_repair_with_threads(ctx, tx, path, cancel, 0, lang);
}

pub fn spawn_repair_with_threads(
    ctx: egui::Context,
    tx: mpsc::Sender<WorkerUpdate>,
    path: PathBuf,
    cancel: Arc<AtomicBool>,
    threads: usize,
    lang: AppLanguage,
) {
    thread::spawn(move || {
        let s = crate::i18n::strings(lang);
        let primary_path = if path.is_file() {
            match discover_split_parts(&path) {
                Ok(Some(set)) => set.first_part().to_path_buf(),
                Ok(None) => path,
                Err(e) => {
                    send(
                        &tx,
                        &ctx,
                        WorkerUpdate::Error(format!("{}: {e}", s.repair_error)),
                    );
                    return;
                }
            }
        } else {
            path
        };
        let msg = match repair_vault_v5_with_threads(&primary_path, None, threads, cancel) {
            Ok(r) => WorkerUpdate::RepairDone {
                text: match lang {
                    AppLanguage::Tr => format!(
                        "{}: {} ({} blok kontrol edildi)",
                        s.repair_done, r.repaired_bytes, r.blocks_checked
                    ),
                    AppLanguage::En => format!(
                        "{}: {} ({} blocks checked)",
                        s.repair_done, r.repaired_bytes, r.blocks_checked
                    ),
                },
                vault_path: primary_path,
            },
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

pub fn spawn_source_scan(
    ctx: egui::Context,
    tx: mpsc::Sender<WorkerUpdate>,
    cancel: Arc<AtomicBool>,
    gen: u64,
    outer_sources: Vec<PathBuf>,
    hidden_sources: Vec<PathBuf>,
) {
    thread::spawn(move || {
        let Some(outer) = scan_sources_sync(&outer_sources, &cancel) else {
            return;
        };
        let hidden = if hidden_sources.is_empty() {
            SourceSizeSummary::default()
        } else {
            let Some(h) = scan_sources_sync(&hidden_sources, &cancel) else {
                return;
            };
            h
        };
        if !cancel.load(std::sync::atomic::Ordering::Relaxed) {
            send(
                &tx,
                &ctx,
                WorkerUpdate::SourceScanDone { gen, outer, hidden },
            );
        }
    });
}

pub fn spawn_split_vault(
    ctx: egui::Context,
    tx: mpsc::Sender<WorkerUpdate>,
    cancel: Arc<AtomicBool>,
    vault: PathBuf,
    output_dir: Option<PathBuf>,
    part_size_bytes: u64,
    lang: AppLanguage,
) {
    thread::spawn(move || {
        let progress = make_progress_cb(tx.clone(), ctx.clone(), None);
        match split_vault_file(
            &vault,
            output_dir.as_deref(),
            part_size_bytes,
            progress,
            cancel,
        ) {
            Ok(parts) => {
                let first_part = parts[0].clone();
                let first_name = first_part
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "vault.001".into());
                let status = match lang {
                    AppLanguage::Tr => {
                        format!("Kasa {} parçaya bölündü -> {first_name}", parts.len())
                    }
                    AppLanguage::En => {
                        format!("Split vault into {} part(s) -> {first_name}", parts.len())
                    }
                };
                send(&tx, &ctx, WorkerUpdate::Log(status.clone()));
                send(&tx, &ctx, WorkerUpdate::SplitDone { status, first_part });
            }
            Err(e) => send(&tx, &ctx, WorkerUpdate::Error(e.to_string())),
        }
    });
}

pub fn spawn_join_vault(
    ctx: egui::Context,
    tx: mpsc::Sender<WorkerUpdate>,
    cancel: Arc<AtomicBool>,
    part: PathBuf,
    output_path: Option<PathBuf>,
    lang: AppLanguage,
) {
    thread::spawn(move || {
        let progress = make_progress_cb(tx.clone(), ctx.clone(), None);
        match join_vault_parts(&part, output_path.as_deref(), progress, cancel) {
            Ok((out_path, total_bytes)) => {
                let out_name = out_path
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "vault".into());
                let status = match lang {
                    AppLanguage::Tr => format!(
                        "Parçalar birleştirildi -> {out_name} ({})",
                        crate::progress::format_bytes(total_bytes)
                    ),
                    AppLanguage::En => format!(
                        "Joined parts -> {out_name} ({})",
                        crate::progress::format_bytes(total_bytes)
                    ),
                };
                send(&tx, &ctx, WorkerUpdate::Log(status.clone()));
                send(
                    &tx,
                    &ctx,
                    WorkerUpdate::JoinDone {
                        status,
                        output_path: out_path,
                    },
                );
            }
            Err(e) => send(&tx, &ctx, WorkerUpdate::Error(e.to_string())),
        }
    });
}

pub fn spawn_queued_job(
    ctx: egui::Context,
    tx: mpsc::Sender<WorkerUpdate>,
    cancel: Arc<AtomicBool>,
    job: QueuedJob,
    lang: AppLanguage,
) -> &'static str {
    spawn_queued_job_with_threads(ctx, tx, cancel, job, 0, lang)
}

pub fn spawn_queued_job_with_threads(
    ctx: egui::Context,
    tx: mpsc::Sender<WorkerUpdate>,
    cancel: Arc<AtomicBool>,
    job: QueuedJob,
    threads: usize,
    lang: AppLanguage,
) -> &'static str {
    let s = crate::i18n::strings(lang);
    match job.kind {
        QueuedJobKind::Encrypt {
            sources,
            password,
            recovery_entropy,
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
        } => {
            spawn_encrypt_with_split_and_threads(
                ctx,
                tx,
                cancel,
                sources,
                password,
                recovery_entropy,
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
                threads,
                lang,
            );
            s.status_enc_running
        }
        QueuedJobKind::EncryptHidden {
            decoy_sources,
            hidden_sources,
            decoy_password,
            hidden_password,
            decoy_recovery_entropy,
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
        } => {
            spawn_encrypt_hidden_with_split_and_threads(
                ctx,
                tx,
                cancel,
                decoy_sources,
                hidden_sources,
                decoy_password,
                hidden_password,
                decoy_recovery_entropy,
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
                threads,
                lang,
            );
            s.status_enc_hidden_running
        }
        QueuedJobKind::Decrypt {
            vaults,
            use_recovery,
            secret,
            keyfile,
            output_dir,
        } => {
            spawn_decrypt_with_threads(
                ctx,
                tx,
                cancel,
                vaults,
                use_recovery,
                secret,
                keyfile,
                output_dir,
                threads,
                lang,
            );
            s.status_dec_running
        }
        QueuedJobKind::Repair { path } => {
            spawn_repair_with_threads(ctx, tx, path, cancel, threads, lang);
            s.repair_running
        }
        QueuedJobKind::IntegrityCheck { path } => {
            spawn_integrity_check_with_threads(ctx, tx, path, threads, lang);
            s.status_checking_integrity
        }
    }
}
