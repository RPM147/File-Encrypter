//! Background worker thread launchers bridging `rpm-core`/`rpm-storage` to `egui`.

use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{mpsc, Arc};
use std::thread;

use eframe::egui;
use rpm_core::{
    check_integrity, hash_keyfile_reader, inspect_header, mnemonic_to_entropy, Auth,
    EncryptOptions, KdfParams, SecretKey,
};
use rpm_storage::{
    decrypt_vault_v5, encrypt_sources_v5, rekey_vault_v5, unique_path, SecureWiper, StorageError,
};
use zeroize::Zeroizing;

use crate::state::WorkerUpdate;

fn send(tx: &mpsc::Sender<WorkerUpdate>, ctx: &egui::Context, msg: WorkerUpdate) {
    let _ = tx.send(msg);
    ctx.request_repaint();
}

fn load_optional_keyfile(path: Option<&Path>) -> Result<Option<SecretKey>, StorageError> {
    let Some(p) = path else {
        return Ok(None);
    };
    let mut f = File::open(p)?;
    Ok(Some(hash_keyfile_reader(&mut f)?))
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
    secure_wipe: bool,
    wipe_passes: u8,
    kdf: KdfParams,
) {
    thread::spawn(move || {
        let keyfile_hash = match load_optional_keyfile(keyfile.as_deref()) {
            Ok(k) => k,
            Err(e) => {
                send(
                    &tx,
                    &ctx,
                    WorkerUpdate::Error(format!("Keyfile error: {e}")),
                );
                return;
            }
        };

        let opts = EncryptOptions {
            kdf,
            chunk_size: rpm_core::constants::DEFAULT_CHUNK_SIZE,
            recovery_key: Some(recovery_entropy),
            keyfile_hash,
            compressed: compress,
        };

        let base_dir = output_dir.unwrap_or_else(|| {
            sources[0]
                .parent()
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
        let out_vault = unique_path(&base_dir.join(format!("{base_name}.vault")));
        send(
            &tx,
            &ctx,
            WorkerUpdate::Log(format!("Encrypting -> {}", out_vault.display())),
        );

        let tx_p = tx.clone();
        let ctx_p = ctx.clone();
        let progress = Arc::new(move |done: u64, total: u64| {
            let frac = if total > 0 {
                (done as f32 / total as f32).clamp(0.0, 1.0)
            } else {
                1.0
            };
            send(&tx_p, &ctx_p, WorkerUpdate::Progress(frac));
        });

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
                send(
                    &tx_skip,
                    &ctx_skip,
                    WorkerUpdate::Log(format!("Skipped: {msg}")),
                );
            },
        );

        match res {
            Ok((_summary, meta)) => {
                if secure_wipe {
                    let wiper = SecureWiper::new(wipe_passes);
                    for s in &sources {
                        let wres = if s.is_dir() {
                            wiper.wipe_folder(s)
                        } else {
                            wiper.wipe_file(s)
                        };
                        if let Err(err) = wres {
                            send(&tx, &ctx, WorkerUpdate::Log(format!("Wipe warning: {err}")));
                        }
                    }
                }
                send(
                    &tx,
                    &ctx,
                    WorkerUpdate::EncryptDone {
                        status: format!(
                            "Encrypted {} file(s) -> {}",
                            meta.file_count,
                            out_vault
                                .file_name()
                                .map(|s| s.to_string_lossy().into_owned())
                                .unwrap_or_else(|| "vault".into())
                        ),
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
) {
    thread::spawn(move || {
        let keyfile_hash = match load_optional_keyfile(keyfile.as_deref()) {
            Ok(k) => k,
            Err(e) => {
                send(
                    &tx,
                    &ctx,
                    WorkerUpdate::Error(format!("Keyfile error: {e}")),
                );
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
        for vault in &vaults {
            let root_out = output_dir.clone().unwrap_or_else(|| {
                vault
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| PathBuf::from("."))
            });
            let stem = vault
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "restored".into());
            let dest = unique_path(&root_out.join(stem));

            let auth = if let Some(ref rk) = recovery_key {
                Auth::RecoveryKey(rk)
            } else {
                Auth::Password {
                    password: secret.as_bytes(),
                    keyfile_hash: keyfile_hash.as_ref(),
                }
            };

            let tx_p = tx.clone();
            let ctx_p = ctx.clone();
            let progress = Arc::new(move |done: u64, total: u64| {
                let frac = if total > 0 {
                    (done as f32 / total as f32).clamp(0.0, 1.0)
                } else {
                    1.0
                };
                send(&tx_p, &ctx_p, WorkerUpdate::Progress(frac));
            });

            match decrypt_vault_v5(vault, &dest, auth, progress, Arc::clone(&cancel)) {
                Ok(summary) => {
                    ok_count += 1;
                    send(
                        &tx,
                        &ctx,
                        WorkerUpdate::Log(format!(
                            "Decrypted {} ({} file(s)) -> {}",
                            vault.display(),
                            summary.files_extracted,
                            dest.display()
                        )),
                    );
                }
                Err(e) => {
                    send(&tx, &ctx, WorkerUpdate::Error(e.to_string()));
                    return;
                }
            }
        }

        send(
            &tx,
            &ctx,
            WorkerUpdate::DecryptDone {
                status: format!("Decrypted {ok_count}/{} vault(s)", vaults.len()),
            },
        );
    });
}

pub fn spawn_integrity_check(ctx: egui::Context, tx: mpsc::Sender<WorkerUpdate>, vault: PathBuf) {
    thread::spawn(move || match check_integrity(&vault) {
        Ok(rep) => {
            let text = format!(
                "INTEGRITY CHECK\nFile Size: {} bytes\nVersion: v{}\nKeyfile Slot: {}\nRecovery Slot: {}\n\n{}",
                rep.file_size,
                rep.version,
                if rep.has_keyfile { "Yes" } else { "No" },
                if rep.has_recovery { "Yes" } else { "No" },
                rep.message
            );
            send(&tx, &ctx, WorkerUpdate::IntegrityDone { text, ok: rep.ok });
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
) {
    thread::spawn(move || {
        let keyfile_hash = match load_optional_keyfile(keyfile.as_deref()) {
            Ok(k) => k,
            Err(e) => {
                send(
                    &tx,
                    &ctx,
                    WorkerUpdate::Error(format!("Keyfile error: {e}")),
                );
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

        match inspect_header(&mut reader, auth) {
            Ok(info) => {
                let m = &info.metadata;
                let mib = (m.original_size as f64) / (1024.0 * 1024.0);
                let mut lines = vec![
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
                    format!(
                        "Keyfile Bound  : {}",
                        if info.has_keyfile { "Yes" } else { "No" }
                    ),
                    format!(
                        "Recovery Slot  : {}",
                        if info.has_recovery { "Yes" } else { "No" }
                    ),
                ];
                if !m.files.is_empty() {
                    lines.push(String::new());
                    lines.push(format!("FILE MANIFEST ({} entries):", m.files.len()));
                    for entry in m.files.iter().take(150) {
                        lines.push(format!("  - {} ({} bytes)", entry.path, entry.size));
                    }
                    if m.files.len() > 150 {
                        lines.push(format!("  ... and {} more", m.files.len() - 150));
                    }
                }
                send(
                    &tx,
                    &ctx,
                    WorkerUpdate::InspectDone {
                        text: lines.join("\n"),
                        status: "Vault metadata unlocked".into(),
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
) {
    thread::spawn(move || {
        let old_kf = match load_optional_keyfile(old_keyfile.as_deref()) {
            Ok(k) => k,
            Err(e) => {
                send(
                    &tx,
                    &ctx,
                    WorkerUpdate::Error(format!("Keyfile error: {e}")),
                );
                return;
            }
        };
        let new_kf = match load_optional_keyfile(new_keyfile.as_deref()) {
            Ok(k) => k,
            Err(e) => {
                send(
                    &tx,
                    &ctx,
                    WorkerUpdate::Error(format!("New keyfile error: {e}")),
                );
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
            Ok(()) => send(
                &tx,
                &ctx,
                WorkerUpdate::RekeyDone {
                    status: format!("Re-key complete: {}", vault.display()),
                },
            ),
            Err(e) => send(&tx, &ctx, WorkerUpdate::Error(e.to_string())),
        }
    });
}
