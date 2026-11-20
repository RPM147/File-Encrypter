//! Headless Pure-Rust CLI for RPM Encrypter v5 (zero GUI dependencies).

use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use clap::{Parser, Subcommand, ValueEnum};
use rand::rngs::OsRng;
use rand::Rng;
use rpm_core::{
    check_integrity, entropy_to_mnemonic, generate_recovery_entropy, hash_keyfile_reader,
    inspect_header, mnemonic_to_entropy, Auth, CryptoError, EncryptOptions, KdfParams, SecretKey,
    VaultMetadata,
};
use rpm_storage::shell_integration;
use rpm_storage::{
    decrypt_vault_v5, encrypt_sources_v5, rekey_vault_v5, unique_path, SecureWiper, StorageError,
};
use zeroize::Zeroizing;

#[derive(Parser, Debug)]
#[command(
    name = "rpm-encrypter-cli",
    version,
    about = "RPM Encrypter v5 CLI (Chunked AES-256-GCM + Argon2id, Zero-Temp-Plaintext)."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Encrypt files or directories into a Vault Format v5 (.vault) archive.
    Encrypt {
        #[arg(required = true)]
        sources: Vec<PathBuf>,
        #[arg(short, long)]
        output_dir: Option<PathBuf>,
        #[arg(long)]
        keyfile: Option<PathBuf>,
        #[arg(long)]
        no_compress: bool,
        #[arg(long)]
        wipe: bool,
        #[arg(long)]
        recovery_out: Option<PathBuf>,
        #[arg(long)]
        password_stdin: bool,
    },
    /// Decrypt one or more .vault files using streaming Chunked AEAD authentication.
    Decrypt {
        #[arg(required = true)]
        vaults: Vec<PathBuf>,
        #[arg(short, long)]
        output_dir: Option<PathBuf>,
        #[arg(long)]
        keyfile: Option<PathBuf>,
        #[arg(long, conflicts_with_all = ["recovery", "recovery_stdin"])]
        password_stdin: bool,
        #[arg(long, conflicts_with_all = ["password_stdin", "recovery_stdin"])]
        recovery: bool,
        #[arg(long, conflicts_with_all = ["password_stdin", "recovery"])]
        recovery_stdin: bool,
    },
    /// Inspect vault integrity (passwordless) or encrypted metadata (header-only).
    Inspect {
        vault: PathBuf,
        #[arg(long)]
        integrity_only: bool,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        keyfile: Option<PathBuf>,
        #[arg(long, conflicts_with_all = ["recovery", "recovery_stdin"])]
        password_stdin: bool,
        #[arg(long, conflicts_with_all = ["password_stdin", "recovery_stdin"])]
        recovery: bool,
        #[arg(long, conflicts_with_all = ["password_stdin", "recovery"])]
        recovery_stdin: bool,
    },
    /// Rotate a vault password (and optionally keyfile) in O(1) without decrypting payload.
    Rekey {
        vault: PathBuf,
        #[arg(long)]
        keyfile: Option<PathBuf>,
        #[arg(long)]
        new_keyfile: Option<PathBuf>,
        #[arg(long, conflicts_with = "new_keyfile")]
        clear_keyfile: bool,
        #[arg(long)]
        password_stdin: bool,
    },
    /// Generate a cryptographically random password and report zxcvbn strength.
    Password {
        #[arg(long, default_value_t = 24)]
        length: usize,
        #[arg(long)]
        no_symbols: bool,
    },
    /// Manage Windows Explorer right-click menu and .vault association (HKCU).
    ShellIntegration {
        #[arg(value_enum)]
        action: ShellAction,
    },
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum ShellAction {
    Status,
    Install,
    Uninstall,
}

fn read_secret_line<R: BufRead>(
    prompt: &str,
    from_stdin: bool,
    confirm: bool,
    stdin: &mut R,
) -> Result<Zeroizing<String>, String> {
    if from_stdin {
        let mut line = String::new();
        stdin
            .read_line(&mut line)
            .map_err(|e| format!("failed reading stdin: {e}"))?;
        let trimmed = line.trim_end_matches(&['\r', '\n'][..]).to_string();
        if trimmed.is_empty() {
            return Err("empty secret input from stdin".into());
        }
        return Ok(Zeroizing::new(trimmed));
    }

    let first = Zeroizing::new(
        rpassword::prompt_password(prompt).map_err(|e| format!("failed reading secret: {e}"))?,
    );
    if first.is_empty() {
        return Err("secret input cannot be empty".into());
    }
    if confirm {
        let second = Zeroizing::new(
            rpassword::prompt_password(format!("Confirm {prompt}"))
                .map_err(|e| format!("failed reading confirmation: {e}"))?,
        );
        if *first != *second {
            return Err("entries do not match".into());
        }
    }
    Ok(first)
}

fn load_keyfile(path: Option<&Path>) -> Result<Option<SecretKey>, String> {
    match path {
        None => Ok(None),
        Some(p) => {
            let mut f =
                File::open(p).map_err(|e| format!("cannot open keyfile {}: {e}", p.display()))?;
            let key = hash_keyfile_reader(&mut f).map_err(|e| e.to_string())?;
            Ok(Some(key))
        }
    }
}

fn format_metadata_plain(meta: &VaultMetadata) -> String {
    let mib = (meta.original_size as f64) / (1024.0 * 1024.0);
    let mut lines = vec![
        format!("Original Name : {}", meta.filename),
        format!(
            "Original Size : {} bytes ({mib:.2} MiB)",
            meta.original_size
        ),
        format!("File Count    : {}", meta.file_count),
        format!("Created       : {}", meta.created_at),
        format!("Source Type   : {}", meta.source_type),
        format!("Compressed    : {}", meta.compressed),
    ];
    if !meta.files.is_empty() {
        lines.push(format!("Manifest ({} entries):", meta.files.len()));
        for f in meta.files.iter().take(100) {
            lines.push(format!("  - {} ({} bytes)", f.path, f.size));
        }
        if meta.files.len() > 100 {
            lines.push(format!("  ... and {} more", meta.files.len() - 100));
        }
    }
    lines.join("\n")
}

fn exit_code_for_storage_error(err: &StorageError) -> i32 {
    match err {
        StorageError::Crypto(CryptoError::AuthenticationFailed | CryptoError::KeyfileRequired) => 2,
        _ => 1,
    }
}

pub fn generate_random_password(length: usize, symbols: bool) -> Zeroizing<String> {
    let mut alphabet: Vec<u8> =
        b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789".to_vec();
    if symbols {
        alphabet.extend_from_slice(b"!@#$%^&*()-_=+[]{}");
    }
    let len = length.clamp(8, 128);
    let mut out = String::with_capacity(len);
    let mut rng = OsRng;
    for _ in 0..len {
        let idx = rng.gen_range(0..alphabet.len());
        out.push(alphabet[idx] as char);
    }
    Zeroizing::new(out)
}

pub fn run_cli_args<I, S, R, W1, W2>(
    args: I,
    stdin: &mut R,
    stdout: &mut W1,
    stderr: &mut W2,
    kdf_override: Option<KdfParams>,
) -> i32
where
    I: IntoIterator<Item = S>,
    S: Into<std::ffi::OsString> + Clone,
    R: BufRead,
    W1: Write,
    W2: Write,
{
    let parsed = match Cli::try_parse_from(args) {
        Ok(c) => c,
        Err(err) => {
            let is_help = err.kind() == clap::error::ErrorKind::DisplayHelp
                || err.kind() == clap::error::ErrorKind::DisplayVersion;
            if is_help {
                let _ = write!(stdout, "{err}");
            } else {
                let _ = write!(stderr, "{err}");
            }
            return if is_help { 0 } else { 2 };
        }
    };

    let cancel = Arc::new(AtomicBool::new(false));
    let kdf = kdf_override.unwrap_or_default();

    match parsed.command {
        Commands::Encrypt {
            sources,
            output_dir,
            keyfile,
            no_compress,
            wipe,
            recovery_out,
            password_stdin,
        } => {
            for s in &sources {
                if !s.exists() {
                    let _ = writeln!(stderr, "Error: source not found: {}", s.display());
                    return 1;
                }
            }
            if let Some(dir) = output_dir.as_deref() {
                if !dir.is_dir() {
                    let _ = writeln!(stderr, "Error: output directory missing: {}", dir.display());
                    return 1;
                }
            }

            let keyfile_hash = match load_keyfile(keyfile.as_deref()) {
                Ok(k) => k,
                Err(e) => {
                    let _ = writeln!(stderr, "Error: {e}");
                    return 1;
                }
            };

            let password = match read_secret_line(
                "Vault password: ",
                password_stdin,
                !password_stdin,
                stdin,
            ) {
                Ok(p) => p,
                Err(e) => {
                    let _ = writeln!(stderr, "Error: {e}");
                    return 1;
                }
            };

            let rec_entropy = generate_recovery_entropy();
            let phrase = match entropy_to_mnemonic(&rec_entropy) {
                Ok(p) => p,
                Err(e) => {
                    let _ = writeln!(stderr, "Error: {e}");
                    return 1;
                }
            };

            let opts = EncryptOptions {
                kdf,
                chunk_size: rpm_core::constants::DEFAULT_CHUNK_SIZE,
                recovery_key: Some(rec_entropy),
                keyfile_hash,
                compressed: !no_compress,
            };

            let base_dir = output_dir.as_deref().unwrap_or_else(|| {
                sources[0]
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or_else(|| Path::new("."))
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

            if let Err(err) = encrypt_sources_v5(
                &sources,
                &out_vault,
                password.as_bytes(),
                &opts,
                Arc::new(|_, _| {}),
                Arc::clone(&cancel),
                |_| {},
            ) {
                let _ = writeln!(stderr, "Error encrypting: {err}");
                return exit_code_for_storage_error(&err);
            }

            if wipe {
                let wiper = SecureWiper::new(1);
                for s in &sources {
                    let res = if s.is_dir() {
                        wiper.wipe_folder(s)
                    } else {
                        wiper.wipe_file(s)
                    };
                    if let Err(e) = res {
                        let _ = writeln!(stderr, "Warning wiping {}: {e}", s.display());
                    }
                }
            }

            let _ = writeln!(stdout, "Encrypted: {}", out_vault.display());
            if let Some(rec_path) = recovery_out {
                if let Some(parent) = rec_path.parent().filter(|p| !p.as_os_str().is_empty()) {
                    let _ = fs::create_dir_all(parent);
                }
                if let Err(e) = fs::write(&rec_path, format!("{}\n", phrase.as_str())) {
                    let _ = writeln!(stderr, "Error writing recovery file: {e}");
                    return 1;
                }
                let _ = writeln!(stdout, "Recovery phrase written to: {}", rec_path.display());
            } else {
                let _ = writeln!(stdout, "\nIMPORTANT - Save this 24-word recovery phrase:");
                let _ = writeln!(stdout, "  {}", phrase.as_str());
            }
            0
        }

        Commands::Decrypt {
            vaults,
            output_dir,
            keyfile,
            password_stdin,
            recovery,
            recovery_stdin,
        } => {
            for v in &vaults {
                if !v.is_file() {
                    let _ = writeln!(stderr, "Error: vault not found: {}", v.display());
                    return 1;
                }
            }
            if let Some(dir) = output_dir.as_deref() {
                if !dir.is_dir() {
                    let _ = writeln!(stderr, "Error: output directory missing: {}", dir.display());
                    return 1;
                }
            }

            let keyfile_hash = match load_keyfile(keyfile.as_deref()) {
                Ok(k) => k,
                Err(e) => {
                    let _ = writeln!(stderr, "Error: {e}");
                    return 1;
                }
            };

            let rec_key: Option<SecretKey>;
            let pw: Option<Zeroizing<String>>;
            if recovery || recovery_stdin {
                let phrase = match read_secret_line(
                    "24-word recovery phrase: ",
                    recovery_stdin,
                    false,
                    stdin,
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = writeln!(stderr, "Error: {e}");
                        return 1;
                    }
                };
                rec_key = Some(match mnemonic_to_entropy(&phrase) {
                    Ok(k) => k,
                    Err(e) => {
                        let _ = writeln!(stderr, "Error: {e}");
                        return 1;
                    }
                });
                pw = None;
            } else {
                pw = Some(
                    match read_secret_line("Vault password: ", password_stdin, false, stdin) {
                        Ok(s) => s,
                        Err(e) => {
                            let _ = writeln!(stderr, "Error: {e}");
                            return 1;
                        }
                    },
                );
                rec_key = None;
            }

            let auth = if let Some(ref rk) = rec_key {
                Auth::RecoveryKey(rk)
            } else {
                Auth::Password {
                    password: pw.as_ref().unwrap().as_bytes(),
                    keyfile_hash: keyfile_hash.as_ref(),
                }
            };

            for v in &vaults {
                let target_root = output_dir.as_deref().unwrap_or_else(|| {
                    v.parent()
                        .filter(|p| !p.as_os_str().is_empty())
                        .unwrap_or_else(|| Path::new("."))
                });
                let stem = v
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "restored".into());
                let dest_dir = unique_path(&target_root.join(stem));
                match decrypt_vault_v5(
                    v,
                    &dest_dir,
                    match auth {
                        Auth::RecoveryKey(r) => Auth::RecoveryKey(r),
                        Auth::Password {
                            password,
                            keyfile_hash,
                        } => Auth::Password {
                            password,
                            keyfile_hash,
                        },
                    },
                    Arc::new(|_, _| {}),
                    Arc::clone(&cancel),
                ) {
                    Ok(summary) => {
                        let _ = writeln!(
                            stdout,
                            "Decrypted: {} -> {} ({} file(s))",
                            v.display(),
                            dest_dir.display(),
                            summary.files_extracted
                        );
                    }
                    Err(err) => {
                        let _ = writeln!(stderr, "Error decrypting {}: {err}", v.display());
                        return exit_code_for_storage_error(&err);
                    }
                }
            }
            0
        }

        Commands::Inspect {
            vault,
            integrity_only,
            json,
            keyfile,
            password_stdin,
            recovery,
            recovery_stdin,
        } => {
            if !vault.is_file() {
                let _ = writeln!(stderr, "Error: vault not found: {}", vault.display());
                return 1;
            }
            if integrity_only {
                match check_integrity(&vault) {
                    Ok(rep) => {
                        if json {
                            let val = serde_json::json!({
                                "path": vault,
                                "ok": rep.ok,
                                "version": rep.version,
                                "file_size": rep.file_size,
                                "sha256": rep.sha256_hex,
                                "has_keyfile": rep.has_keyfile,
                                "has_recovery": rep.has_recovery,
                                "message": rep.message,
                            });
                            let _ =
                                writeln!(stdout, "{}", serde_json::to_string_pretty(&val).unwrap());
                        } else {
                            let _ = writeln!(stdout, "{}", rep.message);
                        }
                        return if rep.ok { 0 } else { 1 };
                    }
                    Err(e) => {
                        let _ = writeln!(stderr, "Error: {e}");
                        return 1;
                    }
                }
            }

            let keyfile_hash = match load_keyfile(keyfile.as_deref()) {
                Ok(k) => k,
                Err(e) => {
                    let _ = writeln!(stderr, "Error: {e}");
                    return 1;
                }
            };

            let rec_key: Option<SecretKey>;
            let pw: Option<Zeroizing<String>>;
            if recovery || recovery_stdin {
                let phrase = match read_secret_line(
                    "24-word recovery phrase: ",
                    recovery_stdin,
                    false,
                    stdin,
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = writeln!(stderr, "Error: {e}");
                        return 1;
                    }
                };
                rec_key = Some(match mnemonic_to_entropy(&phrase) {
                    Ok(k) => k,
                    Err(e) => {
                        let _ = writeln!(stderr, "Error: {e}");
                        return 1;
                    }
                });
                pw = None;
            } else {
                pw = Some(
                    match read_secret_line("Vault password: ", password_stdin, false, stdin) {
                        Ok(s) => s,
                        Err(e) => {
                            let _ = writeln!(stderr, "Error: {e}");
                            return 1;
                        }
                    },
                );
                rec_key = None;
            }

            let auth = if let Some(ref rk) = rec_key {
                Auth::RecoveryKey(rk)
            } else {
                Auth::Password {
                    password: pw.as_ref().unwrap().as_bytes(),
                    keyfile_hash: keyfile_hash.as_ref(),
                }
            };

            let mut reader = match File::open(&vault).map(BufReader::new) {
                Ok(r) => r,
                Err(e) => {
                    let _ = writeln!(stderr, "Error: {e}");
                    return 1;
                }
            };
            match inspect_header(&mut reader, auth) {
                Ok(info) => {
                    if json {
                        let val = serde_json::json!({
                            "path": vault,
                            "version": info.version,
                            "cipher": info.cipher,
                            "chunk_size": info.chunk_size,
                            "has_keyfile": info.has_keyfile,
                            "has_recovery": info.has_recovery,
                            "metadata": info.metadata,
                        });
                        let _ = writeln!(stdout, "{}", serde_json::to_string_pretty(&val).unwrap());
                    } else {
                        let _ = writeln!(
                            stdout,
                            "Version: v{}  Cipher: {}  Chunk: {} KiB\n{}",
                            info.version,
                            info.cipher,
                            info.chunk_size / 1024,
                            format_metadata_plain(&info.metadata)
                        );
                    }
                    0
                }
                Err(err) => {
                    let _ = writeln!(stderr, "Error inspecting {}: {err}", vault.display());
                    match err {
                        CryptoError::AuthenticationFailed | CryptoError::KeyfileRequired => 2,
                        _ => 1,
                    }
                }
            }
        }

        Commands::Rekey {
            vault,
            keyfile,
            new_keyfile,
            clear_keyfile,
            password_stdin,
        } => {
            if !vault.is_file() {
                let _ = writeln!(stderr, "Error: vault not found: {}", vault.display());
                return 1;
            }
            let old_kf = match load_keyfile(keyfile.as_deref()) {
                Ok(k) => k,
                Err(e) => {
                    let _ = writeln!(stderr, "Error: {e}");
                    return 1;
                }
            };
            let new_kf = if clear_keyfile {
                None
            } else if let Some(nk) = new_keyfile.as_deref() {
                match load_keyfile(Some(nk)) {
                    Ok(k) => k,
                    Err(e) => {
                        let _ = writeln!(stderr, "Error: {e}");
                        return 1;
                    }
                }
            } else {
                old_kf.clone()
            };

            let old_pw = match read_secret_line("Current password: ", password_stdin, false, stdin)
            {
                Ok(s) => s,
                Err(e) => {
                    let _ = writeln!(stderr, "Error: {e}");
                    return 1;
                }
            };
            let new_pw =
                match read_secret_line("New password: ", password_stdin, !password_stdin, stdin) {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = writeln!(stderr, "Error: {e}");
                        return 1;
                    }
                };

            match rekey_vault_v5(
                &vault,
                old_pw.as_bytes(),
                new_pw.as_bytes(),
                old_kf.as_ref(),
                new_kf.as_ref(),
                kdf_override,
                Some(&cancel),
            ) {
                Ok(()) => {
                    let _ = writeln!(stdout, "Re-keyed: {}", vault.display());
                    0
                }
                Err(err) => {
                    let _ = writeln!(stderr, "Error re-keying: {err}");
                    exit_code_for_storage_error(&err)
                }
            }
        }

        Commands::Password { length, no_symbols } => {
            let pw = generate_random_password(length, !no_symbols);
            let est = zxcvbn::zxcvbn(pw.as_str(), &[]);
            let _ = writeln!(stdout, "{}", pw.as_str());
            let _ = writeln!(stdout, "Strength score: {}/4", u8::from(est.score()));
            0
        }

        Commands::ShellIntegration { action } => {
            let res = match action {
                ShellAction::Status => Ok(shell_integration::get_status()),
                ShellAction::Install => shell_integration::install_shell_integration(),
                ShellAction::Uninstall => shell_integration::uninstall_shell_integration(),
            };
            match res {
                Ok(st) => {
                    let _ = writeln!(
                        stdout,
                        "supported={} installed={} context_menu={} vault_association={}",
                        st.supported,
                        st.installed,
                        st.context_menu_installed,
                        st.vault_association_installed
                    );
                    0
                }
                Err(err) => {
                    let _ = writeln!(stderr, "Error: {err}");
                    1
                }
            }
        }
    }
}
