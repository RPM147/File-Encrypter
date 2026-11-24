//! Headless Pure-Rust CLI for RPM Encrypter v5 (zero GUI dependencies).

mod diff;
pub mod progress;

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use clap::{Parser, Subcommand, ValueEnum};
use rand::rngs::OsRng;
use rand::Rng;
use rpm_core::{
    entropy_to_mnemonic, generate_recovery_entropy, hash_keyfile_reader,
    inspect_header_seekable_with_kdf, mnemonic_to_entropy, Auth, CryptoError, EncryptOptions,
    HiddenEncryptOptions, KdfParams, SecretKey, VaultMetadata,
};
use rpm_storage::shell_integration;
use rpm_storage::{
    check_compartment_sources, check_vault_integrity_with_parts, check_wipe_targets,
    decrypt_vault_v5_with_stealth_kdf, discover_split_parts, encrypt_hidden_sources_v5,
    encrypt_hidden_sources_v5_split, encrypt_sources_v5, encrypt_sources_v5_split,
    join_vault_parts, open_vault_reader, path_dedup_key, rekey_vault_v5, split_vault_file,
    unique_path, unique_split_base, validate_split_bounds, PathDedupKey, SecureWiper,
    SplitDiscoveryCache, StorageError,
};
use zeroize::Zeroizing;

use progress::CliProgressReporter;
pub use progress::ProgressMode;

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
    /// Compare authenticated file lists by path, size and modification time (headers only).
    Diff(diff::DiffArgs),
    /// Encrypt files or directories into a Vault Format v5 (.vault) archive.
    Encrypt {
        #[arg(required = true)]
        sources: Vec<PathBuf>,
        /// Encrypt the header as well as the payload, using the fixed Stealth KDF profile.
        #[arg(long)]
        stealth: bool,
        /// Protect the encrypted vault against bit rot with interleaved Reed-Solomon parity.
        #[arg(long, conflicts_with = "stealth")]
        reed_solomon: bool,
        /// Pad the output container to this exact size in MiB.
        #[arg(long, value_name = "MiB", value_parser = clap::value_parser!(u64).range(1..=MAX_CONTAINER_MIB))]
        container_mb: Option<u64>,
        /// Split the encrypted output into numbered parts (.001, .002, ...) of at most this size in MiB (e.g. 4000 for FAT32).
        #[arg(long, value_name = "MiB", value_parser = clap::value_parser!(u64).range(1..=MAX_CONTAINER_MIB))]
        split_mb: Option<u64>,
        /// Store these sources in a separately password-protected compartment.
        #[arg(long, value_name = "PATH", num_args = 1.., requires = "container_mb")]
        hidden: Vec<PathBuf>,
        #[arg(long, requires = "hidden")]
        hidden_keyfile: Option<PathBuf>,
        #[arg(long, requires = "hidden")]
        hidden_no_compress: bool,
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
        /// Read the outer password on line one and, with --hidden, the hidden password on line two.
        #[arg(long)]
        password_stdin: bool,
        /// Progress display on stderr: auto (TTY only), always, or never.
        #[arg(long, value_enum, default_value_t = ProgressMode::Auto)]
        progress: ProgressMode,
    },
    /// Decrypt one or more .vault files using streaming Chunked AEAD authentication.
    Decrypt {
        #[arg(required = true)]
        vaults: Vec<PathBuf>,
        #[arg(short, long)]
        output_dir: Option<PathBuf>,
        #[arg(long)]
        keyfile: Option<PathBuf>,
        /// Extract only matching archive paths or folder prefixes (repeatable).
        #[arg(long = "only", value_name = "PATH")]
        only: Vec<String>,
        #[arg(long, conflicts_with_all = ["recovery", "recovery_stdin"])]
        password_stdin: bool,
        #[arg(long, conflicts_with_all = ["password_stdin", "recovery_stdin"])]
        recovery: bool,
        #[arg(long, conflicts_with_all = ["password_stdin", "recovery"])]
        recovery_stdin: bool,
        /// Progress display on stderr: auto (TTY only), always, or never.
        #[arg(long, value_enum, default_value_t = ProgressMode::Auto)]
        progress: ProgressMode,
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
    /// Repair a Reed-Solomon envelope without a password (in place by default).
    Repair {
        vault: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long)]
        json: bool,
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
    /// Split an existing .vault file into numbered multi-part volumes (.001, .002, ...).
    Split {
        vault: PathBuf,
        /// Maximum size of each part in MiB (e.g. 4000 for FAT32).
        #[arg(long, value_name = "MiB", value_parser = clap::value_parser!(u64).range(1..=MAX_CONTAINER_MIB))]
        part_mb: u64,
        #[arg(short, long)]
        output_dir: Option<PathBuf>,
        /// Progress display on stderr: auto (TTY only), always, or never.
        #[arg(long, value_enum, default_value_t = ProgressMode::Auto)]
        progress: ProgressMode,
    },
    /// Join a numbered split volume (.001, .002, ...) back into a single .vault file.
    Join {
        /// Path to any part of the split volume (typically the .001 file).
        part: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Progress display on stderr: auto (TTY only), always, or never.
        #[arg(long, value_enum, default_value_t = ProgressMode::Auto)]
        progress: ProgressMode,
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

const MIB: u64 = 1024 * 1024;
const MAX_CONTAINER_MIB: u64 = rpm_core::constants::MAX_CONTAINER_SIZE / MIB;

fn read_secret_line<R: BufRead>(
    prompt: &str,
    from_stdin: bool,
    confirm: bool,
    stdin: &mut R,
) -> Result<Zeroizing<String>, String> {
    if from_stdin {
        let mut line = Zeroizing::new(String::new());
        stdin
            .read_line(&mut line)
            .map_err(|e| format!("failed reading stdin: {e}"))?;
        let len = line.trim_end_matches(&['\r', '\n'][..]).len();
        line.truncate(len);
        if line.is_empty() {
            return Err("empty secret input from stdin".into());
        }
        return Ok(line);
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
    run_cli_args_with_tty(args, stdin, stdout, stderr, kdf_override, false)
}

pub fn run_cli_args_with_tty<I, S, R, W1, W2>(
    args: I,
    stdin: &mut R,
    stdout: &mut W1,
    stderr: &mut W2,
    kdf_override: Option<KdfParams>,
    stderr_is_tty: bool,
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
    let kdf = kdf_override.unwrap_or(rpm_core::STEALTH_KDF_PARAMS);

    match parsed.command {
        Commands::Diff(args) => match args.run(stdin, stdout, &kdf) {
            Ok(()) => 0,
            Err(err) => {
                let _ = writeln!(stderr, "Error comparing vaults: {err}");
                exit_code_for_storage_error(&err)
            }
        },
        Commands::Encrypt {
            sources,
            container_mb,
            split_mb,
            stealth,
            reed_solomon,
            hidden,
            hidden_keyfile,
            hidden_no_compress,
            output_dir,
            keyfile,
            no_compress,
            wipe,
            recovery_out,
            password_stdin,
            progress,
        } => {
            for s in sources.iter().chain(&hidden) {
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

            if let Some(s_mb) = split_mb {
                if let Err(err) =
                    validate_split_bounds(s_mb * MIB, container_mb.map(|c| c * MIB), reed_solomon)
                {
                    let _ = writeln!(stderr, "Error: {err}");
                    return 1;
                }
            }

            if !hidden.is_empty() {
                if let Err(err) = check_compartment_sources(&sources, &hidden) {
                    let _ = writeln!(stderr, "Error: {err}");
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
            let out_vault = if split_mb.is_some() {
                unique_split_base(&base_dir.join(format!("{base_name}.vault")))
            } else {
                unique_path(&base_dir.join(format!("{base_name}.vault")))
            };
            if wipe {
                if let Err(err) = check_wipe_targets(
                    sources.iter().chain(&hidden),
                    base_dir,
                    keyfile.iter().chain(&hidden_keyfile),
                ) {
                    let _ = writeln!(stderr, "Error: {err}");
                    return 1;
                }
            }
            let reporter = CliProgressReporter::new(progress, stderr_is_tty, "Encrypting");

            let container_size_bytes = container_mb.map(|mb| mb * MIB);
            let split_part_bytes = split_mb.map(|mb| mb * MIB);
            let enc_res: Result<Vec<PathBuf>, StorageError> = if hidden.is_empty() {
                let opts = EncryptOptions {
                    stealth,
                    reed_solomon,
                    kdf,
                    recovery_key: Some(rec_entropy),
                    keyfile_hash,
                    compressed: !no_compress,
                    container_size_bytes,
                    ..Default::default()
                };
                if let Some(part_bytes) = split_part_bytes {
                    encrypt_sources_v5_split(
                        &sources,
                        &out_vault,
                        part_bytes,
                        password.as_bytes(),
                        &opts,
                        reporter.callback(),
                        Arc::clone(&cancel),
                        |_| {},
                    )
                    .map(|(_, _, parts)| parts)
                } else {
                    encrypt_sources_v5(
                        &sources,
                        &out_vault,
                        password.as_bytes(),
                        &opts,
                        reporter.callback(),
                        Arc::clone(&cancel),
                        |_| {},
                    )
                    .map(|_| vec![out_vault.clone()])
                }
            } else {
                let hidden_password = match read_secret_line(
                    "Hidden password: ",
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
                let hidden_keyfile_hash = match load_keyfile(hidden_keyfile.as_deref()) {
                    Ok(k) => k,
                    Err(e) => {
                        let _ = writeln!(stderr, "Error: {e}");
                        return 1;
                    }
                };
                let opts = HiddenEncryptOptions {
                    stealth,
                    reed_solomon,
                    kdf,
                    container_size_bytes: container_size_bytes
                        .expect("--hidden requires --container-mb"),
                    decoy_recovery_key: Some(rec_entropy),
                    decoy_keyfile_hash: keyfile_hash,
                    decoy_compressed: !no_compress,
                    hidden_keyfile_hash,
                    hidden_compressed: !hidden_no_compress,
                    ..Default::default()
                };
                if let Some(part_bytes) = split_part_bytes {
                    encrypt_hidden_sources_v5_split(
                        &sources,
                        &hidden,
                        &out_vault,
                        part_bytes,
                        password.as_bytes(),
                        hidden_password.as_bytes(),
                        &opts,
                        reporter.callback(),
                        Arc::clone(&cancel),
                        |_| {},
                    )
                    .map(|(_, _, _, parts)| parts)
                } else {
                    encrypt_hidden_sources_v5(
                        &sources,
                        &hidden,
                        &out_vault,
                        password.as_bytes(),
                        hidden_password.as_bytes(),
                        &opts,
                        reporter.callback(),
                        Arc::clone(&cancel),
                        |_| {},
                    )
                    .map(|_| vec![out_vault.clone()])
                }
            };
            reporter.finish(stderr);
            let created_outputs = match enc_res {
                Ok(outputs) => outputs,
                Err(err) => {
                    let _ = writeln!(stderr, "Error encrypting: {err}");
                    return exit_code_for_storage_error(&err);
                }
            };

            if wipe {
                let wiper = SecureWiper::new(1);
                for s in sources.iter().chain(&hidden) {
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

            if split_part_bytes.is_some() {
                if created_outputs.len() == 1 {
                    let _ = writeln!(
                        stdout,
                        "Encrypted (1 part): {}",
                        created_outputs[0].display()
                    );
                } else {
                    let _ = writeln!(
                        stdout,
                        "Encrypted ({} parts): {} .. {}",
                        created_outputs.len(),
                        created_outputs[0].display(),
                        created_outputs.last().unwrap().display()
                    );
                }
            } else {
                let _ = writeln!(stdout, "Encrypted: {}", out_vault.display());
            }
            let recovery_label = if hidden.is_empty() {
                "Recovery phrase"
            } else {
                "Outer vault recovery phrase"
            };
            if let Some(rec_path) = recovery_out {
                if let Some(parent) = rec_path.parent().filter(|p| !p.as_os_str().is_empty()) {
                    let _ = fs::create_dir_all(parent);
                }
                if let Err(e) = fs::write(&rec_path, format!("{}\n", phrase.as_str())) {
                    let _ = writeln!(stderr, "Error writing recovery file: {e}");
                    return 1;
                }
                let _ = writeln!(
                    stdout,
                    "{recovery_label} written to: {}",
                    rec_path.display()
                );
            } else {
                let _ = writeln!(
                    stdout,
                    "\nIMPORTANT - {recovery_label} (save these 24 words):"
                );
                let _ = writeln!(stdout, "  {}", phrase.as_str());
            }
            0
        }

        Commands::Decrypt {
            vaults,
            output_dir,
            keyfile,
            only,
            password_stdin,
            recovery,
            recovery_stdin,
            progress,
        } => {
            for v in &vaults {
                if !v.is_file() {
                    let _ = writeln!(stderr, "Error: vault not found: {}", v.display());
                    return 1;
                }
            }
            // Collapse multiple parts of the same split volume (e.g. shell glob `archive.vault.*`)
            // to a single canonical `.001` target in O(D + N) with platform-aware canonical dedup.
            let mut split_cache = SplitDiscoveryCache::default();
            let mut seen_splits: HashSet<PathDedupKey> = HashSet::new();
            let mut normalized_vaults = Vec::with_capacity(vaults.len());
            for v in vaults {
                match split_cache.discover(&v) {
                    Ok(Some(set)) => {
                        let first = set.first_part().to_path_buf();
                        if seen_splits.insert(path_dedup_key(&first)) {
                            normalized_vaults.push(first);
                        }
                    }
                    Ok(None) => {
                        normalized_vaults.push(v);
                    }
                    Err(err) => {
                        let _ = writeln!(stderr, "Error decrypting {}: {err}", v.display());
                        return exit_code_for_storage_error(&err);
                    }
                }
            }
            let vaults = normalized_vaults;
            if !only.is_empty() && vaults.len() > 1 {
                let _ = writeln!(
                    stderr,
                    "Error: --only can only be used with a single .vault file"
                );
                return 1;
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

            let total_vaults = vaults.len();
            for (idx, v) in vaults.iter().enumerate() {
                let target_root = output_dir.as_deref().unwrap_or_else(|| {
                    v.parent()
                        .filter(|p| !p.as_os_str().is_empty())
                        .unwrap_or_else(|| Path::new("."))
                });
                let auth_for_vault = match auth {
                    Auth::RecoveryKey(r) => Auth::RecoveryKey(r),
                    Auth::Password {
                        password,
                        keyfile_hash,
                    } => Auth::Password {
                        password,
                        keyfile_hash,
                    },
                };
                let label = if total_vaults > 1 {
                    format!("[{}/{}] Decrypting", idx + 1, total_vaults)
                } else {
                    "Decrypting".to_string()
                };
                let reporter = CliProgressReporter::new(progress, stderr_is_tty, label);
                let dec_res = decrypt_vault_v5_with_stealth_kdf(
                    v,
                    target_root,
                    auth_for_vault,
                    (!only.is_empty()).then_some(only.as_slice()),
                    &kdf,
                    reporter.callback(),
                    Arc::clone(&cancel),
                );
                reporter.finish(stderr);
                match dec_res {
                    Ok(summary) => {
                        let _ = writeln!(
                            stdout,
                            "Decrypted: {} -> {} ({} file(s))",
                            v.display(),
                            summary.output_path.display(),
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
                match check_vault_integrity_with_parts(&vault) {
                    Ok((rep, split_parts)) => {
                        if json {
                            let val = serde_json::json!({
                                "path": vault,
                                "ok": rep.ok,
                                "version": rep.version,
                                "file_size": rep.file_size,
                                "sha256": rep.sha256_hex,
                                "sha256_only": rep.sha256_only,
                                "has_reed_solomon": rep.has_reed_solomon,
                                "rs_repaired_bytes": rep.rs_repaired_bytes,
                                "has_keyfile": rep.has_keyfile,
                                "has_recovery": rep.has_recovery,
                                "chunk_count": rep.chunk_count,
                                "split_parts": split_parts.unwrap_or(1),
                                "message": rep.message,
                            });
                            let _ =
                                writeln!(stdout, "{}", serde_json::to_string_pretty(&val).unwrap());
                        } else if rep.sha256_only {
                            let _ = writeln!(stdout, "{}", rep.message);
                            if let Some(n) = split_parts {
                                let _ = writeln!(stdout, "split_parts: {n}");
                            }
                        } else if rep.has_reed_solomon {
                            let _ = writeln!(
                                stdout,
                                "{}\nhas_reed_solomon: {}\nrs_repaired_bytes: {}",
                                rep.message, rep.has_reed_solomon, rep.rs_repaired_bytes
                            );
                            if let Some(n) = split_parts {
                                let _ = writeln!(stdout, "split_parts: {n}");
                            }
                        } else {
                            let _ = writeln!(
                                stdout,
                                "{}\nhas_reed_solomon: {}",
                                rep.message, rep.has_reed_solomon
                            );
                            if let Some(n) = split_parts {
                                let _ = writeln!(stdout, "split_parts: {n}");
                            }
                        }
                        return if rep.ok { 0 } else { 1 };
                    }
                    Err(e) => {
                        let _ = writeln!(stderr, "Error: {e}");
                        return 1;
                    }
                }
            }

            // Validate split volume completeness before prompting for credentials.
            let mut reader = match open_vault_reader(&vault) {
                Ok(r) => r,
                Err(e) => {
                    let _ = writeln!(stderr, "Error: {e}");
                    return 1;
                }
            };
            let split_parts = reader.is_split().then_some(reader.part_count());

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

            match inspect_header_seekable_with_kdf(&mut reader, auth, &kdf) {
                Ok(info) => {
                    if json {
                        let val = serde_json::json!({
                            "path": vault,
                            "version": info.version,
                            "cipher": info.cipher,
                            "chunk_size": info.chunk_size,
                            "container_size": info.container_size,
                            "is_hidden_compartment": info.is_hidden_compartment,
                            "is_stealth": info.is_stealth,
                            "has_reed_solomon": info.has_reed_solomon,
                            "rs_repaired_bytes": info.rs_repaired_bytes,
                            "has_keyfile": info.has_keyfile,
                            "has_recovery": info.has_recovery,
                            "split_parts": split_parts.unwrap_or(1),
                            "metadata": info.metadata,
                        });
                        let _ = writeln!(stdout, "{}", serde_json::to_string_pretty(&val).unwrap());
                    } else {
                        let rs_line = if info.has_reed_solomon {
                            format!(
                                "has_reed_solomon: true\nrs_repaired_bytes: {}\n",
                                info.rs_repaired_bytes
                            )
                        } else {
                            "has_reed_solomon: false\n".into()
                        };
                        let split_line = match split_parts {
                            Some(n) => format!("split_parts: {n}\n"),
                            None => String::new(),
                        };
                        let _ = writeln!(
                            stdout,
                            "Version: v{}  Cipher: {}  Chunk: {} KiB\ncontainer_size: {}\nis_hidden_compartment: {}\nis_stealth: {}\n{}{}{}",
                            info.version,
                            info.cipher,
                            info.chunk_size / 1024,
                            info.container_size.map_or_else(|| "none".into(), |n| format!("{n} bytes")),
                            info.is_hidden_compartment,
                            info.is_stealth,
                            rs_line,
                            split_line,
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

        Commands::Repair {
            vault,
            output,
            json,
        } => {
            if !vault.is_file() {
                let _ = writeln!(stderr, "Error: vault not found: {}", vault.display());
                return 1;
            }
            match rpm_storage::repair_vault_v5(&vault, output.as_deref(), cancel) {
                Ok(report) => {
                    if json {
                        let _ =
                            writeln!(stdout, "{}", serde_json::to_string_pretty(&report).unwrap());
                    } else {
                        let _ = writeln!(
                            stdout,
                            "Checked {} blocks, repaired {} bytes (header repaired: {}).",
                            report.blocks_checked, report.repaired_bytes, report.header_repaired
                        );
                    }
                    0
                }
                Err(e) => {
                    let _ = writeln!(stderr, "Repair failed: {e}");
                    1
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
            // Validate split volume completeness before prompting for passwords.
            if let Err(err) = discover_split_parts(&vault) {
                let _ = writeln!(stderr, "Error re-keying: {err}");
                return exit_code_for_storage_error(&err);
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

        Commands::Split {
            vault,
            part_mb,
            output_dir,
            progress,
        } => {
            let reporter = CliProgressReporter::new(progress, stderr_is_tty, "Splitting");
            let res = split_vault_file(
                &vault,
                output_dir.as_deref(),
                part_mb * MIB,
                reporter.callback(),
                Arc::clone(&cancel),
            );
            reporter.finish(stderr);
            match res {
                Ok(parts) => {
                    if parts.len() == 1 {
                        let _ = writeln!(stdout, "Split (1 part): {}", parts[0].display());
                    } else {
                        let _ = writeln!(
                            stdout,
                            "Split ({} parts): {} .. {}",
                            parts.len(),
                            parts[0].display(),
                            parts.last().unwrap().display()
                        );
                    }
                    0
                }
                Err(err) => {
                    let _ = writeln!(stderr, "Error splitting vault: {err}");
                    exit_code_for_storage_error(&err)
                }
            }
        }

        Commands::Join {
            part,
            output,
            progress,
        } => {
            let reporter = CliProgressReporter::new(progress, stderr_is_tty, "Joining");
            let res = join_vault_parts(
                &part,
                output.as_deref(),
                reporter.callback(),
                Arc::clone(&cancel),
            );
            reporter.finish(stderr);
            match res {
                Ok((out_path, total_bytes)) => {
                    let _ = writeln!(
                        stdout,
                        "Joined: {} ({total_bytes} bytes)",
                        out_path.display()
                    );
                    0
                }
                Err(err) => {
                    let _ = writeln!(stderr, "Error joining vault: {err}");
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
