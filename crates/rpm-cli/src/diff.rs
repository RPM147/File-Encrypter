use super::{load_keyfile, read_secret_line, MAX_PIPELINE_THREADS_I64};
use clap::Args;
use rpm_core::{
    diff_metadata, inspect_header_seekable_with_kdf_and_threads, mnemonic_to_entropy, Auth,
    KdfParams, VaultMetadata,
};
use rpm_storage::{open_vault_reader, StorageError};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

#[derive(Args, Debug)]
pub struct DiffArgs {
    vault_a: PathBuf,
    vault_b: PathBuf,
    #[arg(long, conflicts_with = "recovery_a")]
    keyfile_a: Option<PathBuf>,
    #[arg(long, conflicts_with = "recovery_b")]
    keyfile_b: Option<PathBuf>,
    /// Read one secret per line from stdin, A then B (password or selected recovery phrase).
    #[arg(long)]
    password_stdin: bool,
    /// Unlock A with its 24-word recovery phrase.
    #[arg(long)]
    recovery_a: bool,
    /// Unlock B with its 24-word recovery phrase.
    #[arg(long)]
    recovery_b: bool,
    #[arg(long)]
    json: bool,
    /// Worker threads for parallel Reed-Solomon header decoding (0 = auto-detect CPU cores, 1 = single-threaded).
    #[arg(long, value_name = "N", default_value_t = 0, value_parser = clap::value_parser!(u16).range(0..=MAX_PIPELINE_THREADS_I64))]
    threads: u16,
}

impl DiffArgs {
    fn metadata(
        &self,
        label: &str,
        path: &Path,
        keyfile: Option<&Path>,
        recovery: bool,
        kdf: &KdfParams,
        stdin: &mut impl BufRead,
    ) -> Result<VaultMetadata, StorageError> {
        if !path.is_file() {
            return Err(StorageError::InvalidPath(format!(
                "vault not found: {}",
                path.display()
            )));
        }
        let mut reader = open_vault_reader(path)?;
        let keyfile = load_keyfile(keyfile).map_err(StorageError::InvalidPath)?;
        let kind = if recovery {
            "24-word recovery phrase"
        } else {
            "password"
        };
        let secret = read_secret_line(
            &format!("Vault {label} {kind}: "),
            self.password_stdin,
            false,
            stdin,
        )
        .map_err(|message| std::io::Error::new(std::io::ErrorKind::InvalidInput, message))?;
        let entropy;
        let auth = if recovery {
            entropy = mnemonic_to_entropy(&secret)?;
            Auth::RecoveryKey(&entropy)
        } else {
            Auth::Password {
                password: secret.as_bytes(),
                keyfile_hash: keyfile.as_ref(),
            }
        };
        Ok(inspect_header_seekable_with_kdf_and_threads(
            &mut reader,
            auth,
            kdf,
            usize::from(self.threads),
        )?
        .metadata)
    }

    pub fn run(
        &self,
        stdin: &mut impl BufRead,
        stdout: &mut impl Write,
        kdf: &KdfParams,
    ) -> Result<(), StorageError> {
        let a = self.metadata(
            "A",
            &self.vault_a,
            self.keyfile_a.as_deref(),
            self.recovery_a,
            kdf,
            stdin,
        )?;
        let b = self.metadata(
            "B",
            &self.vault_b,
            self.keyfile_b.as_deref(),
            self.recovery_b,
            kdf,
            stdin,
        )?;
        let diff = diff_metadata(&a, &b)?;
        if self.json {
            serde_json::to_writer_pretty(&mut *stdout, &diff)?;
            writeln!(stdout)?;
        } else {
            for (label, entries) in [
                ("Added", diff.added),
                ("Removed", diff.removed),
                ("Unchanged", diff.unchanged),
            ] {
                writeln!(stdout, "{label} ({})", entries.len())?;
                for entry in entries {
                    writeln!(stdout, "  {}", entry.path)?;
                }
            }
            writeln!(stdout, "Changed ({})", diff.changed.len())?;
            for entry in diff.changed {
                writeln!(
                    stdout,
                    "  {} (bytes {} -> {}, mtime {} -> {})",
                    entry.after.path,
                    entry.before.size,
                    entry.after.size,
                    entry.before.modified_unix,
                    entry.after.modified_unix
                )?;
            }
        }
        Ok(())
    }
}
