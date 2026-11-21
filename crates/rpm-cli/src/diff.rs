use super::{load_keyfile, read_secret_line};
use clap::Args;
use rpm_core::{
    diff_metadata, inspect_header_seekable_with_kdf, mnemonic_to_entropy, Auth, KdfParams,
    VaultMetadata,
};
use rpm_storage::StorageError;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
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
        let mut reader = BufReader::new(File::open(path)?);
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
        Ok(inspect_header_seekable_with_kdf(&mut reader, auth, kdf)?.metadata)
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
