# RPM Encrypter User Guide

> Türkçe: [USER_GUIDE.tr.md](USER_GUIDE.tr.md)

RPM Encrypter encrypts files and folders locally on your computer and saves them into a `.vault` archive. This guide covers Vault Format v5.

## Launching the application

On Windows, extract the downloaded ZIP archive into a folder and double-click `rpm-encrypter.exe`. On Linux, extract the `.tar.gz` archive, open a terminal in that folder, and run `./rpm-encrypter`.

The application opens in Turkish by default; switch language (`TR / EN`) and theme (**Dark / Light**) anytime from the bottom of the left sidebar or in **Settings**. On Windows, **Settings** also lets standard (non-admin) users install or remove user-scoped (`HKCU`) Explorer right-click **Encrypt with RPM Encrypter** integration and `.vault` double-click association.

## Encrypting files

During encryption and decryption, live throughput (e.g., `MiB/s`) and an estimated time remaining (ETA) appear next to the progress bar.

1. Drag and drop files or folders onto the window (or use **Add Files...** / **Add Folder...**). Verify the source list and destination directory on the **Encrypt** tab.
2. Enter and confirm a strong, unique password. Optionally bind a non-empty **keyfile** as a second factor; if bound, that exact file is required alongside the password on every unlock, so back it up safely outside the vault.
3. Click **Encrypt Now**. Write down the **24-word BIP-39 recovery phrase** in order and store it separately from the vault, then confirm to start. Anyone holding this phrase can unlock the vault without the password or keyfile.
4. Once finished, test decrypting the new `.vault` into a separate folder before deleting or wiping the originals.

## Container Size (Padding) & Hidden Vault (Plausible Deniability)

Use a fixed-size padded container to hide the true size of your payload or to embed a second, cryptographically indistinguishable hidden compartment inside the same `.vault` file:

- **Container Size (Padding):** In the **Encrypt** tab, change **Container Size (Padding)** from `Auto (Content Size)` to `10 MiB`, `50 MiB`, `100 MiB`, `500 MiB`, or `Custom (MiB)` (1–65536 MiB), or pass `--container-mb <MiB>` in the CLI. Unused space is filled with random `OsRng` bytes, while keeping the exact same public header format.
- **Hidden Vault (Plausible Deniability):** Expand **Hidden Vault (Plausible Deniability)** on the **Encrypt** tab and enable embedding a secondary hidden vault. Select separate hidden sources, a hidden password that **differs** from the outer password, and an optional hidden keyfile. Unlocking with the outer password reveals only the decoy vault; unlocking with the hidden password transparently reveals only the hidden vault.
- **Stealth Mode (Encrypted Header):** Check **Stealth Mode (Encrypted Header)** on the **Encrypt** tab (or pass `--stealth` in CLI) to omit the plaintext `RPMV` magic bytes and JSON header so the entire file looks like uniform random data and can be renamed to any extension (`.bin`, `.dat`, etc.). Stealth containers always use a fixed OWASP Argon2id profile (`64 MiB / 3 iterations / 4 lanes`) regardless of Settings, report only file size and SHA-256 on passwordless integrity checks, and still support padding, Hidden Vault, and the 24-word recovery phrase for the outer vault.
- **Important constraints:**
  - Hidden vaults require a fixed container size (`Auto` cannot be used).
  - **The 24-word recovery phrase unlocks only the outer (decoy) vault;** by design, no recovery phrase is generated for the hidden compartment.
  - To prevent distinguishing padded decoy containers from hidden-vault containers, **Re-Key (`rekey`) is disabled** on all fixed-size padded containers.
  - **Decrypt**, **Inspect**, selective extraction, and **Vault Diff** automatically choose the decoy or hidden compartment based on the credentials provided.

```sh
# Create a 50 MiB container holding an outer decoy vault and an inner hidden vault
./rpm-encrypter-cli encrypt ./DecoyDocs --container-mb 50 --hidden ./SecretDocs --hidden-keyfile ./hidden.key

# Non-interactive scripts: line 1 is outer password, line 2 is hidden password
printf "OuterPass!\nHiddenPass!\n" | ./rpm-encrypter-cli encrypt ./DecoyDocs --container-mb 10 --hidden ./SecretDocs --password-stdin
```

To decrypt or inspect the hidden compartment in `decrypt`, `inspect`, or `diff`, pass the hidden password (and `--keyfile ./hidden.key` if a hidden keyfile was bound).

## Decrypting a vault

Drag and drop `.vault` files onto the window. On the **Decrypt** tab, enter the password and select any bound keyfile (or enter the hidden password and hidden keyfile to unlock a hidden compartment). If you lost the outer password or keyfile, check **Use 24-word recovery phrase instead of password** and enter all 24 words in order. Choose the output folder and click **Decrypt Now**.

## Inspecting a vault and selective extraction

Use the **Inspect** tab to verify integrity or restore specific files without writing the whole archive to disk:

- **Integrity Check (No Password):** Verifies the vault header, chunk framing, exact EOF/container-size boundary, and full-file SHA-256 digest without needing credentials.
- **Inspect Metadata, RAM-Only Preview & Extract Selected:** Unlock the encrypted manifest with a password or recovery phrase, click **Preview** beside any file (up to `16 MiB`) to view UTF-8 text or images (`PNG/JPEG/WebP/GIF/BMP`) purely in RAM after full AEAD authentication completes with zero temporary files on disk (closing, `Esc`, switching tabs, or changing vaults scrubs the preview buffer), or check files/folders and click **Extract Selected**. *(Every chunk in that compartment is still authenticated before anything is returned or written to disk.)*

## Comparing two vaults (Vault Diff)

Under **Inspect → Vault Comparison (Vault Diff)**, pick **Vault A** and **Vault B**, provide credentials (password + optional keyfile, or 24-word recovery phrase) for each side, and click **Compare Vaults**. Only headers are read (no payload decryption). Added and removed paths are reported directionally from A to B; you can also compare the outer and hidden compartments of the same `.vault` file by giving different credentials for A and B. “Unchanged” indicates matching path, size, and modification timestamp — it does not prove identical file bytes.

Terminal equivalent (supports `--json`, `--keyfile-a`, `--keyfile-b`, `--recovery-a`, `--recovery-b`):

```sh
./rpm-encrypter-cli diff ./previous.vault ./current.vault
```

## Settings & Password Generator

- **Settings:** Configure Argon2id memory (`16–256 MiB`), iterations (`1–10`), parallelism (`1–16`), default gzip compression, secure wipe passes, and persistent UI scale (`80–150%`). Click **Save Preferences** to persist settings across restarts.
- **Password Gen:** Independently toggle uppercase letters, lowercase letters, digits, and symbols, and optionally exclude visually ambiguous characters (`0`, `O`, `1`, `l`, `I`).

## Changing a password (Re-Key)

On the **Re-Key** tab, select a standard (non-padded) `.vault` file, enter the current password and any bound keyfile, enter and confirm the new password, choose whether to keep or change the keyfile binding, and click **Re-Key Vault**.

Re-keying only re-wraps the DEK under the new credentials (`O(1)` cryptographic cost) while rewriting the container cleanly on disk. *(Fixed-size padded containers and containers holding a hidden vault reject `rekey` by design.)*

## Quick CLI usage

Examples below assume a terminal opened in the extracted release folder with `./Docs` and `./my.key` nearby. On Windows PowerShell, replace `./rpm-encrypter-cli` with `.\rpm-encrypter-cli.exe`. Save the 24-word recovery phrase printed at the end of `encrypt`.

```sh
# Encrypt a folder with password + keyfile
./rpm-encrypter-cli encrypt ./Docs --keyfile ./my.key

# Pad to a fixed 25 MiB container
./rpm-encrypter-cli encrypt ./Docs --container-mb 25

# Encrypt a folder with encrypted header (Stealth Mode) + 25 MiB padding
./rpm-encrypter-cli encrypt ./Docs --stealth --container-mb 25

# Create an outer + hidden vault (uncompressed hidden compartment + hidden keyfile)
./rpm-encrypter-cli encrypt ./Decoy --container-mb 50 --hidden ./Secret --hidden-keyfile ./hidden.key --hidden-no-compress

# Decrypt the vault
./rpm-encrypter-cli decrypt ./Docs.vault --keyfile ./my.key

# Decrypt with the 24-word recovery phrase (outer compartment only)
./rpm-encrypter-cli decrypt ./Docs.vault --recovery

# Extract only specific file(s) or folder(s) (--only is repeatable)
./rpm-encrypter-cli decrypt ./Docs.vault --only Docs/notes.txt

# Passwordless structural integrity + SHA-256 verification
./rpm-encrypter-cli inspect ./Docs.vault --integrity-only

# Rotate password keeping the same keyfile (non-padded vaults only)
./rpm-encrypter-cli rekey ./Docs.vault --keyfile ./my.key
```

For `encrypt` and `decrypt`, `--progress` controls live throughput and ETA on `stderr`: `auto` (default, TTY only), `always`, or `never`.

```sh
./rpm-encrypter-cli decrypt ./Docs.vault --keyfile ./my.key --progress always
```

## Generating WinGet manifests (Windows)

Place the Windows ZIP package and `SHA256SUMS.txt` into `dist/`, then run from the repository root in PowerShell to emit manifests under `dist/winget/RPM147.RPMEncrypter/4.3.0/`:

```powershell
.\packaging\winget\generate-manifests.ps1 -Version 4.3.0
winget validate --manifest .\dist\winget\RPM147.RPMEncrypter\4.3.0
```

See [WinGet packaging guide](../packaging/winget/README.md) for submission details.

## SSDs and secure wipe caveats

On SSDs and USB flash drives, **secure wipe** cannot guarantee physical erasure of prior blocks due to wear leveling, and backups or synced folders may retain unencrypted copies. Use full-disk encryption from the start for sensitive workloads. See [SECURITY.md](../SECURITY.md).
