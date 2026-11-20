# RPM Encrypter

RPM Encrypter is a cross-platform **local-only** file-encryption utility built with Python and **Flet** (a Flutter-based desktop UI toolkit). It provides strong, modern authenticated encryption (**AES-256-GCM**) with **Argon2id** key derivation while remaining accessible to everyday users.

Everything runs on your own machine — there is no server, account, or cloud component. The only optional network feature is an off-by-default GitHub Releases update check.

## Key Features

- **Plausible Deniability (Hidden Vaults):** Create dual-password vaults. The first password reveals benign "decoy" files, while the second password unlocks a hidden encrypted compartment within the same `.vault` container.
- **Recovery Phrases:** Generate 24-word BIP-39 style recovery phrases as an emergency backup if you forget your master password. (The phrase recovers the decoy/standard content only; a hidden payload is intentionally not recoverable by phrase.)
- **Vault Versioning:** Optionally preserve previous versions of a vault during Re-Key operations so you can roll back changes.
- **Selective Extraction & Vault Info:** Inspect encrypted vault metadata with your password and selectively extract individual files without unpacking the entire archive.
- **Secure Wipe:** Best-effort overwriting of original plaintext files after encryption. Note: overwriting cannot guarantee erasure on SSDs and modern filesystems — see [SECURITY.md](SECURITY.md) for important limitations.
- **Encrypted Notes:** Write and encrypt sensitive text notes directly inside the application.
- **Password Generator:** Generate strong random passwords with configurable length and character classes; the clipboard auto-clears about 30 seconds after a copy.
- **Smart Profiles:** Manage and apply Argon2id and wipe presets dynamically.
- **Native File Selection & Shortcuts:** Pick files and folders through native dialogs, and switch tabs quickly with `Ctrl+1` through `Ctrl+9`.

## Cryptography

- **Symmetric Encryption:** AES-256-GCM (Galois/Counter Mode) for authenticated, tamper-evident encryption.
- **Key Derivation:** Argon2id (winner of the Password Hashing Competition) to defend against GPU-accelerated cracking and side-channel attacks.
- **Envelope Encryption:** File payloads are encrypted using a unique random Data Encryption Key (DEK), while the DEK is encrypted by your password-derived Key Encrypting Key (KEK). Re-keying rotates only the KEK/DEK envelope without re-encrypting gigabytes of data.

### Size limits

Each encrypted item is sealed as a single AES-256-GCM stream (Vault Format v4), which is cryptographically safe up to ~64 GiB of plaintext (the GCM counter limit). RPM Encrypter enforces a conservative **32 GiB per-item payload limit** (half that ceiling). Files larger than this are rejected with a clear message; split them or encrypt a smaller selection.

Known limitation: for very large items the current v4 format writes decrypted output to an app-owned temporary file before the final authentication tag is verified ("release of unverified plaintext"). The output is app-owned, is never used until verification succeeds, and is securely wiped on failure. A future chunked-AEAD format will both lift the size limit and verify each chunk before release.

## Installation & Usage

1. **Clone the repository:**
   ```bash
   git clone https://github.com/RPM147/File-Encrypter.git
   cd File-Encrypter
   ```

2. **Install the dependencies:**
   Ensure you have Python 3.11+ installed, then run:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application:**
   ```bash
   python src/main.py
   ```
   Or via Flet CLI:
   ```bash
   flet run
   ```

## CLI Usage

`src/main.py` (or the `rpm-encrypter` console script after `pip install -e .`) also supports headless CLI commands without initializing Flet:

```bash
python src/main.py --version
python src/main.py encrypt ./notes.txt --recovery-out recovery.txt
python src/main.py decrypt ./notes.txt.vault -o ./restored
python src/main.py inspect ./notes.txt.vault --integrity-only --json
python src/main.py rekey ./notes.txt.vault
```

Passwords are never accepted as CLI flags; use interactive secure prompts or `--password-stdin` / `--recovery-stdin` for automation.

## Windows Shell Integration

On Windows, you can optionally register user-scoped (`HKCU\Software\Classes`, no Administrator rights required) Explorer integration from **Settings → Windows Shell Integration** or via the CLI:

```powershell
python src/main.py shell-integration status
python src/main.py shell-integration install
python src/main.py shell-integration uninstall
```

This adds an **Encrypt with RPM Encrypter** right-click entry for files/folders and associates `.vault` double-click opening with the Decrypt tab. Uninstalling removes all RPM Encrypter entries and leaves unrelated `.vault` associations untouched.

## Building a Desktop Executable

This produces a native desktop bundle under `build\windows\`. The Flutter client is compiled into the app, so the result runs **fully offline** with no first-run download.

Prerequisites (Windows):
- the [Flutter SDK](https://flutter.dev);
- Visual Studio with the **"Desktop development with C++"** workload, **including the Windows 10/11 SDK component**;
- **Windows Developer Mode enabled** — Flutter builds its plugins via symlinks, which Windows only allows in Developer Mode (`start ms-settings:developers`).

Verify your toolchain first:
```powershell
flutter doctor
```
Then build (Windows / PowerShell):
```powershell
.\build.ps1
```
`flet build` reads the app metadata, entry point (`src/main.py`), and bundled dependency list from `pyproject.toml` (`[project]` + `[tool.flet]`). Custom icons live at `src\assets\icon.png` and `launcher\icon.ico`.

## Architecture & Compatibility Policy

The codebase follows a strict layered architecture (`core` → `storage` → `services` → `ui`) under `src/rpm_encrypter/`. Because the project is being reorganized cleanly from scratch, **backward compatibility with legacy code, deprecated module paths, or compatibility shims is intentionally not maintained** — see [ARCHITECTURE.md](ARCHITECTURE.md) for layout rules and format policy.

## Security & Limitations

RPM Encrypter is a local-only tool with real limitations: secure wipe is best-effort, deniability is heuristic, secrets may remain in RAM, and the lockout does not protect the vault file itself. **Please read [SECURITY.md](SECURITY.md)** to understand exactly what this tool does and does not protect before using it for sensitive data.

## Disclaimer

This software is provided "as is", without warranty of any kind. Always keep secure backups of your recovery phrases and passwords. If you lose your password AND your recovery phrase, **your data will be permanently unrecoverable.**

## License

This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
