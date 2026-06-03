# RPM Encrypter

RPM Encrypter is a robust, cross-platform **local-only** file-encryption utility built with Python. Its modern, dark-mode desktop interface is built with **Flet** (a Flutter-based UI toolkit), while the original **CustomTkinter** interface is retained as a fallback. It provides strong, modern encryption (AES-256-GCM with Argon2id key derivation) while remaining highly accessible to everyday users.

Everything runs on your own machine — there is no server, account, or cloud component. The only optional network feature is an off-by-default update check (wired in the legacy interface). RPM Encrypter uses industry-standard cryptographic algorithms including **AES-256-GCM** for authenticated encryption and **Argon2id** for state-of-the-art key derivation.

## ✨ Key Features

- **Plausible Deniability (Hidden Vaults):** Create stealthy, dual-password vaults. The first password reveals benign "decoy" files, while the second password securely unlocks a hidden encrypted sector within the exact same file.
- **Recovery Phrases:** Generate 24-word BIP-39 style recovery phrases to serve as an emergency backup in case you forget your master password. (The phrase recovers the decoy/standard content only; a hidden payload is intentionally not recoverable by phrase.)
- **Vault Versioning:** Optionally preserve previous versions of a vault during Re-Key operations, allowing you to gracefully recover from mistakes or roll back changes.
- **Selective Extraction:** Inspect the contents of a vault and selectively extract individual files without dumping the entire archive to your drive.
- **Secure Wipe:** Best-effort overwriting of your original plaintext files after encryption. Note: overwriting cannot guarantee erasure on SSDs and modern filesystems — see [SECURITY.md](SECURITY.md) for important limitations.
- **Encrypted Notes:** Keep a secure diary, store passwords, or write sensitive text directly inside the application's built-in encrypted text editor.
- **Password Generator:** Generate strong random passwords with configurable length and character classes; the clipboard auto-clears about 30 seconds after a copy.
- **Smart Profiles:** Manage and hot-swap your security parameters (Argon2id memory, iterations, parallelism) dynamically through custom profiles.
- **Simple selection:** Pick files and folders through native dialogs. (Drag-and-drop straight into the window is available in the legacy CustomTkinter interface.)

## 🔐 Cryptography

- **Symmetric Encryption:** AES-256-GCM (Galois/Counter Mode) for authenticated, tamper-evident encryption.
- **Key Derivation:** Argon2id (winner of the Password Hashing Competition) to defend against GPU-accelerated cracking and side-channel attacks.
- **Envelope Encryption:** The potentially massive file payloads are encrypted using a fast Data Encryption Key (DEK), while only the DEK is encrypted by your password-derived Key Encrypting Key (KEK). This ensures lightning-fast password changes (Re-Keying) without having to re-encrypt gigabytes of data.

### Size limits

Each encrypted item is sealed as a single AES-256-GCM stream, which is cryptographically safe up to ~64 GiB of plaintext (the GCM counter limit). RPM Encrypter enforces a conservative **32 GiB per-item payload limit** (half that ceiling). Files larger than this are rejected with a clear message; split them or encrypt a smaller selection.

Known limitation: for very large items the current format writes decrypted output to an app-owned temporary file before the final authentication tag is verified ("release of unverified plaintext"). The output is app-owned, is never used until verification succeeds, and is securely wiped on failure. A future chunked-AEAD format will both lift the size limit and verify each chunk before release.

## 🚀 Installation & Usage

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/rpm-encrypter.git
   cd rpm-encrypter
   ```

2. **Install the dependencies:**
   Ensure you have Python 3.9+ installed, then run:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application:**
   ```bash
   # Modern Flet (Flutter) UI — recommended
   python app_flet.py

   # Legacy CustomTkinter UI — fallback
   python gui_app.py
   ```

## 🛠️ Building a Desktop Executable

### Primary — modern Flet (Flutter) build

This produces a native desktop bundle under `build\windows\`. The Flutter client is compiled into the app, so the result runs **fully offline** with no first-run download.

Prerequisites: the [Flutter SDK](https://flutter.dev) and Visual Studio's **"Desktop development with C++"** workload. Verify your toolchain first:
```powershell
flet doctor
```
Then build (Windows / PowerShell):
```powershell
.\build.ps1
```
`flet build` reads the app metadata and the bundled dependency list from `pyproject.toml` (`[project]` + `[tool.flet]`). For a custom Windows icon, place a PNG at `assets\icon.png`.

### Legacy — CustomTkinter / PyInstaller build

This builds the fallback app inside a clean virtual environment from the pinned `requirements.lock`, using the committed `RPM Encrypter.spec` (which bundles the data files, the drag-and-drop module, and the icon). Output: `dist\RPM Encrypter.exe`.
```powershell
.\build.ps1 -Legacy
```

## Security & Limitations

RPM Encrypter is a local-only tool with real limitations: secure wipe is best-effort, deniability is heuristic, secrets may remain in RAM, and the lockout does not protect the vault file itself. **Please read [SECURITY.md](SECURITY.md)** to understand exactly what this tool does and does not protect before using it for sensitive data.

## ⚠️ Disclaimer

This software is provided "as is", without warranty of any kind. While RPM Encrypter is built utilizing established cryptographic primitives, always ensure you keep secure backups of your recovery phrases and passwords. If you lose your password AND your recovery phrase, **your data will be permanently unrecoverable.**

## 📄 License

This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
