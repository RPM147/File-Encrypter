# RPM Encrypter

RPM Encrypter is a robust, cross-platform local file encryption utility built with Python. Designed with a modern, dark-mode graphical user interface via CustomTkinter, it provides strong, modern encryption (AES-256-GCM with Argon2id key derivation) while remaining highly accessible to everyday users.

RPM Encrypter uses industry-standard cryptographic algorithms including **AES-256-GCM** for authenticated encryption, and **Argon2id** for state-of-the-art key derivation.

## ✨ Key Features

- **Plausible Deniability (Hidden Vaults):** Create stealthy, dual-password vaults. The first password reveals benign "decoy" files, while the second password securely unlocks a hidden encrypted sector within the exact same file.
- **Recovery Phrases:** Generate 24-word BIP-39 style recovery phrases to serve as an emergency backup in case you forget your master password.
- **Vault Versioning:** Automatically preserve previous versions of a vault during Re-Key operations, allowing you to gracefully recover from mistakes or rollback changes.
- **Selective Extraction:** Inspect the contents of a vault and selectively extract individual files without needing to dump the entire archive to your drive.
- **Secure Wipe:** Best-effort overwriting of your original plaintext files after encryption. Note: overwriting cannot guarantee erasure on SSDs and modern filesystems -- see [SECURITY.md](SECURITY.md) for important limitations.
- **Encrypted Notes:** Keep a secure diary, store passwords, or write sensitive text directly inside the application's built-in encrypted text editor.
- **Profile Management:** Manage and hot-swap your security parameters (Argon2id Memory, Iterations, Parallelism) dynamically through custom profiles.
- **Drag & Drop UI:** A beautiful, responsive interface that allows you to drag files and folders straight into the window to initiate batch encryption.

## 🔐 Cryptography

- **Symmetric Encryption:** AES-256-GCM (Galois/Counter Mode) for authenticated, tamper-evident encryption.
- **Key Derivation:** Argon2id (Winner of the Password Hashing Competition) to defend against GPU-accelerated cracking and side-channel attacks.
- **Envelope Encryption:** The potentially massive file payloads are encrypted using a fast Data Encryption Key (DEK), while only the DEK is encrypted by your password-derived Key Encrypting Key (KEK). This ensures lightning-fast password changes (Re-Keying) without having to re-encrypt gigabytes of data.

### Size limits

Each encrypted item is sealed as a single AES-256-GCM stream, which is cryptographically safe up to ~64 GiB of plaintext (the GCM counter limit). RPM Encrypter enforces a conservative **32 GiB per-item payload limit** (half that ceiling). Files larger than this are rejected with a clear message; split them or encrypt a smaller selection.

Known limitation: for very large items the current format writes decrypted output to an app-owned temporary file before the final authentication tag is verified ("release of unverified plaintext"). The output is app-owned, is never used until verification succeeds, and is securely wiped on failure. A future v4 chunked-AEAD format will both lift the size limit and verify each chunk before release.

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
   python gui_app.py
   ```

## 🛠️ Building an Executable

You can compile RPM Encrypter into a standalone executable using [PyInstaller](https://pyinstaller.org/).

1. Install PyInstaller:
   ```bash
   pip install pyinstaller
   ```

2. Compile the application using the included spec (handles data files, the drag-and-drop module, and the icon):
   ```bash
   pyinstaller "RPM Encrypter.spec"
   ```

For a fully reproducible build from pinned dependency versions, run the included script, which builds inside a clean virtual environment from `requirements.lock`:
```powershell
.\build.ps1
```

## Security & Limitations

RPM Encrypter is a local-only tool with real limitations: secure wipe is best-effort, deniability is heuristic, secrets may remain in RAM, and the lockout does not protect the vault file itself. **Please read [SECURITY.md](SECURITY.md)** to understand exactly what this tool does and does not protect before using it for sensitive data.

## ⚠️ Disclaimer

This software is provided "as is", without warranty of any kind. While RPM Encrypter is built utilizing established cryptographic primitives, always ensure you keep secure backups of your recovery phrases and passwords. If you lose your password AND your recovery phrase, **your data will be permanently unrecoverable.**

## 📄 License

This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0)
