# RPM Encrypter

RPM Encrypter is a **Pure-Rust, local-only** file encryption utility using **Chunked AES-256-GCM** (`Vault Format v5`), **Argon2id** key derivation, optional **keyfile two-factor binding**, and deterministic in-memory secret scrubbing (`zeroize` + `VirtualLock`/`mlock`).

Everything runs locally with zero telemetry, cloud accounts, or network dependencies. The retired Python + Flet (Vault Format v4) codebase is archived in [legacy/](legacy/README.md).

## Key Features

- **Chunked Authenticated Encryption (Vault Format v5):** Plaintext streams are encrypted and authenticated in independent `1 MiB` AEAD chunks bound to per-vault context, chunk index, final-chunk flag, and plain length. Corrupted, reordered, truncated, or trailing-appended chunks fail **in RAM before any byte is written to disk**.
- **Zero Plaintext Temp Files:** Packing and unpacking stream over a bounded in-memory pipe directly into/out of the Chunked AEAD stream — no intermediate plaintext `.zip`/`.tar` file is created on disk.
- **Deterministic Memory Scrubbing:** Passwords, keyfile hashes, DEKs, and chunk buffers are zeroized on drop (`zeroize`) and pinned best-effort against swapping (`VirtualLock` on Windows, `mlock` on Unix).
- **Optional Keyfile Two-Factor Unlock:** Bind a vault to any non-empty keyfile (streamed through SHA-256 and mixed via HKDF with the Argon2id key).
- **24-Word BIP-39 Recovery Phrases:** Emergency recovery key slot stored separately from the password slot.
- **O(1) Re-Key:** Rotate passwords and/or keyfiles by re-wrapping only the 32-byte DEK envelope without decrypting gigabytes of payload chunks.
- **Native Desktop GUI + OS Drag-and-Drop (`rpm-encrypter`):** Built with `eframe`/`egui` and `rfd`, supporting external file/folder drag-and-drop and a 30-second auto-clearing clipboard timer.
- **Headless CLI (`rpm-encrypter-cli`):** Scriptable encryption, decryption, inspection, re-keying, password generation, and Windows shell integration without passing passwords on the command line.
- **Windows Shell Integration (User-Scoped HKCU):** Optional right-click **"Encrypt with RPM Encrypter"** menu and `.vault` double-click opening (reversible, zero administrator rights required).

## Building & Running (Pure Rust)

Prerequisites: Rust stable toolchain (`rustc` + `cargo`). On Linux, install GTK3/X11/OpenGL development packages (`libgtk-3-dev`, `libxcb-*`, `libxkbcommon-dev`, `libgl1-mesa-dev`).

```bash
# Run tests & lints
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings

# Launch native desktop GUI
cargo run --release -p rpm-gui

# Or build release binaries under target/release/
cargo build --release --workspace
```

### CLI Usage

Passwords are never accepted as CLI flags; interactive secure prompts or `--password-stdin` / `--recovery-stdin` are used instead:

```bash
cargo run -p rpm-cli -- encrypt ./folder --keyfile ./my.key --recovery-out recovery.txt
cargo run -p rpm-cli -- decrypt ./folder.vault --keyfile ./my.key -o ./restored
cargo run -p rpm-cli -- inspect ./folder.vault --integrity-only --json
cargo run -p rpm-cli -- rekey ./folder.vault --keyfile ./my.key
cargo run -p rpm-cli -- password --length 24
cargo run -p rpm-cli -- shell-integration install   # Windows HKCU only
```

## Architecture & Security

- Architecture overview and module boundaries: [ARCHITECTURE.md](ARCHITECTURE.md)
- Threat model, swap/OS limitations, and SSD wipe caveats: [SECURITY.md](SECURITY.md)

## License

This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0-or-later) — see [LICENSE](LICENSE).
