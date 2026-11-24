# RPM Encrypter

[![CI](https://github.com/RPM147/File-Encrypter/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/RPM147/File-Encrypter/actions/workflows/ci.yml)

**Language / Dil:** **English** (default) · [Türkçe](README.tr.md)

RPM Encrypter is a **Pure-Rust, local-only** file encryption utility using **Chunked AES-256-GCM** (`Vault Format v5`), **Argon2id** key derivation, optional **keyfile two-factor binding**, and deterministic in-memory secret scrubbing (`zeroize` + `VirtualLock`/`mlock`).

Everything runs locally with zero telemetry, cloud accounts, or network dependencies. The retired Python + Flet (Vault Format v4) codebase is preserved in earlier Git history.

[User Guide (English)](docs/USER_GUIDE.md) ([Türkçe](docs/USER_GUIDE.tr.md)) · [Changelog (English)](CHANGELOG.md) ([Türkçe](CHANGELOG.tr.md))

## Key Features

- **Chunked Authenticated Encryption (Vault Format v5):** Plaintext streams are encrypted and authenticated in independent `1 MiB` AEAD chunks bound to per-vault context, chunk index, final-chunk flag, and plain length. Corrupted, reordered, truncated, or trailing-appended chunks fail **in RAM before any byte is written to disk**.
- **Zero Plaintext Temp Files:** Packing and unpacking stream over a bounded in-memory pipe directly into/out of the Chunked AEAD stream — no intermediate plaintext `.zip`/`.tar` file is created on disk.
- **Deterministic Memory Scrubbing:** Passwords, keyfile hashes, DEKs, and chunk buffers are zeroized on drop (`zeroize`) and pinned best-effort against swapping (`VirtualLock` on Windows, `mlock` on Unix).
- **Optional Keyfile Two-Factor Unlock:** Bind a vault to any non-empty keyfile (streamed through SHA-256 and mixed via HKDF with the Argon2id key).
- **24-Word BIP-39 Recovery Phrases:** Emergency recovery key slot stored separately from the password slot.
- **O(1) Re-Key:** Rotate passwords and/or keyfiles by re-wrapping only the 32-byte DEK envelope without decrypting gigabytes of payload chunks.
- **Native Desktop GUI + OS Drag-and-Drop (`rpm-encrypter`):** Built with `eframe`/`egui` and `rfd`, featuring a bilingual Turkish/English UI (`TR`/`EN`), external file/folder drag-and-drop, and an opt-in 30-second auto-clearing clipboard timer for copied secrets.
- **Operational Safety, Presets & Batch Workflow (GUI):** Includes clipboard-safe idle auto-lock & manual session clear (`Ctrl+L`, leaving the OS clipboard untouched), built-in and custom non-secret **Encryption Profiles**, a pre-flight source size / RS parity / container fit estimator, post-op **Show in Folder** / **Verify Now** quick actions, and a zeroizing sequential **Batch Job Queue**.
- **Vault Explorer, Selective Extraction & Enhanced RAM-Only Preview:** Browse unlocked manifests in the GUI **Inspect** tab via a **Folder Tree / Flat List** with tri-state folder checkboxes, type/size filters, and selective extraction (or repeatable `decrypt --only <PATH>` flags in the CLI, guarded by stage-and-swap authentication). Preview files up to `16 MiB` purely in RAM without touching disk — including UTF-8 text with line numbers and `Ctrl+F` search, images with zoom and lossless `90°` rotation, and a read-only Hex + ASCII viewer for binary files.
- **Split / Join Multi-Part Volumes (Virtual Read + Seek):** Split large vaults into numbered parts (`.vault.001`, `.vault.002`, ...) for FAT32 (`4000 MiB`) or upload limits via CLI `--split-mb` / `split` / `join` or GUI **Encrypt** & **Inspect** tools. `decrypt`, selective extract, RAM preview, `inspect`, `diff`, `rekey`, and Reed-Solomon `repair` read split volumes virtually using at most one open file handle and zero temporary merged files on disk.
- **Headless CLI (`rpm-encrypter-cli`):** Scriptable encryption, decryption, inspection, re-keying, password generation, and Windows shell integration without passing passwords on the command line.
- **Container Padding & Hidden Vault (Plausible Deniability):** Pad vaults to fixed MiB container sizes with `OsRng` random bytes (`--container-mb` or GUI Container Size selector) and optionally embed an indistinguishable secondary hidden compartment (`--hidden` or GUI Hidden Vault panel) with independent credentials.
- **Optional Stealth Mode (Encrypted Header):** Encrypt the outer password/recovery slots and frame prefixes with no plaintext `RPMV` header (`--stealth` or GUI Encrypt checkbox), using a fixed OWASP Argon2id profile (`64 MiB / 3 / 4`) so the entire file appears indistinguishable from uniform random bytes regardless of extension.
- **Optional Reed-Solomon Bit-Rot Protection & Repair:** Add ~7% interleaved `RS(255, 239)` parity (`--reed-solomon` in CLI or GUI Encrypt checkbox; mutually exclusive with Stealth) to tolerate and transparently repair up to `512` contiguous corrupted bytes (one disk sector) per `16,320`-byte block, with passwordless atomic repair via CLI `repair` or GUI **Inspect → Repair (Reed-Solomon)**.
- **Header-Only Vault Diff:** Compare two vaults' authenticated file manifests (added, removed, changed, unchanged) from headers alone in GUI **Inspect** or CLI `diff`.
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

### Package a Windows release locally

From the repository root, run the packaging script in PowerShell. It uses the workspace version and writes the portable ZIP and `SHA256SUMS.txt` to `dist/`.

```powershell
.\scripts\package-release.ps1
```

### CLI Usage

Passwords are never accepted as CLI flags; interactive secure prompts or `--password-stdin` / `--recovery-stdin` are used instead:

```bash
cargo run -p rpm-cli -- encrypt ./folder --keyfile ./my.key --recovery-out recovery.txt
cargo run -p rpm-cli -- encrypt ./folder --reed-solomon
cargo run -p rpm-cli -- encrypt ./folder --split-mb 4000
cargo run -p rpm-cli -- encrypt ./folder --stealth --container-mb 50
cargo run -p rpm-cli -- encrypt ./decoy --container-mb 50 --hidden ./secret --hidden-keyfile ./hidden.key
cargo run -p rpm-cli -- split ./folder.vault --part-mb 100
cargo run -p rpm-cli -- join ./folder.vault.001 -o ./folder.joined.vault
cargo run -p rpm-cli -- repair ./folder.vault
cargo run -p rpm-cli -- decrypt ./folder.vault --keyfile ./my.key -o ./restored
cargo run -p rpm-cli -- inspect ./folder.vault --integrity-only --json
cargo run -p rpm-cli -- diff ./vault-a.vault ./vault-b.vault
cargo run -p rpm-cli -- rekey ./folder.vault --keyfile ./my.key
cargo run -p rpm-cli -- password --length 24
cargo run -p rpm-cli -- shell-integration install   # Windows HKCU only
```

To restore selected entries from a single vault, use the paths shown by `inspect`. Repeat `--only` for each file or folder. This example restores one file and the entire `photos` folder into a fresh output directory.

```bash
cargo run -p rpm-cli -- inspect ./folder.vault --keyfile ./my.key
mkdir ./selected
cargo run -p rpm-cli -- decrypt ./folder.vault --keyfile ./my.key -o ./selected --only folder/notes.txt --only folder/photos
```

## Architecture & Security

- Architecture overview and wire formats: [ARCHITECTURE.md](ARCHITECTURE.md) ([Türkçe](ARCHITECTURE.tr.md))
- Non-negotiable design invariants: [docs/DESIGN_INVARIANTS.md](docs/DESIGN_INVARIANTS.md) ([Türkçe](docs/DESIGN_INVARIANTS.tr.md))
- Threat model, swap/OS limitations, and SSD wipe caveats: [SECURITY.md](SECURITY.md) ([Türkçe](SECURITY.tr.md))
- Combinatorial valid-feature test kit: [docs/TEST_KIT.md](docs/TEST_KIT.md) ([Türkçe](docs/TEST_KIT.tr.md))

## License

This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0-or-later) — see [LICENSE](LICENSE).
