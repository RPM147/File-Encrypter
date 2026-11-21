# Changelog

## v4.3.0

- **Optional Stealth Mode (Encrypted Outer Header):** Added `--stealth` in CLI and **Stealth Mode (Encrypted Header)** in GUI Encrypt across unpadded, padded, and hidden-vault containers. Stealth containers omit plaintext `RPMV` magic bytes and JSON headers cleanly, encrypting fixed-size outer password and 24-word recovery slots plus HKDF XOR-masked chunk frame headers with a fixed OWASP Argon2id profile (`64 MiB / 3 iterations / 4 lanes`).
- **Indistinguishable Failures & Digest-Only Integrity Check:** Wrong passwords or missing/wrong keyfiles on Stealth containers uniformly return `CryptoError::AuthenticationFailed` without leaking `KeyfileRequired`. Passwordless integrity checks on non-`RPMV` files return size and SHA-256 digest only (`sha256_only: true`), and `rekey` uniformly refuses in-place rotation with `CryptoError::UnsupportedOperation`.
- **Stealth Storage & UX Polish:** Stealth encryption streams directly to an exclusive new destination file (eliminating `.rpm_tmp_` sibling traces) while excluding any output path inside selected folders; GUI file pickers and Decrypt drag-and-drop accept arbitrary file extensions (`All Files`), and Inspect reports display aligned header mode details (`is_stealth`).

## v4.2.0

- **RAM-Only Zero-Disk Preview:** Added in-memory file inspection (`extract_entry_to_memory_v5` in `rpm-storage` and the **Inspect → Preview** window in `rpm-gui`) across standard, padded, and hidden compartments. Previewed entries up to `16 MiB` are held in zeroized buffers without writing temporary plaintext files to disk, wait until full compartment AEAD authentication completes before display, support paginated UTF-8 text and bounded `PNG/JPEG/WebP/GIF/BMP` image rendering, and clear immediately on close, `Esc`, tab switch, or vault change.
- **Neutral Re-Key Error Reporting:** Unavailable in-place `rekey` on fixed-size containers now returns `CryptoError::UnsupportedOperation` with neutral, localized wording instead of disclosing container padding details.

## v4.1.0

- **Container Padding:** Padded `.vault` containers (`--container-mb` in CLI and **Container Size (Padding)** presets or custom MiB in GUI Encrypt) conceal true archive size with `OsRng` random padding while using the same public `VaultHeader` layout (`container_size` + `container_salt`) and enforcing exact-size integrity checks.
- **Hidden Vault (Plausible Deniability):** Embed a separately encrypted hidden compartment inside any fixed-size container (`--hidden`, `--hidden-keyfile`, `--hidden-no-compress` in CLI; collapsible **Hidden Vault** panel in GUI) with a trailing 108-byte AES-GCM mini-header, randomized pre-gap offset, and HKDF XOR-masked frame prefixes indistinguishable from random padding.
- **Compartment-Aware Operations & Security Boundaries:** `decrypt`, selective extract, `inspect`, and `diff` transparently select the outer or hidden compartment based on the supplied credentials via `inspect_header_seekable` / `unlock_seekable`. `rekey` is uniformly rejected on padded containers to preserve plausible deniability, and the 24-word recovery phrase unlocks only the outer decoy vault.
- **Documentation & Repository Cleanup:** Added bilingual English and Turkish documentation (`docs/USER_GUIDE.md`, `docs/USER_GUIDE.tr.md`, `docs/RELEASE_CHECKLIST.md`, `docs/RELEASE_CHECKLIST.tr.md`), expanded the threat model in `SECURITY.md` for container padding and hidden compartments, and removed the retired Python `legacy/` directory from Git tracking.

## v4.0.2

- Vault Diff compares authenticated file lists from two vault headers. The core API, CLI `diff` command and desktop Inspect tab report added, removed, changed and unchanged paths using file sizes and modification times.
- Upgraded the desktop GUI from eframe 0.31 to 0.37 and removed the obsolete RustSec exceptions for `quick-xml 0.30.0`.
- Settings now expose Argon2id iterations and parallelism and save the interface scale (`ui_scale_percent`, 80–150%).
- The desktop password generator lets you select uppercase letters, lowercase letters, digits and symbols, and exclude visually ambiguous characters.

## v4.0.1

- The desktop app and CLI show live throughput and an estimated time remaining during encryption and decryption. The CLI adds `--progress auto|always|never`.
- Selective extraction counts skipped entries toward the archive’s total unpacked size limit.
- CI checks RustSec advisories, dependency licenses, and dependency sources with `cargo-deny`. GitHub Releases use notes from this changelog and include signed build provenance for the Windows and Linux archives.
- Added a WinGet manifest generator for the portable Windows ZIP.
- Added resilience tests for malformed vault inputs, chunk boundaries, fragmented I/O, and cleanup after late streaming failures.

## v4.0.0

- **Rust migration.** The desktop app and CLI now share a pure Rust implementation. Vault Format v5 is intentionally not backward-compatible with v4; the former Python/Flet app is archived in [legacy/](legacy/README.md) for legacy Vault Format v4 files.
- **Vault Format v5.** Chunked AEAD encrypts and authenticates file contents in 1 MiB AES-256-GCM chunks. Each chunk is bound to its vault and position in the stream.
- **Desktop app.** The native GUI supports Turkish and English, plus drag-and-drop encryption and decryption. Windows builds can embed the application icon, product name and file version in the executable.
- **Selective extraction.** Choose files in the GUI’s Inspect tab, or repeat `decrypt --only` in the CLI to restore individual files or subfolders from one vault.
- **Safer extraction.** Tar-bomb limits cap expanded size, entry count and path depth. Stage-and-swap extraction holds output in a temporary directory until the complete vault stream passes authentication, including during selective restores.
- **Portable releases.** The release workflow tests and builds Windows and Linux packages, then publishes a ZIP, a tar.gz and a shared `SHA256SUMS.txt`. Windows users can also create the ZIP locally with [the packaging script](scripts/package-release.ps1).
