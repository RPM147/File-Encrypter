# Changelog

## v4.6.0

- **Split / Join Multi-Part Volumes & Zero-Temp-Merge Virtual Reader (`rpm-storage`, CLI, GUI):** Added streaming multi-part volume splitting (`.vault.001`, `.vault.002`, ...) with zero changes to Vault Format v5 and zero new external crates. Supports CLI `encrypt --split-mb <MiB>`, standalone `split --part-mb <MiB>` and `join` subcommands, GUI **Split Volume** presets (`25 / 100 / 500 / 2000 / 4000 MiB (FAT32 Safe)` and custom MiB), saved **Encryption Profile** persistence (`split_part_mib`), pre-flight part count estimation, drag-and-drop `.001/.002` deduplication, and a collapsible **Split / Join Vault Volumes** utility in **Inspect**. `decrypt`, selective extraction, RAM-only preview, `inspect`, `diff`, `rekey`, and Reed-Solomon `repair` read split volumes transparently via a single-file-handle virtual `Read + Seek` reader (`SplitVolumeReader`) without writing temporary merged files to disk.
- **Vault Explorer Folder Tree & Filters (GUI Inspect):** Replaced the flat manifest checklist with an interactive **Folder Tree / Flat List** explorer featuring tri-state folder checkboxes, recursive file counts and byte totals, **Expand All / Collapse All**, file-type filters (`Text`, `Image`, `Archive`, `Media`, `Other`) with monospace type badges, and size filters (`<= 16 MiB Previewable`, `< 1 MiB`, `1–16 MiB`, `> 16 MiB`).
- **Enhanced RAM-Only Preview (Text Search, Image Zoom/Rotate & Hex Viewer):** Upgraded the zero-disk RAM preview window with line-snapped UTF-8 pagination, toggleable line numbers, Unicode/Turkish-safe `Ctrl+F` search with match highlighting and cross-page navigation, lossless `90°` CW/CCW image rotation and zoom (`25%–400%` / `100%` / `Fit`) with pixel scrubbing on drop, and a paginated `4 KiB` read-only Hex + ASCII viewer for binary files.
- **Storage Layer Hardening & Audit Fixes:** Hardened multi-part commits with two-phase backup/rollback swap (`ReadOnly` and locked-file protection without split-brain corruption), run-scoped `OutputExclusion` so non-Stealth temp files are never packed into source directories and pre-existing `<base>.NNN` user files are never silently dropped in Stealth mode, split-set overwrite guards in `join` and `repair -o`, NTFS-consistent Unicode case folding (`Ş/ş`, `Ö/ö`, `Ü/ü`, `Ç/ç`, `Ğ/ğ`), full chunk-frame + `final_flag == 1` + EOF verification in `rekey_stream`, `O(N)` split deduplication, short `.rpm_tmp_` staging filenames within 255-byte limits, and GUI `secure_wipe` / hidden-compartment overlap protections matching the CLI.

## v4.5.0

- **Clipboard-Safe Idle Auto-Lock & Manual Panic Clear (`Ctrl+L`):** Added configurable idle timeout (`Off`, `1`, `5`, `15`, `30` min; default `5` min) in **Settings** plus a sidebar **Clear Session (`Ctrl+L`)** action that zeroizes all in-app passwords, recovery phrases, RAM previews, loaded manifests, Vault Diff outputs, generated passwords, activity logs, post-op banners, and pending queued credentials while **never touching or overwriting the OS clipboard**. Active non-preview transfers automatically defer the idle timer.
- **Saved Encryption Profiles (Built-In Presets & Custom Profiles):** Added 3 built-in encryption presets (**Daily Backup**, **Long-Term Archive (RS)**, **Maximum Privacy (Stealth)**) and up to 32 user-defined profiles stored in `config.json` with zero secrets, preserving Stealth/Reed-Solomon mutual exclusion and automatically clamping `Auto` containers to `50 MiB` when **Hidden Vault** is active.
- **Pre-Flight Size, Reed-Solomon Overhead & Container Fit Estimator:** Added non-blocking background source scanning (with cancellation and symlink skipping matching `packager.rs`), exact `RS(255, 239)` wire overhead calculation (`~6.7%`), and live container capacity indicators (**Fits**, **Compression-Dependent**, or **Exceeds Container** with minimum MiB guidance) on the **Encrypt** tab before starting encryption.
- **Post-Operation Quick Actions, Unfocused Completion Alert & Zeroizing Batch Queue:** Added a persistent bottom quick-action strip with one-click **Show in Folder** and **Verify Now**, optional taskbar attention notification when background work completes unfocused, and a sequential zeroizing job queue (**Add to Queue** on **Encrypt**, **Decrypt**, and **Inspect** Repair/Integrity Check) with reorder, pause/resume, cancel-auto-pause, and redacted debug output.
- **Upfront GUI Constraint Clarity, Reliability Hardening & Security Maintenance:** Disabled conflicting Stealth/Reed-Solomon toggles with tooltips and added upfront Re-Key, SSD wipe, non-`.vault` Stealth drop, and `16 MiB` RAM-preview limit notes; hardened gzip CRC32 trailer draining and cross-platform tar path sanitization; updated `url` to `2.5.9` (`RUSTSEC-2026-0592`); fixed edge-case bugs (preview cancel/switch busy-lock release, Windows font fallback, Stealth salt `RPMR` collision avoidance); and added frozen `v4.4.0` golden vault compatibility tests, deterministic fuzzers, and peak-RAM/single-pass I/O regression guards.

## v4.4.0

- **Optional Reed-Solomon Bit-Rot Protection (`RS(255, 239)`):** Added `--reed-solomon` in CLI and **Reed-Solomon Bit-Rot Protection (~7% parity)** in GUI Encrypt across standard, padded, and hidden Vault Format v5 containers. Implemented in pure Rust (`#![forbid(unsafe_code)]`, zero new crates) with 64-way byte interleaving (`15,292 B` inner → `16,320 B` wire blocks), repairing up to `512` contiguous corrupted bytes per block (one disk sector), plus a triplicated CRC32-protected `RPMR` outer header.
- **Transparent Recovery & Passwordless Atomic Repair:** `decrypt`, selective extraction, RAM-only preview, `inspect`, `diff`, and `integrity` checks transparently decode and count repaired bytes without double-counting the final seek block. Added passwordless atomic repair via `rpm-encrypter-cli repair` (in place or `-o <PATH>`) and GUI **Inspect → Repair (Reed-Solomon)** (`repair_vault_v5`).
- **Cryptographic Boundaries & UX Polish:** Reed-Solomon parity is strictly mutually exclusive with Stealth Mode (unencrypted parity syndromes distinguish encoded data from random noise), repairs accidental storage corruption strictly *before* AES-256-GCM verification (valid parity never authenticates tampered ciphertext), preserves intact hidden-compartment recovery when unrelated outer decoy blocks are damaged beyond repair, and rejects in-place `rekey` with neutral `CryptoError::UnsupportedOperation`.

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
