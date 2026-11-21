# Security Model & Limitations

RPM Encrypter is a **local-only, single-user file encryption tool** written in Pure Rust (`Vault Format v5`). It is not a service, has no server, and makes no network connections. This document explains what it protects against and what limits remain.

## Threat model (what it is designed for)

RPM Encrypter protects the **confidentiality and integrity of files at rest** against someone who later obtains your `.vault` files (lost laptop, stolen drive, shared machine, or cloud-sync copy):

- **Chunked Authenticated Encryption (v5):** File streams and encrypted metadata are sealed using **AES-256-GCM** in `1 MiB` authenticated chunks bound to the vault context, chunk sequence number, final-chunk marker, and plaintext length.
- **No Unverified Plaintext Release:** Each chunk is authenticated in RAM **before** any decrypted byte enters the unpacking pipeline or touches disk. Truncation, chunk reordering, trailing bytes, or single-bit flips fail immediately.
- **Zero Plaintext Temp Archives & Atomic Stage-and-Swap:** Packing and unpacking stream over a bounded in-memory pipe directly into/from AEAD chunk processing without creating temporary plaintext archive files on disk. Decryption extracts into a hidden sibling staging folder (`.rpm_unpack_*.part`) enforced by tar-slip, symlink/hardlink, path-depth (`128`), file-count (`500,000`), and unpacked-size (`64 GiB`) limits, promoting verified files atomically only after the final chunk authenticates.
- **Key Derivation & Keyfile Binding:** Passwords are stretched with **Argon2id** (`64 MiB`, `3` iterations, `4` lanes by default) and optionally bound via HKDF-SHA256 to a second-factor keyfile.
- **Deterministic Memory Scrubbing:** Secret keys live at stable 32-byte-aligned heap addresses protected best-effort via refcounted OS page locking (`VirtualLock` on Windows, `mlock` on Unix). Keyfile hashes, passwords, recovery phrases, and plaintext chunk buffers are wrapped in `zeroize` / `Zeroizing` guards and scrubbed deterministically even on early error paths.

## What it does NOT protect against

### Secure wipe is best-effort, not guaranteed erasure

Overwriting original source files after encryption (`--wipe` or checkbox) does **not** guarantee irrecoverability on modern storage:

- **SSDs / flash:** Wear-leveling, TRIM, and over-provisioning mean the drive controller writes to new blocks rather than overwriting physical flash cells in place.
- **Filesystems & caches:** Copy-on-write filesystems (APFS, Btrfs, ZFS, ReFS), journaling, snapshots, thumbnails, and backups can retain prior copies.

Use **full-disk encryption from the start** or physically destroy the medium for high-sensitivity erasure.

### OS memory, swap, hibernation, and GPU/IME buffers

While Pure Rust avoids Python/Dart garbage-collector string retention and scrubs secrets deterministically (`zeroize` + best-effort `VirtualLock`/`mlock`):

- OS page-locking limits (`RLIMIT_MEMLOCK` / working-set quotas) can cause locking to fall back to unlocked memory under pressure.
- Windows hibernation (`hiberfil.sys`), crash dumps, GPU/OS text-rendering caches (`egui`), or IME history may still retain transient UI input outside the application's control.
- RAM-only preview (`Inspect → Preview`) streams entries strictly into zeroized memory buffers and clears decrypted buffers/textures on window close, `Esc`, tab change, or vault change, though OS swap/hibernation and GPU driver texture allocations remain outside application control.
- Use OS full-disk encryption and disable hibernation if your threat model includes physical memory forensics after suspend.

### Other limitations

- **Lost credentials = lost data.** If you lose your password, required keyfile, or 24-word recovery phrase, the vault cannot be opened.
- **Offline brute force.** Anyone with a copy of your `.vault` file can test password guesses offline at hardware speed bounded by your Argon2id settings. Choose a strong passphrase (or bind a high-entropy keyfile).
- **No v4 backward compatibility.** Vault Format v5 intentionally supersedes legacy Python v4 archives (the retired v4 codebase is preserved in earlier Git history).
- **Host trust.** RPM Encrypter cannot defend against malware, keyloggers, compromised OS kernels, or physical hardware implants running on your machine.

## Container Padding & Hidden Vault (Plausible Deniability)

The design targets an observer who has one offline copy of a padded container and lacks the hidden vault credentials. Ordinary padded containers and containers holding a hidden vault use the exact same public header layout (`container_size` and `container_salt`), with zero hidden-vault flags. For containers of equal size, inspecting the bytes cannot distinguish encrypted hidden metadata, masked frame prefixes, or hidden chunks from `OsRng` random padding.

Padded containers disallow `rekey` on both forms so command behavior never reveals whether a hidden compartment exists. As inherent operational limits outside `.vault` byte authentication, multiple container snapshots over time can reveal deltas, and OS recent-file lists, thumbnails, backups, swap/hibernation files, or residual SSD blocks can independently reveal activity.

## Stealth Mode (Encrypted Header / 1st-Layer Deniability)

Stealth Mode omits plaintext `RPMV` magic bytes and JSON headers altogether: bytes `[0..32]` hold a random salt, followed by fixed 108-byte AES-GCM password and recovery slots (or uniform random noise when recovery entropy is omitted), encrypted metadata, HKDF-masked 5-byte frame prefixes, and encrypted chunk payloads. Unpadded, padded, and hidden Stealth files use a fixed OWASP Argon2id baseline (`64 MiB`, `3` iterations, `4` lanes), uniformly return `AuthenticationFailed` when either a password or a required keyfile is wrong/missing, refuse `rekey` with `UnsupportedOperation`, and report only file size + SHA-256 on passwordless integrity checks so non-vault files and Stealth containers look identical without credentials. To avoid `.rpm_tmp_` sibling temp-file traces on disk during Stealth creation, Stealth writes directly to an exclusive new destination file (`create_new`), deleting partial output on returned errors — as an explicit trade-off, sudden power loss or `SIGKILL` mid-write may leave a partial encrypted file at the destination path.

## Reed-Solomon Bit-Rot Protection

Optional Reed-Solomon wrapping uses pure-Rust, `#![forbid(unsafe_code)]` GF(2⁸) `RS(255, 239)` with 64-way interleaving (`15,292` inner bytes per `16,320`-byte block) and a triplicated CRC32-protected `RPMR` outer header:

- **Physical recovery limit:** Repairs up to `512` contiguous corrupted bytes (one disk sector) per `16,320`-byte block and tolerates complete sector-0 wipes via the triplicated outer header and block-0 structural corroboration. Damage exceeding `8` corrupted symbols in any 255-byte interleaved codeword cannot be guaranteed-repaired and may decode to another codeword (which AES-256-GCM rejects).
- **Authentication remains purely cryptographic:** Reed-Solomon parity repairs accidental media corruption *prior* to decryption and never authenticates ciphertext. An attacker who modifies ciphertext and recomputes valid RS parity bytes is rejected by AES-256-GCM with zero promoted plaintext.
- **Incompatibility with Stealth Mode:** Reed-Solomon is strictly mutually exclusive with Stealth Mode (`--stealth` + `--reed-solomon` is rejected) because zero syndromes in unencrypted parity blocks make RS containers distinguishable from uniform random bytes. Padded/RS envelopes also refuse in-place `rekey` (`UnsupportedOperation`).

## Reporting a vulnerability

If you find a security issue, please open an issue without posting sensitive exploit details in public, or contact the maintainer.
