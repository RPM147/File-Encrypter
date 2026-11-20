# RPM Encrypter — Architecture & Compatibility Policy

## Package Layout

```text
Cargo.toml                  # Pure-Rust workspace manifest
crates/
  rpm-core/                 # Vault Format v5 (Chunked AEAD, Argon2id, HKDF, BIP-39, Zeroize/mlock/VirtualLock)
  rpm-storage/              # Zero-temp-plaintext bounded pipe, tar+gzip packager, atomic I/O, wiper, HKCU shell integration
  rpm-cli/                  # Headless CLI binary (rpm-encrypter-cli)
  rpm-gui/                  # Native eframe/egui desktop GUI binary (rpm-encrypter) with OS drag-and-drop
legacy/                     # Archived Python + Flet implementation (Vault Format v4, retired)
```

## Dependency Rules (Acyclic)

1. **`rpm-core`** depends only on pure-Rust crypto/serialization crates (`aes-gcm`, `argon2`, `hkdf`, `sha2`, `bip39`, `zeroize`, `serde`, and Win32/Unix memory-locking bindings). It never performs UI, archive, or registry work.
2. **`rpm-storage`** depends on `rpm-core` and implements streaming tar/deflate packing, bounded in-memory piping, crash-safe atomic writes, best-effort wiping, config storage, and Windows HKCU shell integration.
3. **`rpm-cli`** depends on `rpm-core` and `rpm-storage` only (zero GUI crates).
4. **`rpm-gui`** wires `eframe`/`egui` + `rfd` + `zxcvbn` to background worker threads driving `rpm-core` and `rpm-storage`.

## Clean-Slate / No Backward Compatibility Policy

RPM Encrypter has migrated from Python + Flet to **Pure Rust** with **Vault Format v5**:

- Legacy Python + Flet code (`Vault Format v4`) is archived untouched under [legacy/](legacy/README.md) solely as historical reference and is no longer maintained or built.
- Vault Format **v5 (`Chunked AES-256-GCM`)** breaks compatibility with v4 archives on purpose to eliminate the v4 32 GiB payload cap and unverified-plaintext temporary archive limits, while adding second-factor keyfiles and deterministic secret zeroization.
