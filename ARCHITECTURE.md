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

## Locked Vault Format v5 Wire Specification

Vault Format **v5** is frozen at `VAULT_VERSION = 5`:

```text
+-------------------+-----------+-----------------------------------------------+
| Offset / Field    | Size      | Description                                   |
+-------------------+-----------+-----------------------------------------------+
| Magic             | 4 bytes   | "RPMV"                                        |
| Version           | 1 byte    | 0x05                                          |
| HeaderLength      | 4 bytes   | u32 BE length of HeaderJSON (1..=1 MiB)       |
| HeaderJSON        | N bytes   | UTF-8 JSON VaultHeader                        |
| EncryptedMetadata | M bytes   | AES-256-GCM(DEK, meta_nonce, JSON, AAD=CTX)   |
| ChunkFrames[0..k] | Variable  | Repeating chunk frames until final_flag == 1  |
+-------------------+-----------+-----------------------------------------------+
```

- **Context Derivation (`payload_context`):**
  `SHA-256("RPMV5-CTX" || version || len(cipher) || cipher || chunk_size || compressed_flag || vault_id)` binds every immutable archive parameter to metadata, key slots, the `7`-byte HKDF stream nonce prefix (`"rpm-v5-stream-nonce"`), and every chunk AAD.
  (`FLAG_HAS_KEYFILE` remains mutable in `VaultHeader.flags` to allow O(1) `rekey_stream`, and is authenticated by `password_slot_aad`.)
- **Chunk Frame Layout (`CHUNK_SIZE = 1 MiB` default, allowed `[16 KiB, 16 MiB]`):**
  `plain_len (u32 BE) || final_flag (1 byte: 0 or 1) || AES-256-GCM(DEK, nonce_prefix || chunk_idx || final_flag, plaintext, AAD="RPMV5-CHUNK" || payload_ctx || chunk_idx || final_flag || plain_len)`.
  All chunks must be non-empty except the final chunk (`final_flag == 1`), which terminates at EOF with zero trailing bytes allowed.

## Clean-Slate / No Backward Compatibility Policy

RPM Encrypter has migrated from Python + Flet to **Pure Rust** with **Vault Format v5**:

- Legacy Python + Flet code (`Vault Format v4`) is archived untouched under [legacy/](legacy/README.md) solely as historical reference and is no longer maintained or built.
- Vault Format **v5 (`Chunked AES-256-GCM`)** breaks compatibility with v4 archives on purpose to eliminate the v4 32 GiB payload cap and unverified-plaintext temporary archive limits, while adding second-factor keyfiles and deterministic secret zeroization.
