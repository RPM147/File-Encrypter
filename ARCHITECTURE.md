# RPM Encrypter — Architecture & Compatibility Policy

> Design invariants & non-negotiable engineering rules: [docs/DESIGN_INVARIANTS.md](docs/DESIGN_INVARIANTS.md) · [Türkçe](docs/DESIGN_INVARIANTS.tr.md)

## Package Layout

```text
Cargo.toml                  # Pure-Rust workspace manifest (no unsafe RS/crypto wrappers)
crates/
  rpm-core/                 # Vault Format v5 (Chunked AEAD, Argon2id, HKDF, BIP-39, Hidden RPMH, Stealth, RS RPMR, Diff, Zeroize/VirtualLock/mlock)
  rpm-storage/              # Bounded zero-temp-plaintext pipe, tar+gzip packager, atomic I/O, RAM-only preview, wiper, config, HKCU shell integration
  rpm-cli/                  # Headless CLI binary (rpm-encrypter-cli)
  rpm-gui/                  # Native eframe/egui desktop GUI binary (rpm-encrypter) with OS drag-and-drop & RAM preview
```

## Dependency Rules (Acyclic)

1. **`rpm-core`** depends only on pure-Rust crypto/serialization crates (`aes-gcm`, `argon2`, `hkdf`, `sha2`, `bip39`, `base64`, `zeroize`, `serde`, `serde_json`, `thiserror`, `rand`, and Win32/Unix memory-locking bindings). Pure-Rust protocol/FEC modules such as `rs.rs` enforce `#![forbid(unsafe_code)]`. It never performs UI, archive, or registry work.
2. **`rpm-storage`** depends on `rpm-core` and implements streaming tar/deflate packing and bounded unpacking, bounded in-memory piping, crash-safe atomic writes, RAM-only entry preview, best-effort wiping, config persistence, and Windows HKCU shell integration.
3. **`rpm-cli`** depends on `rpm-core` and `rpm-storage` only (zero GUI crates).
4. **`rpm-gui`** wires `eframe`/`egui` + `rfd` + `zxcvbn` to background worker threads driving `rpm-core` and `rpm-storage`.

## Locked Vault Format v5 Wire Specifications

Vault Format **v5** is frozen at `VAULT_VERSION = 5`:

### 1. Standard & Padded Outer Vault (`RPMV`)

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
| RandomPadding     | Variable  | OsRng bytes up to container_size (if padded)  |
+-------------------+-----------+-----------------------------------------------+
```

- **Context Derivation (`payload_context`):**
  `SHA-256("RPMV5-CTX" || version || len(cipher) || cipher || chunk_size || compressed_flag || vault_id [|| container_size || container_salt])` binds every immutable archive parameter (and optional container geometry) to metadata, key slots, the `7`-byte HKDF stream nonce prefix (`"rpm-v5-stream-nonce"`), and every chunk AAD.
  (`FLAG_HAS_KEYFILE` remains mutable in `VaultHeader.flags` to allow O(1) `rekey_stream`, and is authenticated by `password_slot_aad`.)
- **Chunk Frame Layout (`CHUNK_SIZE = 1 MiB` default, allowed `[16 KiB, 16 MiB]`):**
  `plain_len (u32 BE) || final_flag (1 byte: 0 or 1) || AES-256-GCM(DEK, nonce_prefix || chunk_idx || final_flag, plaintext, AAD="RPMV5-CHUNK" || payload_ctx || chunk_idx || final_flag || plain_len)`.
  All chunks must be non-empty except the final chunk (`final_flag == 1`), which terminates at EOF (for unpadded vaults) or inside bounded random padding (for fixed-size `container_size` vaults in `[64 KiB, 64 GiB]`).

### 2. Container Padding & Hidden Compartment (`RPMH`)

- Standard padded containers (`--container-mb`) and hidden-vault containers share the exact same public outer `VaultHeader` layout (`container_size` + `container_salt`, zero hidden-vault flags).
- Inside the fixed container geometry, an optional secondary hidden compartment writes its `RPMH` encrypted payload frames (with HKDF-masked 5-byte chunk frame prefixes) followed by encrypted metadata and a trailing `108`-byte AES-256-GCM mini-header (`12`-byte nonce + `80`-byte packed payload + `16`-byte tag) at the end of the container. All unused space is filled with `OsRng` random bytes.

### 3. Optional Stealth Mode (Encrypted Header)

```text
+-------------------+-----------+-----------------------------------------------+
| Offset / Field    | Size      | Description                                   |
+-------------------+-----------+-----------------------------------------------+
| OuterSalt         | 32 bytes  | Random Argon2id / recovery salt               |
| PasswordSlot      | 108 bytes | AES-256-GCM(KEK, nonce, 80B slot, AAD)        |
| RecoverySlot      | 108 bytes | AES-256-GCM slot (or 108B OsRng random bytes) |
| EncryptedMetadata | Variable  | AES-256-GCM(DEK, meta_nonce, JSON, AAD=CTX)   |
| MaskedChunkFrames | Variable  | HKDF-masked 5-byte frame prefixes + AEAD      |
| RandomPadding     | Variable  | Optional OsRng + hidden compartment tail      |
+-------------------+-----------+-----------------------------------------------+
```

- Unpadded, padded, and hidden Stealth vaults carry **zero** unauthenticated magic strings, lengths, or KDF settings. All Stealth vaults enforce the fixed OWASP Argon2id baseline (`64 MiB`, `3` iterations, `4` lanes), return `AuthenticationFailed` uniformly on wrong password/keyfile, refuse `rekey` (`UnsupportedOperation`), report SHA-256 + file size on passwordless checks, and write directly via `create_new` (never via sibling `.rpm_tmp_*` files).

### 4. Optional Reed-Solomon Bit-Rot Wrapper (`RPMR`)

```text
+-------------------+-----------+-----------------------------------------------+
| Offset / Field    | Size      | Description                                   |
+-------------------+-----------+-----------------------------------------------+
| PrefixHeader      | 48 bytes  | 3x 16-byte copy ("RPMR\x01\x10\x40..." + CRC32)|
| RSBlocks[0..n]    | n*16,320B | 64-way interleaved GF(2^8) RS(255, 239)       |
+-------------------+-----------+-----------------------------------------------+
```

- Each `16,320`-byte wire block interleaves `64` shortened systematic `RS(255, 239)` codewords (`15,292` inner payload bytes + `4`-byte inner length + `1,024` parity bytes), deterministically repairing up to **`512` contiguous corrupted bytes** (one disk sector) per block, while tolerating sector-0 damage via the triplicated CRC32 header and block-0 `RPMV` corroboration.
- **Strictly mutually exclusive with Stealth Mode:** RS parity leaves zero-syndrome mathematical structure and cannot coexist with uniform-random Stealth containers.
- **Authentication remains purely cryptographic:** RS repairs physical media corruption prior to inner decryption; inner AES-256-GCM tags always decide authenticity.

### 5. RAM-Only Zero-Disk Preview

- `rpm-storage::preview` streams decrypted bytes directly from the verified chunk stream through tar/gzip into zeroized RAM (`DEFAULT_PREVIEW_MAX_BYTES = 16 MiB` default cap) without temporary files.
- `rpm-gui` keeps decoded preview state closed until the **entire compartment stream** completes final-chunk AEAD authentication, and scrubs buffers/textures on `Esc`, close, tab switch, or vault switch.

## Clean-Slate / No v4 Backward Compatibility Policy

RPM Encrypter migrated from Python + Flet to **Pure Rust** with **Vault Format v5**:

- Legacy Python + Flet code (`Vault Format v4`) is preserved in earlier Git history and is no longer tracked or built.
- Vault Format **v5 (`Chunked AES-256-GCM`)** intentionally broke compatibility with v4 archives to eliminate the v4 32 GiB payload cap and unverified-plaintext temporary archive limits.
- Within **v5 (`v4.4.0+`)**, backward compatibility across releases is strictly preserved (see `INV-01` in [docs/DESIGN_INVARIANTS.md](docs/DESIGN_INVARIANTS.md)).

## Related Documents

- [SECURITY.md](SECURITY.md) — Threat model, memory locking, SSD/swap caveats, and feature guarantees
- [docs/DESIGN_INVARIANTS.md](docs/DESIGN_INVARIANTS.md) ([Türkçe](docs/DESIGN_INVARIANTS.tr.md)) — Non-negotiable architectural and security invariants
- [docs/TEST_KIT.md](docs/TEST_KIT.md) ([Türkçe](docs/TEST_KIT.tr.md)) — Combinatorial valid-feature matrix across all four crates
