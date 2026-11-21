# Design Invariants & Engineering Guardrails

> Türkçe: [DESIGN_INVARIANTS.tr.md](DESIGN_INVARIANTS.tr.md) · Wire Layout: [ARCHITECTURE.md](../ARCHITECTURE.md) · Threat Model: [SECURITY.md](../SECURITY.md)

This document records the **non-negotiable architectural, cryptographic, and governance invariants** for RPM Encrypter (`v4.4.0+`). New features, refactors, or automated changes must preserve every rule below unless an intentional major format bump (`VAULT_VERSION > 5`) is explicitly planned and approved.

---

## Cryptographic & Format Invariants

### `INV-01` — Vault Format v5 (`v4.4.0+`) Backward Compatibility
- Existing vaults created by released `v4.4.0+` builds (Standard, Compressed, Keyfile, Padded, Hidden `RPMH`, Stealth, and Reed-Solomon `RPMR`) **must continue to verify, inspect, repair, and decrypt identically** in future releases.
- Future extensions inside `v5` must be strictly additive (or gated on new explicit fields/magic versions) and verified against frozen golden vault fixtures before merge.

### `INV-02` — Zero Unverified Plaintext Release
- Decryption to disk **must** extract into a sibling hidden staging directory (`.rpm_unpack_*.part`) and atomically promote verified output **only after** the final AEAD chunk (`final_flag == 1`) authenticates. On error or cancellation, staging directories are removed with zero plaintext left at the destination.
- RAM-only preview (`Inspect -> Preview`, default limit `16 MiB`) **must not display decrypted contents** until the entire compartment stream verifies its final AEAD chunk.
- **No `--password` CLI flag** and **no unauthenticated size/KDF allocation** from untrusted file headers (JSON header capped at `MAX_HEADER_SIZE = 1 MiB`, KDF parameters strictly validated).

### `INV-03` — Single-Pass Streaming & Bounded O(1) Memory
- Encryption, decryption, inspection, verification, and Reed-Solomon repair **must** stream chunk-by-chunk / block-by-block with bounded heap memory (`O(chunk_size)` or `O(RS_BLOCK_WIRE_SIZE)`), never buffering entire multi-gigabyte vaults in RAM.
- Decryption, RS repair, and Stealth verification **must complete in a single pass** (~`1x` read I/O) — never run a separate full-file verification pre-pass before streaming decryption.

### `INV-04` — Mutual Exclusion of Stealth Mode and Reed-Solomon
- `--stealth` (`EncryptOptions.stealth = true`) and `--reed-solomon` (`EncryptOptions.reed_solomon = true`) **must always remain mutually exclusive** and fail fast in core, storage, CLI, and GUI.
- **Why:** RS parity blocks produce deterministic algebraic zero-syndrome structure and a `RPMR` header, directly breaking Stealth Mode's first-layer indistinguishability from uniform random bytes.

### `INV-05` — Stealth Mode Fixed Security Baseline & Zero Temp Traces
- All Stealth containers (unpadded, padded, hidden) **must** enforce `STEALTH_KDF_PARAMS` (`Argon2id 64 MiB / 3 iterations / 4 lanes`) in production regardless of user KDF preferences (since Stealth headers carry zero unauthenticated KDF metadata).
- Wrong passwords, wrong/missing keyfiles, and corrupted or too-short inputs **must** collapse uniformly to `AuthenticationFailed` so neither keyfile presence nor compartment existence is leaked.
- Passwordless `inspect --integrity-only` / GUI integrity check on non-`RPMV`/non-`RPMR` files **must** compute only file size and `SHA-256`.
- Stealth creation writes directly to an exclusive destination (`create_new`), deleting partial output on returned error rather than leaving `.rpm_tmp_*` sibling rename artifacts.

### `INV-06` — Plausible Deniability Parity & `rekey` Restrictions
- Standard padded containers (`container_size`) and padded containers containing a hidden compartment (`RPMH`) **must** produce bit-level-identical outer `VaultHeader` shapes (`zero` hidden-vault flags), identical outer error semantics, and identical container byte distributions (`OsRng` padding).
- Padded, Hidden, Stealth, and Reed-Solomon containers **must** reject `rekey` with `UnsupportedOperation` (protecting plausible deniability and preventing desynchronized outer/RS parity).

---

## Implementation, Safety & Governance Invariants

### `INV-07` — Pure-Rust Safety, Deterministic Zeroization, Acyclic Crates & Zero Telemetry
- Crate graph remains strictly acyclic: `rpm-core` -> `rpm-storage` -> {`rpm-cli`, `rpm-gui`}.
- Pure-Rust protocol/FEC code (`crates/rpm-core/src/rs.rs`) maintains `#![forbid(unsafe_code)]`. Unsafe FFI is isolated solely to OS memory-locking (`VirtualLock`/`mlock`) behind safe `SecretKey` guards wrapped in `zeroize` / `Zeroizing`.
- Third-party crates must pass `cargo-deny` (`deny.toml`: RustSec advisories, allowed OSI licenses, crates.io-only sources) and keep `Cargo.lock` deterministic (`--locked`).
- Zero telemetry, zero analytics, zero network clients.

### `INV-08` — Hostile Archive Extraction Bounds
- Both disk extraction and RAM-only preview **must** sanitize every tar entry path against traversal (`..`, root prefixes, Windows drive letters, NUL bytes), skip or reject symlinks and hardlinks, skip the target vault file if nested in source paths, and enforce `UnpackLimits` (`max_path_depth = 128`, `max_file_count = 500_000`, `max_total_bytes = 64 GiB`).

### `INV-09` — CI Gates, Dependabot & Solo-Dev `main` Safe Mode
- CI runs `cargo fmt --all -- --check`, `cargo clippy --locked --workspace --all-targets -- -D warnings`, `cargo test --locked --workspace --lib`, `cargo test --locked --workspace` (Windows + Linux), and `cargo-deny`.
- Weekly Dependabot PRs track Cargo and GitHub Actions updates in grouped PRs without bypassing `deny.toml`.
- **GitHub `main` Branch Ruleset (Solo-Dev Safe Mode):** Configured under **Repository Settings -> Rules -> Rulesets** targeting the **Default branch (`main`)** with **Restrict deletions** and **Block force pushes** enabled (enforcement **Active**), keeping direct fast-forward pushes ergonomic for solo releases while preventing accidental history loss.
