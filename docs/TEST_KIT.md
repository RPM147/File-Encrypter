# Combinatorial Valid-Feature Test Kit

> **English** (default) · [Türkçe](TEST_KIT.tr.md)

The RPM Encrypter combinatorial test kit systematically validates every **valid feature combination** across all four workspace crates (`rpm-core`, `rpm-storage`, `rpm-cli`, `rpm-gui`). By scope, negative/forced-constraint failure modes (such as combining `--stealth` with `--reed-solomon` or running `rekey` on padded containers) are intentionally excluded here and continue to live in their dedicated security/resilience suites.

## Test Suites & Combination Coverage

### 1. Core Crypto & Format Matrix ([combinatorial_core_matrix.rs](../crates/rpm-core/tests/combinatorial_core_matrix.rs))
- **`core_vault_matrix_standard_24` / `core_vault_matrix_stealth_24` / `core_vault_matrix_reed_solomon_24` (72 configurations total):**
  Full Cartesian product of:
  - `EnvelopeMode`: `{Standard, Stealth, ReedSolomon}` (3)
  - `ContainerLayout`: `{Unpadded, Padded (128 KiB), Hidden (160 KiB)}` (3)
  - `outer_compress`: `{false, true}` (2)
  - `outer_keyfile`: `{false, true}` (2)
  - For `Hidden`: `hidden_compress` (`{false, true}`) × `hidden_keyfile` (`{false, true}`) (4)
  - Exercises BIP-39 24-word recovery round-trips, wire magic/padding invariants, passwordless `check_integrity`, header inspection (`inspect_header_seekable_with_kdf`), full stream decryption under outer Password, outer RecoveryKey, and Hidden Password, `diff_metadata`, transparent `512`-byte contiguous sector bit-rot recovery + `repair_vault_stream` on all `ReedSolomon` configs, and all valid `rekey_stream` credential/keyfile transitions on `Standard + Unpadded` configs.
- **`core_chunk_size_and_payload_boundary_matrix` (75 runs):**
  `3` envelope modes × `2` chunk sizes (`16 KiB`, `64 KiB`) × `2` compression states × `6` boundary lengths (`0`, `1`, `chunk-1`, `chunk`, `chunk+1`, `2*chunk+17`) plus `1 MiB + 13` default-chunk runs across all 3 envelope modes.
- **`core_argon2id_kdf_profile_matrix` (19 runs):**
  `4` valid Argon2id profiles (`16 MiB/1/1`, `16 MiB/2/4`, `32 MiB/2/2`, OWASP `64 MiB/3/4`) across `{Standard, Padded, Hidden, ReedSolomon}`, plus production `STEALTH_KDF_PARAMS` (`64 MiB/3/4`) verification across `{Unpadded, Padded, Hidden}`.
- **`core_diff_full_state_matrix`:**
  Added, removed, size-changed, mtime-changed, size+mtime-changed, unchanged, empty↔non-empty, identical, and forward/reverse directional symmetry.

### 2. Storage Workflows Matrix ([combinatorial_storage_matrix.rs](../crates/rpm-storage/tests/combinatorial_storage_matrix.rs))
- **`storage_vault_matrix_standard_24` / `storage_vault_matrix_stealth_24` / `storage_vault_matrix_reed_solomon_24` (72 configurations total):**
  Same 72-configuration matrix driven end-to-end on real directories containing UTF-8 Turkish text (`Iğdır-ölçü.txt`), PNG images, binary blobs, `0 B` files, nested directories, and empty directories — verifying zero `.rpm_tmp_*` leftovers, extensionless/`.bin` Stealth handling, transparent RS `512`-byte damage survival across RAM preview (`extract_entry_to_memory_v5_with_stealth_kdf`), selective extraction, full decrypt, copy + in-place `repair_vault_v5`, and `rekey_vault_v5`.
- **`storage_payload_edge_cases_and_stealth_self_exclusion_matrix`:**
  `3` envelope modes × `2` compression states covering duplicate basenames from distinct folders, Unicode/emoji filenames, `0 B` files, empty directories, `unique_path` collisions, Stealth self-exclusion when writing inside a source folder, and symlink skipping.
- **`storage_wipe_passes_and_output_modes_matrix` (60 runs):**
  `wipe_passes ∈ 1..=5` × `3` envelope modes × `{single file, nested directory}` × `{sibling output, custom output dir}`.
- **`storage_config_launch_and_shell_integration_matrix`:**
  `AppConfig` round-trip persistence in isolated temporary storage (`ThemeMode` × `AppLanguage` × `ui_scale_percent` × compression × wipe passes × Argon2id presets), all valid `parse_gui_launch_args` inputs, and full `MemoryRegistryBackend` install/status/uninstall lifecycle (never touching real `%APPDATA%` or the Windows registry).

### 3. Headless CLI Matrix ([combinatorial_cli_matrix.rs](../crates/rpm-cli/tests/combinatorial_cli_matrix.rs))
- **`cli_vault_matrix_standard_24` / `cli_vault_matrix_stealth_24` / `cli_vault_matrix_reed_solomon_24` (72 configurations total):**
  Exercises `rpm_cli::run_cli_args` across all 72 configurations rotating `--recovery-out` vs stdout 24-word capture, `-o <dir>` vs sibling output, `--progress {auto, always, never}`, `--wipe`, `.bin`/extensionless Stealth renaming, `inspect --integrity-only` (`--json` & plain), RS `512`-byte corruption → transparent `decrypt` → `repair -o` (`--json`) & in-place `repair`, `inspect` / `decrypt` / repeatable `--only` via both `--password-stdin` and `--recovery-stdin`, `diff`, and `rekey` (`--keyfile`, `--new-keyfile`, `--clear-keyfile`).
- **`cli_batch_decrypt_diff_password_and_shell_status_matrix`:**
  Multi-vault batch `decrypt`, `diff` across all valid auth pairings (`pw+kf/pw`, `rec/pw`, `pw+kf/rec`, `rec/rec`), `password --length {12,16,24,32,64}` × `{default, --no-symbols}`, and read-only `shell-integration status`.

### 4. Desktop GUI State, Render & Workers Matrix ([combinatorial_gui_matrix.rs](../crates/rpm-gui/tests/combinatorial_gui_matrix.rs))
- **`gui_pwgen_full_150_cartesian_matrix` (150 configurations):**
  All `15` non-empty character-class subsets × `exclude_ambiguous ∈ {false, true}` × `length ∈ {12, 16, 24, 32, 64}`, including `zxcvbn` strength scoring in TR/EN and 30-second clipboard auto-clear setup.
- **`gui_settings_theme_lang_scale_and_all_tabs_headless_render_matrix`:**
  Isolated `ThemeMode` × `AppLanguage` × `7` UI scale presets × Argon2id/compression/wipe persistence plus headless `egui::Context::run_ui` rendering of all 6 tabs (including Hidden Vault panel, recovery modal, and shell confirmation modal) in TR/EN × Dark/Light.
- **`gui_encrypt_container_presets_and_mode_matrix`:**
  All `ContainerSizePreset` presets (`Auto`, `10/50/100/500 MiB`, `Custom`) × `{Normal, Stealth, ReedSolomon}` × hidden/compression/keyfile/output options.
- **`gui_preview_all_5_image_formats_multipage_utf8_and_lifecycle_matrix`:**
  Encoding and headless `PreviewState` rendering for all `5` image codecs (`PNG`, `JPEG`, `WebP`, `GIF`, `BMP`), short & `>16 KiB` multi-page UTF-8 text, binary notice, and cleanup via `clear_preview`, `dismiss_modals` (`Esc`), tab switch, and `reset_manifest`.
- **`gui_drag_drop_shortcuts_launch_and_manifest_filter_matrix`:**
  All `6` active tabs × `{regular file, .bin stealth file, .vault, folder}` drop routing, `Ctrl+1..6` shortcuts, `Esc` modal clearing, and manifest search/selection.
- **`gui_workers_all_10_operations_and_bilingual_reports_matrix`:**
  Drives all `10` asynchronous GUI workers (`spawn_encrypt`, `spawn_encrypt_hidden`, `spawn_integrity_check`, `spawn_repair`, `spawn_inspect`, `spawn_preview`, `spawn_selective_extract`, `spawn_decrypt`, `spawn_vault_diff`, `spawn_rekey`) across Standard, Padded, Hidden, damaged Reed-Solomon, and production-KDF Stealth containers with TR/EN colon-alignment verification.

## Foundation Safety Nets (Included in `cargo test --workspace`)

- **Frozen `v4.4.0` Golden Vault Compatibility ([golden_compatibility_tests.rs](../crates/rpm-core/tests/golden_compatibility_tests.rs), [golden_storage_compatibility_tests.rs](../crates/rpm-storage/tests/golden_storage_compatibility_tests.rs)):**
  Reads 8 immutable `v4.4.0` fixtures in [crates/rpm-core/tests/fixtures/v4_4_0/](../crates/rpm-core/tests/fixtures/v4_4_0/) (`304,231` bytes total including `golden.key` and `fixtures_manifest.json`), verifying SHA-256 fixture integrity, password + 24-word recovery unlock, hidden compartments, RAM preview, cross-vault `diff`, and 512-byte RS damage repair.
- **Deterministic Malformed-Input Fuzzing & Tar/Gzip Rollback ([fuzz_malformed_inputs.rs](../crates/rpm-core/tests/fuzz_malformed_inputs.rs), [fuzz_storage_inputs.rs](../crates/rpm-storage/tests/fuzz_storage_inputs.rs)):**
  Reproducible `SplitMix64` fuzzing (`RPM_FUZZ_SEED`, `RPM_FUZZ_ITERS`) over core header/stealth/RS/diff parsers and storage unpack/preview/repair flows, plus authenticated malicious archive rollback tests (Tar-Slip `..`/`\`/drive prefixes, symlinks/hardlinks, corrupted gzip CRC32 trailers).
- **Peak Heap & Single-Pass I/O Regression Guard ([perf_and_memory_guard.rs](../crates/rpm-core/tests/perf_and_memory_guard.rs)):**
  Validates O(1) bounded streaming heap usage and `~1x` single-pass read I/O across `16 MiB` Standard, RS, and Stealth operations, plus an `#[ignore]` release benchmark invoked via `.\scripts\run-benchmarks.ps1`.

## Running Locally

```powershell
# Run only the four combinatorial matrices (debug)
.\scripts\run-combinatorial-tests.ps1

# Run the four combinatorial matrices in optimized --release mode (~seconds)
.\scripts\run-combinatorial-tests.ps1 -Release

# Run combinatorial matrices + rustfmt, Clippy (-D warnings), and full workspace tests
.\scripts\run-combinatorial-tests.ps1 -FullWorkspace

# Run the --release 16 MiB throughput & heap benchmark
.\scripts\run-benchmarks.ps1
```
