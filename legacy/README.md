# Legacy Python + Flet Codebase (Vault Format v4)

This directory archives the retired Python + Flet implementation (Vault Format v4, pre-Rust rewrite) for historical reference.

Active development has moved to the Pure Rust Cargo workspace at the repository root (`crates/rpm-core`, `crates/rpm-storage`, `crates/rpm-cli`, `crates/rpm-gui`), implementing Vault Format v5 (Chunked AEAD) with deterministic memory zeroization (`zeroize`), `VirtualLock`/`mlock`, zero-temp-plaintext streaming, native OS drag-and-drop, and a single native binary distribution.
