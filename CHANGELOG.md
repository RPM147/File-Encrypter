# Changelog

## v4.0.0

- **Rust migration.** The desktop app and CLI now share a pure Rust implementation. Vault Format v5 is intentionally not backward-compatible with v4; the former Python/Flet app is archived in [legacy/](legacy/README.md) for legacy Vault Format v4 files.
- **Vault Format v5.** Chunked AEAD encrypts and authenticates file contents in 1 MiB AES-256-GCM chunks. Each chunk is bound to its vault and position in the stream.
- **Desktop app.** The native GUI supports Turkish and English, plus drag-and-drop encryption and decryption. Windows builds can embed the application icon, product name and file version in the executable.
- **Selective extraction.** Choose files in the GUI’s Inspect tab, or repeat `decrypt --only` in the CLI to restore individual files or subfolders from one vault.
- **Safer extraction.** Tar-bomb limits cap expanded size, entry count and path depth. Stage-and-swap extraction holds output in a temporary directory until the complete vault stream passes authentication, including during selective restores.
- **Portable releases.** The release workflow tests and builds Windows and Linux packages, then publishes a ZIP, a tar.gz and a shared `SHA256SUMS.txt`. Windows users can also create the ZIP locally with [the packaging script](scripts/package-release.ps1).
