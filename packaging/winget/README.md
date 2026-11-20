# WinGet Manifest Generation

`generate-manifests.ps1` generates WinGet (`1.9.0` schema) portable ZIP manifests for `RPM147.RPMEncrypter` without mutating tracked repository files.

## Generate manifests

From the repository root, after building a Windows release package (`.\scripts\package-release.ps1`) or copying `SHA256SUMS.txt` into `dist/`:

```powershell
.\packaging\winget\generate-manifests.ps1
```

Or specify an explicit release version and SHA-256 hash:

```powershell
.\packaging\winget\generate-manifests.ps1 -Version 4.0.0 -Sha256 <64-hex-sha256>
```

Manifests are written to `dist/winget/RPM147.RPMEncrypter/<Version>/`:
- `RPM147.RPMEncrypter.yaml`
- `RPM147.RPMEncrypter.installer.yaml` (`rpm-encrypter.exe` and `rpm-encrypter-cli.exe`)
- `RPM147.RPMEncrypter.locale.en-US.yaml`

## Validate and submit

```powershell
winget validate --manifest .\dist\winget\RPM147.RPMEncrypter\4.0.0
```

Submit the generated folder under `manifests/r/RPM147/RPMEncrypter/<Version>/` in `microsoft/winget-pkgs`.
