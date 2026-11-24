# WinGet Manifesti Oluşturma

> [English](README.md) (varsayılan) · **Türkçe**

`generate-manifests.ps1`, izlenen depo dosyalarını değiştirmeden `RPM147.RPMEncrypter` için taşınabilir ZIP WinGet (`1.9.0` şeması) manifestlerini oluşturur.

## Manifestleri oluşturma

Windows sürüm paketini oluşturduktan (`.\scripts\package-release.ps1`) veya `SHA256SUMS.txt` dosyasını `dist/` içine kopyaladıktan sonra proje kökünden PowerShell’de çalıştırın:

```powershell
.\packaging\winget\generate-manifests.ps1
```

Veya açık bir sürüm numarası ve SHA-256 özeti belirtin:

```powershell
.\packaging\winget\generate-manifests.ps1 -Version 4.6.0 -Sha256 <64-hex-sha256>
```

Manifestler `dist/winget/RPM147.RPMEncrypter/<Version>/` altına yazılır:
- `RPM147.RPMEncrypter.yaml`
- `RPM147.RPMEncrypter.installer.yaml` (`rpm-encrypter.exe` ve `rpm-encrypter-cli.exe`)
- `RPM147.RPMEncrypter.locale.en-US.yaml`

## Doğrulama ve gönderim

```powershell
winget validate --manifest .\dist\winget\RPM147.RPMEncrypter\4.6.0
```

Oluşturulan klasörü `microsoft/winget-pkgs` deposunda `manifests/r/RPM147/RPMEncrypter/<Version>/` altına gönderin.
