[CmdletBinding()]
param(
    [string]$Version,
    [string]$Sha256,
    [ValidateNotNullOrEmpty()][string]$OutDir = 'dist/winget'
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

Push-Location -LiteralPath $repoRoot
try {
    if ([string]::IsNullOrWhiteSpace($Version)) {
        $inWorkspacePackage = $false
        foreach ($line in Get-Content -LiteralPath 'Cargo.toml') {
            if ($line -match '^\s*\[') {
                $inWorkspacePackage = $line -match '^\s*\[workspace\.package\]\s*(?:#.*)?$'
            } elseif ($inWorkspacePackage -and $line -match '^\s*version\s*=\s*["'']([^"'']+)["'']\s*(?:#.*)?$') {
                $Version = $Matches[1]
                break
            }
        }
    }
    if ($Version -notmatch '\A[0-9A-Za-z][0-9A-Za-z.+-]*\z') {
        throw 'A filename-safe version is required. Set -Version or [workspace.package].version in Cargo.toml.'
    }

    $archiveName = "rpm-encrypter-$Version-windows-x86_64.zip"

    if ([string]::IsNullOrWhiteSpace($Sha256)) {
        $sumsPath = Join-Path $repoRoot 'dist\SHA256SUMS.txt'
        if (Test-Path -LiteralPath $sumsPath -PathType Leaf) {
            foreach ($line in Get-Content -LiteralPath $sumsPath) {
                if ($line -match '\A([0-9A-Fa-f]{64})\s+\*?(.+)\z') {
                    $candidateFile = [IO.Path]::GetFileName($Matches[2].Trim())
                    if ($candidateFile -eq $archiveName) {
                        $Sha256 = $Matches[1]
                        break
                    }
                }
            }
        }
        if ([string]::IsNullOrWhiteSpace($Sha256)) {
            $zipPath = Join-Path $repoRoot (Join-Path 'dist' $archiveName)
            if (Test-Path -LiteralPath $zipPath -PathType Leaf) {
                $Sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $zipPath).Hash
            }
        }
    }

    if ([string]::IsNullOrWhiteSpace($Sha256) -or $Sha256 -notmatch '\A[0-9A-Fa-f]{64}\z') {
        throw "A valid 64-character SHA-256 hash is required. Pass -Sha256 or build $archiveName into dist/ first."
    }

    $shaUpper = $Sha256.ToUpperInvariant()
    $baseOut = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutDir)
    $manifestDir = Join-Path $baseOut (Join-Path 'RPM147.RPMEncrypter' $Version)
    [void][IO.Directory]::CreateDirectory($manifestDir)

    $installerUrl = "https://github.com/RPM147/File-Encrypter/releases/download/v$Version/$archiveName"
    $releaseNotesUrl = "https://github.com/RPM147/File-Encrypter/releases/tag/v$Version"

    $versionYaml = @"
# yaml-language-server: `$schema=https://aka.ms/winget-manifest.version.1.9.0.schema.json

PackageIdentifier: RPM147.RPMEncrypter
PackageVersion: $Version
DefaultLocale: en-US
ManifestType: version
ManifestVersion: 1.9.0
"@

    $installerYaml = @"
# yaml-language-server: `$schema=https://aka.ms/winget-manifest.installer.1.9.0.schema.json

PackageIdentifier: RPM147.RPMEncrypter
PackageVersion: $Version
InstallerLocale: en-US
InstallerType: zip
NestedInstallerType: portable
NestedInstallerFiles:
  - RelativeFilePath: rpm-encrypter.exe
    PortableCommandAlias: rpm-encrypter
  - RelativeFilePath: rpm-encrypter-cli.exe
    PortableCommandAlias: rpm-encrypter-cli
Installers:
  - Architecture: x64
    InstallerUrl: $installerUrl
    InstallerSha256: $shaUpper
ManifestType: installer
ManifestVersion: 1.9.0
"@

    $localeYaml = @"
# yaml-language-server: `$schema=https://aka.ms/winget-manifest.defaultLocale.1.9.0.schema.json

PackageIdentifier: RPM147.RPMEncrypter
PackageVersion: $Version
PackageLocale: en-US
Publisher: RPM147
PublisherUrl: https://github.com/RPM147
PublisherSupportUrl: https://github.com/RPM147/File-Encrypter/issues
PackageName: RPM Encrypter
PackageUrl: https://github.com/RPM147/File-Encrypter
License: AGPL-3.0-or-later
LicenseUrl: https://github.com/RPM147/File-Encrypter/blob/main/LICENSE
ShortDescription: Pure-Rust local file and folder encryption tool using Chunked AES-256-GCM and Argon2id.
Tags:
  - encryption
  - security
  - aes-gcm
  - argon2
  - rust
  - portable
ReleaseNotesUrl: $releaseNotesUrl
ManifestType: defaultLocale
ManifestVersion: 1.9.0
"@

    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    $files = [ordered]@{
        'RPM147.RPMEncrypter.yaml'              = ($versionYaml -replace "`r`n", "`n").TrimEnd("`n") + "`n"
        'RPM147.RPMEncrypter.installer.yaml'    = ($installerYaml -replace "`r`n", "`n").TrimEnd("`n") + "`n"
        'RPM147.RPMEncrypter.locale.en-US.yaml' = ($localeYaml -replace "`r`n", "`n").TrimEnd("`n") + "`n"
    }

    foreach ($entry in $files.GetEnumerator()) {
        $dest = Join-Path $manifestDir $entry.Key
        [IO.File]::WriteAllText($dest, $entry.Value, $utf8NoBom)
        Write-Output $dest
    }
} finally {
    Pop-Location
}
