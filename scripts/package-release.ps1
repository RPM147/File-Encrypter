[CmdletBinding()]
param(
    [string]$Version,
    [switch]$SkipBuild,
    [ValidateNotNullOrEmpty()][string]$OutDir = 'dist'
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $repoRoot
try {
    if ([string]::IsNullOrWhiteSpace($Version)) {
        $inWorkspacePackage = $false
        foreach ($line in Get-Content -LiteralPath Cargo.toml) {
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

    if (-not $SkipBuild) {
        cargo build --release --workspace
        if ($LASTEXITCODE -ne 0) { throw "Cargo build failed with exit code $LASTEXITCODE." }
    }

    $entries = [ordered]@{
        'rpm-encrypter.exe'     = 'target/release/rpm-encrypter.exe'
        'rpm-encrypter-cli.exe' = 'target/release/rpm-encrypter-cli.exe'
        'README.md'             = 'README.md'
        'SECURITY.md'           = 'SECURITY.md'
        'LICENSE'               = 'LICENSE'
        'docs/USER_GUIDE.md'    = 'docs/USER_GUIDE.md'
        'docs/USER_GUIDE.tr.md' = 'docs/USER_GUIDE.tr.md'
    }
    $missing = @(
        foreach ($entry in $entries.GetEnumerator()) {
            $source = Join-Path $repoRoot $entry.Value
            if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
                $entry.Value
            }
        }
    )
    if ($missing.Count -gt 0) {
        throw ("Missing release artifact(s): " + ($missing -join ', ') + ". Run 'cargo build --release --workspace' or omit -SkipBuild.")
    }

    $outputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutDir)
    [void][IO.Directory]::CreateDirectory($outputPath)
    $archiveName = "rpm-encrypter-$Version-windows-x86_64.zip"
    $archivePath = Join-Path $outputPath $archiveName
    $tempPath = Join-Path $outputPath ([IO.Path]::GetRandomFileName())

    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    try {
        $archive = [IO.Compression.ZipFile]::Open($tempPath, [IO.Compression.ZipArchiveMode]::Create)
        try {
            foreach ($entry in $entries.GetEnumerator()) {
                $source = Join-Path $repoRoot $entry.Value
                [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive, $source, $entry.Key)
            }
        } finally {
            $archive.Dispose()
        }

        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $tempPath).Hash.ToLowerInvariant()
        Move-Item -LiteralPath $tempPath -Destination $archivePath -Force
        $checksumPath = Join-Path $outputPath 'SHA256SUMS.txt'
        [IO.File]::WriteAllText($checksumPath, "$hash  $archiveName" + [char]10, [Text.Encoding]::ASCII)
        Write-Output $archivePath, $checksumPath
    } finally {
        if ([IO.File]::Exists($tempPath)) { [IO.File]::Delete($tempPath) }
    }
} finally {
    Pop-Location
}
