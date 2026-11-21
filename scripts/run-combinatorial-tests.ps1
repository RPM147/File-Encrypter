[CmdletBinding()]
param(
    [switch]$Release,
    [switch]$FullWorkspace
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

function Ensure-ToolchainOnPath {
    $cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath (Join-Path $cargoBin 'cargo.exe'))) {
        $env:PATH = "$cargoBin;$env:PATH"
    }

    if (-not (Get-Command dlltool -ErrorAction SilentlyContinue)) {
        $winGetRoot = Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Packages'
        if (Test-Path -LiteralPath $winGetRoot) {
            $llvm = Get-ChildItem -LiteralPath $winGetRoot -Directory -Filter 'MartinStorsjo.LLVM-MinGW*' -ErrorAction SilentlyContinue |
                ForEach-Object { Get-ChildItem -LiteralPath $_.FullName -Directory -ErrorAction SilentlyContinue } |
                Sort-Object Name -Descending |
                Select-Object -First 1
            if ($llvm) {
                $llvmBin = Join-Path $llvm.FullName 'bin'
                if (Test-Path -LiteralPath $llvmBin) {
                    $env:PATH = "$llvmBin;$env:PATH"
                }
            }
        }
    }
}

function Invoke-Checked {
    param(
        [string]$Label,
        [string[]]$CommandArgs
    )
    Write-Host "==> $Label" -ForegroundColor Cyan
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    & cargo @CommandArgs
    $code = $LASTEXITCODE
    $sw.Stop()
    if ($code -ne 0) {
        throw "$Label failed with exit code $code after $($sw.Elapsed.TotalSeconds.ToString('F2'))s."
    }
    return [pscustomobject]@{
        Suite   = $Label
        Status  = 'PASS'
        Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 2)
    }
}

Push-Location -LiteralPath $repoRoot
try {
    Ensure-ToolchainOnPath
    $results = @()

    $extraProfileArgs = if ($Release) { @('--release') } else { @() }
    $suites = @(
        @{ Label = 'rpm-core combinatorial_core_matrix'; Args = @('test', '--locked') + $extraProfileArgs + @('-p', 'rpm-core', '--test', 'combinatorial_core_matrix') },
        @{ Label = 'rpm-storage combinatorial_storage_matrix'; Args = @('test', '--locked') + $extraProfileArgs + @('-p', 'rpm-storage', '--test', 'combinatorial_storage_matrix') },
        @{ Label = 'rpm-cli combinatorial_cli_matrix'; Args = @('test', '--locked') + $extraProfileArgs + @('-p', 'rpm-cli', '--test', 'combinatorial_cli_matrix') },
        @{ Label = 'rpm-gui combinatorial_gui_matrix'; Args = @('test', '--locked') + $extraProfileArgs + @('-p', 'rpm-gui', '--test', 'combinatorial_gui_matrix') }
    )

    if (-not $FullWorkspace -or $Release) {
        foreach ($s in $suites) {
            $results += Invoke-Checked -Label $s.Label -CommandArgs $s.Args
        }
    }

    if ($FullWorkspace) {
        $results += Invoke-Checked -Label 'cargo fmt --check' -CommandArgs @('fmt', '--all', '--', '--check')
        $results += Invoke-Checked -Label 'cargo clippy --workspace --all-targets' -CommandArgs @('clippy', '--locked', '--workspace', '--all-targets', '--', '-D', 'warnings')
        if (-not $Release) {
            $results += Invoke-Checked -Label 'cargo test --workspace --lib (fast)' -CommandArgs @('test', '--locked', '--workspace', '--lib')
        }
        $results += Invoke-Checked -Label 'cargo test --workspace' -CommandArgs @('test', '--locked', '--workspace')
    }

    Write-Host "`nCombinatorial Test Kit Summary:" -ForegroundColor Green
    $results | Format-Table -AutoSize
} finally {
    Pop-Location
}
