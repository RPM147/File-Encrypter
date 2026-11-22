[CmdletBinding()]
param()

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

Push-Location -LiteralPath $repoRoot
try {
    Ensure-ToolchainOnPath
    & cargo test --locked --release -p rpm-core --test perf_and_memory_guard bench_throughput_summary -- --ignored --nocapture
    exit $LASTEXITCODE
} finally {
    Pop-Location
}
