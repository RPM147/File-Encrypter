# Build script for RPM Encrypter (Windows / PowerShell).
#
# Builds the Flet (Flutter) desktop app via `flet build windows` and compiles
# the Unicode-path launcher wrapper.
# Reads app metadata + bundled dependencies from pyproject.toml
# ([project] + [tool.flet]). Output: build\windows\
# Requires: Flutter SDK + Visual Studio "Desktop development with C++".
# Verify once with `flet doctor` before the first build.
$ErrorActionPreference = "Stop"

# Force UTF-8 first so flet's progress output does not fail on non-UTF-8
# console code pages (e.g. Turkish cp1254).
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

# Pre-flight: Flutter's Windows build creates symlinks for its plugins, which
# requires Windows Developer Mode.
$devMode = 0
try {
    $devMode = (Get-ItemProperty `
        -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" `
        -Name AllowDevelopmentWithoutDevLicense -ErrorAction Stop `
    ).AllowDevelopmentWithoutDevLicense
} catch { }
if ($devMode -ne 1) {
    throw @"
Windows Developer Mode is OFF, but Flet/Flutter Windows builds need it for plugin symlinks.
  1. Enable it:  Settings > System > For developers > Developer Mode  (or run: start ms-settings:developers)
  2. Make sure the Windows 10/11 SDK is installed via the Visual Studio Installer
     (the 'Desktop development with C++' workload includes it as a separate component).
Then re-run .\build.ps1
"@
}

python -m pip install --upgrade "flet-cli==0.85.2"
flet build windows
if ($LASTEXITCODE -ne 0) { throw "flet build windows failed (exit code $LASTEXITCODE)" }

Write-Host "Flet build complete - compiling Unicode-path launcher..."

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) {
    throw "vswhere.exe not found - is Visual Studio installed?"
}
$vsInstall = & $vswhere -latest -products * -property installationPath `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64
if (-not $vsInstall) {
    throw "Visual Studio / Build Tools with C++ desktop tools not found (needed for launcher compilation)."
}
$vcvars = Join-Path $vsInstall "VC\Auxiliary\Build\vcvarsall.bat"

$launcherOut = "build\windows\RPM Encrypter.exe"
cmd /c "`"$vcvars`" amd64 && rc /nologo /fo launcher\launcher.res launcher\launcher.rc && cl /nologo /O2 /Fo`"launcher\launcher.obj`" launcher\launcher.c launcher\launcher.res /Fe`"$launcherOut`" /link /SUBSYSTEM:WINDOWS kernel32.lib user32.lib shell32.lib"
if ($LASTEXITCODE -ne 0) { throw "Launcher compilation failed (exit code $LASTEXITCODE)" }

# Clean up intermediate build artifacts
Remove-Item "launcher\launcher.res" -ErrorAction SilentlyContinue
Remove-Item "launcher\launcher.obj" -ErrorAction SilentlyContinue

Write-Host "Build complete: build\windows\"
Write-Host "  Launcher  : build\windows\RPM Encrypter.exe  (users should run THIS)"
Write-Host "  Flet app  : build\windows\rpm-encrypter.exe  (launched by the wrapper)"
