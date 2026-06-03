# Build script for RPM Encrypter (Windows / PowerShell).
#
# DEFAULT  ->  Builds the modern Flet (Flutter) desktop app via `flet build windows`.
#              Reads app metadata + bundled dependencies from pyproject.toml
#              ([project] + [tool.flet]). Output: build\windows\
#              Requires: Flutter SDK + Visual Studio "Desktop development with C++".
#              Verify once with `flet doctor` before the first build.
#
# -Legacy  ->  Rebuilds the old CustomTkinter app via PyInstaller from a CLEAN
#              virtual environment using the exact locked versions in
#              requirements.lock, so the fallback artifact stays reproducible.
#              Uses "RPM Encrypter.spec". Output: dist\RPM Encrypter.exe
param([switch]$Legacy)
$ErrorActionPreference = "Stop"

if ($Legacy) {
    # ---- Legacy CustomTkinter build (PyInstaller, reproducible from requirements.lock) ----
    $venv = ".build-venv"
    if (Test-Path $venv) { Remove-Item -Recurse -Force $venv }
    python -m venv $venv

    $py = Join-Path $venv "Scripts\python.exe"
    & $py -m pip install --upgrade pip
    & $py -m pip install -r requirements.lock
    & $py -m pip install pyinstaller==6.20.0 pyinstaller-hooks-contrib==2026.5
    & $py -m PyInstaller "RPM Encrypter.spec" --noconfirm --clean

    Write-Host "Legacy build complete: dist\RPM Encrypter.exe"
    return
}

# ---- Primary Flet (Flutter) desktop build ----
# flet build resolves the Python app + its [project.dependencies] into a native
# Flutter desktop bundle (the desktop client is compiled, so there is NO runtime
# download from GitHub -- the app stays fully offline / local-only).
#
# Force UTF-8 first. flet's rich-based progress UI prints glyphs such as the
# spinner BLACK CIRCLE (U+25CF); on a non-UTF-8 Windows console (e.g. the Turkish
# cp1254 code page) that aborts the build with a UnicodeEncodeError before Flutter
# is ever invoked. UTF-8 mode makes flet's child process emit encodable output.
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

# Pre-flight: Flutter's Windows build creates symlinks for its plugins, which
# requires Windows Developer Mode. Fail early with an actionable message instead
# of a deep Flutter error after several minutes of building.
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

Write-Host "Flet build complete: build\windows\"
