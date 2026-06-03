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
python -m pip install --upgrade "flet-cli==0.85.2"
flet build windows

Write-Host "Flet build complete: build\windows\"
