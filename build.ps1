# Reproducible local build for RPM Encrypter (Windows / PowerShell).
# Builds dist\RPM Encrypter.exe from a CLEAN virtual environment using the exact
# locked dependency versions, so the release artifact is predictable.
$ErrorActionPreference = "Stop"

$venv = ".build-venv"
if (Test-Path $venv) { Remove-Item -Recurse -Force $venv }
python -m venv $venv

$py = Join-Path $venv "Scripts\python.exe"
& $py -m pip install --upgrade pip
& $py -m pip install -r requirements.lock
& $py -m pip install pyinstaller==6.20.0 pyinstaller-hooks-contrib==2026.5
& $py -m PyInstaller "RPM Encrypter.spec" --noconfirm --clean

Write-Host "Build complete: dist\RPM Encrypter.exe"
