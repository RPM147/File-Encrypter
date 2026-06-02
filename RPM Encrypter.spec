# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_data_files, collect_all

# tkinterdnd2 ships a native tkdnd Tcl package (data + platform shared libraries)
# that a bare hiddenimport does NOT bundle; collect_all grabs its datas, binaries,
# and submodules so drag-and-drop works in the frozen executable.
tkdnd_datas, tkdnd_binaries, tkdnd_hiddenimports = collect_all('tkinterdnd2')

datas = [('icon.ico', '.')]
datas += collect_data_files('customtkinter')
datas += tkdnd_datas


a = Analysis(
    ['gui_app.py'],
    pathex=[],
    binaries=tkdnd_binaries,
    datas=datas,
    hiddenimports=['tkinterdnd2'] + tkdnd_hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='RPM Encrypter',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['icon.ico'],
)
