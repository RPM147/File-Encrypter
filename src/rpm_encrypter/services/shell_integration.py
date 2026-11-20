"""User-scoped Windows Explorer context menu and .vault file association helpers.

All writes stay strictly under HKCU\\Software\\Classes (no Administrator rights
needed) and go through a pluggable registry backend so unit tests never touch
the host Windows registry.
"""

import ctypes
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

VAULT_PROG_ID = "RPMEncrypter.Vault"
VAULT_EXT_KEY = r"Software\Classes\.vault"
PROG_ID_KEY = r"Software\Classes\RPMEncrypter.Vault"
FILE_MENU_KEY = r"Software\Classes\*\shell\RPMEncrypter.Encrypt"
DIR_MENU_KEY = r"Software\Classes\Directory\shell\RPMEncrypter.Encrypt"

_SHCNE_ASSOCCHANGED = 0x08000000
_SHCNF_IDLIST = 0x0000


class ShellIntegrationError(RuntimeError):
    """Raised when shell integration cannot be queried or modified."""


@dataclass(frozen=True)
class ShellIntegrationStatus:
    """Snapshot of Windows shell integration registration state."""

    supported: bool
    installed: bool
    context_menu_installed: bool
    vault_association_installed: bool
    command_preview: str


class RegistryBackend(Protocol):
    """Minimal registry operations needed for user-scoped shell registration."""

    def get_value(self, subkey: str, name: str = "") -> str | None: ...

    def set_value(self, subkey: str, name: str, value: str) -> None: ...

    def delete_tree(self, subkey: str) -> None: ...

    def notify_shell(self) -> None: ...


class _WinRegBackend:
    """HKCU-only registry backend using Python's stdlib winreg."""

    def get_value(self, subkey: str, name: str = "") -> str | None:
        import winreg

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey, 0, winreg.KEY_READ) as key:
                value, _ = winreg.QueryValueEx(key, name)
                return str(value) if value is not None else None
        except FileNotFoundError:
            return None

    def set_value(self, subkey: str, name: str, value: str) -> None:
        import winreg

        with winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER, subkey, 0, winreg.KEY_WRITE
        ) as key:
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)

    def delete_tree(self, subkey: str) -> None:
        import winreg

        def _delete_rec(cur: str) -> None:
            try:
                with winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    cur,
                    0,
                    winreg.KEY_READ | winreg.KEY_WRITE,
                ) as key:
                    children: list[str] = []
                    idx = 0
                    while True:
                        try:
                            children.append(winreg.EnumKey(key, idx))
                            idx += 1
                        except OSError:
                            break
                for child in children:
                    _delete_rec(f"{cur}\\{child}")
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, cur)
            except FileNotFoundError:
                return

        _delete_rec(subkey)

    def notify_shell(self) -> None:
        try:
            ctypes.windll.shell32.SHChangeNotify(
                _SHCNE_ASSOCCHANGED, _SHCNF_IDLIST, None, None
            )
        except Exception:
            pass


def is_supported() -> bool:
    """Return True when running on Windows."""
    return sys.platform == "win32"


def resolve_launch_command() -> tuple[str, str | None]:
    """Return (quoted command prefix, optional icon path) for Explorer invocations."""
    if getattr(sys, "frozen", False):
        exe = Path(sys.executable).resolve()
        launcher = exe.with_name("RPM Encrypter.exe")
        target = launcher if launcher.is_file() else exe
        return f'"{target}"', str(target)

    main_py = Path(__file__).resolve().parents[2] / "main.py"
    py_exe = Path(sys.executable)
    if sys.platform == "win32":
        pyw = py_exe.with_name("pythonw.exe")
        if pyw.is_file():
            py_exe = pyw
    ico = Path(__file__).resolve().parents[3] / "launcher" / "icon.ico"
    icon_path = str(ico) if ico.is_file() else None
    return f'"{py_exe}" "{main_py}"', icon_path


def _resolve_backend(backend: RegistryBackend | None) -> RegistryBackend:
    if backend is not None:
        return backend
    if not is_supported():
        raise ShellIntegrationError(
            "Windows shell integration is only supported on Windows."
        )
    return _WinRegBackend()


def get_status(backend: RegistryBackend | None = None) -> ShellIntegrationStatus:
    """Inspect whether context menu and .vault association are installed."""
    if backend is None and not is_supported():
        return ShellIntegrationStatus(
            supported=False,
            installed=False,
            context_menu_installed=False,
            vault_association_installed=False,
            command_preview="",
        )

    reg = backend if backend is not None else _WinRegBackend()
    ext_prog = reg.get_value(VAULT_EXT_KEY, "")
    open_cmd = reg.get_value(f"{PROG_ID_KEY}\\shell\\open\\command", "")
    file_cmd = reg.get_value(f"{FILE_MENU_KEY}\\command", "")
    dir_cmd = reg.get_value(f"{DIR_MENU_KEY}\\command", "")

    vault_assoc = ext_prog == VAULT_PROG_ID and bool(open_cmd)
    ctx_menu = bool(file_cmd) and bool(dir_cmd)
    cmd_preview = file_cmd or open_cmd or resolve_launch_command()[0]
    return ShellIntegrationStatus(
        supported=True,
        installed=vault_assoc and ctx_menu,
        context_menu_installed=ctx_menu,
        vault_association_installed=vault_assoc,
        command_preview=cmd_preview,
    )


def install_shell_integration(
    backend: RegistryBackend | None = None,
    command_prefix: str | None = None,
    icon_path: str | None = None,
) -> ShellIntegrationStatus:
    """Register HKCU context menu ('Encrypt with RPM Encrypter') and .vault association."""
    reg = _resolve_backend(backend)
    default_cmd, default_icon = resolve_launch_command()
    cmd_prefix = command_prefix if command_prefix is not None else default_cmd
    icon = icon_path if icon_path is not None else default_icon

    reg.set_value(VAULT_EXT_KEY, "", VAULT_PROG_ID)
    reg.set_value(PROG_ID_KEY, "", "RPM Encrypter Vault")
    if icon:
        reg.set_value(f"{PROG_ID_KEY}\\DefaultIcon", "", f'"{icon}",0')
    reg.set_value(f"{PROG_ID_KEY}\\shell\\open", "", "Decrypt with RPM Encrypter")
    reg.set_value(
        f"{PROG_ID_KEY}\\shell\\open\\command", "", f'{cmd_prefix} --gui-decrypt "%1"'
    )

    for menu_key in (FILE_MENU_KEY, DIR_MENU_KEY):
        reg.set_value(menu_key, "", "Encrypt with RPM Encrypter")
        if icon:
            reg.set_value(menu_key, "Icon", icon)
        reg.set_value(f"{menu_key}\\command", "", f'{cmd_prefix} --gui-encrypt "%1"')

    reg.notify_shell()
    return get_status(backend=reg)


def uninstall_shell_integration(
    backend: RegistryBackend | None = None,
) -> ShellIntegrationStatus:
    """Remove HKCU shell integration keys created by RPM Encrypter."""
    reg = _resolve_backend(backend)
    if reg.get_value(VAULT_EXT_KEY, "") == VAULT_PROG_ID:
        reg.delete_tree(VAULT_EXT_KEY)
    reg.delete_tree(PROG_ID_KEY)
    reg.delete_tree(FILE_MENU_KEY)
    reg.delete_tree(DIR_MENU_KEY)
    reg.notify_shell()
    return get_status(backend=reg)


__all__ = [
    "DIR_MENU_KEY",
    "FILE_MENU_KEY",
    "PROG_ID_KEY",
    "RegistryBackend",
    "ShellIntegrationError",
    "ShellIntegrationStatus",
    "VAULT_EXT_KEY",
    "VAULT_PROG_ID",
    "get_status",
    "install_shell_integration",
    "is_supported",
    "resolve_launch_command",
    "uninstall_shell_integration",
]
