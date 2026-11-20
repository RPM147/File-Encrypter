"""Unit tests for launch routing and Windows HKCU shell integration (memory-backed)."""

import sys
from pathlib import Path

import pytest

from rpm_encrypter.services.launch import LaunchRequest, parse_launch_argv
from rpm_encrypter.services import shell_integration
from rpm_encrypter.services.shell_integration import (
    DIR_MENU_KEY,
    FILE_MENU_KEY,
    PROG_ID_KEY,
    VAULT_EXT_KEY,
    VAULT_PROG_ID,
    ShellIntegrationError,
    get_status,
    install_shell_integration,
    uninstall_shell_integration,
)


class _MemoryRegistryBackend:
    """In-memory fake HKCU registry so tests never touch the host registry."""

    def __init__(self):
        self.keys: dict[str, dict[str, str]] = {}
        self.notifications = 0

    def get_value(self, subkey: str, name: str = "") -> str | None:
        return self.keys.get(subkey, {}).get(name)

    def set_value(self, subkey: str, name: str, value: str) -> None:
        self.keys.setdefault(subkey, {})[name] = value

    def delete_tree(self, subkey: str) -> None:
        prefix = f"{subkey}\\"
        for k in [key for key in self.keys if key == subkey or key.startswith(prefix)]:
            del self.keys[k]

    def notify_shell(self) -> None:
        self.notifications += 1


# --- launch argv routing --------------------------------------------------

def test_parse_launch_argv_covers_gui_bare_paths_and_cli_routes():
    assert parse_launch_argv([]) == LaunchRequest(mode="gui")
    assert parse_launch_argv(["--gui-encrypt", "a.txt", "dir"]) == LaunchRequest(
        mode="gui", tab="encrypt", paths=("a.txt", "dir")
    )
    assert parse_launch_argv(["--gui-decrypt", "secret.vault"]) == LaunchRequest(
        mode="gui", tab="decrypt", paths=("secret.vault",)
    )
    # Bare paths: all .vault -> decrypt; anything else -> encrypt.
    assert parse_launch_argv(["a.VAULT", "b.vault"]) == LaunchRequest(
        mode="gui", tab="decrypt", paths=("a.VAULT", "b.vault")
    )
    assert parse_launch_argv(["doc.txt", "a.vault"]) == LaunchRequest(
        mode="gui", tab="encrypt", paths=("doc.txt", "a.vault")
    )
    # CLI subcommands & flags.
    for cmd in (
        ["encrypt", "a.txt"],
        ["decrypt", "a.vault"],
        ["inspect", "a.vault"],
        ["rekey", "a.vault"],
        ["shell-integration", "status"],
        ["--help"],
        ["-h"],
        ["--version"],
        ["--unknown-flag"],
    ):
        req = parse_launch_argv(cmd)
        assert req.mode == "cli"
        assert req.cli_argv == tuple(cmd)


# --- shell integration (in-memory registry) -------------------------------

def test_shell_integration_install_status_and_uninstall():
    reg = _MemoryRegistryBackend()

    initial = get_status(backend=reg)
    assert initial.supported is True
    assert initial.installed is False

    installed = install_shell_integration(
        backend=reg,
        command_prefix='"C:\\Apps\\RPM Encrypter.exe"',
        icon_path="C:\\Apps\\RPM Encrypter.exe",
    )
    assert installed.installed is True
    assert installed.context_menu_installed is True
    assert installed.vault_association_installed is True
    assert reg.notifications == 1

    assert reg.get_value(VAULT_EXT_KEY, "") == VAULT_PROG_ID
    assert (
        reg.get_value(f"{PROG_ID_KEY}\\shell\\open\\command", "")
        == '"C:\\Apps\\RPM Encrypter.exe" --gui-decrypt "%1"'
    )
    assert (
        reg.get_value(f"{FILE_MENU_KEY}\\command", "")
        == '"C:\\Apps\\RPM Encrypter.exe" --gui-encrypt "%1"'
    )
    assert (
        reg.get_value(f"{DIR_MENU_KEY}\\command", "")
        == '"C:\\Apps\\RPM Encrypter.exe" --gui-encrypt "%1"'
    )
    assert reg.get_value(FILE_MENU_KEY, "Icon") == "C:\\Apps\\RPM Encrypter.exe"

    after_remove = uninstall_shell_integration(backend=reg)
    assert after_remove.installed is False
    assert after_remove.context_menu_installed is False
    assert after_remove.vault_association_installed is False
    assert reg.keys == {}
    assert reg.notifications == 2


def test_uninstall_preserves_foreign_vault_association():
    reg = _MemoryRegistryBackend()
    install_shell_integration(backend=reg, command_prefix='"C:\\rpm.exe"', icon_path="")
    reg.set_value(VAULT_EXT_KEY, "", "OtherApp.Vault")

    uninstall_shell_integration(backend=reg)
    assert reg.get_value(VAULT_EXT_KEY, "") == "OtherApp.Vault"
    assert PROG_ID_KEY not in reg.keys
    assert FILE_MENU_KEY not in reg.keys
    assert DIR_MENU_KEY not in reg.keys


def test_shell_integration_unsupported_platform_guards(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    st = get_status()
    assert st.supported is False
    assert st.installed is False

    with pytest.raises(ShellIntegrationError):
        install_shell_integration()
    with pytest.raises(ShellIntegrationError):
        uninstall_shell_integration()


def test_resolve_launch_command_frozen_prefers_launcher_wrapper(tmp_path, monkeypatch):
    fake_real = tmp_path / "rpm-encrypter.exe"
    fake_wrapper = tmp_path / "RPM Encrypter.exe"
    fake_real.write_bytes(b"")
    fake_wrapper.write_bytes(b"")

    monkeypatch.setattr(shell_integration.sys, "frozen", True, raising=False)
    monkeypatch.setattr(shell_integration.sys, "executable", str(fake_real))
    cmd, icon = shell_integration.resolve_launch_command()
    assert cmd == f'"{fake_wrapper}"'
    assert Path(icon) == fake_wrapper
