"""Headless CLI tests (100% Flet-free round trips with fast Argon2 params)."""

import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from rpm_encrypter import cli
from rpm_encrypter.core import VAULT_VERSION, VaultCrypto
from rpm_encrypter.services import APP_NAME, APP_VERSION, shell_integration
from rpm_encrypter.services.app_services import AppServices
from rpm_encrypter.storage import activity_log, config as app_config, scanner, versioning


ROOT = Path(__file__).resolve().parents[2]
PASSWORD = "CliTestPassword!99"
NEW_PASSWORD = "CliRotatedPassword!77"


@pytest.fixture
def fast_services(tmp_path, monkeypatch):
    monkeypatch.setattr(app_config, "CONFIG_FILE", tmp_path / "cfg.json")
    monkeypatch.setattr(activity_log, "DB_PATH", tmp_path / "act.db")
    monkeypatch.setattr(scanner, "CACHE_FILE", tmp_path / "lib.json")
    monkeypatch.setattr(versioning, "VERSIONS_ROOT_DEFAULT", tmp_path / "versions")
    svc = AppServices()
    svc.crypto = VaultCrypto(argon_memory=8192, argon_iterations=1, argon_parallelism=1)
    svc.inspector.crypto = svc.crypto
    return svc


def test_cli_and_routing_modules_are_flet_free_and_no_password_flag():
    for rel in (
        "src/main.py",
        "src/rpm_encrypter/cli.py",
        "src/rpm_encrypter/services/launch.py",
        "src/rpm_encrypter/services/shell_integration.py",
    ):
        txt = (ROOT / rel).read_text(encoding="utf-8")
        assert "import flet" not in txt
        assert "from flet" not in txt

    parser = cli.build_parser()
    assert "--password " not in parser.format_help()
    for action in parser._actions:
        assert "--password" not in action.option_strings


def test_cli_version_returns_zero():
    out = io.StringIO()
    err = io.StringIO()
    rc = cli.main(["--version"], stdout=out, stderr=err)
    assert rc == 0
    assert f"{APP_NAME} {APP_VERSION}" in out.getvalue()
    assert err.getvalue() == ""


def test_cli_encrypt_inspect_rekey_decrypt_and_recovery_round_trip(tmp_path, fast_services):
    src_dir = tmp_path / "payload"
    src_dir.mkdir()
    secret_file = src_dir / "note.txt"
    secret_file.write_bytes(b"hello cli roundtrip!" * 50)

    vault_out = tmp_path / "vaults"
    vault_out.mkdir()
    rec_file = tmp_path / "recovery.txt"

    # Encrypt via --password-stdin and save recovery phrase.
    out, err = io.StringIO(), io.StringIO()
    rc = cli.main(
        [
            "encrypt",
            str(src_dir),
            "-o",
            str(vault_out),
            "--recovery-out",
            str(rec_file),
            "--password-stdin",
        ],
        services=fast_services,
        stdin=io.StringIO(f"{PASSWORD}\n"),
        stdout=out,
        stderr=err,
    )
    assert rc == 0, err.getvalue()
    vault = vault_out / "payload.vault"
    assert vault.is_file()
    phrase = rec_file.read_text(encoding="utf-8").strip()
    assert len(phrase.split()) == 24

    # Integrity-only JSON inspection (no password).
    out = io.StringIO()
    rc = cli.main(
        ["inspect", str(vault), "--integrity-only", "--json"],
        services=fast_services,
        stdout=out,
        stderr=io.StringIO(),
    )
    assert rc == 0
    integrity_json = json.loads(out.getvalue())
    assert integrity_json["ok"] is True
    assert len(integrity_json["sha256"]) == 64

    # Authenticated JSON inspect (header only).
    out = io.StringIO()
    rc = cli.main(
        ["inspect", str(vault), "--password-stdin", "--json"],
        services=fast_services,
        stdin=io.StringIO(f"{PASSWORD}\n"),
        stdout=out,
        stderr=io.StringIO(),
    )
    assert rc == 0
    meta_json = json.loads(out.getvalue())
    assert meta_json["metadata"]["filename"] == "payload"
    assert VAULT_VERSION == 4

    # Wrong password decrypt returns exit code 2.
    bad_out = tmp_path / "bad_out"
    bad_out.mkdir()
    err = io.StringIO()
    rc = cli.main(
        ["decrypt", str(vault), "-o", str(bad_out), "--password-stdin"],
        services=fast_services,
        stdin=io.StringIO("WrongPw!\n"),
        stdout=io.StringIO(),
        stderr=err,
    )
    assert rc == 2
    assert "Authentication failed" in err.getvalue()

    # Recovery phrase decrypt round trip before re-key.
    rec_out = tmp_path / "rec_out"
    rec_out.mkdir()
    rc = cli.main(
        ["decrypt", str(vault), "-o", str(rec_out), "--recovery-stdin"],
        services=fast_services,
        stdin=io.StringIO(f"{phrase}\n"),
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )
    assert rc == 0
    assert (rec_out / "payload" / "note.txt").read_bytes() == secret_file.read_bytes()

    # Re-key vault to NEW_PASSWORD via stdin (2 lines).
    rc = cli.main(
        ["rekey", str(vault), "--password-stdin"],
        services=fast_services,
        stdin=io.StringIO(f"{PASSWORD}\n{NEW_PASSWORD}\n"),
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )
    assert rc == 0

    # Old password fails after re-key; new password succeeds.
    assert (
        cli.main(
            ["decrypt", str(vault), "-o", str(bad_out), "--password-stdin"],
            services=fast_services,
            stdin=io.StringIO(f"{PASSWORD}\n"),
            stdout=io.StringIO(),
            stderr=io.StringIO(),
        )
        == 2
    )
    ok_out = tmp_path / "ok_out"
    ok_out.mkdir()
    assert (
        cli.main(
            ["decrypt", str(vault), "-o", str(ok_out), "--password-stdin"],
            services=fast_services,
            stdin=io.StringIO(f"{NEW_PASSWORD}\n"),
            stdout=io.StringIO(),
            stderr=io.StringIO(),
        )
        == 0
    )
    assert (ok_out / "payload" / "note.txt").read_bytes() == secret_file.read_bytes()


def test_cli_encrypt_wipe_removes_original(tmp_path, fast_services):
    target = tmp_path / "ephemeral.txt"
    target.write_bytes(b"burn after encrypting" * 10)
    out = io.StringIO()
    rc = cli.main(
        ["encrypt", str(target), "--wipe", "--password-stdin"],
        services=fast_services,
        stdin=io.StringIO(f"{PASSWORD}\n"),
        stdout=out,
        stderr=io.StringIO(),
    )
    assert rc == 0
    assert not target.exists()
    assert (tmp_path / "ephemeral.txt.vault").is_file()


def test_cli_shell_integration_subcommands_delegate_cleanly(monkeypatch):
    monkeypatch.setattr(
        shell_integration,
        "get_status",
        lambda: SimpleNamespace(
            supported=True,
            installed=False,
            context_menu_installed=False,
            vault_association_installed=False,
            command_preview="",
        ),
    )
    monkeypatch.setattr(
        shell_integration,
        "install_shell_integration",
        lambda: SimpleNamespace(
            supported=True,
            installed=True,
            context_menu_installed=True,
            vault_association_installed=True,
            command_preview="x",
        ),
    )
    monkeypatch.setattr(
        shell_integration,
        "uninstall_shell_integration",
        lambda: SimpleNamespace(
            supported=True,
            installed=False,
            context_menu_installed=False,
            vault_association_installed=False,
            command_preview="x",
        ),
    )

    out1 = io.StringIO()
    assert cli.main(["shell-integration", "status"], stdout=out1) == 0
    assert "installed=False" in out1.getvalue()

    out2 = io.StringIO()
    assert cli.main(["shell-integration", "install"], stdout=out2) == 0
    assert "installed=True" in out2.getvalue()

    out3 = io.StringIO()
    assert cli.main(["shell-integration", "uninstall"], stdout=out3) == 0
    assert "installed=False" in out3.getvalue()
