"""Stage 7 (Re-Key + version history) tests.

The RekeyController is FLET-FREE and exercised headlessly with real crypto
round-trips using a fast (hermetic) KDF config. Re-Key re-seals only the DEK
envelope via crypto.rekey_vault (the payload is never decrypted); version history
is managed entirely through VaultVersionManager. Screen/dispatcher behavior is
tested with fake services, no display required.
"""
import json
import queue
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def fast_services(tmp_path, monkeypatch):
    import app_config, activity_log, vault_scanner, versioning

    cfg = tmp_path / "cfg.json"
    cfg.write_text(json.dumps({"settings": {
        "argon2_memory": 8192,
        "argon2_time": 1,
        "argon2_par": 1,
        "wipe_passes": 1,
    }}), encoding="utf-8")
    monkeypatch.setattr(app_config, "CONFIG_FILE", cfg)
    monkeypatch.setattr(activity_log, "DB_PATH", tmp_path / "activity.db")
    monkeypatch.setattr(vault_scanner, "CACHE_FILE", tmp_path / "lib.json")
    monkeypatch.setattr(versioning, "VERSIONS_ROOT_DEFAULT", tmp_path / "versions", raising=False)
    from ui_flet.services import AppServices

    return AppServices()


def _enable_versioning(services, tmp_path):
    import versioning

    services.versioner = versioning.VaultVersionManager(
        versions_root=tmp_path / "versions",
        enabled=True,
        max_versions_per_vault=5,
        max_total_size_bytes=64 * 1024 * 1024,
    )
    return services.versioner


def _drain(q):
    out = []
    while not q.empty():
        out.append(q.get_nowait())
    return out


def _make_vault(services, path, password="OldPw1!", text="top secret note body"):
    path = Path(path)
    services.crypto.encrypt_note(text, path, password, note_title=path.name)
    return path, text


# ------------------------------------------------------------------ controller
def test_rekey_controller_rekeys_vault_and_saves_version(fast_services, tmp_path):
    from crypto_core import AuthenticationError
    from ui_flet.controllers.rekey_controller import RekeyController

    _enable_versioning(fast_services, tmp_path)
    vault, text = _make_vault(fast_services, tmp_path / "v.vault", "OldPw1!")
    before = fast_services.stats.snapshot()["rekeyed"]

    RekeyController(fast_services)._rekey_worker(vault, "OldPw1!", "NewPw2!")

    assert fast_services.crypto.decrypt_note(vault, "NewPw2!") == text
    with pytest.raises(AuthenticationError):
        fast_services.crypto.decrypt_note(vault, "OldPw1!")
    assert fast_services.stats.snapshot()["rekeyed"] == before + 1

    versions = fast_services.versioner.list_versions(vault)
    assert len(versions) == 1
    assert fast_services.crypto.decrypt_note(versions[0].path, "OldPw1!") == text

    assert not vault.with_suffix(".rekey.tmp").exists()
    msgs = _drain(fast_services.msg_queue)
    assert any(m["type"] == "batch_done" and "Re-key complete" in m.get("text", "") for m in msgs)


def test_rekey_wrong_password_leaves_original_and_removes_tmp(fast_services, tmp_path):
    from crypto_core import AuthenticationError
    from ui_flet.controllers.rekey_controller import RekeyController

    vault, text = _make_vault(fast_services, tmp_path / "v.vault", "RightPw1!")

    RekeyController(fast_services)._rekey_worker(vault, "WrongPw9!", "NewPw2!")

    assert fast_services.crypto.decrypt_note(vault, "RightPw1!") == text
    with pytest.raises(AuthenticationError):
        fast_services.crypto.decrypt_note(vault, "NewPw2!")
    assert not vault.with_suffix(".rekey.tmp").exists()
    msgs = _drain(fast_services.msg_queue)
    assert any(
        m["type"] == "batch_done" and "wrong current password" in m.get("text", "") for m in msgs
    )


def test_rekey_controller_cancel_removes_tmp(fast_services, tmp_path, monkeypatch):
    from crypto_core import OperationCancelledError
    from ui_flet.controllers.rekey_controller import RekeyController

    vault, _text = _make_vault(fast_services, tmp_path / "v.vault", "OldPw1!")

    def fake_rekey(input_path, output_path, old_pw, new_pw, cancel_check=None):
        Path(output_path).write_bytes(b"partial rekey tmp")
        raise OperationCancelledError("cancelled")

    monkeypatch.setattr(fast_services.crypto, "rekey_vault", fake_rekey)

    RekeyController(fast_services)._rekey_worker(vault, "OldPw1!", "NewPw2!")

    assert not vault.with_suffix(".rekey.tmp").exists()
    msgs = _drain(fast_services.msg_queue)
    assert any(m["type"] == "batch_done" and "Cancelled" in m.get("text", "") for m in msgs)


def test_rekey_controller_version_history_actions(fast_services, tmp_path):
    from ui_flet.controllers.rekey_controller import RekeyController

    versioner = _enable_versioning(fast_services, tmp_path)
    vault, _text = _make_vault(fast_services, tmp_path / "v.vault", "Pw1!")
    ctrl = RekeyController(fast_services)

    # Craft two version files with distinct filename timestamps to assert
    # newest-first ordering deterministically (no 1-second sleep needed).
    vdir = versioner._vault_versions_dir(vault)
    vdir.mkdir(parents=True, exist_ok=True)
    older = vdir / "v__2026-06-03T10-00-00.vault"
    newer = vdir / "v__2026-06-03T12-00-00.vault"
    shutil.copy2(vault, older)
    shutil.copy2(vault, newer)

    ctrl._post_versions(vault)
    msgs = _drain(fast_services.msg_queue)
    versions_msg = [m for m in msgs if m["type"] == "rekey_versions"][0]
    assert versions_msg["error"] == ""
    entries = versions_msg["entries"]
    assert len(entries) == 2
    assert entries[0]["name"] == "v__2026-06-03T12-00-00.vault"  # newest first
    assert entries[1]["name"] == "v__2026-06-03T10-00-00.vault"
    assert "display_timestamp" in entries[0] and "display_size" in entries[0]

    newest_payload = entries[0]

    # Restore as Copy must not modify the current vault.
    original_bytes = vault.read_bytes()
    ctrl._restore_copy_worker(newest_payload, vault)
    _drain(fast_services.msg_queue)
    copies = list(vault.parent.glob("v__restored_*.vault"))
    assert copies
    assert vault.read_bytes() == original_bytes

    # Replace Current makes the current vault bytes equal the version bytes.
    vault.write_bytes(b"CHANGED CONTENT - not a real vault")
    ctrl._replace_current_worker(newest_payload, vault)
    _drain(fast_services.msg_queue)
    assert vault.read_bytes() == Path(newest_payload["path"]).read_bytes()

    # Delete Version removes the version file.
    ctrl._delete_version_worker(newest_payload, vault)
    _drain(fast_services.msg_queue)
    assert not Path(newest_payload["path"]).exists()


def test_rekey_controller_is_flet_free_and_rekey_only():
    root = Path(__file__).resolve().parents[1]
    src = (root / "ui_flet" / "controllers" / "rekey_controller.py").read_text(encoding="utf-8")
    assert "import flet" not in src and "from flet" not in src
    assert ".rekey_vault(" in src
    assert "verify_password_and_get_header" not in src
    assert "encrypt_file(" not in src and "decrypt_file(" not in src
    assert "encrypt_stream(" not in src and "decrypt_stream(" not in src
    assert "encrypt_note(" not in src and "decrypt_note(" not in src


def test_event_dispatcher_routes_rekey_events():
    from ui_flet.events import EventDispatcher

    calls = []

    class FakeSink:
        def on_rekey_versions(self, msg):
            calls.append(("versions", msg))

        def on_rekey_password_strength(self, msg):
            calls.append(("strength", msg))

        def on_rekey_version_action(self, msg):
            calls.append(("action", msg))

    dispatcher = EventDispatcher(FakeSink())
    dispatcher.dispatch({"type": "rekey_versions", "entries": []})
    dispatcher.dispatch({"type": "rekey_password_strength", "score": 3})
    dispatcher.dispatch({"type": "rekey_version_action", "text": "ok"})
    assert [c[0] for c in calls] == ["versions", "strength", "action"]


# ---------------------------------------------------------------------- screen
class _FakePage:
    def __init__(self):
        self.services = []
        self.overlay = []
        self.update_calls = 0
        self.web = False
        self.dialogs = []
        self.pop_calls = 0

    def update(self):
        self.update_calls += 1

    def run_task(self, *args, **kwargs):
        return None

    def show_dialog(self, dialog):
        self.dialogs.append(dialog)

    def pop_dialog(self):
        self.pop_calls += 1


class _FakeShell:
    def __init__(self, page):
        self.page = page
        self.status_text = SimpleNamespace(value="")
        self.progress_bar = SimpleNamespace(value=0)
        self.progress_pct = SimpleNamespace(value="0%")
        self.busy_control = None

    def set_busy(self, control):
        self.busy_control = control
        control.disabled = True

    def safe_update(self):
        self.page.update()
        return True


def _screen_services():
    return SimpleNamespace(
        is_processing=False,
        cancel_requested=False,
        versioner=SimpleNamespace(enabled=False),
    )


def _shell_services():
    return SimpleNamespace(
        shutdown_requested=False,
        cancel_requested=False,
        is_processing=False,
        msg_queue=queue.Queue(),
        versioner=SimpleNamespace(enabled=False),
        stats=SimpleNamespace(snapshot=lambda: {
            "encrypted": 0, "decrypted": 0, "rekeyed": 0, "uptime": "0s"
        }),
    )


def test_rekey_file_picker_is_registered_as_service_not_visual_control():
    ft = pytest.importorskip("flet")
    from ui_flet.screens.rekey_screen import RekeyScreen

    page = _FakePage()
    screen = RekeyScreen(page, _screen_services(), _FakeShell(page))
    screen.build()
    screen.build()

    assert page.overlay == []
    assert page.services == [screen.vault_picker]
    assert all(isinstance(item, ft.FilePicker) for item in page.services)


def test_rekey_screen_source_does_not_use_overlay():
    root = Path(__file__).resolve().parents[1]
    src = (root / "ui_flet" / "screens" / "rekey_screen.py").read_text(encoding="utf-8")
    assert "page.overlay" not in src
    assert ".overlay" not in src


def test_shell_mounts_rekey_screen_on_navigate():
    pytest.importorskip("flet")
    from ui_flet.shell import AppShell

    page = _FakePage()
    shell = AppShell(page, _shell_services())
    assert shell.rekey_screen is None

    shell.navigate("rekey")

    assert shell.rekey_screen is not None
    assert page.overlay == []
    assert any(item is shell.rekey_screen.vault_picker for item in page.services)


def test_rekey_screen_validates_inputs(tmp_path):
    pytest.importorskip("flet")
    from ui_flet.screens.rekey_screen import RekeyScreen

    page = _FakePage()
    screen = RekeyScreen(page, _screen_services(), _FakeShell(page))
    vault = tmp_path / "real.vault"
    vault.write_bytes(b"x")

    screen.vault_field.value = ""
    screen._do_rekey()
    assert screen.shell.status_text.value == "Select a vault file"

    screen.vault_field.value = str(tmp_path / "note.txt")
    screen._do_rekey()
    assert screen.shell.status_text.value == "Re-Key requires a .vault file"

    screen.vault_field.value = str(vault)
    screen.current_password_field.value = ""
    screen.new_password_field.value = ""
    screen.confirm_password_field.value = ""
    screen._do_rekey()
    assert screen.shell.status_text.value == "Enter the current password"

    screen.current_password_field.value = "Old1!"
    screen._do_rekey()
    assert screen.shell.status_text.value == "Enter the new password"

    screen.new_password_field.value = "New1!"
    screen.confirm_password_field.value = "Other2!"
    screen._do_rekey()
    assert screen.shell.status_text.value == "New password and confirmation do not match"

    screen.new_password_field.value = "Old1!"
    screen.confirm_password_field.value = "Old1!"
    screen._do_rekey()
    assert screen.shell.status_text.value == "New password is the same as the current one"

    assert screen.services.is_processing is False  # no worker started for invalid input


def test_rekey_screen_renders_and_selects_versions():
    pytest.importorskip("flet")
    from ui_flet.screens.rekey_screen import RekeyScreen

    page = _FakePage()
    screen = RekeyScreen(page, _screen_services(), _FakeShell(page))
    screen.build()

    entries = [
        {"path": "C:/v/a__2.vault", "name": "a__2.vault",
         "display_timestamp": "2026-06-03 12:00:00", "display_size": "1.00 MiB", "size_bytes": 1},
        {"path": "C:/v/a__1.vault", "name": "a__1.vault",
         "display_timestamp": "2026-06-03 10:00:00", "display_size": "1.00 MiB", "size_bytes": 1},
    ]
    screen.on_rekey_versions({"entries": entries, "error": "", "vault": "C:/v/a.vault"})
    assert len(screen.version_list.controls) == 2

    screen._select_version(1)
    assert screen._selected_version_index == 1
    assert screen._selected_entry_payload() == entries[1]


def test_rekey_screen_replace_and_delete_require_confirmation_dialog(tmp_path):
    ft = pytest.importorskip("flet")
    from ui_flet.screens.rekey_screen import RekeyScreen

    page = _FakePage()
    screen = RekeyScreen(page, _screen_services(), _FakeShell(page))
    vault = tmp_path / "real.vault"
    vault.write_bytes(b"x")
    screen.vault_field.value = str(vault)
    screen._version_entries = [{
        "path": str(tmp_path / "ver.vault"), "name": "ver.vault",
        "display_timestamp": "2026-06-03 10:00:00", "display_size": "1.00 MiB", "size_bytes": 1,
    }]
    screen._selected_version_index = 0

    screen._confirm_replace_current()
    assert len(page.dialogs) == 1
    assert isinstance(page.dialogs[0], ft.AlertDialog)
    assert screen.services.is_processing is False  # not executed until the dialog action

    screen._confirm_delete_version()
    assert len(page.dialogs) == 2
    assert isinstance(page.dialogs[1], ft.AlertDialog)
    assert screen.services.is_processing is False


def test_rekey_password_strength_event_updates_label():
    pytest.importorskip("flet")
    from ui_flet.screens.rekey_screen import RekeyScreen

    page = _FakePage()
    screen = RekeyScreen(page, _screen_services(), _FakeShell(page))

    screen.on_rekey_password_strength({"score": 4, "crack_time": "centuries"})
    assert "Strong" in screen.strength_text.value
    assert "centuries" in screen.strength_text.value
