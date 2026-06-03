"""Stage 6 (Encrypted Notes) tests.

The NotesController is FLET-FREE and exercised headlessly with real crypto note
round-trips using a fast (hermetic) KDF config. Notes are password-only and go
through the backend note wrappers (encrypt_note / decrypt_note); a wrong password
is reported via batch_done (NOT auth_error). Screen/dispatcher behavior is tested
with fake services, no display required.
"""
import json
import queue
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


def _drain(q):
    out = []
    while not q.empty():
        out.append(q.get_nowait())
    return out


# ------------------------------------------------------------------ controller
def test_notes_controller_encrypts_and_decrypts_note_round_trip(fast_services, tmp_path):
    from ui_flet.controllers.notes_controller import NotesController

    vault = tmp_path / "mynote.vault"
    text = "Top secret note line 1\nLine 2 with symbols !@#$ and unicode-free ASCII"
    ctrl = NotesController(fast_services)

    ctrl._encrypt_worker(text, vault, "NotePw1!")
    assert vault.exists()

    ctrl._decrypt_worker(vault, "NotePw1!")
    msgs = _drain(fast_services.msg_queue)

    decrypted = [m for m in msgs if m["type"] == "note_decrypted"]
    assert decrypted and decrypted[0]["text"] == text

    batch_texts = [m.get("text", "") for m in msgs if m["type"] == "batch_done"]
    assert any("Note saved to" in t for t in batch_texts)
    assert any("Note loaded" in t for t in batch_texts)


def test_notes_wrong_password_posts_batch_done_not_auth_error(fast_services, tmp_path):
    from ui_flet.controllers.notes_controller import NotesController

    vault = tmp_path / "n.vault"
    ctrl = NotesController(fast_services)
    ctrl._encrypt_worker("hello world", vault, "RightPw1!")
    _drain(fast_services.msg_queue)

    ctrl._decrypt_worker(vault, "WrongPw1!")
    msgs = _drain(fast_services.msg_queue)

    assert not any(m["type"] == "note_decrypted" for m in msgs)
    assert not any(m["type"] == "auth_error" for m in msgs)
    batch = [m for m in msgs if m["type"] == "batch_done"]
    assert batch and any("Wrong Password" in m.get("text", "") for m in batch)


def test_notes_encrypt_failure_does_not_leave_final_partial(fast_services, tmp_path, monkeypatch):
    from ui_flet.controllers.notes_controller import NotesController

    final = tmp_path / "fail.vault"

    def boom(note_text, p, password, note_title="x", recovery_key=None):
        # Write a partial into the atomic temp, then fail mid-write.
        Path(p).write_bytes(b"partial ciphertext")
        raise RuntimeError("disk full")

    monkeypatch.setattr(fast_services.crypto, "encrypt_note", boom)

    NotesController(fast_services)._encrypt_worker("x", final, "pw")

    assert not final.exists()
    assert list(tmp_path.glob(".rpm_vaulttmp_*.part")) == []
    msgs = _drain(fast_services.msg_queue)
    assert any(
        m["type"] == "batch_done" and "Note save failed" in m.get("text", "") for m in msgs
    )


def test_notes_controller_is_flet_free_and_uses_note_api_only():
    root = Path(__file__).resolve().parents[1]
    src = (root / "ui_flet" / "controllers" / "notes_controller.py").read_text(encoding="utf-8")
    assert "import flet" not in src and "from flet" not in src
    assert "atomic_output(" in src
    assert ".encrypt_note(" in src and ".decrypt_note(" in src
    assert "encrypt_file(" not in src and "decrypt_file(" not in src
    assert "package_" not in src and "extract_archive" not in src


def test_event_dispatcher_routes_note_decrypted():
    from ui_flet.events import EventDispatcher

    captured = []

    class FakeSink:
        def on_note_decrypted(self, text):
            captured.append(text)

    EventDispatcher(FakeSink()).dispatch({"type": "note_decrypted", "text": "hello"})
    assert captured == ["hello"]


# ---------------------------------------------------------------------- screen
class _FakePage:
    def __init__(self):
        self.services = []
        self.overlay = []
        self.update_calls = 0
        self.web = False

    def update(self):
        self.update_calls += 1

    def run_task(self, *args, **kwargs):
        return None


class _FakeShell:
    def __init__(self, page):
        self.page = page
        self.status_text = SimpleNamespace(value="")
        self.busy_control = None

    def set_busy(self, control):
        self.busy_control = control
        control.disabled = True

    def safe_update(self):
        self.page.update()
        return True


def _screen_services():
    return SimpleNamespace(is_processing=False, cancel_requested=False)


def _shell_services():
    return SimpleNamespace(
        shutdown_requested=False,
        cancel_requested=False,
        is_processing=False,
        msg_queue=queue.Queue(),
        stats=SimpleNamespace(snapshot=lambda: {
            "encrypted": 0, "decrypted": 0, "rekeyed": 0, "uptime": "0s"
        }),
    )


def test_notes_file_pickers_are_registered_as_services_not_visual_controls():
    ft = pytest.importorskip("flet")
    from ui_flet.screens.notes_screen import NotesScreen

    page = _FakePage()
    screen = NotesScreen(page, _screen_services(), _FakeShell(page))
    screen.build()
    screen.build()

    assert page.overlay == []
    assert page.services == [screen.save_picker, screen.load_picker]
    assert all(isinstance(item, ft.FilePicker) for item in page.services)


def test_notes_screen_source_does_not_use_overlay():
    root = Path(__file__).resolve().parents[1]
    src = (root / "ui_flet" / "screens" / "notes_screen.py").read_text(encoding="utf-8")
    assert "page.overlay" not in src
    assert ".overlay" not in src


def test_shell_mounts_notes_screen_on_navigate():
    pytest.importorskip("flet")
    from ui_flet.shell import AppShell

    page = _FakePage()
    shell = AppShell(page, _shell_services())
    assert shell.notes_screen is None

    shell.navigate("notes")

    assert shell.notes_screen is not None
    assert page.overlay == []
    assert any(item is shell.notes_screen.save_picker for item in page.services)
    assert any(item is shell.notes_screen.load_picker for item in page.services)


def test_notes_screen_normalizes_save_and_load_paths(tmp_path):
    pytest.importorskip("flet")
    from ui_flet.screens.notes_screen import NotesScreen

    page = _FakePage()
    screen = NotesScreen(page, _screen_services(), _FakeShell(page))

    assert str(screen._normalize_save_path("C:/x/note")).endswith(".vault")
    assert screen._normalize_save_path("C:/x/note.txt") is None  # non-.vault rejected

    vault = tmp_path / "real.vault"
    vault.write_bytes(b"ciphertext")
    assert screen._normalize_load_path(str(vault)) == vault
    assert screen._normalize_load_path(str(tmp_path / "nope.txt")) is None
    assert screen._normalize_load_path(str(tmp_path / "missing.vault")) is None


def test_notes_screen_on_note_decrypted_updates_editor():
    pytest.importorskip("flet")
    from ui_flet.screens.notes_screen import NotesScreen

    page = _FakePage()
    screen = NotesScreen(page, _screen_services(), _FakeShell(page))
    screen.build()
    screen.empty_text.visible = True

    screen.on_note_decrypted("secret")

    assert screen.note_field.value == "secret"
    assert screen.empty_text.visible is False


def test_notes_screen_has_no_dead_search_or_unsafe_copy_controls():
    root = Path(__file__).resolve().parents[1]
    src = (root / "ui_flet" / "screens" / "notes_screen.py").read_text(encoding="utf-8")
    assert "Search notes" not in src
    assert "notes_search" not in src
    assert "set_clipboard" not in src
    assert "Copy" not in src  # no clipboard control in Stage 6 (Stage 11 owns it)
