from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def hermetic_home(tmp_path, monkeypatch):
    """Keep AppServices construction off the real home dir."""
    import app_config, activity_log, vault_scanner, versioning
    monkeypatch.setattr(app_config, "CONFIG_FILE", tmp_path / "cfg.json")
    monkeypatch.setattr(activity_log, "DB_PATH", tmp_path / "activity.db")
    monkeypatch.setattr(vault_scanner, "CACHE_FILE", tmp_path / "lib.json")
    monkeypatch.setattr(versioning, "VERSIONS_ROOT_DEFAULT", tmp_path / "versions",
                        raising=False)
    return tmp_path


def test_app_services_builds_all_backend_services(hermetic_home):
    from ui_flet.services import AppServices
    import crypto_core, file_handler, app_state, activity_log, vault_scanner, versioning
    s = AppServices()
    assert isinstance(s.crypto, crypto_core.VaultCrypto)
    assert isinstance(s.packager, file_handler.FolderPackager)
    assert isinstance(s.wiper, file_handler.SecureWiper)
    assert isinstance(s.inspector, file_handler.VaultInspector)
    assert isinstance(s.limiter, app_state.AttemptLimiter)
    assert isinstance(s.stats, app_state.SessionStats)
    assert isinstance(s.activity_logger, activity_log.ActivityLogger)
    assert isinstance(s.scanner, vault_scanner.VaultScanner)
    assert isinstance(s.versioner, versioning.VaultVersionManager)


def test_msg_queue_is_bounded(hermetic_home):
    from ui_flet.services import AppServices
    assert AppServices().msg_queue.maxsize == 1000


class _FakeSink:
    def __init__(self):
        self.calls = []
    def on_log(self, text): self.calls.append(("log", text))
    def on_progress_start(self): self.calls.append(("progress_start",))
    def on_progress(self, done, total): self.calls.append(("progress", done, total))
    def on_error(self, text): self.calls.append(("error", text))
    def on_auth_error(self, rem, lock): self.calls.append(("auth_error", rem, lock))
    def on_batch_done(self, text): self.calls.append(("batch_done", text))


def test_event_dispatcher_routes_every_message_type():
    from ui_flet.events import EventDispatcher
    sink = _FakeSink()
    d = EventDispatcher(sink)
    d.dispatch({"type": "log", "text": "hi"})
    d.dispatch({"type": "progress_start"})
    d.dispatch({"type": "progress", "done": 3, "total": 4})
    d.dispatch({"type": "error", "text": "boom"})
    d.dispatch({"type": "auth_error", "remaining": 2, "lockout": 0})
    d.dispatch({"type": "batch_done", "text": "done"})
    assert sink.calls == [
        ("log", "hi"),
        ("progress_start",),
        ("progress", 3, 4),
        ("error", "boom"),
        ("auth_error", 2, 0),
        ("batch_done", "done"),
    ]


def test_event_dispatcher_ignores_unknown_type():
    from ui_flet.events import EventDispatcher
    sink = _FakeSink()
    EventDispatcher(sink).dispatch({"type": "totally_unknown"})
    assert sink.calls == []


def test_cleanup_orphaned_temp_files_targets_rpm_temp_patterns(hermetic_home, tmp_path, monkeypatch):
    import tempfile as _t
    from ui_flet.services import AppServices
    s = AppServices()
    fake_temp = tmp_path / "t"
    fake_temp.mkdir()
    target = fake_temp / ".rpm_pack_demo.zip"
    target.write_bytes(b"plaintext-ish")
    monkeypatch.setattr(_t, "gettempdir", lambda: str(fake_temp))
    wiped = []
    s.wiper.wipe_file = lambda p: wiped.append(p)
    s.cleanup_orphaned_temp_files()
    assert any(str(target) == str(p) for p in wiped)


def test_stage1_bridge_modules_are_flet_free():
    for rel in ("ui_flet/services.py", "ui_flet/events.py"):
        src = (ROOT / rel).read_text(encoding="utf-8")
        assert "import flet" not in src
        assert "from flet" not in src
