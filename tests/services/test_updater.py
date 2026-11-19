import io
import json
import time

from rpm_encrypter.services import updater
from rpm_encrypter.services.app_services import AppServices
from rpm_encrypter.storage import activity_log, config as app_config, scanner, versioning


class _FakeHTTPResponse:
    def __init__(self, status: int, payload: dict):
        self.status = status
        self._buf = io.BytesIO(json.dumps(payload).encode("utf-8"))

    def read(self):
        return self._buf.read()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_check_for_update_detects_newer_release_and_strips_v_prefix(monkeypatch):
    def fake_urlopen(req, timeout=5):
        return _FakeHTTPResponse(
            200,
            {
                "tag_name": "v3.1.0",
                "html_url": "https://github.com/RPM147/File-Encrypter/releases/tag/v3.1.0",
                "body": "Bug fixes",
            },
        )

    monkeypatch.setattr(updater.urllib.request, "urlopen", fake_urlopen)
    info = updater.check_for_update("3.0.0")
    assert info is not None
    assert info["version"] == "3.1.0"
    assert info["url"].endswith("v3.1.0")


def test_check_for_update_returns_none_when_up_to_date(monkeypatch):
    def fake_urlopen(req, timeout=5):
        return _FakeHTTPResponse(200, {"tag_name": "v3.0.0"})

    monkeypatch.setattr(updater.urllib.request, "urlopen", fake_urlopen)
    assert updater.check_for_update("3.0.0") is None


def test_start_update_check_is_noop_when_disabled(tmp_path, monkeypatch):
    monkeypatch.setattr(app_config, "CONFIG_FILE", tmp_path / "cfg.json")
    monkeypatch.setattr(activity_log, "DB_PATH", tmp_path / "act.db")
    monkeypatch.setattr(scanner, "CACHE_FILE", tmp_path / "lib.json")
    monkeypatch.setattr(versioning, "VERSIONS_ROOT_DEFAULT", tmp_path / "versions")

    called = []
    monkeypatch.setattr(updater, "check_for_update", lambda v: called.append(v))

    services = AppServices()
    assert services.start_update_check("3.0.0") is False
    assert called == []


def test_start_update_check_posts_queue_event_when_enabled(tmp_path, monkeypatch):
    monkeypatch.setattr(app_config, "CONFIG_FILE", tmp_path / "cfg.json")
    monkeypatch.setattr(activity_log, "DB_PATH", tmp_path / "act.db")
    monkeypatch.setattr(scanner, "CACHE_FILE", tmp_path / "lib.json")
    monkeypatch.setattr(versioning, "VERSIONS_ROOT_DEFAULT", tmp_path / "versions")

    app_config.save_setting("check_updates", True)
    monkeypatch.setattr(
        updater,
        "check_for_update",
        lambda v: {"version": "3.2.0", "url": "https://example.invalid/v3.2.0", "changelog": ""},
    )

    services = AppServices()
    assert services.start_update_check("3.0.0") is True

    deadline = time.monotonic() + 2.0
    msg = None
    while time.monotonic() < deadline:
        if not services.msg_queue.empty():
            msg = services.msg_queue.get_nowait()
            break
        time.sleep(0.02)

    assert msg == {
        "type": "update_available",
        "info": {"version": "3.2.0", "url": "https://example.invalid/v3.2.0", "changelog": ""},
    }
