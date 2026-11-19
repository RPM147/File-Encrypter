import json
from pathlib import Path

import pytest


@pytest.fixture
def fast_services(tmp_path, monkeypatch):
    from rpm_encrypter.storage import activity_log, config as app_config, scanner as vault_scanner, versioning

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
    from rpm_encrypter.services.app_services import AppServices

    return AppServices()


def _drain(q):
    out = []
    while not q.empty():
        out.append(q.get_nowait())
    return out


def test_encrypt_controller_round_trips(fast_services, tmp_path):
    from rpm_encrypter.services.controllers.encrypt_controller import EncryptController

    src = tmp_path / "secret.txt"
    src.write_bytes(b"stage 2 payload " * 200)
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    EncryptController(fast_services)._worker(
        [str(src)], "PwStage2!", None, True, False, str(out_dir)
    )
    msgs = _drain(fast_services.msg_queue)
    assert any(m["type"] == "batch_done" and "1/1" in m.get("text", "") for m in msgs)
    vaults = list(out_dir.glob("*.vault"))
    assert len(vaults) == 1

    restored = tmp_path / "restored.bin"
    header = fast_services.crypto.decrypt_file(vaults[0], restored, "PwStage2!")
    assert header.payload.filename == "secret.txt"


def test_encrypt_wrong_password_rejected(fast_services, tmp_path):
    from rpm_encrypter.services.controllers.encrypt_controller import EncryptController
    from rpm_encrypter.core import AuthenticationError

    src = tmp_path / "a.txt"
    src.write_bytes(b"x" * 500)
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    EncryptController(fast_services)._worker(
        [str(src)], "RightPw1!", None, True, False, str(out_dir)
    )
    vault = next(iter(out_dir.glob("*.vault")))
    with pytest.raises(AuthenticationError):
        fast_services.crypto.decrypt_file(vault, tmp_path / "o.bin", "WrongPw9!")


def test_encrypt_output_collision_creates_distinct_vaults(fast_services, tmp_path):
    from rpm_encrypter.services.controllers.encrypt_controller import EncryptController

    src = tmp_path / "dup.txt"
    src.write_bytes(b"y" * 300)
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    ctrl = EncryptController(fast_services)
    ctrl._worker([str(src)], "PwStage2!", None, True, False, str(out_dir))
    ctrl._worker([str(src)], "PwStage2!", None, True, False, str(out_dir))
    names = sorted(p.name for p in out_dir.glob("*.vault"))
    assert names == ["dup.txt.vault", "dup.txt_1.vault"]


def test_encrypt_secure_wipe_removes_original(fast_services, tmp_path):
    from rpm_encrypter.services.controllers.encrypt_controller import EncryptController

    src = tmp_path / "wipeme.txt"
    src.write_bytes(b"z" * 400)
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    EncryptController(fast_services)._worker(
        [str(src)], "PwStage2!", None, True, True, str(out_dir)
    )
    assert not src.exists()
    assert len(list(out_dir.glob("*.vault"))) == 1


def test_encrypt_controller_is_flet_free():
    root = Path(__file__).resolve().parents[2]
    src = (root / "src" / "rpm_encrypter" / "services" / "controllers" / "encrypt_controller.py").read_text(
        encoding="utf-8"
    )
    assert "import flet" not in src
    assert "from flet" not in src


from pathlib import Path
from types import SimpleNamespace

import pytest


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

    def set_busy(self, control):
        control.disabled = True

    def safe_update(self):
        self.page.update()
        return True


def _stats_snapshot():
    return {
        "encrypted": 0,
        "decrypted": 0,
        "rekeyed": 0,
        "uptime": "0s",
    }


def _shell_services():
    return SimpleNamespace(
        shutdown_requested=False,
        cancel_requested=False,
        is_processing=False,
        msg_queue=SimpleNamespace(get_nowait=lambda: None),
        stats=SimpleNamespace(snapshot=_stats_snapshot),
    )


def test_encrypt_file_pickers_are_registered_as_services_not_overlay():
    ft = pytest.importorskip("flet")
    from rpm_encrypter.ui.screens.encrypt_screen import EncryptScreen

    page = _FakePage()
    services = SimpleNamespace(is_processing=False, cancel_requested=False)
    shell = _FakeShell(page)

    screen = EncryptScreen(page, services, shell)
    screen.build()
    screen.build()

    assert page.overlay == []
    assert len(page.services) == 5
    assert all(isinstance(item, ft.FilePicker) for item in page.services)
    assert page.services == [
        screen.file_picker,
        screen.folder_picker,
        screen.output_picker,
        screen.hidden_file_picker,
        screen.hidden_folder_picker,
    ]


def test_encrypt_screen_no_longer_uses_page_overlay_for_file_picker():
    root = Path(__file__).resolve().parents[2]
    src = (root / "src" / "rpm_encrypter" / "ui" / "screens" / "encrypt_screen.py").read_text(
        encoding="utf-8"
    )
    assert "_ensure_overlay" not in src
    assert "page.overlay" not in src
    assert ".overlay" not in src
    assert "register_page_services" in src


def test_app_shell_safe_update_stops_on_destroyed_session():
    pytest.importorskip("flet")
    from rpm_encrypter.ui.shell import AppShell

    class DeadPage(_FakePage):
        def update(self):
            raise RuntimeError("An attempt to fetch destroyed session.")

    services = _shell_services()
    shell = AppShell(DeadPage(), services)

    assert shell.safe_update() is False
    assert services.shutdown_requested is True
    assert services.cancel_requested is True


def test_app_shell_safe_update_reraises_unrelated_runtime_error():
    pytest.importorskip("flet")
    from rpm_encrypter.ui.shell import AppShell

    class BadPage(_FakePage):
        def update(self):
            raise RuntimeError("some other Flet error")

    services = _shell_services()
    shell = AppShell(BadPage(), services)

    with pytest.raises(RuntimeError, match="some other Flet error"):
        shell.safe_update()
    assert services.shutdown_requested is False


def test_clock_loop_uses_safe_update_not_raw_page_update():
    root = Path(__file__).resolve().parents[2]
    app_src = (root / "src" / "rpm_encrypter" / "ui" / "app.py").read_text(encoding="utf-8")
    assert "shell.safe_update()" in app_src
    assert "shell.page.update()" not in app_src
