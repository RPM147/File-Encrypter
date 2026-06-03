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
    from ui_flet.screens.encrypt_screen import EncryptScreen

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
    root = Path(__file__).resolve().parents[1]
    src = (root / "ui_flet" / "screens" / "encrypt_screen.py").read_text(
        encoding="utf-8"
    )
    assert "_ensure_overlay" not in src
    assert "page.overlay" not in src
    assert ".overlay" not in src
    assert "page.services" in src or ".services" in src


def test_app_shell_safe_update_stops_on_destroyed_session():
    pytest.importorskip("flet")
    from ui_flet.shell import AppShell

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
    from ui_flet.shell import AppShell

    class BadPage(_FakePage):
        def update(self):
            raise RuntimeError("some other Flet error")

    services = _shell_services()
    shell = AppShell(BadPage(), services)

    with pytest.raises(RuntimeError, match="some other Flet error"):
        shell.safe_update()
    assert services.shutdown_requested is False


def test_clock_loop_uses_safe_update_not_raw_page_update():
    root = Path(__file__).resolve().parents[1]
    app_src = (root / "ui_flet" / "app.py").read_text(encoding="utf-8")
    assert "shell.safe_update()" in app_src
    assert "shell.page.update()" not in app_src
