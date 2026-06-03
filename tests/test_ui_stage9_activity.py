"""Stage 9 (Activity feed + logging toggle) tests.

The ActivityController is FLET-FREE and exercised directly: it normalizes log
rows into ActivityRow objects (preserving newest-first order), toggles and
persists the logging-enabled setting via app_config, and clears the feed through
the backend service only -- it never writes a new log entry. Screen behavior
(initial render, empty state, disabled-state hint, runtime toggle, refresh limit,
confirmation-gated clear, shell mounting, source boundaries) is tested headlessly
with fake page/shell/logger objects -- no display required.
"""
import json
import queue
from pathlib import Path
from types import SimpleNamespace

import pytest

from ui_flet.controllers.activity_controller import ActivityController, ActivityRow


ROOT = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------- fixtures/fakes
@pytest.fixture
def hermetic_cfg(tmp_path, monkeypatch):
    cfg = tmp_path / "config.json"
    import app_config

    monkeypatch.setattr(app_config, "CONFIG_FILE", cfg)
    return cfg


class FakeLogger:
    def __init__(self, rows=None, enabled=False):
        self.rows = rows or []
        self.enabled = enabled
        self.limits = []
        self.clear_count = 0

    def get_logs(self, limit=100):
        self.limits.append(limit)
        return self.rows[:limit]

    def clear_logs(self):
        self.clear_count += 1
        self.rows = []


class FakePage:
    def __init__(self):
        self.services = []
        self.overlay = []
        self.dialogs = []
        self.update_calls = 0

    def update(self):
        self.update_calls += 1

    def show_dialog(self, dialog):
        self.dialogs.append(dialog)

    def pop_dialog(self):
        if self.dialogs:
            self.dialogs.pop()


class FakeShell:
    def __init__(self, page):
        self.page = page
        self.status_text = SimpleNamespace(value="Ready")

    def safe_update(self):
        self.page.update()
        return True


def _services(logger):
    return SimpleNamespace(
        activity_logger=logger,
        shutdown_requested=False,
        cancel_requested=False,
        is_processing=False,
    )


def _shell_services(logger):
    return SimpleNamespace(
        activity_logger=logger,
        shutdown_requested=False,
        cancel_requested=False,
        is_processing=False,
        msg_queue=queue.Queue(),
        stats=SimpleNamespace(snapshot=lambda: {
            "encrypted": 0, "decrypted": 0, "rekeyed": 0, "uptime": "0s"
        }),
    )


def _make_screen(logger, page=None):
    from ui_flet.screens.activity_screen import ActivityScreen

    page = page or FakePage()
    services = _services(logger)
    shell = FakeShell(page)
    return ActivityScreen(page, services, shell), page, shell


def _collect_texts(control):
    """Recursively collect every string .value found in a Flet control tree."""
    out = []
    value = getattr(control, "value", None)
    if isinstance(value, str):
        out.append(value)
    content = getattr(control, "content", None)
    if content is not None:
        out.extend(_collect_texts(content))
    for attr in ("controls", "actions"):
        children = getattr(control, attr, None)
        if children:
            for child in children:
                out.extend(_collect_texts(child))
    title = getattr(control, "title", None)
    if title is not None:
        out.extend(_collect_texts(title))
    return out


SAMPLE_ROWS = [
    {"timestamp": "2026-06-03 10:00:00", "action": "Encrypt",
     "filename": "alpha.txt", "status": "Success", "details": "ok"},
    {"timestamp": "2026-06-03 09:00:00", "action": "Decrypt",
     "filename": "beta.txt", "status": "Failed", "details": None},
]


# ===================================================== 1. controller boundary
def test_controller_source_boundary():
    src = (ROOT / "ui_flet" / "controllers" / "activity_controller.py").read_text(encoding="utf-8")
    assert "import flet" not in src and "from flet" not in src
    assert "tkinter" not in src
    assert "customtkinter" not in src
    assert "import sqlite3" not in src
    assert "views.activity_view" not in src
    assert "activity_view" not in src
    assert "import gui_app" not in src and "from gui_app" not in src
    assert "log_event" not in src


# ===================================================== 2. get_rows normalization
def test_controller_get_rows_normalizes_and_preserves_order():
    logger = FakeLogger(rows=list(SAMPLE_ROWS))
    rows = ActivityController(_services(logger)).get_rows(limit=200)

    assert all(isinstance(r, ActivityRow) for r in rows)
    assert [r.action for r in rows] == ["Encrypt", "Decrypt"]  # order preserved
    assert rows[0].filename == "alpha.txt"
    # None details normalize to "".
    assert rows[1].details == ""
    assert logger.limits == [200]


def test_controller_get_rows_handles_missing_keys_and_no_logger():
    logger = FakeLogger(rows=[{"action": "Inspect"}])
    rows = ActivityController(_services(logger)).get_rows()
    assert rows[0].action == "Inspect"
    assert rows[0].timestamp == "" and rows[0].filename == "" and rows[0].details == ""

    none_services = SimpleNamespace(activity_logger=None)
    assert ActivityController(none_services).get_rows() == []


def test_controller_get_rows_swallows_logger_errors():
    class BoomLogger:
        enabled = True

        def get_logs(self, limit=100):
            raise RuntimeError("db locked")

    assert ActivityController(_services(BoomLogger())).get_rows() == []


# ===================================================== 3. clear_logs
def test_controller_clear_logs_calls_once():
    logger = FakeLogger(rows=list(SAMPLE_ROWS))
    ctrl = ActivityController(_services(logger))
    ctrl.clear_logs()
    assert logger.clear_count == 1


# ===================================================== 4. logging toggle persistence
def test_controller_toggle_persists_setting(hermetic_cfg):
    logger = FakeLogger(enabled=False)
    ctrl = ActivityController(_services(logger))

    assert ctrl.set_logging_enabled(True) is True
    assert logger.enabled is True
    saved = json.loads(hermetic_cfg.read_text(encoding="utf-8"))
    assert saved["settings"]["logging_enabled"] is True

    assert ctrl.set_logging_enabled(False) is False
    assert logger.enabled is False
    saved = json.loads(hermetic_cfg.read_text(encoding="utf-8"))
    assert saved["settings"]["logging_enabled"] is False


# ===================================================== 5. initial render
def test_screen_initial_render_shows_rows_and_checkbox_state():
    pytest.importorskip("flet")
    logger = FakeLogger(rows=list(SAMPLE_ROWS), enabled=True)
    screen, _page, _shell = _make_screen(logger)

    root = screen.build()
    texts = _collect_texts(root)

    assert "Activity" in texts
    assert any("alpha.txt" in t for t in texts)
    assert any("Encrypt" in t for t in texts)
    assert screen.logging_checkbox.value is True


# ===================================================== 6. empty state
def test_screen_empty_state():
    pytest.importorskip("flet")
    logger = FakeLogger(rows=[], enabled=True)
    screen, _page, _shell = _make_screen(logger)
    screen.build()

    texts = _collect_texts(screen.rows_list)
    assert "No activity recorded yet." in texts


# ===================================================== 7. disabled-state hint
def test_screen_disabled_state_hint_visible_when_logging_off():
    pytest.importorskip("flet")
    logger = FakeLogger(rows=[], enabled=False)
    screen, _page, _shell = _make_screen(logger)
    screen.build()

    assert screen.disabled_hint.visible is True
    assert "will not be recorded" in screen.disabled_hint.value


def test_screen_disabled_hint_hidden_when_logging_on():
    pytest.importorskip("flet")
    logger = FakeLogger(rows=[], enabled=True)
    screen, _page, _shell = _make_screen(logger)
    screen.build()

    assert screen.disabled_hint.visible is False


# ===================================================== 8. toggle runtime + status
def test_screen_toggle_updates_runtime_and_status(hermetic_cfg):
    pytest.importorskip("flet")
    logger = FakeLogger(rows=[], enabled=False)
    screen, _page, shell = _make_screen(logger)
    screen.build()

    screen.logging_checkbox.value = True
    screen._toggle_logging()
    assert logger.enabled is True
    assert shell.status_text.value == "Activity logging enabled"
    assert screen.disabled_hint.visible is False

    screen.logging_checkbox.value = False
    screen._toggle_logging()
    assert logger.enabled is False
    assert shell.status_text.value == "Activity logging disabled"
    assert screen.disabled_hint.visible is True


# ===================================================== 9. refresh uses limit 200
def test_screen_refresh_requests_200_and_reports_count():
    pytest.importorskip("flet")
    logger = FakeLogger(rows=list(SAMPLE_ROWS), enabled=True)
    screen, _page, shell = _make_screen(logger)
    screen.build()
    logger.limits.clear()

    screen._refresh()
    assert logger.limits == [200]
    assert shell.status_text.value == "Activity refreshed (2 rows)"


# ===================================================== 10. clear confirmation
def test_screen_clear_requires_confirmation():
    pytest.importorskip("flet")
    logger = FakeLogger(rows=list(SAMPLE_ROWS), enabled=True)
    screen, page, shell = _make_screen(logger)
    screen.build()

    # Opening the dialog must NOT clear logs.
    screen._confirm_clear()
    assert len(page.dialogs) == 1
    assert logger.clear_count == 0

    # Confirming clears, closes the dialog, renders empty, sets status.
    screen._clear_activity_confirmed()
    assert logger.clear_count == 1
    assert page.dialogs == []
    assert _collect_texts(screen.rows_list) == ["No activity recorded yet."]
    assert shell.status_text.value == "Activity log cleared"


def test_screen_clear_cancel_closes_dialog_only():
    pytest.importorskip("flet")
    logger = FakeLogger(rows=list(SAMPLE_ROWS), enabled=True)
    screen, page, _shell = _make_screen(logger)
    screen.build()

    screen._confirm_clear()
    screen._cancel_clear()
    assert page.dialogs == []
    assert logger.clear_count == 0


# ===================================================== 11. shell mounting
def test_shell_mounts_activity_screen_and_reuses_instance():
    pytest.importorskip("flet")
    from ui_flet.shell import AppShell

    page = FakePage()
    shell = AppShell(page, _shell_services(FakeLogger(rows=list(SAMPLE_ROWS), enabled=False)))
    assert shell.activity_screen is None

    control = shell._placeholder("activity")
    assert control is not None
    first = shell.activity_screen
    assert first is not None

    shell._placeholder("activity")
    assert shell.activity_screen is first  # reused


# ===================================================== 12. source scan (screen)
def test_screen_source_avoids_old_ui_and_overlay():
    src = (ROOT / "ui_flet" / "screens" / "activity_screen.py").read_text(encoding="utf-8")
    assert "messagebox" not in src
    assert "tkinter" not in src
    assert "customtkinter" not in src
    assert "views.activity_view" not in src
    assert "page.overlay" not in src
    assert ".overlay" not in src


# ===================================================== 13. backend untouched
def test_backend_activity_log_api_intact():
    src = (ROOT / "activity_log.py").read_text(encoding="utf-8")
    assert "def get_logs" in src
    assert "def clear_logs" in src
    # The backend log store must not have been folded into the Flet view layer.
    assert "import flet" not in src and "from flet" not in src
