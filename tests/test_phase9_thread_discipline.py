import logging
import threading
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]

try:
    from gui_app import assert_main_thread
except Exception as exc:  # pragma: no cover - depends on local GUI availability
    assert_main_thread = None
    GUI_IMPORT_ERROR = exc
else:
    GUI_IMPORT_ERROR = None


def _require_gui_helper():
    if GUI_IMPORT_ERROR is not None:
        pytest.skip(f"gui_app import unavailable: {GUI_IMPORT_ERROR}")


def _worker_call(fn):
    results = []
    errors = []

    def run():
        try:
            results.append(fn())
        except Exception as exc:
            errors.append(exc)

    thread = threading.Thread(target=run, name="phase9-test-worker")
    thread.start()
    thread.join()
    return results, errors


def _method_slice(source: str, method_name: str) -> str:
    marker = f"    def {method_name}"
    start = source.index(marker)
    next_def = source.find("\n    def ", start + len(marker))
    if next_def == -1:
        return source[start:]
    return source[start:next_def]


def test_assert_main_thread_returns_true_and_logs_nothing_on_main_thread(caplog):
    _require_gui_helper()

    caplog.set_level(logging.WARNING, logger="RPM_GUI")

    assert assert_main_thread("main-thread-test") is True
    assert not [
        record for record in caplog.records
        if record.name == "RPM_GUI" and record.levelno >= logging.WARNING
    ]


def test_assert_main_thread_warns_and_returns_false_off_thread(caplog):
    _require_gui_helper()

    caplog.set_level(logging.WARNING, logger="RPM_GUI")
    results, errors = _worker_call(lambda: assert_main_thread("worker-thread-test"))

    assert errors == []
    assert results == [False]
    assert any(
        record.name == "RPM_GUI"
        and record.levelno == logging.WARNING
        and "worker-thread-test" in record.getMessage()
        and "Off-main-thread UI mutation" in record.getMessage()
        for record in caplog.records
    )


def test_assert_main_thread_can_raise_in_strict_dev_mode(monkeypatch):
    _require_gui_helper()

    monkeypatch.setenv("RPM_STRICT_UI_THREAD", "1")
    results, errors = _worker_call(lambda: assert_main_thread("strict-worker-test"))

    assert results == []
    assert len(errors) == 1
    assert isinstance(errors[0], RuntimeError)
    assert "strict-worker-test" in str(errors[0])


def test_selective_extract_worker_no_longer_mutates_completion_widgets_directly():
    source = (ROOT / "views" / "inspect_view.py").read_text(encoding="utf-8")
    body = _method_slice(source, "_selective_extract_worker")

    assert "self.progress_bar.stop()" not in body
    assert "self.is_processing = False" not in body
    assert "self._set_status(" not in body
    assert '"type": "batch_done"' in body


def test_vault_diff_worker_no_longer_mutates_completion_widgets_directly():
    source = (ROOT / "views" / "inspect_view.py").read_text(encoding="utf-8")
    body = _method_slice(source, "_vault_diff_worker")

    assert "self.progress_bar.stop()" not in body
    assert "self.is_processing = False" not in body
    assert "self._set_status(" not in body
    assert "self.after(0, update_ui)" in body
    assert '"type": "batch_done"' in body
