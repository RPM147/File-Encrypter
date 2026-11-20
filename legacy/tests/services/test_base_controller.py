"""Unit tests for the shared Flet-free BaseController helpers."""

import logging
import queue
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from rpm_encrypter.services.controllers import BaseController
from rpm_encrypter.services.events import LogEvent, ProgressEvent
from rpm_encrypter.services.controllers.activity_controller import ActivityController
from rpm_encrypter.services.controllers.decrypt_controller import DecryptController
from rpm_encrypter.services.controllers.encrypt_controller import EncryptController
from rpm_encrypter.services.controllers.inspect_controller import InspectController
from rpm_encrypter.services.controllers.library_controller import LibraryController
from rpm_encrypter.services.controllers.notes_controller import NotesController
from rpm_encrypter.services.controllers.rekey_controller import RekeyController
from rpm_encrypter.services.controllers.settings_controller import SettingsController


class _FakeActivityLogger:
    def __init__(self):
        self.events = []

    def log_event(self, action, target, result, details=""):
        self.events.append((action, target, result, details))


class _FakeWiper:
    def __init__(self, fail=False):
        self.fail = fail
        self.files = []
        self.folders = []

    def wipe_file(self, path):
        if self.fail:
            raise OSError("simulated wipe failure")
        self.files.append(path)
        Path(path).unlink()

    def wipe_folder(self, path):
        if self.fail:
            raise OSError("simulated wipe failure")
        self.folders.append(path)


def _services(**overrides):
    base = dict(
        msg_queue=queue.Queue(maxsize=10),
        activity_logger=None,
        cancel_requested=False,
        _temp_files_lock=threading.Lock(),
        _active_temp_files=[],
        wiper=_FakeWiper(),
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def test_put_and_log_enqueue_messages():
    services = _services()
    ctrl = BaseController(services)
    ctrl._put(ProgressEvent(done=1, total=2))
    ctrl._log("hello")
    assert services.msg_queue.get_nowait() == ProgressEvent(done=1, total=2)
    assert services.msg_queue.get_nowait() == LogEvent(text="hello")


def test_put_drops_message_when_queue_is_full():
    services = _services(msg_queue=queue.Queue(maxsize=1))
    ctrl = BaseController(services)
    ctrl._put(LogEvent(text="1"))
    ctrl._put(LogEvent(text="2"), timeout=0.01)  # must not raise
    assert services.msg_queue.qsize() == 1


def test_log_activity_only_when_logger_present():
    BaseController(_services())._log_activity("Encrypt", "a.txt", "Success")  # no-op

    activity = _FakeActivityLogger()
    BaseController(_services(activity_logger=activity))._log_activity(
        "Encrypt", "a.txt", "Success", "details"
    )
    assert activity.events == [("Encrypt", "a.txt", "Success", "details")]


def test_spawn_runs_target_on_daemon_thread():
    done = threading.Event()
    seen = []

    def target(value):
        seen.append(value)
        done.set()

    thread = BaseController(_services())._spawn(target, 42)
    assert thread.daemon is True
    assert done.wait(2.0)
    thread.join(2.0)
    assert seen == [42]


def test_cancel_check_reflects_services_flag():
    services = _services()
    ctrl = BaseController(services)
    assert ctrl._cancel_check() is False
    services.cancel_requested = True
    assert ctrl._cancel_check() is True


def test_track_and_wipe_temp_file(tmp_path):
    services = _services()
    ctrl = BaseController(services)
    temp = tmp_path / "temp.bin"
    temp.write_bytes(b"secret")

    ctrl._track_temp(None)
    ctrl._track_temp(temp)
    ctrl._track_temp(temp)
    assert services._active_temp_files == [temp]

    ctrl._wipe_temp_file(temp)
    assert services._active_temp_files == []
    assert services.wiper.files == [temp]
    assert not temp.exists()
    ctrl._wipe_temp_file(None)  # no-op


def test_wipe_temp_file_failure_logs_basename_only_and_unlinks(tmp_path, caplog):
    services = _services(wiper=_FakeWiper(fail=True))
    ctrl = BaseController(services)
    secret_dir = tmp_path / "TOPSECRET_PARENT_DIR"
    secret_dir.mkdir()
    temp = secret_dir / "leftover.tmp"
    temp.write_bytes(b"x")
    ctrl._track_temp(temp)

    with caplog.at_level(logging.WARNING, logger="RPM_GUI"):
        ctrl._wipe_temp_file(temp)

    assert not temp.exists()
    assert services._active_temp_files == []
    assert "leftover.tmp" in caplog.text
    assert "TOPSECRET_PARENT_DIR" not in caplog.text


def test_wipe_temp_dir_uses_wiper_and_falls_back_to_rmtree(tmp_path):
    services = _services()
    ctrl = BaseController(services)
    d = tmp_path / "extract"
    d.mkdir()
    ctrl._wipe_temp_dir(d)
    assert services.wiper.folders == [d]

    ctrl._wipe_temp_dir(None)
    ctrl._wipe_temp_dir(tmp_path / "missing")

    failing = BaseController(_services(wiper=_FakeWiper(fail=True)))
    (d / "f.txt").write_text("x")
    failing._wipe_temp_dir(d)
    assert not d.exists()


@pytest.mark.parametrize(
    "controller_cls",
    [
        ActivityController,
        DecryptController,
        EncryptController,
        InspectController,
        LibraryController,
        NotesController,
        RekeyController,
        SettingsController,
    ],
)
def test_stateful_controllers_inherit_base_controller(controller_cls):
    assert issubclass(controller_cls, BaseController)
