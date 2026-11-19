"""Shared Flet-free base class for stateful background controllers."""

import logging
import queue
import shutil
import threading
from pathlib import Path
from typing import Optional

from rpm_encrypter.storage.log_hygiene import redact_path

logger = logging.getLogger("RPM_GUI")


class BaseController:
    """Common queue, activity-logging, thread-spawning, and temp-cleanup helpers."""

    def __init__(self, services):
        self.services = services

    def _put(self, msg: dict, timeout: float = 0.1) -> None:
        try:
            self.services.msg_queue.put(msg, timeout=timeout)
        except queue.Full:
            pass

    def _log(self, text: str) -> None:
        self._put({"type": "log", "text": text})

    def _log_activity(self, action: str, target: str, result: str, details: str = "") -> None:
        logger_obj = getattr(self.services, "activity_logger", None)
        if logger_obj:
            logger_obj.log_event(action, target, result, details)

    def _spawn(self, target, *args) -> threading.Thread:
        thread = threading.Thread(target=target, args=args, daemon=True)
        thread.start()
        return thread

    def _cancel_check(self) -> bool:
        return bool(getattr(self.services, "cancel_requested", False))

    def _track_temp(self, temp_path: Optional[Path]) -> None:
        if temp_path is None:
            return
        with self.services._temp_files_lock:
            if temp_path not in self.services._active_temp_files:
                self.services._active_temp_files.append(temp_path)

    def _wipe_temp_file(self, temp_path: Optional[Path]) -> None:
        if temp_path is None:
            return
        with self.services._temp_files_lock:
            try:
                self.services._active_temp_files.remove(temp_path)
            except ValueError:
                pass
        try:
            if temp_path.exists():
                self.services.wiper.wipe_file(temp_path)
        except Exception as exc:
            logger.warning(
                "Failed to securely wipe temp file %s: %s",
                redact_path(temp_path),
                exc,
            )
            try:
                temp_path.unlink(missing_ok=True)
            except Exception:
                pass

    def _wipe_temp_dir(self, temp_dir: Optional[Path]) -> None:
        if temp_dir is None or not temp_dir.exists():
            return
        try:
            self.services.wiper.wipe_folder(temp_dir)
        except Exception:
            shutil.rmtree(temp_dir, ignore_errors=True)
