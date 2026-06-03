"""Vault Library controller for the Flet UI.

This module intentionally imports no Flet symbols. It manages the monitored-
directory config and drives unauthenticated VaultScanner library scans on a
worker thread, reporting results through the Stage-1 message queue protocol.

The Library is deliberately NON-sensitive: it never asks for a password, never
decrypts, and never unlocks authenticated metadata. It only runs directory scans
via services.scanner.scan_directories, which returns the limited, spoofable
header fields (filename on disk, bucketed container_size, locked placeholders).
"""
import logging
import queue
import threading
from pathlib import Path
from typing import List

from app_config import _load_cfg, _mutate_cfg
from log_hygiene import redact_path

logger = logging.getLogger("RPM_GUI")


class LibraryController:
    """Drives monitored-directory config and VaultScanner library scans.
    FLET-FREE -> unit-testable without a display."""

    def __init__(self, services):
        self.services = services

    def start_scan(self, directories=None):
        dirs = list(directories) if directories is not None else self.load_dirs()
        threading.Thread(target=self._scan_worker, args=(dirs,), daemon=True).start()

    def _put(self, msg, timeout=0.1):
        try:
            self.services.msg_queue.put(msg, timeout=timeout)
        except queue.Full:
            pass

    def _log_activity(self, action, target, result, details=""):
        logger_obj = getattr(self.services, "activity_logger", None)
        if logger_obj:
            logger_obj.log_event(action, target, result, details)

    # ----------------------------------------------------- monitored-dir config
    @staticmethod
    def _clean_path(path) -> str:
        return str(path or "").strip().strip('"')

    @classmethod
    def _resolved_path(cls, path) -> str:
        raw = cls._clean_path(path)
        if not raw:
            return ""
        try:
            return str(Path(raw).expanduser().resolve())
        except (OSError, RuntimeError):
            return str(Path(raw).expanduser().absolute())

    @classmethod
    def _path_key(cls, path) -> str:
        resolved = cls._resolved_path(path)
        return resolved.replace("\\", "/").casefold()

    @staticmethod
    def load_dirs() -> List[str]:
        dirs = _load_cfg().get("library_dirs", [])
        return [str(d) for d in dirs if str(d).strip()]

    @classmethod
    def add_dir(cls, path) -> bool:
        value = cls._resolved_path(path)
        if not value:
            return False
        value_key = cls._path_key(value)
        added = False

        def _add(cfg):
            nonlocal added
            dirs = [str(d) for d in cfg.get("library_dirs", []) if str(d).strip()]
            existing_keys = {cls._path_key(d) for d in dirs}
            if value_key not in existing_keys:
                dirs.append(value)
                cfg["library_dirs"] = dirs
                added = True

        _mutate_cfg(_add)
        return added

    @classmethod
    def remove_dir(cls, path) -> bool:
        value_key = cls._path_key(path)
        if not value_key:
            return False
        removed = False

        def _remove(cfg):
            nonlocal removed
            dirs = [str(d) for d in cfg.get("library_dirs", []) if str(d).strip()]
            new_dirs = [d for d in dirs if cls._path_key(d) != value_key]
            removed = len(new_dirs) != len(dirs)
            cfg["library_dirs"] = new_dirs

        _mutate_cfg(_remove)
        return removed

    # ----------------------------------------------------------------- scanning
    def _scan_worker(self, dirs):
        dirs = [str(Path(d).resolve()) for d in dirs if str(d).strip()]
        try:
            results = self.services.scanner.scan_directories(dirs)
            self._log_activity(
                "Library Scan",
                f"{len(dirs)} directories",
                "Success",
                f"Found {len(results)} vaults",
            )
            self._put({"type": "library_results", "data": results, "error": ""}, timeout=1.0)
        except Exception as exc:
            logger.exception("Library scan failed")
            self._log_activity("Library Scan", f"{len(dirs)} directories", "Failed", str(exc))
            self._put(
                {"type": "library_results", "data": [], "error": f"Scan failed: {exc}"},
                timeout=1.0,
            )
