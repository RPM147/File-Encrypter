"""Vault Library controller for the Flet UI (Flet-free)."""

import logging
from pathlib import Path
from typing import List

from rpm_encrypter.storage.config import _load_cfg, _mutate_cfg
from .base import BaseController

logger = logging.getLogger("RPM_GUI")


class LibraryController(BaseController):
    """Drives monitored-directory config and VaultScanner library scans."""

    def start_scan(self, directories=None):
        dirs = list(directories) if directories is not None else self.load_dirs()
        self._spawn(self._scan_worker, dirs)

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
