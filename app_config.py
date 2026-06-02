"""Persistent config, settings, and recent-paths helpers for RPM Encrypter.

Phase 26 (ARCH-01) Stage 0: extracted verbatim from gui_app.py so the GUI shell
no longer owns config I/O. gui_app re-imports these names, so existing call
sites and tests are unaffected.
"""
import os
import sys
import json
import tempfile
import logging
from pathlib import Path
from typing import List

logger = logging.getLogger("RPM_GUI")

CONFIG_FILE = Path.home() / ".rpm_encrypter.json"
MAX_RECENT  = 8


def _load_cfg() -> dict:
    try:
        if CONFIG_FILE.exists():
            return json.loads(CONFIG_FILE.read_text("utf-8"))
    except Exception:
        pass
    return {}


def _save_cfg(data: dict) -> None:
    """Atomic config file write to prevent corruption."""
    try:
        fd, tmp_path = tempfile.mkstemp(
            dir=CONFIG_FILE.parent,
            prefix='.rpm_encrypter_tmp_',
            suffix='.json'
        )
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            Path(tmp_path).replace(CONFIG_FILE)
        except:
            Path(tmp_path).unlink(missing_ok=True)
            raise
    except Exception as exc:
        logger.warning("Failed to save config: %s", exc)


def get_recent(key: str) -> List[str]:
    """Return list of recent paths for the given key, filtering out non-existent ones."""
    return [p for p in _load_cfg().get(key, []) if Path(p).exists()]


def push_recent(key: str, path: str) -> None:
    cfg = _load_cfg()
    lst = cfg.get(key, [])
    if path in lst:
        lst.remove(path)
    lst.insert(0, path)
    cfg[key] = lst[:MAX_RECENT]
    _save_cfg(cfg)


def get_setting(key: str, default=None):
    return _load_cfg().get("settings", {}).get(key, default)


def save_setting(key: str, value) -> None:
    cfg = _load_cfg()
    cfg.setdefault("settings", {})[key] = value
    _save_cfg(cfg)


def resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)
