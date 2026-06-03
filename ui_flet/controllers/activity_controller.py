"""Activity feed controller for the Flet UI (Stage 9).

Reads the local activity log, manages the logging-enabled setting, and clears
the feed. It intentionally imports no Flet symbols so it is unit-testable
without a display, and it never writes new log entries: viewing, refreshing,
toggling, and clearing must not create activity of their own.

The persisted log itself is owned by the frozen backend service
(services.activity_logger, an activity_log.ActivityLogger). This controller only
talks to that service object and to app_config for the persisted setting.
"""
from dataclasses import dataclass
from typing import Any

import app_config


@dataclass(frozen=True)
class ActivityRow:
    timestamp: str
    action: str
    filename: str
    status: str
    details: str = ""


class ActivityController:
    """Reads and manages the local activity feed.
    FLET-FREE -> unit-testable without a display."""

    def __init__(self, services):
        self.services = services

    def is_logging_enabled(self) -> bool:
        logger = getattr(self.services, "activity_logger", None)
        if logger is not None and hasattr(logger, "enabled"):
            return bool(logger.enabled)
        return bool(app_config.get_setting("logging_enabled", False))

    def set_logging_enabled(self, enabled: bool) -> bool:
        enabled = bool(enabled)
        app_config.save_setting("logging_enabled", enabled)
        logger = getattr(self.services, "activity_logger", None)
        if logger is not None and hasattr(logger, "enabled"):
            logger.enabled = enabled
        return enabled

    def get_rows(self, limit: int = 200) -> list[ActivityRow]:
        limit = int(limit)
        if limit <= 0:
            limit = 200
        logger = getattr(self.services, "activity_logger", None)
        if logger is None:
            return []
        try:
            raw_rows = logger.get_logs(limit=limit)
        except Exception:
            return []
        rows: list[ActivityRow] = []
        for raw in raw_rows or []:
            rows.append(ActivityRow(
                timestamp=str(raw.get("timestamp", "") or ""),
                action=str(raw.get("action", "") or ""),
                filename=str(raw.get("filename", "") or ""),
                status=str(raw.get("status", "") or ""),
                details=str(raw.get("details", "") or ""),
            ))
        return rows

    def clear_logs(self) -> None:
        logger = getattr(self.services, "activity_logger", None)
        if logger is None:
            return
        logger.clear_logs()
