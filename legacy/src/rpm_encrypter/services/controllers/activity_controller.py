"""Activity feed controller for the Flet UI (Flet-free)."""

from dataclasses import dataclass

from rpm_encrypter.storage import config as app_config
from .base import BaseController


@dataclass(frozen=True)
class ActivityRow:
    timestamp: str
    action: str
    filename: str
    status: str
    details: str = ""


class ActivityController(BaseController):
    """Reads and manages the local activity feed."""

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
            rows.append(
                ActivityRow(
                    timestamp=str(raw.get("timestamp", "") or ""),
                    action=str(raw.get("action", "") or ""),
                    filename=str(raw.get("filename", "") or ""),
                    status=str(raw.get("status", "") or ""),
                    details=str(raw.get("details", "") or ""),
                )
            )
        return rows

    def clear_logs(self) -> None:
        logger = getattr(self.services, "activity_logger", None)
        if logger is None:
            return
        logger.clear_logs()
