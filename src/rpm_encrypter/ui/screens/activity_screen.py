"""Activity feed screen for the Flet UI (Stage 9).

Renders the most recent rows from the local ActivityLogger (newest first),
offers a Refresh and a confirmation-gated Clear Log, and exposes the
logging-enabled setting as an opt-in toggle. Logging is off by default and only
records operation metadata plus the file's NAME locally; vault contents, keys,
passwords, and recovery phrases are never logged or shown here.

Flet 0.85.2 notes:
  - Confirmation uses ft.AlertDialog shown via page.show_dialog(dialog) and
    closed via page.pop_dialog(), matching the Re-Key screen.
  - The row area is a scrollable Column of cards (same pattern as the Library
    screen) rather than a DataTable, to stay on stable installed APIs.
"""

import flet as ft

from rpm_encrypter.services.controllers.activity_controller import ActivityController, ActivityRow
from rpm_encrypter.ui.components import (
    card_panel,
    empty_text,
    set_screen_status,
    show_confirm_dialog,
)
from rpm_encrypter.ui.tokens import COLORS, SPACING, TYPE

PRIVACY_HINT = (
    "Records operation metadata and the file's NAME locally on this device. "
    "Off by default; vault contents are never logged."
)
DISABLED_HINT = "Activity logging is disabled. Future operations will not be recorded."


class ActivityScreen:
    """Activity feed screen for the Flet UI."""

    def __init__(self, page: ft.Page, services, shell):
        self.page = page
        self.services = services
        self.shell = shell
        self.controller = ActivityController(services)

        self.logging_checkbox = ft.Checkbox(
            label="Enable Activity Logging",
            value=self.controller.is_logging_enabled(),
            on_change=self._toggle_logging,
            active_color=COLORS["accent"],
            label_style=ft.TextStyle(size=TYPE["body"]["size"], color=COLORS["text_primary"]),
        )
        self.logging_hint = ft.Text(
            PRIVACY_HINT,
            size=TYPE["caption"]["size"],
            color=COLORS["text_secondary"],
        )
        self.disabled_hint = ft.Text(
            DISABLED_HINT,
            size=TYPE["caption"]["size"],
            color=COLORS["text_secondary"],
            visible=not self.controller.is_logging_enabled(),
        )
        self.refresh_button = ft.Button("Refresh", on_click=self._refresh)
        self.clear_button = ft.Button("Clear Log", on_click=self._confirm_clear)

        self.empty_text = empty_text("No activity recorded yet.")
        self.rows_list = ft.Column(
            spacing=6,
            scroll=ft.ScrollMode.AUTO,
            horizontal_alignment=ft.CrossAxisAlignment.STRETCH,
        )
        self.table_container = ft.Container(
            content=self.rows_list,
            height=520,
            padding=10,
            bgcolor=COLORS["bg"],
            border_radius=SPACING["radius"],
        )

    def _toggle_logging(self, _event=None) -> None:
        enabled = self.controller.set_logging_enabled(bool(self.logging_checkbox.value))
        self.logging_checkbox.value = enabled
        self._render_logging_state()
        set_screen_status(
            self.shell,
            "Activity logging enabled" if enabled else "Activity logging disabled",
        )

    def _render_logging_state(self) -> None:
        enabled = self.controller.is_logging_enabled()
        self.disabled_hint.visible = not enabled

    def _refresh(self, _event=None) -> None:
        rows = self.controller.get_rows(limit=200)
        self._render_rows(rows)
        self._render_logging_state()
        set_screen_status(self.shell, f"Activity refreshed ({len(rows)} rows)")

    def _render_rows(self, rows: list[ActivityRow]) -> None:
        if not rows:
            self.rows_list.controls = [self.empty_text]
            return
        self.rows_list.controls = [self._activity_row(r) for r in rows]

    def _activity_row(self, row: ActivityRow) -> ft.Control:
        header = ft.Row(
            [
                ft.Text(
                    row.timestamp or "-",
                    size=TYPE["caption"]["size"],
                    color=COLORS["text_secondary"],
                ),
                ft.Text(
                    row.action or "-",
                    size=TYPE["body"]["size"],
                    weight=ft.FontWeight.W_600,
                    color=COLORS["text_primary"],
                ),
                ft.Text(
                    row.status or "-",
                    size=TYPE["caption"]["size"],
                    color=self._status_color(row.status),
                ),
            ],
            spacing=14,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
        )
        controls = [
            header,
            ft.Text(
                f"File: {row.filename}" if row.filename else "File: -",
                size=TYPE["caption"]["size"],
                color=COLORS["text_secondary"],
                tooltip=row.filename or None,
            ),
        ]
        if row.details:
            controls.append(
                ft.Text(
                    f"-> {row.details}",
                    size=TYPE["caption"]["size"],
                    color=COLORS["text_secondary"],
                    tooltip=row.details,
                )
            )
        return ft.Container(
            content=ft.Column(controls, spacing=2),
            padding=ft.Padding.symmetric(horizontal=10, vertical=8),
            bgcolor=COLORS["bg"],
            border_radius=SPACING["radius"],
        )

    def _status_color(self, status: str) -> str:
        lowered = (status or "").strip().lower()
        if lowered == "success":
            return COLORS["success"]
        if lowered in ("failed", "fail", "error"):
            return COLORS["error"]
        return COLORS["text_secondary"]

    def _confirm_clear(self, _event=None) -> None:
        show_confirm_dialog(
            self.page,
            self.shell,
            title="Clear Activity Log",
            body="Delete all activity log entries from this device?",
            action_label="Clear",
            on_confirm=self._clear_activity_confirmed,
            on_cancel=self._cancel_clear,
            pop_on_confirm=False,
        )

    def _cancel_clear(self, _event=None) -> None:
        self.page.pop_dialog()
        self.shell.safe_update()

    def _clear_activity_confirmed(self, _event=None) -> None:
        try:
            self.controller.clear_logs()
        except Exception as exc:
            self.page.pop_dialog()
            set_screen_status(self.shell, f"Clear activity failed: {exc}")
            return
        self.page.pop_dialog()
        self._render_rows([])
        set_screen_status(self.shell, "Activity log cleared")

    def build(self) -> ft.Control:
        self._render_rows(self.controller.get_rows(limit=200))
        self._render_logging_state()
        return ft.Container(
            content=ft.Column(
                [
                    ft.Text(
                        "Activity",
                        size=TYPE["page_title"]["size"],
                        weight=ft.FontWeight.W_600,
                        color=COLORS["text_primary"],
                    ),
                    card_panel(
                        "Logging",
                        [
                            self.logging_checkbox,
                            self.logging_hint,
                            self.disabled_hint,
                            ft.Row([self.refresh_button, self.clear_button], spacing=10),
                        ],
                        stretch=False,
                    ),
                    card_panel("Activity Log", [self.table_container], stretch=False),
                ],
                spacing=18,
                scroll=ft.ScrollMode.AUTO,
                horizontal_alignment=ft.CrossAxisAlignment.STRETCH,
            ),
            padding=24,
            expand=True,
        )
