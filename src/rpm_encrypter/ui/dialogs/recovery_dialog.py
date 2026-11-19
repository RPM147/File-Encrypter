"""Recovery phrase reveal and acknowledgment modal dialog."""

import flet as ft

from rpm_encrypter.services.recovery_copy import get_recovery_dialog_copy
from rpm_encrypter.ui.components import set_screen_status
from rpm_encrypter.ui.tokens import COLORS, TYPE


def show_recovery_dialog(
    page,
    shell,
    *,
    phrase: str,
    hidden_mode: bool,
    on_confirm,
    on_cancel,
    on_unavailable=None,
) -> ft.AlertDialog | None:
    """Display the 24-word recovery phrase dialog and require user confirmation."""
    recovery_copy = get_recovery_dialog_copy(hidden_mode)
    confirmed = ft.Checkbox(
        label=recovery_copy.checkbox_text,
        value=False,
        active_color=COLORS["accent"],
        label_style=ft.TextStyle(size=TYPE["body"]["size"], color=COLORS["text_primary"]),
    )

    def _cancel(_e=None):
        if hasattr(page, "pop_dialog"):
            page.pop_dialog()
        on_cancel()

    def _continue(_e=None):
        if not confirmed.value:
            set_screen_status(shell, "Confirm that you saved the recovery phrase", is_error=True)
            return
        if hasattr(page, "pop_dialog"):
            page.pop_dialog()
        on_confirm()

    dialog = ft.AlertDialog(
        modal=True,
        title=ft.Text(recovery_copy.title),
        content=ft.Container(
            width=560,
            content=ft.Column(
                [
                    ft.Text(
                        recovery_copy.heading,
                        size=TYPE["section"]["size"],
                        weight=ft.FontWeight.W_600,
                        color=COLORS["text_primary"],
                    ),
                    ft.Text(
                        recovery_copy.description,
                        size=TYPE["body"]["size"],
                        color=COLORS["text_secondary"],
                    ),
                    ft.TextField(
                        value=phrase,
                        read_only=True,
                        multiline=True,
                        min_lines=3,
                        max_lines=5,
                        text_style=ft.TextStyle(font_family="Courier New"),
                        color=COLORS["text_primary"],
                        border_color=COLORS["border"],
                    ),
                    confirmed,
                ],
                tight=True,
                spacing=12,
            ),
        ),
        actions=[
            ft.Button("Cancel", on_click=_cancel),
            ft.Button("Continue", on_click=_continue),
        ],
    )

    if not hasattr(page, "show_dialog"):
        if on_unavailable is not None:
            on_unavailable()
        set_screen_status(shell, "Recovery dialog unavailable", is_error=True)
        return None

    page.show_dialog(dialog)
    shell.safe_update()
    return dialog
