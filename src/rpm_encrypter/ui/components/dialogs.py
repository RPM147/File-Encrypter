"""Shared modal dialog helpers for Flet screens."""

import flet as ft


def show_confirm_dialog(
    page,
    shell,
    *,
    title: str,
    body: str,
    action_label: str,
    on_confirm,
    cancel_label: str = "Cancel",
    on_cancel=None,
    pop_on_confirm: bool = True,
) -> ft.AlertDialog:
    """Display a modal two-button confirmation dialog."""

    def _cancel(_e=None):
        if on_cancel is not None:
            on_cancel()
            return
        page.pop_dialog()
        shell.safe_update()

    def _confirm(_e=None):
        if pop_on_confirm:
            page.pop_dialog()
        on_confirm()

    dialog = ft.AlertDialog(
        modal=True,
        title=ft.Text(title),
        content=ft.Text(body),
        actions=[
            ft.Button(cancel_label, on_click=_cancel),
            ft.Button(action_label, on_click=_confirm),
        ],
    )
    page.show_dialog(dialog)
    shell.safe_update()
    return dialog
