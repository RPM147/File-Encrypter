"""Vault Diff modal dialog for InspectScreen."""

from pathlib import Path

import flet as ft

from rpm_encrypter.services.controllers.inspect_controller import InspectController
from rpm_encrypter.ui.components import set_screen_status


def show_vault_diff_dialog(
    page,
    shell,
    services,
    *,
    picker_a,
    picker_b,
    busy_control,
) -> ft.AlertDialog | None:
    """Open the Vault Diff dialog and launch InspectController on Compare."""
    path_a_field = ft.TextField(label="Vault A path", expand=True)
    path_b_field = ft.TextField(label="Vault B path", expand=True)
    pw_a_field = ft.TextField(label="Vault A password", password=True, can_reveal_password=True)
    pw_b_field = ft.TextField(label="Vault B password", password=True, can_reveal_password=True)

    async def _pick_vault(target: str):
        picker = picker_a if target == "a" else picker_b
        field = path_a_field if target == "a" else path_b_field
        try:
            files = await picker.pick_files(allow_multiple=False)
            if files:
                item = files[0]
                field.value = getattr(item, "path", "") or getattr(item, "name", "")
            shell.safe_update()
        except Exception as exc:
            set_screen_status(shell, f"Vault picker failed: {exc}", is_error=True)

    def _cancel(_e=None):
        if hasattr(page, "pop_dialog"):
            page.pop_dialog()
        shell.safe_update()

    def _compare(_e=None):
        path_a = Path((path_a_field.value or "").strip().strip('"'))
        path_b = Path((path_b_field.value or "").strip().strip('"'))
        pw_a = pw_a_field.value or ""
        pw_b = pw_b_field.value or ""
        if not path_a.is_file() or not path_b.is_file() or not pw_a or not pw_b:
            set_screen_status(shell, "Vault paths and passwords are required", is_error=True)
            return
        if hasattr(page, "pop_dialog"):
            page.pop_dialog()
        services.is_processing = True
        services.cancel_requested = False
        shell.set_busy(busy_control)
        shell.status_text.value = "Computing Vault Diff..."
        shell.safe_update()
        InspectController(services).start_vault_diff(path_a, pw_a, path_b, pw_b)

    dialog = ft.AlertDialog(
        modal=True,
        title=ft.Text("Vault Diff"),
        content=ft.Container(
            width=620,
            content=ft.Column(
                [
                    ft.Row(
                        [
                            path_a_field,
                            ft.Button(
                                "Browse",
                                on_click=lambda _e: page.run_task(_pick_vault, "a"),
                            ),
                        ],
                        spacing=10,
                    ),
                    pw_a_field,
                    ft.Row(
                        [
                            path_b_field,
                            ft.Button(
                                "Browse",
                                on_click=lambda _e: page.run_task(_pick_vault, "b"),
                            ),
                        ],
                        spacing=10,
                    ),
                    pw_b_field,
                ],
                spacing=12,
            ),
        ),
        actions=[
            ft.Button("Cancel", on_click=_cancel),
            ft.Button("Compare", on_click=_compare),
        ],
    )
    if hasattr(page, "show_dialog"):
        page.show_dialog(dialog)
        shell.safe_update()
        return dialog

    set_screen_status(shell, "Dialog unavailable", is_error=True)
    return None
