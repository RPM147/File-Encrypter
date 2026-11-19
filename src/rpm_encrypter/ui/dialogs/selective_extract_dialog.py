"""Selective Extract modal dialog for InspectScreen."""

from pathlib import Path
import shutil
import tempfile

import flet as ft

from rpm_encrypter.services.controllers.inspect_controller import InspectController
from rpm_encrypter.ui.components import set_screen_status
from rpm_encrypter.ui.tokens import COLORS, SPACING, TYPE


def show_selective_extract_dialog(
    page,
    shell,
    services,
    *,
    metadata: dict,
    vault_path: Path,
    password,
    recovery_key,
    output_picker,
    busy_control,
) -> ft.AlertDialog | None:
    """Open the Selective Extract dialog and launch InspectController on Extract."""
    files = metadata.get("files", [])
    if not files:
        set_screen_status(shell, "No files available for Selective Extract", is_error=True)
        return None

    checks = [
        ft.Checkbox(
            label=f"{item.get('path', '')} ({int(item.get('size', 0) or 0):,} bytes)",
            value=False,
            data=item.get("path", ""),
            active_color=COLORS["accent"],
            label_style=ft.TextStyle(size=TYPE["body"]["size"], color=COLORS["text_primary"]),
        )
        for item in files
    ]

    output_field = ft.TextField(
        label="Output directory",
        expand=True,
        color=COLORS["text_primary"],
        border_color=COLORS["border"],
        focused_border_color=COLORS["accent"],
    )

    async def _pick_output():
        try:
            folder = await output_picker.get_directory_path()
            if folder:
                output_field.value = folder
            shell.safe_update()
        except Exception as exc:
            set_screen_status(shell, f"Output picker failed: {exc}", is_error=True)

    def _cancel(_e=None):
        if hasattr(page, "pop_dialog"):
            page.pop_dialog()
        shell.safe_update()

    def _extract(_e=None):
        selected = [c.data for c in checks if c.value]
        if not selected:
            set_screen_status(shell, "Select at least one file", is_error=True)
            return
        out_raw = (output_field.value or "").strip()
        out_dir = Path(out_raw)
        if not out_raw or not out_dir.is_dir():
            set_screen_status(shell, "Select a valid output directory", is_error=True)
            return
        try:
            if InspectController.temp_space_warning_needed(
                metadata,
                shutil.disk_usage(tempfile.gettempdir()).free,
            ):
                set_screen_status(
                    shell, "Temp drive may not have enough free space", is_error=True
                )
                return
            selected_size = InspectController.estimate_selected_size(metadata, selected)
            if shutil.disk_usage(out_dir).free < selected_size:
                set_screen_status(
                    shell, "Output drive does not have enough free space", is_error=True
                )
                return
        except Exception:
            pass

        if hasattr(page, "pop_dialog"):
            page.pop_dialog()
        services.is_processing = True
        services.cancel_requested = False
        shell.set_busy(busy_control)
        shell.status_text.value = "Extracting selected files..."
        shell.safe_update()
        InspectController(services).start_selective_extract(
            vault_path,
            password,
            recovery_key,
            selected,
            out_dir,
        )

    dialog = ft.AlertDialog(
        modal=True,
        title=ft.Text("Selective Extract"),
        content=ft.Container(
            width=620,
            height=430,
            content=ft.Column(
                [
                    ft.Text(
                        "Full decrypt to a secure temporary archive is required first.",
                        size=TYPE["caption"]["size"],
                        color=COLORS["text_secondary"],
                    ),
                    ft.Container(
                        content=ft.Column(checks, scroll=ft.ScrollMode.AUTO),
                        height=260,
                        padding=10,
                        bgcolor=COLORS["bg"],
                        border_radius=SPACING["radius"],
                    ),
                    ft.Row(
                        [
                            output_field,
                            ft.Button(
                                "Browse",
                                on_click=lambda _e: page.run_task(_pick_output),
                            ),
                        ],
                        spacing=10,
                    ),
                ],
                spacing=12,
            ),
        ),
        actions=[
            ft.Button("Cancel", on_click=_cancel),
            ft.Button("Extract", on_click=_extract),
        ],
    )
    if hasattr(page, "show_dialog"):
        page.show_dialog(dialog)
        shell.safe_update()
        return dialog

    set_screen_status(shell, "Dialog unavailable", is_error=True)
    return None
