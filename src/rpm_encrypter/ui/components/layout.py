"""Shared layout primitives and page-service helpers for Flet screens."""

from typing import Iterable

import flet as ft

from rpm_encrypter.ui.tokens import COLORS, SPACING, TYPE


def card_panel(
    title: str,
    controls: Iterable[ft.Control],
    *,
    stretch: bool = True,
) -> ft.Container:
    """Wrap section controls in the standard themed card container."""
    col_kwargs = {"spacing": 12}
    if stretch:
        col_kwargs["horizontal_alignment"] = ft.CrossAxisAlignment.STRETCH
    return ft.Container(
        content=ft.Column(
            [
                ft.Text(
                    title,
                    size=TYPE["section"]["size"],
                    weight=ft.FontWeight.W_600,
                    color=COLORS["text_primary"],
                ),
                *controls,
            ],
            **col_kwargs,
        ),
        padding=SPACING["card_pad"],
        bgcolor=COLORS["surface_card"],
        border_radius=SPACING["radius"],
    )


def empty_text(text: str) -> ft.Text:
    """Render muted body text for empty-state placeholders."""
    return ft.Text(text, size=TYPE["body"]["size"], color=COLORS["text_secondary"])


def hint_text(text: str) -> ft.Text:
    """Render muted caption text for field or panel hints."""
    return ft.Text(text, size=TYPE["caption"]["size"], color=COLORS["text_secondary"])


def source_row(
    label: str,
    on_remove,
    *,
    subtitle: str | None = None,
    remove_label: str = "Remove",
) -> ft.Container:
    """Render a consistent selectable item row with a Remove action."""
    row_controls: list[ft.Control] = [
        ft.Text(
            label,
            size=TYPE["body"]["size"],
            color=COLORS["text_primary"],
            expand=True,
        )
    ]
    if subtitle is not None:
        row_controls.append(
            ft.Text(
                subtitle,
                size=TYPE["caption"]["size"],
                color=COLORS["text_secondary"],
                expand=True,
            )
        )
    row_controls.append(ft.Button(remove_label, on_click=on_remove))
    return ft.Container(
        content=ft.Row(row_controls, vertical_alignment=ft.CrossAxisAlignment.CENTER),
        padding=ft.Padding.symmetric(horizontal=10, vertical=6),
        bgcolor=COLORS["bg"],
        border_radius=SPACING["radius"],
    )


def register_page_services(page, *services) -> None:
    """Register Flet service controls (FilePicker, Clipboard) on page.services once."""
    page_services = page.services
    for service in services:
        if not any(existing is service for existing in page_services):
            page_services.append(service)


def set_screen_status(
    shell,
    text: str,
    *,
    is_error: bool = False,
    snackbar: bool = False,
) -> None:
    """Update status text (and optionally show a snackbar) and refresh safely."""
    if (is_error or snackbar) and hasattr(shell, "show_snackbar"):
        shell.show_snackbar(text, is_error=is_error)
        return
    shell.status_text.value = text
    shell.safe_update()


def finish_screen_operation(services, shell, status_text: str) -> None:
    """Reset shared busy/progress state after a screen-driven operation finishes."""
    services.is_processing = False
    shell.status_text.value = status_text
    shell.progress_bar.value = 0
    shell.progress_pct.value = "0%"
    if hasattr(shell, "clear_busy"):
        shell.clear_busy()
    elif shell.busy_control is not None:
        shell.busy_control.disabled = False
        shell.busy_control = None
    shell.safe_update()
