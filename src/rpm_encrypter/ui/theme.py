"""Builds the Flet Theme from the pure-Python tokens."""

import flet as ft

from .tokens import COLORS, apply_palette


def build_theme(choice: str = "Dark") -> ft.Theme:
    """Build a Material theme from the selected app palette."""
    apply_palette(choice)
    return ft.Theme(
        color_scheme=ft.ColorScheme(
            primary=COLORS["accent"],
            surface=COLORS["surface_card"],
            error=COLORS["error"],
            on_surface=COLORS["text_primary"],
        ),
        scaffold_bgcolor=COLORS["bg"],
        use_material3=True,
    )
