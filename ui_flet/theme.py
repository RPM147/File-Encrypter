"""Builds the Flet Theme from the pure-Python tokens.

Adapted to the INSTALLED Flet (0.85.x): the Material-3 ``ColorScheme`` no longer
has a ``background`` field (it was removed upstream), so the app background is
carried by ``scaffold_bgcolor`` on the Theme — and by ``page.bgcolor`` in app.py
— instead of ``ColorScheme(background=...)``. See UI.md Stage 0 notes.
"""
import flet as ft
from ui_flet.tokens import COLORS, apply_palette


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
