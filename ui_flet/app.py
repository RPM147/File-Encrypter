"""Entry point for the Flet shell. Stage 0: window + shell + 1 Hz clock.

Adapted to the INSTALLED Flet (0.85.x): the app is launched via ``ft.run(main)``
(the current entry point) rather than the older ``ft.app(target=main)``.
"""
import asyncio
from datetime import datetime

import flet as ft

from app_config import get_setting
from app_constants import APP_NAME, APP_VERSION
from ui_flet.tokens import COLORS, apply_ui_scale
from ui_flet.theme import build_theme
from ui_flet.shell import AppShell
from ui_flet.services import AppServices


async def _clock_loop(shell: AppShell):
    while not getattr(shell.services, "shutdown_requested", False):
        shell.clock_text.value = datetime.now().strftime("%H:%M:%S")
        shell.refresh_stats()
        if not shell.safe_update():
            break
        await asyncio.sleep(1)


def main(page: ft.Page):
    theme_choice = get_setting("theme", "Dark")
    scale_choice = get_setting("ui_scale", "100%")
    apply_ui_scale(scale_choice)

    page.title = f"{APP_NAME} v{APP_VERSION}"
    page.theme_mode = ft.ThemeMode.LIGHT if theme_choice == "Classic" else ft.ThemeMode.DARK
    page.theme = build_theme(theme_choice)
    page.bgcolor = COLORS["bg"]
    page.padding = 0
    # Adapt window sizing to the installed Flet API (page.window.* on recent versions):
    try:
        page.window.width = 1180
        page.window.height = 820
        page.window.min_width = 1024
        page.window.min_height = 600
    except Exception:
        pass

    services = AppServices()
    services.cleanup_orphaned_temp_files()
    services.start_background_prune()
    services.stats.mark_start()

    shell = AppShell(page, services)

    def _request_close(event=None):
        event_type = getattr(event, "type", None)
        event_value = getattr(event_type, "value", event_type)
        if event is None or event_value == "close":
            services.shutdown_requested = True
            services.cancel_requested = True

    # Best-effort close hook for Flet 0.85.x. Real-screen worker joining comes
    # later; Stage 1 only needs the shared cancel flag to be raised on close.
    try:
        page.window.on_event = _request_close
    except Exception:
        pass

    page.add(shell.build())
    shell.maybe_show_update_prompt()
    page.run_task(shell._poll_loop)
    page.run_task(_clock_loop, shell)


def run():
    ft.run(main)


if __name__ == "__main__":
    run()
