"""Entry module for launching the Flet desktop UI."""

import asyncio
from datetime import datetime

import flet as ft

from rpm_encrypter.services import APP_NAME, APP_VERSION, AppServices, LaunchRequest
from rpm_encrypter.storage.config import get_setting
from .shell import AppShell
from .theme import build_theme
from .tokens import COLORS, apply_ui_scale


async def _clock_loop(shell: AppShell):
    while not getattr(shell.services, "shutdown_requested", False):
        shell.clock_text.value = datetime.now().strftime("%H:%M:%S")
        shell.refresh_stats()
        if not shell.safe_update():
            break
        await asyncio.sleep(1)


def main(page: ft.Page, launch_request: LaunchRequest | None = None):
    theme_choice = get_setting("theme", "Dark")
    scale_choice = get_setting("ui_scale", "100%")
    apply_ui_scale(scale_choice)

    page.title = f"{APP_NAME} v{APP_VERSION}"
    page.theme_mode = ft.ThemeMode.LIGHT if theme_choice == "Classic" else ft.ThemeMode.DARK
    page.theme = build_theme(theme_choice)
    page.bgcolor = COLORS["bg"]
    page.padding = 0
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

    try:
        page.window.on_event = _request_close
    except Exception:
        pass

    page.on_keyboard_event = shell.on_keyboard_event

    page.add(shell.build())
    if launch_request is not None:
        shell.apply_launch_request(launch_request)
    shell.maybe_show_update_prompt()
    services.start_update_check(APP_VERSION)
    page.run_task(shell._poll_loop)
    page.run_task(_clock_loop, shell)


def run(launch_request: LaunchRequest | None = None):
    if launch_request is None:
        ft.run(main)
    else:
        ft.run(lambda page: main(page, launch_request))


if __name__ == "__main__":
    run()
