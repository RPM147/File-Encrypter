"""The application shell: sidebar nav + content switcher + status bar.

Stage 2 mounts the normal-vault Encrypt screen; the other screens remain
placeholders for later stages.

Adapted to the INSTALLED Flet (0.85.x): the padding/alignment helpers moved from
the lowercase module functions (``ft.padding.symmetric`` / ``ft.alignment.center``)
to class members -- ``ft.Padding.symmetric(...)`` and ``ft.Alignment.CENTER``.
"""
import asyncio
import queue

import flet as ft
from app_config import get_setting, save_setting
from app_constants import APP_NAME, APP_VERSION
from ui_flet.events import EventDispatcher
from ui_flet.screens.encrypt_screen import EncryptScreen
from ui_flet.screens.decrypt_screen import DecryptScreen
from ui_flet.screens.inspect_screen import InspectScreen
from ui_flet.screens.library_screen import LibraryScreen
from ui_flet.screens.notes_screen import NotesScreen
from ui_flet.screens.rekey_screen import RekeyScreen
from ui_flet.screens.password_screen import PasswordScreen
from ui_flet.screens.activity_screen import ActivityScreen
from ui_flet.screens.settings_screen import SettingsScreen
from ui_flet.services import AppServices
from ui_flet.theme import build_theme
from ui_flet.tokens import (
    COLORS,
    TYPE,
    SPACING,
    NAV_ITEMS,
    TOP_NAV_KEYS,
    apply_ui_scale as apply_token_scale,
)


class AppShell:
    def __init__(self, page: ft.Page, services: AppServices):
        self.page = page
        self.services = services
        self.dispatcher = EventDispatcher(self)
        self.active_key = "encrypt"
        self._labels = dict(NAV_ITEMS)
        self._nav_controls = {}
        self.busy_control = None
        self._progress_reset_token = 0
        self.encrypt_screen = None
        self.decrypt_screen = None
        self.inspect_screen = None
        self.library_screen = None
        self.notes_screen = None
        self.rekey_screen = None
        self.password_screen = None
        self.activity_screen = None
        self.settings_screen = None
        self.progress_bar = ft.ProgressBar(
            value=0,
            color=COLORS["accent"],
            bgcolor=COLORS["border"],
        )
        self.progress_pct = ft.Text(
            "0%",
            size=TYPE["caption"]["size"],
            color=COLORS["text_secondary"],
        )
        self.stats_text = ft.Text(
            "",
            size=TYPE["caption"]["size"],
            color=COLORS["text_secondary"],
        )
        self._content = ft.AnimatedSwitcher(
            content=self._placeholder("encrypt"),
            transition=ft.AnimatedSwitcherTransition.FADE,
            duration=180,
        )
        self.status_text = ft.Text(
            "Ready",
            size=TYPE["body"]["size"],
            color=COLORS["text_secondary"],
        )
        self.clock_text = ft.Text(
            "",
            size=TYPE["body"]["size"],
            color=COLORS["text_secondary"],
        )
        self._root = None

    # --- content screens (remaining placeholders are replaced in later stages) ---
    def _placeholder(self, key: str) -> ft.Control:
        if key == "encrypt":
            if self.encrypt_screen is None:
                self.encrypt_screen = EncryptScreen(self.page, self.services, self)
            return self.encrypt_screen.build()

        if key == "decrypt":
            if self.decrypt_screen is None:
                self.decrypt_screen = DecryptScreen(self.page, self.services, self)
            return self.decrypt_screen.build()

        if key == "inspect":
            if self.inspect_screen is None:
                self.inspect_screen = InspectScreen(self.page, self.services, self)
            return self.inspect_screen.build()

        if key == "library":
            if self.library_screen is None:
                self.library_screen = LibraryScreen(self.page, self.services, self)
            return self.library_screen.build()

        if key == "notes":
            if self.notes_screen is None:
                self.notes_screen = NotesScreen(self.page, self.services, self)
            return self.notes_screen.build()

        if key == "rekey":
            if self.rekey_screen is None:
                self.rekey_screen = RekeyScreen(self.page, self.services, self)
            return self.rekey_screen.build()

        if key == "password":
            if self.password_screen is None:
                self.password_screen = PasswordScreen(self.page, self.services, self)
            return self.password_screen.build()

        if key == "activity":
            if self.activity_screen is None:
                self.activity_screen = ActivityScreen(self.page, self.services, self)
            return self.activity_screen.build()

        if key == "settings":
            if self.settings_screen is None:
                self.settings_screen = SettingsScreen(self.page, self.services, self)
            return self.settings_screen.build()

        return ft.Container(
            content=ft.Text(
                f"{self._labels[key]} -- coming soon",
                size=TYPE["page_title"]["size"],
                weight=ft.FontWeight.W_600,
                color=COLORS["text_primary"],
            ),
            alignment=ft.Alignment.CENTER,
            expand=True,
        )

    def _nav_button(self, key: str) -> ft.Control:
        is_active = key == self.active_key
        btn = ft.Container(
            content=ft.Text(
                self._labels[key],
                size=TYPE["body"]["size"],
                color=COLORS["accent"] if is_active else COLORS["text_primary"],
            ),
            padding=ft.Padding.symmetric(horizontal=16, vertical=12),
            bgcolor=COLORS["surface_card"] if is_active else None,
            border_radius=SPACING["radius"],
            on_click=lambda e, k=key: self.navigate(k),
            ink=True,
        )
        self._nav_controls[key] = btn
        return btn

    def navigate(self, key: str) -> None:
        self.active_key = key
        for k, c in self._nav_controls.items():
            active = k == key
            c.bgcolor = COLORS["surface_card"] if active else None
            c.content.color = COLORS["accent"] if active else COLORS["text_primary"]
        self._content.content = self._placeholder(key)
        self.safe_update()

    def _clear_screen_cache(self) -> None:
        self.encrypt_screen = None
        self.decrypt_screen = None
        self.inspect_screen = None
        self.library_screen = None
        self.notes_screen = None
        self.rekey_screen = None
        self.password_screen = None
        self.activity_screen = None
        self.settings_screen = None

    def _rebuild_root(self) -> None:
        active = self.active_key
        self._nav_controls = {}
        self._clear_screen_cache()
        self.active_key = active
        root = self.build()
        controls = getattr(self.page, "controls", None)
        if isinstance(controls, list) and controls:
            controls[0] = root
        else:
            self._content.content = self._placeholder(active)
        self.safe_update()

    def apply_theme(self, choice: str) -> None:
        self.page.theme_mode = ft.ThemeMode.LIGHT if choice == "Classic" else ft.ThemeMode.DARK
        self.page.theme = build_theme(choice)
        self.page.bgcolor = COLORS["bg"]
        self._rebuild_root()

    def apply_ui_scale(self, choice: str) -> None:
        apply_token_scale(choice)
        self._rebuild_root()

    def set_busy(self, control) -> None:
        self.busy_control = control
        control.disabled = True

    def show_snackbar(self, text: str, is_error: bool = False) -> None:
        """Set persistent status and best-effort transient snackbar.

        Flet 0.85.2 does not expose the old page-level snackbar helper. Assigning
        page.snack_bar and opening the control is compatible with fake-page tests
        and avoids page-level open/close helpers.
        """
        self.status_text.value = text
        try:
            self.page.snack_bar = ft.SnackBar(
                content=ft.Text(text),
                bgcolor=COLORS["error"] if is_error else COLORS["surface_card"],
            )
            self.page.snack_bar.open = True
        except Exception:
            pass
        self.safe_update()

    def safe_update(self) -> bool:
        if getattr(self.services, "shutdown_requested", False):
            return False
        try:
            self.page.update()
            return True
        except RuntimeError as exc:
            if "destroyed session" in str(exc):
                self.services.shutdown_requested = True
                self.services.cancel_requested = True
                return False
            raise

    # --- EventDispatcher sink methods. They mutate controls only; the poll loop
    # calls page.update() once after dispatching queued messages.
    def on_log(self, text: str) -> None:
        self.status_text.value = text
        if self.active_key == "rekey" and self.rekey_screen is not None:
            self.rekey_screen.on_log(text)

    def on_progress_start(self) -> None:
        self._progress_reset_token += 1
        self.progress_bar.color = COLORS["accent"]
        self.progress_bar.value = 0
        self.progress_pct.value = "0%"

    def on_progress(self, done: int, total: int) -> None:
        p = done / total if total else 0
        p = max(0, min(p, 1))
        self.progress_bar.value = p
        self.progress_pct.value = f"{int(p * 100)}%"

    def on_error(self, text: str) -> None:
        self.status_text.value = text
        self._reset_progress_idle()
        if self.busy_control is not None:
            self.busy_control.disabled = False
            self.busy_control = None

    def on_auth_error(self, rem: int, lock: int) -> None:
        self.status_text.value = (
            f"Locked out -- {lock}s" if lock
            else f"Wrong password -- {rem} attempts remaining"
        )
        self._reset_progress_idle()
        if self.decrypt_screen is not None:
            self.decrypt_screen.on_auth_error(rem, lock)
        if self.inspect_screen is not None:
            self.inspect_screen.on_auth_error(rem, lock)

    def on_inspect_result(self, msg: dict) -> None:
        if self.inspect_screen is not None:
            self.inspect_screen.on_inspect_result(msg)

    def on_integrity_result(self, msg: dict) -> None:
        if self.inspect_screen is not None:
            self.inspect_screen.on_integrity_result(msg)

    def on_verify_result(self, msg: dict) -> None:
        if self.inspect_screen is not None:
            self.inspect_screen.on_verify_result(msg)

    def on_selective_extract_result(self, msg: dict) -> None:
        if self.inspect_screen is not None:
            self.inspect_screen.on_selective_extract_result(msg)

    def on_vault_diff_result(self, msg: dict) -> None:
        if self.inspect_screen is not None:
            self.inspect_screen.on_vault_diff_result(msg)

    def on_library_results(self, msg: dict) -> None:
        if self.library_screen is not None:
            self.library_screen.on_library_results(msg)

    def on_note_decrypted(self, text: str) -> None:
        if self.notes_screen is not None:
            self.notes_screen.on_note_decrypted(text)

    def on_rekey_versions(self, msg: dict) -> None:
        if self.rekey_screen is not None:
            self.rekey_screen.on_rekey_versions(msg)

    def on_rekey_password_strength(self, msg: dict) -> None:
        if self.rekey_screen is not None:
            self.rekey_screen.on_rekey_password_strength(msg)

    def on_rekey_version_action(self, msg: dict) -> None:
        if self.rekey_screen is not None:
            self.rekey_screen.on_rekey_version_action(msg)

    def on_batch_done(self, text: str, success=None) -> None:
        self.services.is_processing = False
        self.status_text.value = text
        if self.busy_control is not None:
            self.busy_control.disabled = False
            self.busy_control = None
        if success is None:
            lower = (text or "").lower()
            success = not any(
                word in lower
                for word in ("fail", "error", "cancel", "wrong", "corrupt", "locked")
            )
        if success:
            self._reset_completed_workflow(text)
            self._show_success_progress_then_reset()
        else:
            self._reset_progress_idle()

    def _reset_completed_workflow(self, text: str) -> None:
        lower = (text or "").lower()
        if "encrypted" in lower and self.encrypt_screen is not None:
            self.encrypt_screen.reset_form()
        elif "decrypted" in lower and self.decrypt_screen is not None:
            self.decrypt_screen.reset_form()

    def _reset_progress_idle(self) -> None:
        self._progress_reset_token += 1
        self.progress_bar.color = COLORS["accent"]
        self.progress_bar.value = 0
        self.progress_pct.value = "0%"

    def _show_success_progress_then_reset(self) -> None:
        self._progress_reset_token += 1
        token = self._progress_reset_token
        self.progress_bar.value = 1
        self.progress_bar.color = COLORS["success"]
        self.progress_pct.value = "100%"
        try:
            self.page.run_task(self._reset_progress_after_delay, token)
        except Exception:
            pass

    async def _reset_progress_after_delay(self, token: int, delay: float = 1.6):
        await asyncio.sleep(delay)
        if token != self._progress_reset_token:
            return
        self.progress_bar.color = COLORS["accent"]
        self.progress_bar.value = 0
        self.progress_pct.value = "0%"
        self.safe_update()

    async def _poll_loop(self):
        while not getattr(self.services, "shutdown_requested", False):
            dirty = False
            try:
                while True:
                    msg = self.services.msg_queue.get_nowait()
                    self.dispatcher.dispatch(msg)
                    dirty = True
            except queue.Empty:
                pass
            if dirty and not self.safe_update():
                break
            await asyncio.sleep(0.1)

    def refresh_stats(self) -> None:
        snap = self.services.stats.snapshot()
        kb = int(snap.get("bytes_total", 0) or 0) // 1024
        self.stats_text.value = (
            f"Encrypted: {snap.get('encrypted', 0)}\n"
            f"Decrypted: {snap.get('decrypted', 0)}\n"
            f"Re-Keyed: {snap.get('rekeyed', 0)}\n"
            f"Files: {snap.get('files_total', 0)}\n"
            f"Data: {kb:,} KB\n"
            f"Uptime: {snap.get('uptime', '00:00:00')}"
        )

    def maybe_show_update_prompt(self) -> None:
        if get_setting("update_prompt_shown", False):
            return
        save_setting("update_prompt_shown", True)

        def _keep_off(_e=None):
            save_setting("check_updates", False)
            if hasattr(self.page, "pop_dialog"):
                self.page.pop_dialog()
            self.show_snackbar("Update checks remain disabled")

        def _enable(_e=None):
            save_setting("check_updates", True)
            if self.settings_screen is not None:
                self.settings_screen.updates_checkbox.value = True
            if hasattr(self.page, "pop_dialog"):
                self.page.pop_dialog()
            self.show_snackbar("Update checks enabled")

        if not hasattr(self.page, "show_dialog"):
            return

        dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text("Update Checks"),
            content=ft.Text(
                "Check for updates automatically on startup? This is optional and "
                "can be changed later in Settings."
            ),
            actions=[
                ft.Button("Keep Off", on_click=_keep_off),
                ft.Button("Enable", on_click=_enable),
            ],
        )
        self.page.show_dialog(dialog)
        self.safe_update()

    def build(self) -> ft.Control:
        brand = ft.Column(
            [
                ft.Text(
                    APP_NAME,
                    size=TYPE["section"]["size"],
                    weight=ft.FontWeight.W_700,
                    color=COLORS["text_primary"],
                ),
                ft.Text(
                    f"v{APP_VERSION}   AES-256-GCM",
                    size=TYPE["caption"]["size"],
                    color=COLORS["text_secondary"],
                ),
            ],
            spacing=2,
        )
        top = ft.Column([self._nav_button(k) for k in TOP_NAV_KEYS], spacing=4)
        self.refresh_stats()
        stats = ft.Container(
            content=self.stats_text,
            padding=SPACING["card_pad"],
            bgcolor=COLORS["bg"],
            border_radius=SPACING["radius"],
        )
        settings_btn = self._nav_button("settings")
        lower_controls = [stats, settings_btn]

        sidebar = ft.Container(
            width=210,
            bgcolor=COLORS["bg_sidebar"],
            padding=ft.Padding.symmetric(horizontal=12, vertical=20),
            content=ft.Column(
                [
                    brand,
                    ft.Divider(color=COLORS["border"]),
                    top,
                    ft.Container(expand=True),
                    *lower_controls,
                ],
                expand=True,
                spacing=14,
            ),
        )

        status_bar = ft.Container(
            height=34,
            padding=ft.Padding.symmetric(horizontal=18),
            content=ft.Row(
                [
                    self.status_text,
                    ft.Container(expand=True),
                    ft.Container(width=180, content=self.progress_bar),
                    self.progress_pct,
                    self.clock_text,
                ],
            ),
        )

        content_col = ft.Column(
            [ft.Container(self._content, expand=True), status_bar],
            expand=True,
            spacing=0,
        )
        self._root = ft.Row(
            [
                sidebar,
                ft.Container(content_col, expand=True, bgcolor=COLORS["bg"]),
            ],
            expand=True,
            spacing=0,
        )
        return self._root
