"""Application shell: sidebar navigation, content switcher, update banner, and status bar."""

import asyncio
import queue
import webbrowser

import flet as ft

from rpm_encrypter.services import APP_NAME, APP_VERSION, AppServices, LaunchRequest
from rpm_encrypter.services.events import (
    InspectResultEvent,
    IntegrityResultEvent,
    LibraryResultsEvent,
    RekeyPasswordStrengthEvent,
    RekeyVersionActionEvent,
    RekeyVersionsEvent,
    SelectiveExtractResultEvent,
    VaultDiffResultEvent,
    VerifyResultEvent,
)
from rpm_encrypter.storage.config import get_setting, save_setting
from .events import EventDispatcher
from .screens.activity_screen import ActivityScreen
from .screens.decrypt_screen import DecryptScreen
from .screens.encrypt_screen import EncryptScreen
from .screens.inspect_screen import InspectScreen
from .screens.library_screen import LibraryScreen
from .screens.notes_screen import NotesScreen
from .screens.password_screen import PasswordScreen
from .screens.rekey_screen import RekeyScreen
from .screens.settings_screen import SettingsScreen
from .theme import build_theme
from .tokens import (
    COLORS,
    NAV_ITEMS,
    SPACING,
    TOP_NAV_KEYS,
    TYPE,
    apply_ui_scale as apply_token_scale,
)


_SCREEN_REGISTRY: dict[str, tuple[str, type]] = {
    "encrypt": ("encrypt_screen", EncryptScreen),
    "decrypt": ("decrypt_screen", DecryptScreen),
    "inspect": ("inspect_screen", InspectScreen),
    "library": ("library_screen", LibraryScreen),
    "notes": ("notes_screen", NotesScreen),
    "rekey": ("rekey_screen", RekeyScreen),
    "password": ("password_screen", PasswordScreen),
    "activity": ("activity_screen", ActivityScreen),
    "settings": ("settings_screen", SettingsScreen),
}


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
        self._update_info = None
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
        self.cancel_btn = ft.TextButton(
            "Cancel",
            on_click=self.request_cancel,
            visible=False,
        )
        self.stats_text = ft.Text(
            "",
            size=TYPE["caption"]["size"],
            color=COLORS["text_secondary"],
        )
        self._content = ft.AnimatedSwitcher(
            content=self._mount_screen("encrypt"),
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
        self._update_banner_title = None
        self._update_banner_sub = None
        self._update_banner = self._create_update_banner()
        self._root = None

    def _create_update_banner(self) -> ft.Container:
        self._update_banner_title = ft.Text(
            "",
            size=TYPE["caption"]["size"],
            weight=ft.FontWeight.W_600,
            color=COLORS["accent"],
        )
        self._update_banner_sub = ft.Text(
            "Click to download",
            size=TYPE["caption"]["size"],
            color=COLORS["text_secondary"],
        )
        text_col = ft.Column(
            [self._update_banner_title, self._update_banner_sub],
            spacing=2,
            expand=True,
        )
        text_btn = ft.Container(
            content=text_col,
            on_click=self._open_update_url,
            expand=True,
            ink=True,
        )
        dismiss_btn = ft.TextButton("✕", on_click=self._dismiss_update_banner)
        banner = ft.Container(
            content=ft.Row(
                [text_btn, dismiss_btn],
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                spacing=4,
            ),
            padding=ft.Padding.symmetric(horizontal=10, vertical=8),
            bgcolor=COLORS["surface_card"],
            border_radius=SPACING["radius"],
            visible=False,
        )
        self._sync_update_banner(banner)
        return banner

    def _sync_update_banner(self, banner: ft.Container | None = None) -> None:
        target = banner if banner is not None else self._update_banner
        if target is None:
            return
        if self._update_info:
            ver = self._update_info.get("version", "")
            self._update_banner_title.value = f"New version: v{ver}"
            target.visible = True
        else:
            self._update_banner_title.value = ""
            target.visible = False

    def _open_update_url(self, _e=None) -> None:
        if self._update_info and self._update_info.get("url"):
            webbrowser.open(self._update_info["url"])

    def _dismiss_update_banner(self, _e=None) -> None:
        self._update_info = None
        self._sync_update_banner()
        self.safe_update()

    def _mount_screen(self, key: str) -> ft.Control:
        attr, screen_cls = _SCREEN_REGISTRY[key]
        screen = getattr(self, attr)
        if screen is None:
            screen = screen_cls(self.page, self.services, self)
            setattr(self, attr, screen)
        return screen.build()

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
        self._content.content = self._mount_screen(key)
        self.safe_update()

    def apply_launch_request(self, request: LaunchRequest) -> None:
        """Navigate and pre-populate sources when launched with Explorer/CLI targets."""
        if not request.paths or request.tab not in ("encrypt", "decrypt"):
            return
        self.navigate(request.tab)
        if request.tab == "encrypt" and self.encrypt_screen is not None:
            added = self.encrypt_screen.add_paths(request.paths)
            if added:
                self.status_text.value = f"Loaded {added} item(s) for encryption"
        elif request.tab == "decrypt" and self.decrypt_screen is not None:
            added, invalid = self.decrypt_screen.add_paths(request.paths)
            if added:
                self.status_text.value = f"Loaded {added} vault(s) for decryption"
            elif invalid:
                self.status_text.value = "Only .vault files can be decrypted"
        self.safe_update()

    def on_keyboard_event(self, e) -> None:
        if (
            getattr(e, "ctrl", False)
            and not getattr(e, "alt", False)
            and not getattr(e, "shift", False)
            and not getattr(e, "meta", False)
        ):
            key = str(getattr(e, "key", "") or "")
            if key.isdigit():
                idx = int(key) - 1
                if 0 <= idx < len(NAV_ITEMS):
                    self.navigate(NAV_ITEMS[idx][0])

    def _clear_screen_cache(self) -> None:
        for attr, _ in _SCREEN_REGISTRY.values():
            setattr(self, attr, None)

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
            self._content.content = self._mount_screen(active)
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
        self.cancel_btn.visible = True
        self.cancel_btn.disabled = False

    def clear_busy(self) -> None:
        if self.busy_control is not None:
            self.busy_control.disabled = False
            self.busy_control = None
        self.cancel_btn.visible = False
        self.cancel_btn.disabled = False

    def request_cancel(self, _e=None) -> None:
        self.services.cancel_requested = True
        self.cancel_btn.disabled = True
        self.status_text.value = "Cancelling..."
        self.safe_update()

    def show_snackbar(self, text: str, is_error: bool = False) -> None:
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

    # --- EventDispatcher sink methods ---
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
        self.clear_busy()

    def on_auth_error(self, rem: int, lock: int) -> None:
        self.status_text.value = (
            f"Locked out -- {lock}s" if lock
            else f"Wrong password -- {rem} attempts remaining"
        )
        self._reset_progress_idle()
        self.clear_busy()
        if self.decrypt_screen is not None:
            self.decrypt_screen.on_auth_error(rem, lock)
        if self.inspect_screen is not None:
            self.inspect_screen.on_auth_error(rem, lock)

    def on_inspect_result(self, event: InspectResultEvent) -> None:
        if self.inspect_screen is not None:
            self.inspect_screen.on_inspect_result(event)

    def on_integrity_result(self, event: IntegrityResultEvent) -> None:
        if self.inspect_screen is not None:
            self.inspect_screen.on_integrity_result(event)

    def on_verify_result(self, event: VerifyResultEvent) -> None:
        if self.inspect_screen is not None:
            self.inspect_screen.on_verify_result(event)

    def on_selective_extract_result(self, event: SelectiveExtractResultEvent) -> None:
        if self.inspect_screen is not None:
            self.inspect_screen.on_selective_extract_result(event)

    def on_vault_diff_result(self, event: VaultDiffResultEvent) -> None:
        if self.inspect_screen is not None:
            self.inspect_screen.on_vault_diff_result(event)

    def on_library_results(self, event: LibraryResultsEvent) -> None:
        if self.library_screen is not None:
            self.library_screen.on_library_results(event)

    def on_note_decrypted(self, text: str) -> None:
        if self.notes_screen is not None:
            self.notes_screen.on_note_decrypted(text)

    def on_rekey_versions(self, event: RekeyVersionsEvent) -> None:
        if self.rekey_screen is not None:
            self.rekey_screen.on_rekey_versions(event)

    def on_rekey_password_strength(self, event: RekeyPasswordStrengthEvent) -> None:
        if self.rekey_screen is not None:
            self.rekey_screen.on_rekey_password_strength(event)

    def on_rekey_version_action(self, event: RekeyVersionActionEvent) -> None:
        if self.rekey_screen is not None:
            self.rekey_screen.on_rekey_version_action(event)

    def on_update_available(self, info: dict) -> None:
        if not info:
            return
        self._update_info = info
        self._sync_update_banner()
        self.safe_update()

    def on_batch_done(self, text: str, success=None) -> None:
        self.services.is_processing = False
        self.status_text.value = text
        self.clear_busy()
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
            if hasattr(self.services, "start_update_check"):
                self.services.start_update_check(APP_VERSION)

        if not hasattr(self.page, "show_dialog"):
            return

        dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text("Privacy & Update Checks"),
            content=ft.Text(
                "Update checks and activity logging are OFF by default. "
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
        self._update_banner = self._create_update_banner()
        stats = ft.Container(
            content=self.stats_text,
            padding=SPACING["card_pad"],
            bgcolor=COLORS["bg"],
            border_radius=SPACING["radius"],
        )
        settings_btn = self._nav_button("settings")
        lower_controls = [self._update_banner, stats, settings_btn]

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
                    self.cancel_btn,
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
