"""Password Generator screen for the Flet UI (Stage 8).

Generate a secure random password (length + character classes), show its
strength via the shared app_constants / optional zxcvbn, copy it to the
clipboard with an automatic clear after 30 seconds, and transfer it into the
existing Encrypt password field.

Flet 0.85.2 notes:
  - The clipboard is a Flet SERVICE (ft.Clipboard); it is registered through
    page.services (never as a visual control) and written with await set(text).
  - The clear timer uses a monotonically increasing token so a stale timer can
    never wipe a password copied by a newer copy action.
"""
import asyncio

import flet as ft

from app_constants import DEFAULT_PW_LEN
from ui_flet.controllers.password_controller import (
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    PasswordController,
)
from ui_flet.tokens import COLORS, TYPE, SPACING


class PasswordScreen:
    """Password generator screen for the Flet UI."""

    def __init__(self, page: ft.Page, services, shell):
        self.page = page
        self.services = services
        self.shell = shell
        self.controller = PasswordController()
        self.clipboard = ft.Clipboard()
        self._clipboard_token = 0
        self._clipboard_clear_seconds = 30

        self.length_slider = ft.Slider(
            min=MIN_PASSWORD_LENGTH,
            max=MAX_PASSWORD_LENGTH,
            divisions=MAX_PASSWORD_LENGTH - MIN_PASSWORD_LENGTH,
            round=0,
            value=DEFAULT_PW_LEN,
            active_color=COLORS["accent"],
            inactive_color=COLORS["border"],
            on_change=self._on_length_change,
            expand=True,
        )
        self.length_label = ft.Text(
            str(DEFAULT_PW_LEN),
            size=TYPE["body"]["size"],
            weight=ft.FontWeight.W_600,
            color=COLORS["text_primary"],
        )
        self.uppercase_checkbox = ft.Checkbox(
            label="A-Z",
            value=True,
            active_color=COLORS["accent"],
            label_style=ft.TextStyle(size=TYPE["body"]["size"], color=COLORS["text_primary"]),
        )
        self.lowercase_checkbox = ft.Checkbox(
            label="a-z",
            value=True,
            active_color=COLORS["accent"],
            label_style=ft.TextStyle(size=TYPE["body"]["size"], color=COLORS["text_primary"]),
        )
        self.digits_checkbox = ft.Checkbox(
            label="0-9",
            value=True,
            active_color=COLORS["accent"],
            label_style=ft.TextStyle(size=TYPE["body"]["size"], color=COLORS["text_primary"]),
        )
        self.symbols_checkbox = ft.Checkbox(
            label="Symbols",
            value=True,
            active_color=COLORS["accent"],
            label_style=ft.TextStyle(size=TYPE["body"]["size"], color=COLORS["text_primary"]),
        )
        self.ambiguous_checkbox = ft.Checkbox(
            label="Exclude ambiguous (0O1lI|`)",
            value=False,
            active_color=COLORS["accent"],
            label_style=ft.TextStyle(size=TYPE["body"]["size"], color=COLORS["text_primary"]),
        )
        self.result_field = ft.TextField(
            label="Generated password",
            read_only=True,
            password=False,
            can_reveal_password=False,
            expand=True,
            text_size=TYPE["body"]["size"],
            text_style=ft.TextStyle(font_family="Courier New"),
            color=COLORS["text_primary"],
            border_color=COLORS["border"],
            focused_border_color=COLORS["accent"],
        )
        self.strength_text = ft.Text(
            "Strength: -",
            size=TYPE["caption"]["size"],
            color=COLORS["text_secondary"],
        )
        self.generate_button = ft.Button("Generate Password", on_click=self._generate_password)
        self.copy_button = ft.Button("Copy", on_click=lambda e: self.page.run_task(self._copy_password))
        self.transfer_button = ft.Button("Transfer to Encrypt", on_click=self._transfer_to_encrypt)

    # --- Flet 0.85.2: the clipboard is a SERVICE registered via page.services ---
    def _ensure_services(self) -> None:
        services = self.page.services
        if not any(existing is self.clipboard for existing in services):
            services.append(self.clipboard)

    def _panel(self, title: str, controls: list) -> ft.Control:
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
                spacing=12,
            ),
            padding=SPACING["card_pad"],
            bgcolor=COLORS["surface_card"],
            border_radius=SPACING["radius"],
        )

    def _set_status(self, text: str) -> None:
        self.shell.status_text.value = text
        self.shell.safe_update()

    # --- length ---
    def _length(self) -> int:
        return int(self.length_slider.value or DEFAULT_PW_LEN)

    def _on_length_change(self, _event=None) -> None:
        self.length_label.value = str(self._length())
        self.shell.safe_update()

    # --- generate ---
    def _generate_password(self, _event=None) -> None:
        try:
            password = self.controller.generate_password(
                length=self._length(),
                use_upper=bool(self.uppercase_checkbox.value),
                use_lower=bool(self.lowercase_checkbox.value),
                use_digits=bool(self.digits_checkbox.value),
                use_symbols=bool(self.symbols_checkbox.value),
                exclude_ambiguous=bool(self.ambiguous_checkbox.value),
            )
        except ValueError as exc:
            self.result_field.value = ""
            self.strength_text.value = "Strength: -"
            self.strength_text.color = COLORS["text_secondary"]
            self._set_status(str(exc))
            return

        self.result_field.value = password
        self._render_strength(password)
        self._set_status("Password generated")

    def _render_strength(self, password: str) -> None:
        result = self.controller.strength(password)
        self.strength_text.value = result.text
        self.strength_text.color = result.color or COLORS["text_secondary"]

    # --- copy + auto-clear ---
    async def _copy_password(self):
        password = self.result_field.value or ""
        if not password:
            self._set_status("Generate a password first")
            return
        try:
            await self.clipboard.set(password)
        except Exception as exc:
            self._set_status(f"Clipboard failed: {exc}")
            return
        self._clipboard_token += 1
        token = self._clipboard_token
        self._set_status("Copied! Clipboard will be cleared in 30s.")
        self.page.run_task(self._clear_clipboard_after_delay, token)

    async def _clear_clipboard_after_delay(self, token: int):
        await asyncio.sleep(self._clipboard_clear_seconds)
        await self._clear_clipboard_if_current(token)

    async def _clear_clipboard_if_current(self, token: int):
        if token != self._clipboard_token:
            return
        if getattr(self.services, "shutdown_requested", False):
            return
        try:
            await self.clipboard.set("")
        except Exception:
            return
        self.shell.status_text.value = "Clipboard cleared"
        self.shell.safe_update()

    # --- transfer ---
    def _transfer_to_encrypt(self, _event=None) -> None:
        password = self.result_field.value or ""
        if not password:
            self._set_status("Generate a password first")
            return
        self.shell.navigate("encrypt")
        encrypt_screen = self.shell.encrypt_screen
        if encrypt_screen is None:
            self._set_status("Encrypt screen unavailable")
            return
        encrypt_screen.password_field.value = password
        if hasattr(encrypt_screen, "confirm_password_field"):
            encrypt_screen.confirm_password_field.value = password
        if hasattr(encrypt_screen, "_update_strength"):
            encrypt_screen._update_strength()
        self.shell.status_text.value = "Password transferred to Encrypt tab"
        self.shell.safe_update()

    def build(self) -> ft.Control:
        self._ensure_services()
        return ft.Container(
            content=ft.Column(
                [
                    ft.Text(
                        "Password Generator",
                        size=TYPE["page_title"]["size"],
                        weight=ft.FontWeight.W_600,
                        color=COLORS["text_primary"],
                    ),
                    self._panel(
                        "Options",
                        [
                            ft.Row(
                                [
                                    ft.Text(
                                        "Length:",
                                        size=TYPE["body"]["size"],
                                        color=COLORS["text_primary"],
                                    ),
                                    self.length_slider,
                                    self.length_label,
                                ],
                                spacing=12,
                                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                            ),
                            ft.Row(
                                [
                                    self.uppercase_checkbox,
                                    self.lowercase_checkbox,
                                    self.digits_checkbox,
                                    self.symbols_checkbox,
                                    self.ambiguous_checkbox,
                                ],
                                spacing=14,
                                wrap=True,
                                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                            ),
                            ft.Row([self.generate_button], spacing=10),
                        ],
                    ),
                    self._panel(
                        "Result",
                        [
                            ft.Row(
                                [
                                    self.result_field,
                                    self.copy_button,
                                    self.transfer_button,
                                ],
                                spacing=10,
                                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                            ),
                            self.strength_text,
                        ],
                    ),
                ],
                spacing=18,
                scroll=ft.ScrollMode.AUTO,
            ),
            padding=24,
            expand=True,
        )
