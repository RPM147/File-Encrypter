"""Encrypt screen for the Flet UI normal and hidden-vault paths."""
from pathlib import Path

import flet as ft

from app_constants import (
    CONTAINER_SIZE_CHOICES,
    STRENGTH_COLORS,
    ZXCVBN_AVAILABLE,
    container_label_to_mb,
    zxcvbn,
)
from crypto_core import entropy_to_mnemonic, generate_recovery_entropy
from recovery_dialog_copy import get_recovery_dialog_copy
from ui_flet.controllers.encrypt_controller import EncryptController
from ui_flet.controllers.settings_controller import SettingsController
from ui_flet.tokens import COLORS, SPACING, TYPE


HIDDEN_SIZE_CHOICES = ["10 MB", "100 MB", "500 MB", "1 GB", "5 GB", "10 GB"]


class EncryptScreen:
    """Collect encrypt inputs and start EncryptController."""

    def __init__(self, page: ft.Page, services, shell):
        self.page = page
        self.services = services
        self.shell = shell
        self.sources = []
        self.hidden_sources = []
        self.out_dir = ""
        self._pending_encrypt_args = None

        self.file_picker = ft.FilePicker()
        self.folder_picker = ft.FilePicker()
        self.output_picker = ft.FilePicker()
        self.hidden_file_picker = ft.FilePicker()
        self.hidden_folder_picker = ft.FilePicker()

        self.source_list = ft.Column(spacing=6, scroll=ft.ScrollMode.AUTO)
        self.hidden_source_list = ft.Column(spacing=6, scroll=ft.ScrollMode.AUTO)
        self.path_field = ft.TextField(
            label="Path",
            expand=True,
            text_size=TYPE["body"]["size"],
            color=COLORS["text_primary"],
            border_color=COLORS["border"],
            focused_border_color=COLORS["accent"],
        )
        self.password_field = ft.TextField(
            label="Password",
            password=True,
            can_reveal_password=True,
            on_change=self._update_strength,
            text_size=TYPE["body"]["size"],
            color=COLORS["text_primary"],
            border_color=COLORS["border"],
            focused_border_color=COLORS["accent"],
        )
        self.confirm_password_field = ft.TextField(
            label="Confirm Password",
            password=True,
            can_reveal_password=True,
            text_size=TYPE["body"]["size"],
            color=COLORS["text_primary"],
            border_color=COLORS["border"],
            focused_border_color=COLORS["accent"],
        )
        self.strength_text = ft.Text(
            "Strength: -",
            size=TYPE["caption"]["size"],
            color=COLORS["text_secondary"],
        )
        self.container_dropdown = ft.Dropdown(
            label="Container Size",
            value=CONTAINER_SIZE_CHOICES[0],
            options=[ft.DropdownOption(key=label, text=label) for label in CONTAINER_SIZE_CHOICES],
            width=190,
            text_size=TYPE["body"]["size"],
            color=COLORS["text_primary"],
            border_color=COLORS["border"],
            focused_border_color=COLORS["accent"],
        )
        self.profile_dropdown = ft.Dropdown(
            label="Profile",
            value="Custom",
            options=[ft.DropdownOption(key="Custom", text="Custom")],
            on_select=self._apply_profile,
            width=200,
            text_size=TYPE["body"]["size"],
            color=COLORS["text_primary"],
            border_color=COLORS["border"],
            focused_border_color=COLORS["accent"],
        )
        self.compress_checkbox = ft.Checkbox(
            label="Compress",
            value=True,
            active_color=COLORS["accent"],
            label_style=ft.TextStyle(size=TYPE["body"]["size"], color=COLORS["text_primary"]),
        )
        self.secure_wipe_checkbox = ft.Checkbox(
            label="Securely wipe originals after encrypt",
            value=False,
            active_color=COLORS["accent"],
            label_style=ft.TextStyle(size=TYPE["body"]["size"], color=COLORS["text_primary"]),
        )
        self.save_next_checkbox = ft.Checkbox(
            label="Save .vault next to source",
            value=True,
            on_change=self._toggle_output_override,
            active_color=COLORS["accent"],
            label_style=ft.TextStyle(size=TYPE["body"]["size"], color=COLORS["text_primary"]),
        )
        self.output_field = ft.TextField(
            label="Output directory",
            value="",
            expand=True,
            disabled=True,
            text_size=TYPE["body"]["size"],
            color=COLORS["text_primary"],
            border_color=COLORS["border"],
            focused_border_color=COLORS["accent"],
        )
        self.output_browse_button = ft.Button(
            "Browse",
            disabled=True,
            on_click=lambda _e: self.page.run_task(self._pick_output_dir),
        )

        self.hidden_toggle = ft.Checkbox(
            label="Enable Hidden Vault",
            value=False,
            on_change=self._toggle_hidden_mode,
            active_color=COLORS["accent"],
            label_style=ft.TextStyle(size=TYPE["body"]["size"], color=COLORS["text_primary"]),
        )
        self.hidden_password_field = ft.TextField(
            label="Hidden Password",
            password=True,
            can_reveal_password=True,
            text_size=TYPE["body"]["size"],
            color=COLORS["text_primary"],
            border_color=COLORS["border"],
            focused_border_color=COLORS["accent"],
        )
        self.hidden_confirm_password_field = ft.TextField(
            label="Confirm Hidden Password",
            password=True,
            can_reveal_password=True,
            text_size=TYPE["body"]["size"],
            color=COLORS["text_primary"],
            border_color=COLORS["border"],
            focused_border_color=COLORS["accent"],
        )
        self.hidden_size_dropdown = ft.Dropdown(
            label="Hidden Container Size",
            value="100 MB",
            options=[ft.DropdownOption(key=label, text=label) for label in HIDDEN_SIZE_CHOICES],
            width=210,
            text_size=TYPE["body"]["size"],
            color=COLORS["text_primary"],
            border_color=COLORS["border"],
            focused_border_color=COLORS["accent"],
        )
        self.hidden_panel = ft.Column(visible=False, spacing=12)
        self.encrypt_button = ft.Button("Encrypt", on_click=self._start_encrypt)

    def _ensure_picker_services(self) -> None:
        services = self.page.services
        for picker in (
            self.file_picker,
            self.folder_picker,
            self.output_picker,
            self.hidden_file_picker,
            self.hidden_folder_picker,
        ):
            if not any(existing is picker for existing in services):
                services.append(picker)

    def _panel(self, title: str, controls: list[ft.Control]) -> ft.Control:
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
                horizontal_alignment=ft.CrossAxisAlignment.STRETCH,
            ),
            padding=SPACING["card_pad"],
            bgcolor=COLORS["surface_card"],
            border_radius=SPACING["radius"],
        )

    def _set_status(self, text: str, is_error=False) -> None:
        if hasattr(self.shell, "show_snackbar"):
            self.shell.show_snackbar(text, is_error=is_error)
            return
        self.shell.status_text.value = text
        self.shell.safe_update()

    def _refresh_profiles(self) -> None:
        try:
            names = SettingsController(self.services).list_profiles()
        except Exception:
            names = []
        options = ["Custom"] + [name for name in names if name != "Custom"]
        self.profile_dropdown.options = [
            ft.DropdownOption(key=name, text=name) for name in options
        ]
        if self.profile_dropdown.value not in options:
            self.profile_dropdown.value = "Custom"

    def _apply_profile(self, _event=None) -> None:
        name = self.profile_dropdown.value or "Custom"
        if name == "Custom":
            self._set_status("Profile: Custom")
            return
        try:
            applied = SettingsController(self.services).apply_profile(name)
        except ValueError as exc:
            self.profile_dropdown.value = "Custom"
            self._set_status(str(exc), is_error=True)
            return
        if applied:
            self._set_status(f"Profile '{name}' applied")
        else:
            self.profile_dropdown.value = "Custom"
            self._set_status("Profile unavailable", is_error=True)

    def reset_form(self) -> None:
        self.sources = []
        self.hidden_sources = []
        self.out_dir = ""
        self.path_field.value = ""
        self.password_field.value = ""
        self.confirm_password_field.value = ""
        self.strength_text.value = "Strength: -"
        self.strength_text.color = COLORS["text_secondary"]
        self.container_dropdown.value = CONTAINER_SIZE_CHOICES[0]
        self.compress_checkbox.value = True
        self.secure_wipe_checkbox.value = False
        self.save_next_checkbox.value = True
        self.output_field.value = ""
        self.hidden_toggle.value = False
        self.hidden_password_field.value = ""
        self.hidden_confirm_password_field.value = ""
        self.hidden_size_dropdown.value = "100 MB"
        self.profile_dropdown.value = "Custom"
        self._toggle_output_override()
        self._toggle_hidden_mode()
        self._render_sources()
        self._render_hidden_sources()

    def _append_source(self, path_text: str) -> None:
        value = (path_text or "").strip().strip('"')
        if not value:
            return
        path = str(Path(value))
        if path not in self.sources:
            self.sources.append(path)
            self._render_sources()

    def _append_hidden_source(self, path_text: str) -> None:
        value = (path_text or "").strip().strip('"')
        if not value:
            return
        path = str(Path(value))
        if path not in self.hidden_sources:
            self.hidden_sources.append(path)
            self._render_hidden_sources()

    def _remove_source(self, path: str) -> None:
        self.sources = [p for p in self.sources if p != path]
        self._render_sources()
        self.shell.safe_update()

    def _remove_hidden_source(self, path: str) -> None:
        self.hidden_sources = [p for p in self.hidden_sources if p != path]
        self._render_hidden_sources()
        self.shell.safe_update()

    def _render_sources(self) -> None:
        self.source_list.controls = self._source_rows(
            self.sources,
            "No sources selected",
            self._remove_source,
        )

    def _render_hidden_sources(self) -> None:
        self.hidden_source_list.controls = self._source_rows(
            self.hidden_sources,
            "No hidden sources selected",
            self._remove_hidden_source,
        )

    def _source_rows(self, paths, empty_text, remove_handler):
        if not paths:
            return [
                ft.Text(
                    empty_text,
                    size=TYPE["body"]["size"],
                    color=COLORS["text_secondary"],
                )
            ]

        rows = []
        for path in paths:
            p = Path(path)
            rows.append(
                ft.Container(
                    content=ft.Row(
                        [
                            ft.Text(
                                p.name or path,
                                size=TYPE["body"]["size"],
                                color=COLORS["text_primary"],
                                expand=True,
                            ),
                            ft.Text(
                                str(p.parent),
                                size=TYPE["caption"]["size"],
                                color=COLORS["text_secondary"],
                                expand=True,
                            ),
                            ft.Button("Remove", on_click=lambda _e, value=path: remove_handler(value)),
                        ],
                        vertical_alignment=ft.CrossAxisAlignment.CENTER,
                    ),
                    padding=ft.Padding.symmetric(horizontal=10, vertical=6),
                    bgcolor=COLORS["bg"],
                    border_radius=SPACING["radius"],
                )
            )
        return rows

    def _add_path_from_field(self, _event=None) -> None:
        self._append_source(self.path_field.value)
        self.path_field.value = ""
        self.shell.safe_update()

    async def _pick_files(self):
        try:
            files = await self.file_picker.pick_files(allow_multiple=True)
            for item in files or []:
                self._append_source(getattr(item, "path", "") or getattr(item, "name", ""))
            self.shell.safe_update()
        except Exception as exc:
            self._set_status(f"File picker failed: {exc}", is_error=True)

    async def _pick_folder(self):
        try:
            folder = await self.folder_picker.get_directory_path()
            if folder:
                self._append_source(folder)
            self.shell.safe_update()
        except Exception as exc:
            self._set_status(f"Folder picker failed: {exc}", is_error=True)

    async def _pick_output_dir(self):
        try:
            folder = await self.output_picker.get_directory_path()
            if folder:
                self.out_dir = folder
                self.output_field.value = folder
            self.shell.safe_update()
        except Exception as exc:
            self._set_status(f"Output picker failed: {exc}", is_error=True)

    async def _pick_hidden_files(self):
        try:
            files = await self.hidden_file_picker.pick_files(allow_multiple=True)
            for item in files or []:
                self._append_hidden_source(getattr(item, "path", "") or getattr(item, "name", ""))
            self.shell.safe_update()
        except Exception as exc:
            self._set_status(f"Hidden file picker failed: {exc}", is_error=True)

    async def _pick_hidden_folder(self):
        try:
            folder = await self.hidden_folder_picker.get_directory_path()
            if folder:
                self._append_hidden_source(folder)
            self.shell.safe_update()
        except Exception as exc:
            self._set_status(f"Hidden folder picker failed: {exc}", is_error=True)

    def _update_strength(self, _event=None) -> None:
        password = self.password_field.value or ""
        if not password:
            self.strength_text.value = "Strength: -"
            self.strength_text.color = COLORS["text_secondary"]
            return

        if ZXCVBN_AVAILABLE and zxcvbn is not None:
            try:
                score = int(zxcvbn(password).get("score", 0))
            except Exception:
                score = 0
        else:
            length = len(password)
            score = 0
            if length >= 20:
                score = 4
            elif length >= 16:
                score = 3
            elif length >= 12:
                score = 2
            elif length >= 8:
                score = 1

        color, label = STRENGTH_COLORS.get(score, STRENGTH_COLORS[0])
        self.strength_text.value = f"Strength: {label}"
        self.strength_text.color = color

    def _toggle_output_override(self, _event=None) -> None:
        save_next = bool(self.save_next_checkbox.value)
        self.output_field.disabled = save_next
        self.output_browse_button.disabled = save_next
        if _event is not None:
            self.shell.safe_update()

    def _toggle_hidden_mode(self, _event=None) -> None:
        self.hidden_panel.visible = bool(self.hidden_toggle.value)
        self.shell.safe_update()

    def _validate_start(self):
        sources = list(self.sources)
        if not sources:
            return None, "Add a file or folder"

        password = self.password_field.value or ""
        confirm = self.confirm_password_field.value or ""
        if not password:
            return None, "Enter a password"
        if password != confirm:
            return None, "Passwords do not match"

        save_next = bool(self.save_next_checkbox.value)
        out_dir = None
        if not save_next:
            raw_out = (self.output_field.value or self.out_dir or "").strip()
            if not raw_out or not Path(raw_out).is_dir():
                return None, "Select a valid output directory"
            out_dir = raw_out

        hidden_mode = bool(self.hidden_toggle.value)
        hidden_password = None
        hidden_size_label = self.hidden_size_dropdown.value or "100 MB"
        hidden_sources = []
        if hidden_mode:
            hidden_password = self.hidden_password_field.value or ""
            hidden_confirm = self.hidden_confirm_password_field.value or ""
            if not hidden_password:
                return None, "Enter a hidden password"
            if hidden_password != hidden_confirm:
                return None, "Hidden passwords do not match"
            if password == hidden_password:
                return None, "Decoy and hidden passwords must be different"
            hidden_sources = list(self.hidden_sources)
            if not hidden_sources:
                return None, "Add at least one hidden source"
            if hidden_size_label not in HIDDEN_SIZE_CHOICES:
                return None, "Select an explicit hidden container size"

        label = self.container_dropdown.value or CONTAINER_SIZE_CHOICES[0]
        return {
            "sources": sources,
            "password": password,
            "container_mb": container_label_to_mb(label),
            "compress": bool(self.compress_checkbox.value),
            "secure_wipe": bool(self.secure_wipe_checkbox.value),
            "out_dir": out_dir,
            "hidden_mode": hidden_mode,
            "hidden_password": hidden_password,
            "hidden_size_label": hidden_size_label,
            "hidden_sources": hidden_sources,
        }, ""

    def _start_encrypt(self, _event=None) -> None:
        if self.services.is_processing:
            return

        args, error = self._validate_start()
        if error:
            self._set_status(error, is_error=True)
            return

        self.services.is_processing = True
        self.services.cancel_requested = False
        self._pending_encrypt_args = args

        recovery_key = generate_recovery_entropy()
        phrase = entropy_to_mnemonic(recovery_key)
        self._show_recovery_dialog(
            phrase=phrase,
            hidden_mode=bool(args["hidden_mode"]),
            recovery_key=recovery_key,
        )

    def _show_recovery_dialog(self, phrase: str, hidden_mode: bool, recovery_key: bytes) -> None:
        recovery_copy = get_recovery_dialog_copy(hidden_mode)
        confirmed = ft.Checkbox(
            label=recovery_copy.checkbox_text,
            value=False,
            active_color=COLORS["accent"],
            label_style=ft.TextStyle(size=TYPE["body"]["size"], color=COLORS["text_primary"]),
        )

        def _cancel(_e=None):
            if hasattr(self.page, "pop_dialog"):
                self.page.pop_dialog()
            self.services.is_processing = False
            self._pending_encrypt_args = None
            self._set_status("Encryption cancelled")

        def _continue(_e=None):
            if not confirmed.value:
                self._set_status("Confirm that you saved the recovery phrase", is_error=True)
                return
            if hasattr(self.page, "pop_dialog"):
                self.page.pop_dialog()
            self._continue_after_recovery(recovery_key)

        dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text(recovery_copy.title),
            content=ft.Container(
                width=560,
                content=ft.Column(
                    [
                        ft.Text(
                            recovery_copy.heading,
                            size=TYPE["section"]["size"],
                            weight=ft.FontWeight.W_600,
                            color=COLORS["text_primary"],
                        ),
                        ft.Text(
                            recovery_copy.description,
                            size=TYPE["body"]["size"],
                            color=COLORS["text_secondary"],
                        ),
                        ft.TextField(
                            value=phrase,
                            read_only=True,
                            multiline=True,
                            min_lines=3,
                            max_lines=5,
                            text_style=ft.TextStyle(font_family="Courier New"),
                            color=COLORS["text_primary"],
                            border_color=COLORS["border"],
                        ),
                        confirmed,
                    ],
                    tight=True,
                    spacing=12,
                ),
            ),
            actions=[
                ft.Button("Cancel", on_click=_cancel),
                ft.Button("Continue", on_click=_continue),
            ],
        )

        if not hasattr(self.page, "show_dialog"):
            self.services.is_processing = False
            self._pending_encrypt_args = None
            self._set_status("Recovery dialog unavailable", is_error=True)
            return

        self.page.show_dialog(dialog)
        self.shell.safe_update()

    def _continue_after_recovery(self, recovery_key: bytes) -> None:
        args = self._pending_encrypt_args
        if not args:
            self.services.is_processing = False
            return

        self.shell.set_busy(self.encrypt_button)
        self.shell.status_text.value = "Deriving key (Argon2id)..."
        self.shell.safe_update()

        EncryptController(self.services).start(
            args["sources"],
            args["password"],
            args["container_mb"],
            args["compress"],
            args["secure_wipe"],
            args["out_dir"],
            recovery_key=recovery_key,
            hidden_mode=args["hidden_mode"],
            hidden_password=args["hidden_password"],
            hidden_size_label=args["hidden_size_label"],
            hidden_sources=args["hidden_sources"],
        )
        self._pending_encrypt_args = None

    def build(self) -> ft.Control:
        self._ensure_picker_services()
        self._refresh_profiles()
        self._render_sources()
        self._render_hidden_sources()
        self._toggle_output_override()
        self.hidden_panel.controls = [
            ft.Text(
                "Hidden data has no recovery phrase and requires the hidden password.",
                size=TYPE["caption"]["size"],
                color=COLORS["text_secondary"],
            ),
            ft.Row(
                [
                    ft.Button("Add Hidden File", on_click=lambda _e: self.page.run_task(self._pick_hidden_files)),
                    ft.Button("Add Hidden Folder", on_click=lambda _e: self.page.run_task(self._pick_hidden_folder)),
                ],
                spacing=10,
            ),
            ft.Container(
                content=self.hidden_source_list,
                height=150,
                padding=10,
                bgcolor=COLORS["bg"],
                border_radius=SPACING["radius"],
            ),
            self.hidden_password_field,
            self.hidden_confirm_password_field,
            self.hidden_size_dropdown,
        ]
        self.hidden_panel.visible = bool(self.hidden_toggle.value)
        return ft.Container(
            content=ft.Column(
                [
                    ft.Text(
                        "Encrypt",
                        size=TYPE["page_title"]["size"],
                        weight=ft.FontWeight.W_600,
                        color=COLORS["text_primary"],
                    ),
                    self._panel(
                        "Sources",
                        [
                            ft.Row(
                                [
                                    ft.Button("Add File", on_click=lambda _e: self.page.run_task(self._pick_files)),
                                    ft.Button("Add Folder", on_click=lambda _e: self.page.run_task(self._pick_folder)),
                                ],
                                spacing=10,
                            ),
                            ft.Row(
                                [
                                    self.path_field,
                                    ft.Button("Add", on_click=self._add_path_from_field),
                                ],
                                spacing=10,
                            ),
                            ft.Container(
                                content=self.source_list,
                                height=220,
                                padding=10,
                                bgcolor=COLORS["bg"],
                                border_radius=SPACING["radius"],
                            ),
                        ],
                    ),
                    self._panel(
                        "Options",
                        [
                            self.password_field,
                            self.confirm_password_field,
                            self.strength_text,
                            ft.Row(
                                [
                                    self.profile_dropdown,
                                    self.container_dropdown,
                                    self.compress_checkbox,
                                    self.secure_wipe_checkbox,
                                ],
                                spacing=18,
                                wrap=True,
                                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                            ),
                            self.save_next_checkbox,
                            ft.Row(
                                [
                                    self.output_field,
                                    self.output_browse_button,
                                ],
                                spacing=10,
                            ),
                            self.hidden_toggle,
                            self.hidden_panel,
                            ft.Row(
                                [ft.Container(expand=True), self.encrypt_button],
                                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                            ),
                        ],
                    ),
                ],
                spacing=18,
                scroll=ft.ScrollMode.AUTO,
                horizontal_alignment=ft.CrossAxisAlignment.STRETCH,
            ),
            padding=24,
            expand=True,
        )
