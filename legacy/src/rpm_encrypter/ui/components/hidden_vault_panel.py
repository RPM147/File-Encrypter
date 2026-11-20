"""Reusable Hidden Vault section component for EncryptScreen."""

from pathlib import Path

import flet as ft

from rpm_encrypter.ui.tokens import COLORS, SPACING, TYPE
from .layout import empty_text, hint_text, set_screen_status, source_row

HIDDEN_SIZE_CHOICES = ["10 MB", "100 MB", "500 MB", "1 GB", "5 GB", "10 GB"]
HIDDEN_RECOVERY_WARNING = "Hidden data has no recovery phrase and requires the hidden password."


class HiddenVaultPanel:
    """Encapsulates hidden-compartment controls, pickers, source list, and validation."""

    def __init__(self, page: ft.Page, shell):
        self.page = page
        self.shell = shell
        self.sources: list[str] = []

        self.file_picker = ft.FilePicker()
        self.folder_picker = ft.FilePicker()
        self.source_list = ft.Column(spacing=6, scroll=ft.ScrollMode.AUTO)

        self.toggle = ft.Checkbox(
            label="Enable Hidden Vault",
            value=False,
            on_change=self.toggle_visibility,
            active_color=COLORS["accent"],
            label_style=ft.TextStyle(size=TYPE["body"]["size"], color=COLORS["text_primary"]),
        )
        self.password_field = ft.TextField(
            label="Hidden Password",
            password=True,
            can_reveal_password=True,
            text_size=TYPE["body"]["size"],
            color=COLORS["text_primary"],
            border_color=COLORS["border"],
            focused_border_color=COLORS["accent"],
        )
        self.confirm_password_field = ft.TextField(
            label="Confirm Hidden Password",
            password=True,
            can_reveal_password=True,
            text_size=TYPE["body"]["size"],
            color=COLORS["text_primary"],
            border_color=COLORS["border"],
            focused_border_color=COLORS["accent"],
        )
        self.size_dropdown = ft.Dropdown(
            label="Hidden Container Size",
            value="100 MB",
            options=[ft.DropdownOption(key=label, text=label) for label in HIDDEN_SIZE_CHOICES],
            width=210,
            text_size=TYPE["body"]["size"],
            color=COLORS["text_primary"],
            border_color=COLORS["border"],
            focused_border_color=COLORS["accent"],
        )
        self.panel = ft.Column(visible=False, spacing=12)

    def reset(self) -> None:
        self.sources = []
        self.toggle.value = False
        self.password_field.value = ""
        self.confirm_password_field.value = ""
        self.size_dropdown.value = "100 MB"
        self.panel.visible = False
        self.render_sources()

    def append_source(self, path_text: str) -> None:
        value = (path_text or "").strip().strip('"')
        if not value:
            return
        path = str(Path(value))
        if path not in self.sources:
            self.sources.append(path)
            self.render_sources()

    def remove_source(self, path: str) -> None:
        self.sources = [p for p in self.sources if p != path]
        self.render_sources()
        self.shell.safe_update()

    def render_sources(self) -> None:
        if not self.sources:
            self.source_list.controls = [empty_text("No hidden sources selected")]
            return
        rows = []
        for path in self.sources:
            p = Path(path)
            rows.append(
                source_row(
                    p.name or path,
                    lambda _e, value=path: self.remove_source(value),
                    subtitle=str(p.parent),
                )
            )
        self.source_list.controls = rows

    def toggle_visibility(self, _event=None) -> None:
        self.panel.visible = bool(self.toggle.value)
        self.shell.safe_update()

    async def pick_files(self) -> None:
        try:
            files = await self.file_picker.pick_files(allow_multiple=True)
            for item in files or []:
                self.append_source(getattr(item, "path", "") or getattr(item, "name", ""))
            self.shell.safe_update()
        except Exception as exc:
            set_screen_status(self.shell, f"Hidden file picker failed: {exc}", is_error=True)

    async def pick_folder(self) -> None:
        try:
            folder = await self.folder_picker.get_directory_path()
            if folder:
                self.append_source(folder)
            self.shell.safe_update()
        except Exception as exc:
            set_screen_status(self.shell, f"Hidden folder picker failed: {exc}", is_error=True)

    def build_controls(self) -> ft.Column:
        self.render_sources()
        self.panel.controls = [
            hint_text(HIDDEN_RECOVERY_WARNING),
            ft.Row(
                [
                    ft.Button(
                        "Add Hidden File",
                        on_click=lambda _e: self.page.run_task(self.pick_files),
                    ),
                    ft.Button(
                        "Add Hidden Folder",
                        on_click=lambda _e: self.page.run_task(self.pick_folder),
                    ),
                ],
                spacing=10,
            ),
            ft.Container(
                content=self.source_list,
                height=150,
                padding=10,
                bgcolor=COLORS["bg"],
                border_radius=SPACING["radius"],
            ),
            self.password_field,
            self.confirm_password_field,
            self.size_dropdown,
        ]
        self.panel.visible = bool(self.toggle.value)
        return self.panel

    def validate(self, decoy_password: str) -> tuple[dict | None, str]:
        hidden_size_label = self.size_dropdown.value or "100 MB"
        if not self.toggle.value:
            return {
                "hidden_mode": False,
                "hidden_password": None,
                "hidden_size_label": hidden_size_label,
                "hidden_sources": [],
            }, ""

        hidden_password = self.password_field.value or ""
        hidden_confirm = self.confirm_password_field.value or ""
        if not hidden_password:
            return None, "Enter a hidden password"
        if hidden_password != hidden_confirm:
            return None, "Hidden passwords do not match"
        if decoy_password == hidden_password:
            return None, "Decoy and hidden passwords must be different"
        hidden_sources = list(self.sources)
        if not hidden_sources:
            return None, "Add at least one hidden source"
        if hidden_size_label not in HIDDEN_SIZE_CHOICES:
            return None, "Select an explicit hidden container size"
        return {
            "hidden_mode": True,
            "hidden_password": hidden_password,
            "hidden_size_label": hidden_size_label,
            "hidden_sources": hidden_sources,
        }, ""
