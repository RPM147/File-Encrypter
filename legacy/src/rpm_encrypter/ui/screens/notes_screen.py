"""Encrypted Notes screen for the Flet UI (Stage 6).

Password + a multiline editor -> Save Note as an encrypted `.vault` via
crypto.encrypt_note -> Load Note via crypto.decrypt_note back into the editor.

Notes are password-only (matching the old Notes UI): no recovery-phrase path here.
Plaintext note content stays in the editor and in-process strings only -- there is
no clipboard control in this stage (clipboard auto-clear is a Stage-11 concern).
"""

from pathlib import Path

import flet as ft

from rpm_encrypter.services.controllers.notes_controller import NotesController
from rpm_encrypter.ui.components import (
    card_panel,
    empty_text,
    register_page_services,
    set_screen_status,
)
from rpm_encrypter.ui.tokens import COLORS, TYPE

_EMPTY_HINT = "Write a note, then save it as an encrypted .vault file."


class NotesScreen:
    """Collect note text + password and drive NotesController save/load."""

    def __init__(self, page: ft.Page, services, shell):
        self.page = page
        self.services = services
        self.shell = shell

        self.save_picker = ft.FilePicker()
        self.load_picker = ft.FilePicker()

        self.password_field = ft.TextField(
            label="Note Password",
            password=True,
            can_reveal_password=True,
            width=360,
            text_size=TYPE["body"]["size"],
            color=COLORS["text_primary"],
            border_color=COLORS["border"],
            focused_border_color=COLORS["accent"],
        )
        self.note_field = ft.TextField(
            multiline=True,
            min_lines=18,
            max_lines=32,
            on_change=self._on_note_change,
            hint_text="Type your note here...",
            text_size=TYPE["body"]["size"],
            color=COLORS["text_primary"],
            border_color=COLORS["border"],
            focused_border_color=COLORS["accent"],
        )
        self.empty_text = empty_text(_EMPTY_HINT)
        self.save_button = ft.Button(
            "Save Note", on_click=lambda _e: self.page.run_task(self._save_note)
        )
        self.load_button = ft.Button(
            "Load Note", on_click=lambda _e: self.page.run_task(self._load_note)
        )

    def _password(self):
        return self.password_field.value or ""

    def _note_text(self):
        return self.note_field.value or ""

    def _normalize_save_path(self, path):
        raw = (path or "").strip().strip('"')
        if not raw:
            return None
        p = Path(raw)
        if p.suffix == "":
            p = p.with_suffix(".vault")
        elif p.suffix.lower() != ".vault":
            set_screen_status(self.shell, "Notes must be saved as .vault files")
            return None
        return p

    def _normalize_load_path(self, path):
        raw = (path or "").strip().strip('"')
        if not raw:
            set_screen_status(self.shell, "Select a .vault note file")
            return None
        if not raw.lower().endswith(".vault"):
            set_screen_status(self.shell, "Notes must be .vault files")
            return None
        p = Path(raw)
        if not p.is_file():
            set_screen_status(self.shell, "Note file does not exist")
            return None
        return p

    def _on_note_change(self, _event=None):
        if self.empty_text.visible:
            self.empty_text.visible = False
            self.shell.safe_update()

    async def _save_note(self):
        if self.services.is_processing:
            return
        password = self._password()
        if not password:
            set_screen_status(self.shell, "Enter a note password")
            return
        text = self._note_text()
        if not text:
            set_screen_status(self.shell, "Write something to encrypt")
            return

        try:
            try:
                result = await self.save_picker.save_file(
                    dialog_title="Save Encrypted Note",
                    file_name="note.vault",
                    file_type=ft.FilePickerFileType.CUSTOM,
                    allowed_extensions=["vault"],
                )
            except (TypeError, AttributeError):
                result = await self.save_picker.save_file(
                    dialog_title="Save Encrypted Note", file_name="note.vault"
                )
        except Exception as exc:
            set_screen_status(self.shell, f"Save dialog failed: {exc}")
            return
        if not result:
            return
        path = self._normalize_save_path(result)
        if path is None:
            return

        self.services.is_processing = True
        self.services.cancel_requested = False
        self.shell.set_busy(self.save_button)
        set_screen_status(self.shell, "Encrypting note...")
        NotesController(self.services).start_encrypt(text, path, password)

    async def _load_note(self):
        if self.services.is_processing:
            return
        password = self._password()
        if not password:
            set_screen_status(self.shell, "Enter a note password")
            return

        try:
            try:
                files = await self.load_picker.pick_files(
                    allow_multiple=False,
                    file_type=ft.FilePickerFileType.CUSTOM,
                    allowed_extensions=["vault"],
                )
            except (TypeError, AttributeError):
                files = await self.load_picker.pick_files(allow_multiple=False)
        except Exception as exc:
            set_screen_status(self.shell, f"Load dialog failed: {exc}")
            return
        if not files:
            return
        item = files[0]
        raw = getattr(item, "path", "") or getattr(item, "name", "")
        path = self._normalize_load_path(raw)
        if path is None:
            return

        self.note_field.value = ""
        self.empty_text.visible = False
        self.services.is_processing = True
        self.services.cancel_requested = False
        self.shell.set_busy(self.load_button)
        set_screen_status(self.shell, "Decrypting note...")
        NotesController(self.services).start_decrypt(path, password)

    def on_note_decrypted(self, text):
        self.note_field.value = text
        self.empty_text.visible = False

    def build(self) -> ft.Control:
        register_page_services(self.page, self.save_picker, self.load_picker)
        self.empty_text.visible = not bool(self.note_field.value)
        return ft.Container(
            content=ft.Column(
                [
                    ft.Text(
                        "Notes",
                        size=TYPE["page_title"]["size"],
                        weight=ft.FontWeight.W_600,
                        color=COLORS["text_primary"],
                    ),
                    card_panel(
                        "Controls",
                        [
                            self.password_field,
                            ft.Row([self.save_button, self.load_button], spacing=10),
                        ],
                    ),
                    card_panel("Editor", [self.empty_text, self.note_field]),
                ],
                spacing=18,
                scroll=ft.ScrollMode.AUTO,
                horizontal_alignment=ft.CrossAxisAlignment.STRETCH,
            ),
            padding=24,
            expand=True,
        )
