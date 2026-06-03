"""Encrypted Notes screen for the Flet UI (Stage 6).

Password + a multiline editor -> Save Note as an encrypted `.vault` via
crypto.encrypt_note -> Load Note via crypto.decrypt_note back into the editor.

Notes are password-only (matching the old Notes UI): no recovery-phrase path here.
Plaintext note content stays in the editor and in-process strings only -- there is
no clipboard control in this stage (clipboard auto-clear is a Stage-11 concern).
"""
from pathlib import Path

import flet as ft

from ui_flet.controllers.notes_controller import NotesController
from ui_flet.tokens import COLORS, TYPE, SPACING


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
        self.empty_text = ft.Text(
            _EMPTY_HINT,
            size=TYPE["body"]["size"],
            color=COLORS["text_secondary"],
        )
        self.save_button = ft.Button(
            "Save Note", on_click=lambda _e: self.page.run_task(self._save_note)
        )
        self.load_button = ft.Button(
            "Load Note", on_click=lambda _e: self.page.run_task(self._load_note)
        )

    # --- Flet 0.85.2: FilePicker is a SERVICE, registered via page.services ---
    def _ensure_picker_services(self) -> None:
        services = self.page.services
        for picker in (self.save_picker, self.load_picker):
            if not any(existing is picker for existing in services):
                services.append(picker)

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
                horizontal_alignment=ft.CrossAxisAlignment.STRETCH,
            ),
            padding=SPACING["card_pad"],
            bgcolor=COLORS["surface_card"],
            border_radius=SPACING["radius"],
        )

    def _set_status(self, text: str) -> None:
        self.shell.status_text.value = text
        self.shell.safe_update()

    # --- inputs ---
    def _password(self):
        # The raw value is used as the crypto password (never stripped, so an
        # intentional leading/trailing space is preserved).
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
            self._set_status("Notes must be saved as .vault files")
            return None
        return p

    def _normalize_load_path(self, path):
        raw = (path or "").strip().strip('"')
        if not raw:
            self._set_status("Select a .vault note file")
            return None
        if not raw.lower().endswith(".vault"):
            self._set_status("Notes must be .vault files")
            return None
        p = Path(raw)
        if not p.is_file():
            self._set_status("Note file does not exist")
            return None
        return p

    # --- empty-state ---
    def _on_note_change(self, _event=None):
        if self.empty_text.visible:
            self.empty_text.visible = False
            self.shell.safe_update()

    # --- actions ---
    async def _save_note(self):
        if self.services.is_processing:
            return
        password = self._password()
        if not password:
            self._set_status("Enter a note password")
            return
        text = self._note_text()
        if not text:
            self._set_status("Write something to encrypt")
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
            self._set_status(f"Save dialog failed: {exc}")
            return
        if not result:
            return
        path = self._normalize_save_path(result)
        if path is None:
            return

        self.services.is_processing = True
        self.services.cancel_requested = False
        self.shell.set_busy(self.save_button)
        self._set_status("Encrypting note...")
        NotesController(self.services).start_encrypt(text, path, password)

    async def _load_note(self):
        if self.services.is_processing:
            return
        password = self._password()
        if not password:
            self._set_status("Enter a note password")
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
            self._set_status(f"Load dialog failed: {exc}")
            return
        if not files:
            return
        item = files[0]
        raw = getattr(item, "path", "") or getattr(item, "name", "")
        path = self._normalize_load_path(raw)
        if path is None:
            return

        # Clear the editor before starting decrypt, matching the old UI.
        self.note_field.value = ""
        self.empty_text.visible = False
        self.services.is_processing = True
        self.services.cancel_requested = False
        self.shell.set_busy(self.load_button)
        self._set_status("Decrypting note...")
        NotesController(self.services).start_decrypt(path, password)

    # --- result handler (called by AppShell on the poll loop) ---
    def on_note_decrypted(self, text):
        # The shared on_batch_done re-enables the busy button and clears
        # is_processing; this only fills the editor. The poll loop flushes after
        # dispatch, so no direct page.update() is needed here.
        self.note_field.value = text
        self.empty_text.visible = False

    def build(self) -> ft.Control:
        self._ensure_picker_services()
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
                    self._panel(
                        "Controls",
                        [
                            self.password_field,
                            ft.Row([self.save_button, self.load_button], spacing=10),
                        ],
                    ),
                    self._panel(
                        "Editor",
                        [
                            self.empty_text,
                            self.note_field,
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
