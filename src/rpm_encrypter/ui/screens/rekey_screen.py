"""Re-Key + version-history screen for the Flet UI (Stage 7).

Pick a vault -> current/new/confirm passwords -> re-encrypt only the DEK envelope
via crypto.rekey_vault (the payload is never decrypted) -> atomically replace the
current vault. Version history (saved automatically before each re-key) can be
refreshed, restored as a copy, used to replace the current vault, or deleted.

Replace Current and Delete Version are destructive and require an explicit local
confirmation dialog.
"""
from pathlib import Path

import flet as ft

from rpm_encrypter.services.controllers.rekey_controller import RekeyController
from rpm_encrypter.services.events import (
    RekeyPasswordStrengthEvent,
    RekeyVersionActionEvent,
    RekeyVersionsEvent,
)
from rpm_encrypter.ui.components import (
    card_panel,
    empty_text,
    register_page_services,
    set_screen_status,
    show_confirm_dialog,
)
from rpm_encrypter.ui.tokens import COLORS, TYPE, SPACING


_EXPLANATION = (
    "Change a vault password by re-encrypting the small key envelope. "
    "The encrypted payload is not decrypted."
)
_STRENGTH_LABELS = {0: "Very weak", 1: "Weak", 2: "Fair", 3: "Good", 4: "Strong"}


class RekeyScreen:
    """Collect Re-Key inputs and manage version history via RekeyController."""

    def __init__(self, page: ft.Page, services, shell):
        self.page = page
        self.services = services
        self.shell = shell
        self._version_entries = []
        self._selected_version_index = None

        self.vault_picker = ft.FilePicker()

        self.vault_field = ft.TextField(
            label="Vault",
            expand=True,
            text_size=TYPE["body"]["size"],
            color=COLORS["text_primary"],
            border_color=COLORS["border"],
            focused_border_color=COLORS["accent"],
        )
        self.current_password_field = ft.TextField(
            label="Current Password",
            password=True,
            can_reveal_password=True,
            text_size=TYPE["body"]["size"],
            color=COLORS["text_primary"],
            border_color=COLORS["border"],
            focused_border_color=COLORS["accent"],
        )
        self.new_password_field = ft.TextField(
            label="New Password",
            password=True,
            can_reveal_password=True,
            on_change=self._on_new_password_change,
            text_size=TYPE["body"]["size"],
            color=COLORS["text_primary"],
            border_color=COLORS["border"],
            focused_border_color=COLORS["accent"],
        )
        self.confirm_password_field = ft.TextField(
            label="Confirm New Password",
            password=True,
            can_reveal_password=True,
            text_size=TYPE["body"]["size"],
            color=COLORS["text_primary"],
            border_color=COLORS["border"],
            focused_border_color=COLORS["accent"],
        )
        self.strength_text = ft.Text("", size=TYPE["caption"]["size"], color=COLORS["text_secondary"])

        self.browse_button = ft.Button("Browse", on_click=lambda _e: self.page.run_task(self._pick_vault))
        self.rekey_button = ft.Button("Re-Key Vault", on_click=self._do_rekey)
        self.refresh_versions_button = ft.Button("Refresh", on_click=self._refresh_versions)
        self.restore_copy_button = ft.Button("Restore as Copy", on_click=self._restore_copy)
        self.replace_current_button = ft.Button("Replace Current", on_click=self._confirm_replace_current)
        self.delete_version_button = ft.Button("Delete Version", on_click=self._confirm_delete_version)

        self.version_list = ft.Column(spacing=6, scroll=ft.ScrollMode.AUTO)
        self.log_box = ft.TextField(
            multiline=True,
            read_only=True,
            min_lines=5,
            max_lines=8,
            text_size=TYPE["caption"]["size"],
            color=COLORS["text_primary"],
            border_color=COLORS["border"],
        )

    # --- inputs (passwords are never stripped) ---
    def _selected_vault_path(self):
        raw = (self.vault_field.value or "").strip().strip('"')
        if not raw:
            set_screen_status(self.shell, "Select a vault file")
            return None
        if not raw.lower().endswith(".vault"):
            set_screen_status(self.shell, "Re-Key requires a .vault file")
            return None
        p = Path(raw)
        if not p.is_file():
            set_screen_status(self.shell, "Vault file does not exist")
            return None
        return p

    def _current_password(self):
        return self.current_password_field.value or ""

    def _new_password(self):
        return self.new_password_field.value or ""

    def _confirm_password(self):
        return self.confirm_password_field.value or ""

    # --- picker ---
    async def _pick_vault(self):
        try:
            try:
                files = await self.vault_picker.pick_files(
                    allow_multiple=False,
                    file_type=ft.FilePickerFileType.CUSTOM,
                    allowed_extensions=["vault"],
                )
            except (TypeError, AttributeError):
                files = await self.vault_picker.pick_files(allow_multiple=False)
            if files:
                item = files[0]
                raw = getattr(item, "path", "") or getattr(item, "name", "")
                if raw:
                    self.vault_field.value = raw
                    self._refresh_versions()
                    return
            self.shell.safe_update()
        except Exception as exc:
            set_screen_status(self.shell, f"File picker failed: {exc}")

    # --- re-key ---
    def _do_rekey(self, _event=None):
        if self.services.is_processing:
            set_screen_status(self.shell, "Busy")
            return
        vault = self._selected_vault_path()
        if vault is None:
            return
        old_pw = self._current_password()
        new_pw = self._new_password()
        confirm = self._confirm_password()
        if not old_pw:
            set_screen_status(self.shell, "Enter the current password")
            return
        if not new_pw:
            set_screen_status(self.shell, "Enter the new password")
            return
        if new_pw != confirm:
            set_screen_status(self.shell, "New password and confirmation do not match")
            return
        if new_pw == old_pw:
            set_screen_status(self.shell, "New password is the same as the current one")
            return

        self.services.is_processing = True
        self.services.cancel_requested = False
        self.shell.set_busy(self.rekey_button)
        self.log_box.value = ""
        self.shell.progress_bar.value = None  # Flet indeterminate
        self.shell.progress_pct.value = "KDF..."
        self.shell.status_text.value = "Deriving key (Argon2id)..."
        self.shell.safe_update()
        RekeyController(self.services).start_rekey(vault, old_pw, new_pw)

    # --- password strength ---
    def _on_new_password_change(self, _event=None):
        pw = self._new_password()
        if not pw:
            self.strength_text.value = ""
            self.shell.safe_update()
            return
        RekeyController(self.services).start_strength_check(pw)

    def on_rekey_password_strength(self, event: RekeyPasswordStrengthEvent):
        score = int(event.score or 0)
        crack_time = event.crack_time
        label = _STRENGTH_LABELS.get(score, "Very weak")
        if crack_time:
            self.strength_text.value = f"New password strength: {label} - Est. crack time: {crack_time}"
        else:
            self.strength_text.value = f"New password strength: {label}"

    # --- log (forwarded by the shell only while Re-Key is the active screen) ---
    def on_log(self, text):
        lines = (self.log_box.value or "").splitlines()
        lines.append(text)
        if len(lines) > 200:
            lines = lines[-200:]
        self.log_box.value = "\n".join(lines)

    # --- version history ---
    def _refresh_versions(self, _event=None):
        vault = self._selected_vault_path()
        if vault is None:
            return
        self.version_list.controls = [empty_text("Loading versions...")]
        self.shell.safe_update()
        RekeyController(self.services).start_refresh_versions(vault)

    def on_rekey_versions(self, event: RekeyVersionsEvent):
        error = event.error
        if error:
            self._version_entries = []
            self._selected_version_index = None
            self.version_list.controls = [empty_text(error)]
            return
        self._version_entries = list(event.entries)
        self._selected_version_index = None
        self._render_versions()

    def _render_versions(self) -> None:
        if not self._version_entries:
            versioner = getattr(self.services, "versioner", None)
            if not getattr(versioner, "enabled", False):
                self.version_list.controls = [
                    empty_text("Versioning is disabled. Enable it in Settings -> Vault Versioning.")
                ]
            else:
                self.version_list.controls = [empty_text("No versions found for this vault.")]
            return

        rows = []
        for i, entry in enumerate(self._version_entries):
            selected = i == self._selected_version_index
            rows.append(
                ft.Container(
                    content=ft.Column(
                        [
                            ft.Text(
                                f"{entry.get('display_timestamp', '')}    {entry.get('display_size', '')}",
                                size=TYPE["body"]["size"],
                                color=COLORS["text_primary"],
                            ),
                            ft.Text(
                                entry.get("name", ""),
                                size=TYPE["caption"]["size"],
                                color=COLORS["text_secondary"],
                            ),
                        ],
                        spacing=2,
                    ),
                    padding=ft.Padding.symmetric(horizontal=10, vertical=6),
                    bgcolor=COLORS["surface_card"] if selected else COLORS["bg"],
                    border_radius=SPACING["radius"],
                    on_click=lambda _e, idx=i: self._select_version(idx),
                    ink=True,
                )
            )
        self.version_list.controls = rows

    def _select_version(self, index):
        self._selected_version_index = index
        self._render_versions()
        self.shell.safe_update()

    def _selected_entry_payload(self):
        if not self._version_entries or self._selected_version_index is None:
            set_screen_status(self.shell, "Select a version entry")
            return None
        if self._selected_version_index >= len(self._version_entries):
            set_screen_status(self.shell, "Select a version entry")
            return None
        return self._version_entries[self._selected_version_index]

    def on_rekey_version_action(self, event: RekeyVersionActionEvent):
        text = event.text
        error = event.error
        # is_processing / busy_control are cleared by the shared on_batch_done,
        # which the controller also posts for every version action.
        if error:
            self.shell.status_text.value = f"{text}: {error}" if text else error
        else:
            self.shell.status_text.value = text

    # --- version actions ---
    def _restore_copy(self, _event=None):
        vault = self._selected_vault_path()
        if vault is None:
            return
        entry = self._selected_entry_payload()
        if entry is None:
            return
        if self.services.is_processing:
            set_screen_status(self.shell, "Busy")
            return
        self.services.is_processing = True
        self.services.cancel_requested = False
        self.shell.set_busy(self.restore_copy_button)
        set_screen_status(self.shell, "Restoring version as copy...")
        RekeyController(self.services).start_restore_copy(entry, vault)

    def _confirm_replace_current(self, _event=None):
        vault = self._selected_vault_path()
        if vault is None:
            return
        entry = self._selected_entry_payload()
        if entry is None:
            return
        show_confirm_dialog(self.page, self.shell, 
            title="Replace Current Vault?",
            body=(
                "This REPLACES the current vault file with the selected version:\n"
                f"  Version: {entry.get('display_timestamp', '')}\n"
                f"  Size:    {entry.get('display_size', '')}\n\n"
                "The current vault will be overwritten. This cannot be undone."
            ),
            action_label="Replace",
            on_confirm=lambda: self._replace_current_confirmed(vault, entry),
        )

    def _replace_current_confirmed(self, vault, entry):
        if self.services.is_processing:
            set_screen_status(self.shell, "Busy")
            return
        self.services.is_processing = True
        self.services.cancel_requested = False
        self.shell.set_busy(self.replace_current_button)
        set_screen_status(self.shell, "Replacing current vault...")
        RekeyController(self.services).start_replace_current(entry, vault)

    def _confirm_delete_version(self, _event=None):
        vault = self._selected_vault_path()
        if vault is None:
            return
        entry = self._selected_entry_payload()
        if entry is None:
            return
        show_confirm_dialog(self.page, self.shell, 
            title="Delete Version?",
            body=(
                "This permanently deletes the selected version file:\n"
                f"  Version: {entry.get('display_timestamp', '')}\n"
                f"  Size:    {entry.get('display_size', '')}\n\n"
                "This cannot be undone."
            ),
            action_label="Delete",
            on_confirm=lambda: self._delete_version_confirmed(vault, entry),
        )

    def _delete_version_confirmed(self, vault, entry):
        if self.services.is_processing:
            set_screen_status(self.shell, "Busy")
            return
        self.services.is_processing = True
        self.services.cancel_requested = False
        self.shell.set_busy(self.delete_version_button)
        set_screen_status(self.shell, "Deleting version...")
        RekeyController(self.services).start_delete_version(entry, vault)

    def build(self) -> ft.Control:
        register_page_services(self.page, self.vault_picker)
        self._render_versions()
        return ft.Container(
            content=ft.Column(
                [
                    ft.Text(
                        "Re-Key",
                        size=TYPE["page_title"]["size"],
                        weight=ft.FontWeight.W_600,
                        color=COLORS["text_primary"],
                    ),
                    ft.Text(_EXPLANATION, size=TYPE["caption"]["size"], color=COLORS["text_secondary"]),
                    card_panel(
                        "Vault",
                        [ft.Row([self.vault_field, self.browse_button], spacing=10)],
                    ),
                    card_panel(
                        "Passwords",
                        [
                            self.current_password_field,
                            self.new_password_field,
                            self.confirm_password_field,
                            self.strength_text,
                        ],
                    ),
                    card_panel(
                        "Action",
                        [
                            ft.Row([self.rekey_button], spacing=10),
                            self.log_box,
                        ],
                    ),
                    card_panel(
                        "Version History",
                        [
                            ft.Row(
                                [
                                    self.refresh_versions_button,
                                    self.restore_copy_button,
                                    self.replace_current_button,
                                    self.delete_version_button,
                                ],
                                spacing=10,
                                wrap=True,
                            ),
                            ft.Container(
                                content=self.version_list,
                                height=360,
                                padding=10,
                                bgcolor=COLORS["bg"],
                                border_radius=SPACING["radius"],
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
