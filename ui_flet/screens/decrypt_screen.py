"""Decrypt screen for the Flet UI (password + recovery-phrase paths).

Stage 3: pick one or more `.vault` files -> password OR 24-word recovery phrase
-> output dir -> Decrypt -> restore the packaged file/folder into a collision-safe
extract directory, with progress/status via the Stage-1 bridge.

The cross-cutting recovery-phrase generation/reveal/confirm dialog and hidden-vault
setup remain deferred to Stage 11; this screen only accepts an existing phrase.
"""
from pathlib import Path
import secrets
import shutil

import flet as ft

from app_config import get_recent
from crypto_core import mnemonic_to_entropy
from recovery_dialog_copy import DECRYPT_RECOVERY_LABEL
from ui_flet.controllers.decrypt_controller import DecryptController
from ui_flet.tokens import COLORS, TYPE, SPACING


class DecryptScreen:
    """Collect vault decrypt inputs and start DecryptController."""

    def __init__(self, page: ft.Page, services, shell):
        self.page = page
        self.services = services
        self.shell = shell
        self.paths = []

        self.vault_picker = ft.FilePicker()
        self.output_picker = ft.FilePicker()

        self.source_list = ft.Column(spacing=6, scroll=ft.ScrollMode.AUTO)
        self.path_field = ft.TextField(
            label="Vault path",
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
            text_size=TYPE["body"]["size"],
            color=COLORS["text_primary"],
            border_color=COLORS["border"],
            focused_border_color=COLORS["accent"],
        )
        self.recovery_field = ft.TextField(
            label="Recovery phrase (24 words)",
            multiline=True,
            min_lines=3,
            max_lines=5,
            visible=False,
            text_size=TYPE["body"]["size"],
            color=COLORS["text_primary"],
            border_color=COLORS["border"],
            focused_border_color=COLORS["accent"],
        )
        self.use_recovery_checkbox = ft.Checkbox(
            label=DECRYPT_RECOVERY_LABEL,
            value=False,
            on_change=self._toggle_recovery,
            active_color=COLORS["accent"],
            label_style=ft.TextStyle(size=TYPE["body"]["size"], color=COLORS["text_primary"]),
        )
        self.attempts_text = ft.Text(
            "",
            size=TYPE["caption"]["size"],
            color=COLORS["text_secondary"],
        )
        self.output_field = ft.TextField(
            label="Output directory",
            value="",
            expand=True,
            text_size=TYPE["body"]["size"],
            color=COLORS["text_primary"],
            border_color=COLORS["border"],
            focused_border_color=COLORS["accent"],
        )
        self.decrypt_button = ft.Button("Decrypt", on_click=self._start_decrypt)

    # --- Flet 0.85.2: FilePicker is a SERVICE, registered via page.services ---
    def _ensure_picker_services(self) -> None:
        services = self.page.services
        for picker in (self.vault_picker, self.output_picker):
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

    # --- status helpers ---
    def _set_status(self, text: str) -> None:
        self.shell.status_text.value = text
        self.shell.safe_update()

    def _set_attempt_status(self, remaining, lockout) -> None:
        if lockout:
            self.attempts_text.value = f"Locked out - {lockout}s"
            self.attempts_text.color = COLORS["error"]
        elif remaining is not None:
            self.attempts_text.value = f"{remaining} attempts remaining"
            self.attempts_text.color = (
                COLORS["error"] if remaining <= 2 else COLORS["text_secondary"]
            )
        else:
            self.attempts_text.value = ""
            self.attempts_text.color = COLORS["text_secondary"]

    def on_auth_error(self, remaining, lockout) -> None:
        # Forwarded by AppShell from the bridge; the poll loop flushes the update.
        self._set_attempt_status(remaining, lockout)

    def reset_form(self) -> None:
        self.paths = []
        self.path_field.value = ""
        self.password_field.value = ""
        self.recovery_field.value = ""
        self.recovery_field.visible = False
        self.password_field.visible = True
        self.use_recovery_checkbox.value = False
        self.attempts_text.value = ""
        self.output_field.value = ""
        self._render_sources()

    # --- source management (.vault-only) ---
    def _append_source(self, path_text: str) -> str:
        """Add a .vault path. Returns 'added', 'dup', 'invalid', or 'empty'."""
        value = (path_text or "").strip().strip('"')
        if not value:
            return "empty"
        if not value.lower().endswith(".vault"):
            return "invalid"
        path = str(Path(value))
        if path not in self.paths:
            self.paths.append(path)
            self._render_sources()
            return "added"
        return "dup"

    def _apply_default_output(self) -> None:
        if self.paths and not (self.output_field.value or "").strip():
            self.output_field.value = str(Path(self.paths[0]).parent)

    def _remove_source(self, path: str) -> None:
        self.paths = [p for p in self.paths if p != path]
        self._render_sources()
        self.shell.safe_update()

    def _render_sources(self) -> None:
        if not self.paths:
            self.source_list.controls = [
                ft.Text(
                    "No vault files selected",
                    size=TYPE["body"]["size"],
                    color=COLORS["text_secondary"],
                )
            ]
            return

        rows = []
        for path in self.paths:
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
                            ft.Button("Remove", on_click=lambda _e, value=path: self._remove_source(value)),
                        ],
                        vertical_alignment=ft.CrossAxisAlignment.CENTER,
                    ),
                    padding=ft.Padding.symmetric(horizontal=10, vertical=6),
                    bgcolor=COLORS["bg"],
                    border_radius=SPACING["radius"],
                )
            )
        self.source_list.controls = rows

    def _add_path_from_field(self, _event=None) -> None:
        result = self._append_source(self.path_field.value)
        self.path_field.value = ""
        self._apply_default_output()
        if result == "invalid":
            self._set_status("Only .vault files can be decrypted")
        else:
            self.shell.safe_update()

    def _add_recent(self, raw: str) -> None:
        result = self._append_source(raw)
        self._apply_default_output()
        if result == "invalid":
            self._set_status("Only .vault files can be decrypted")
        else:
            self.shell.safe_update()

    def _build_recent(self) -> ft.Control:
        try:
            recent = get_recent("dec_sources")[:5]
        except Exception:
            recent = []
        if not recent:
            return ft.Container(height=0, padding=0)
        chips = [
            ft.Text("Recent:", size=TYPE["caption"]["size"], color=COLORS["text_secondary"]),
        ]
        for raw in recent:
            name = Path(raw).name or raw
            chips.append(ft.Button(name, on_click=lambda _e, value=raw: self._add_recent(value)))
        return ft.Row(chips, spacing=8, wrap=True, vertical_alignment=ft.CrossAxisAlignment.CENTER)

    # --- pickers ---
    async def _pick_vaults(self):
        try:
            try:
                files = await self.vault_picker.pick_files(
                    allow_multiple=True,
                    file_type=ft.FilePickerFileType.CUSTOM,
                    allowed_extensions=["vault"],
                )
            except (TypeError, AttributeError):
                # Flet 0.85.2 may reject the filter kwargs; fall back and filter
                # ourselves (.vault enforcement lives in _append_source).
                files = await self.vault_picker.pick_files(allow_multiple=True)
            added = invalid = 0
            for item in files or []:
                raw = getattr(item, "path", "") or getattr(item, "name", "")
                result = self._append_source(raw)
                if result == "added":
                    added += 1
                elif result == "invalid":
                    invalid += 1
            self._apply_default_output()
            if invalid and not added:
                self._set_status("Only .vault files can be decrypted")
            else:
                self.shell.safe_update()
        except Exception as exc:
            self._set_status(f"File picker failed: {exc}")

    async def _pick_output_dir(self):
        try:
            folder = await self.output_picker.get_directory_path()
            if folder:
                self.output_field.value = folder
            self.shell.safe_update()
        except Exception as exc:
            self._set_status(f"Output picker failed: {exc}")

    def _toggle_recovery(self, _event=None) -> None:
        use_recovery = bool(self.use_recovery_checkbox.value)
        self.recovery_field.visible = use_recovery
        self.password_field.visible = not use_recovery
        self.shell.safe_update()

    def _start_decrypt(self, _event=None):
        if self.services.is_processing:
            return

        paths = list(self.paths)
        if not paths:
            self._set_status("Select one or more .vault files")
            return

        password = None
        recovery_key = None
        if self.use_recovery_checkbox.value:
            phrase = (self.recovery_field.value or "").strip()
            if not phrase:
                self._set_status("Enter your 24-word recovery phrase")
                return
            try:
                recovery_key = mnemonic_to_entropy(phrase)
            except ValueError as exc:
                self._set_status(f"Invalid recovery phrase: {exc}")
                return
        else:
            locked, secs = self.services.limiter.is_locked()
            if locked:
                self._set_attempt_status(self.services.limiter.attempts_remaining(), secs)
                self._set_status(f"Locked out - {secs}s")
                return
            password = self.password_field.value or ""
            if not password:
                self._set_status("Enter the vault password")
                return

        output_dir = Path((self.output_field.value or "").strip() or Path(paths[0]).parent)
        if not output_dir.is_dir():
            self._set_status("Output directory does not exist")
            return

        # Write permission probe, mirroring the old view.
        test_file = output_dir / f".rpm_test_{secrets.token_hex(4)}"
        try:
            test_file.touch()
            test_file.unlink()
        except PermissionError:
            self._set_status(f"Cannot write to directory: {output_dir}")
            return
        except Exception as exc:
            self._set_status(f"Directory access failed: {exc}")
            return

        # Low-space guard. Stage 11 may add a confirmation dialog; for Stage 3,
        # do not silently continue when the estimate is unsafe.
        try:
            total_vault_size = sum(Path(p).stat().st_size for p in paths)
            free_space = shutil.disk_usage(output_dir).free
            if free_space < total_vault_size * 1.5:
                self._set_status("Low disk space for decrypt output")
                return
        except Exception as exc:
            self._set_status(f"Disk space check failed: {exc}")
            return

        self.services.is_processing = True
        self.services.cancel_requested = False
        self.attempts_text.value = ""
        self.shell.set_busy(self.decrypt_button)
        self.shell.safe_update()
        DecryptController(self.services).start(paths, password, output_dir, recovery_key)

    def build(self) -> ft.Control:
        self._ensure_picker_services()
        self._render_sources()
        return ft.Container(
            content=ft.Column(
                [
                    ft.Text(
                        "Decrypt",
                        size=TYPE["page_title"]["size"],
                        weight=ft.FontWeight.W_600,
                        color=COLORS["text_primary"],
                    ),
                    self._panel(
                        "Sources",
                        [
                            ft.Row(
                                [
                                    ft.Button("Add Vault", on_click=lambda _e: self.page.run_task(self._pick_vaults)),
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
                            self._build_recent(),
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
                        "Authentication",
                        [
                            self.password_field,
                            self.recovery_field,
                            self.use_recovery_checkbox,
                            self.attempts_text,
                        ],
                    ),
                    self._panel(
                        "Output",
                        [
                            ft.Row(
                                [
                                    self.output_field,
                                    ft.Button("Browse", on_click=lambda _e: self.page.run_task(self._pick_output_dir)),
                                ],
                                spacing=10,
                            ),
                            ft.Row(
                                [ft.Container(expand=True), self.decrypt_button],
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
