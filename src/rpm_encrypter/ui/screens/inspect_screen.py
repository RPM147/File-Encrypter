"""Vault Info / Inspect screen for the Flet UI."""
from pathlib import Path

import flet as ft

from rpm_encrypter.core import mnemonic_to_entropy
from rpm_encrypter.services.recovery_copy import INSPECT_RECOVERY_LABEL
from rpm_encrypter.services.controllers.inspect_controller import InspectController
from rpm_encrypter.services.events import (
    InspectResultEvent,
    IntegrityResultEvent,
    SelectiveExtractResultEvent,
    VaultDiffResultEvent,
    VerifyResultEvent,
)
from rpm_encrypter.ui.components import (
    AutoClearClipboard,
    card_panel,
    finish_screen_operation,
    register_page_services,
    set_screen_status,
)
from rpm_encrypter.ui.dialogs import show_selective_extract_dialog, show_vault_diff_dialog
from rpm_encrypter.ui.tokens import COLORS, SPACING, TYPE
from .inspect_formatters import build_fingerprint_rows, format_vault_metadata


_RESULTS_HELP = (
    "Vault metadata appears here after Inspect Vault.\n\n"
    "Use Integrity Check to verify structure without a password.\n"
    "Use Verify vs Saved to compare against a previously saved fingerprint."
)


class InspectScreen:
    """Collect Vault Info inputs and drive InspectController."""

    def __init__(self, page: ft.Page, services, shell):
        self.page = page
        self.services = services
        self.shell = shell
        self.current_metadata = {}
        self.current_path = None
        self.current_auth_password = None
        self.current_auth_recovery_key = None
        self._pending_auth_password = None
        self._pending_auth_recovery_key = None
        self._pending_auth_path = None
        self.last_sha = ""

        self.vault_picker = ft.FilePicker()
        self.selective_output_picker = ft.FilePicker()
        self.diff_vault_a_picker = ft.FilePicker()
        self.diff_vault_b_picker = ft.FilePicker()
        self.clipboard = ft.Clipboard()
        # Getter (not the instance) so a swapped `self.clipboard` is honoured.
        self.clipboard_guard = AutoClearClipboard(
            page, shell, services, lambda: self.clipboard, clear_seconds=30
        )

        self.path_field = ft.TextField(
            label="Vault path",
            expand=True,
            on_change=self._on_path_changed,
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
            label=INSPECT_RECOVERY_LABEL,
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
        self.results_text = ft.Text(
            _RESULTS_HELP,
            size=TYPE["caption"]["size"],
            color=COLORS["text_primary"],
            font_family="Courier New",
            selectable=True,
        )
        self.fingerprint_list = ft.Column(
            spacing=8,
            scroll=ft.ScrollMode.AUTO,
            horizontal_alignment=ft.CrossAxisAlignment.STRETCH,
        )

        self.inspect_button = ft.Button("Inspect Vault", on_click=self._start_inspect)
        self.integrity_button = ft.Button("Integrity Check", on_click=self._start_integrity)
        self.verify_button = ft.Button("Verify vs Saved", on_click=self._start_verify)
        self.copy_sha_button = ft.Button("Copy SHA-256", on_click=lambda _e: self.page.run_task(self._copy_sha))
        self.selective_button = ft.Button("Selective Extract", on_click=self._open_selective_extract)
        self.diff_button = ft.Button("Vault Diff", on_click=self._open_vault_diff)
        self.clear_button = ft.Button("Clear All", on_click=self._clear_fingerprints)

    # --- status / results helpers ---
    def _set_results(self, text: str) -> None:
        self.results_text.value = text or "No results."

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
        self._set_attempt_status(remaining, lockout)

    # --- validation ---
    def _selected_path(self):
        raw = (self.path_field.value or "").strip().strip('"')
        if not raw:
            set_screen_status(self.shell, "Select a .vault file", is_error=True)
            return None
        if not raw.lower().endswith(".vault"):
            set_screen_status(self.shell, "Only .vault files can be inspected", is_error=True)
            return None
        path = Path(raw)
        if not path.is_file():
            set_screen_status(self.shell, "Vault file does not exist", is_error=True)
            return None
        return path

    def _on_path_changed(self, _event=None):
        path = self._raw_path()
        if self.current_path is not None and path and Path(path).resolve() != self.current_path.resolve():
            self.current_metadata = {}
            self.current_path = None
            self.current_auth_password = None
            self.current_auth_recovery_key = None

    def _raw_path(self):
        raw = (self.path_field.value or "").strip().strip('"')
        return raw or None

    def _has_current_context(self) -> bool:
        path = self._selected_path()
        if path is None:
            return False
        if self.current_path is None or not self.current_metadata:
            set_screen_status(self.shell, "Inspect Vault first", is_error=True)
            return False
        if path.resolve() != self.current_path.resolve():
            set_screen_status(self.shell, "Path changed. Inspect Vault again.", is_error=True)
            return False
        if self.current_auth_password is None and self.current_auth_recovery_key is None:
            set_screen_status(self.shell, "Inspect Vault again before extracting", is_error=True)
            return False
        return True

    # --- actions ---
    def _start_inspect(self, _event=None):
        if self.services.is_processing:
            return
        path = self._selected_path()
        if path is None:
            return

        password = None
        recovery_key = None
        if self.use_recovery_checkbox.value:
            phrase = (self.recovery_field.value or "").strip()
            if not phrase:
                set_screen_status(self.shell, "Enter your 24-word recovery phrase", is_error=True)
                return
            try:
                recovery_key = mnemonic_to_entropy(phrase)
            except ValueError as exc:
                set_screen_status(self.shell, f"Invalid recovery phrase: {exc}", is_error=True)
                return
        else:
            locked, secs = self.services.limiter.is_locked()
            if locked:
                self._set_attempt_status(self.services.limiter.attempts_remaining(), secs)
                set_screen_status(self.shell, f"Locked out - {secs}s", is_error=True)
                return
            password = self.password_field.value or ""
            if not password:
                set_screen_status(self.shell, "Enter the vault password", is_error=True)
                return

        self.services.is_processing = True
        self.services.cancel_requested = False
        self._pending_auth_path = path
        self._pending_auth_password = password
        self._pending_auth_recovery_key = recovery_key
        self.attempts_text.value = ""
        self.shell.set_busy(self.inspect_button)
        self.shell.safe_update()
        InspectController(self.services).start_inspect(path, password, recovery_key)

    def _start_integrity(self, _event=None):
        if self.services.is_processing:
            return
        path = self._selected_path()
        if path is None:
            return
        self.services.is_processing = True
        self.services.cancel_requested = False
        self.shell.set_busy(self.integrity_button)
        self._set_results("Hashing vault... large files may take a while")
        self.shell.safe_update()
        InspectController(self.services).start_integrity_check(path)

    def _start_verify(self, _event=None):
        if self.services.is_processing:
            return
        path = self._selected_path()
        if path is None:
            return
        self.services.is_processing = True
        self.services.cancel_requested = False
        self.shell.set_busy(self.verify_button)
        self._set_results("Verifying against saved fingerprint...")
        self.shell.safe_update()
        InspectController(self.services).start_verify_saved(path)

    async def _copy_sha(self):
        path = self._selected_path()
        if path is None:
            return
        rec = InspectController.load_fingerprints().get(str(path.resolve()))
        if not rec or not rec.get("sha256"):
            set_screen_status(self.shell, "Run Integrity Check first", is_error=True)
            return
        await self.clipboard_guard.copy(
            rec["sha256"],
            copied_status=f"SHA-256 copied: {rec['sha256'][:16]}...",
            on_error=lambda exc: set_screen_status(
                self.shell, f"Clipboard failed: {exc}", is_error=True
            ),
        )

    def _clear_fingerprints(self, _event=None):
        InspectController.clear_fingerprints()
        self._refresh_fingerprint_panel()
        self.shell.status_text.value = "All fingerprints cleared"
        self.shell.safe_update()

    def _toggle_recovery(self, _event=None):
        use_recovery = bool(self.use_recovery_checkbox.value)
        self.recovery_field.visible = use_recovery
        self.password_field.visible = not use_recovery
        self.shell.safe_update()

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
                    self.path_field.value = raw
                    self._on_path_changed()
            self.shell.safe_update()
        except Exception as exc:
            set_screen_status(self.shell, f"File picker failed: {exc}", is_error=True)

    # --- dialogs ---
    def _open_selective_extract(self, _event=None):
        if self.services.is_processing:
            return
        if not self._has_current_context():
            return
        show_selective_extract_dialog(
            self.page,
            self.shell,
            self.services,
            metadata=self.current_metadata,
            vault_path=self.current_path,
            password=self.current_auth_password,
            recovery_key=self.current_auth_recovery_key,
            output_picker=self.selective_output_picker,
            busy_control=self.selective_button,
        )

    def _open_vault_diff(self, _event=None):
        if self.services.is_processing:
            return
        show_vault_diff_dialog(
            self.page,
            self.shell,
            self.services,
            picker_a=self.diff_vault_a_picker,
            picker_b=self.diff_vault_b_picker,
            busy_control=self.diff_button,
        )

    # --- result handlers (called by AppShell on the poll loop) ---
    def on_inspect_result(self, event: InspectResultEvent):
        error = event.error
        if error:
            self.current_metadata = {}
            self.current_path = None
            self.current_auth_password = None
            self.current_auth_recovery_key = None
            self._set_results(error)
            finish_screen_operation(self.services, self.shell, error)
            return
        self.current_metadata = event.metadata
        path_str = event.path
        self.current_path = Path(path_str) if path_str else self._pending_auth_path
        self.current_auth_password = self._pending_auth_password
        self.current_auth_recovery_key = self._pending_auth_recovery_key
        self._pending_auth_path = None
        self._pending_auth_password = None
        self._pending_auth_recovery_key = None
        self.attempts_text.value = ""
        self._set_results(format_vault_metadata(self.current_metadata))
        finish_screen_operation(self.services, self.shell, "Vault inspection complete")

    def on_integrity_result(self, event: IntegrityResultEvent):
        ok = bool(event.ok)
        if ok:
            self.last_sha = event.sha
        self._set_results(event.msg)
        if ok:
            self._refresh_fingerprint_panel()
        finish_screen_operation(self.services, self.shell, "Integrity check complete" if ok else "Integrity check failed")

    def on_verify_result(self, event: VerifyResultEvent):
        status = event.status
        current_sha = event.current_sha
        saved_sha = event.saved_sha
        recorded = event.recorded
        if status == "missing":
            text = "No saved fingerprint for this vault"
            status_line = "No saved fingerprint"
        elif status == "unchanged":
            text = (
                "UNCHANGED - current SHA-256 matches saved fingerprint\n"
                f"SHA-256 : {current_sha}\n"
                f"Recorded: {recorded}"
            )
            status_line = "Fingerprint unchanged"
        elif status == "mismatch":
            text = (
                "MISMATCH - current SHA-256 differs from saved fingerprint\n"
                f"Current SHA-256: {current_sha}\n"
                f"Saved SHA-256  : {saved_sha}\n"
                f"Saved on       : {recorded}\n\n"
                "A mismatch means this vault file changed since the fingerprint was saved."
            )
            status_line = "Fingerprint mismatch"
        else:
            text = event.error or "Verification error"
            status_line = "Verification error"
        self._set_results(text)
        finish_screen_operation(self.services, self.shell, status_line)

    def on_selective_extract_result(self, event: SelectiveExtractResultEvent):
        if event.error:
            self._set_results(f"Selective Extract failed: {event.error}")
        else:
            self._set_results(
                f"Selective Extract complete\n\nCopied {event.count} file(s) to:\n{event.output_dir}"
            )

    def on_vault_diff_result(self, event: VaultDiffResultEvent):
        self._set_results(event.text or "No diff results.")

    # --- rendering ---
    def _refresh_fingerprint_panel(self) -> None:
        self.fingerprint_list.controls = build_fingerprint_rows(
            InspectController.load_fingerprints()
        )

    def _refresh_and_update(self, _event=None):
        self._refresh_fingerprint_panel()
        self.shell.safe_update()

    def build(self) -> ft.Control:
        register_page_services(
            self.page,
            self.vault_picker,
            self.selective_output_picker,
            self.diff_vault_a_picker,
            self.diff_vault_b_picker,
            self.clipboard,
        )
        self._refresh_fingerprint_panel()
        return ft.Container(
            content=ft.Column(
                [
                    ft.Text(
                        "Vault Info",
                        size=TYPE["page_title"]["size"],
                        weight=ft.FontWeight.W_600,
                        color=COLORS["text_primary"],
                    ),
                    card_panel(
                        "Vault",
                        [
                            ft.Row(
                                [
                                    self.path_field,
                                    ft.Button("Browse", on_click=lambda _e: self.page.run_task(self._pick_vault)),
                                ],
                                spacing=10,
                            ),
                        ],
                    ),
                    card_panel(
                        "Authentication",
                        [
                            self.password_field,
                            self.recovery_field,
                            self.use_recovery_checkbox,
                            self.attempts_text,
                        ],
                    ),
                    card_panel(
                        "Actions",
                        [
                            ft.Row(
                                [self.inspect_button, self.integrity_button, self.verify_button],
                                spacing=10,
                                wrap=True,
                            ),
                            ft.Row(
                                [self.copy_sha_button, self.selective_button, self.diff_button],
                                spacing=10,
                                wrap=True,
                            ),
                        ],
                    ),
                    card_panel(
                        "Results",
                        [
                            ft.Container(
                                content=ft.Column([self.results_text], scroll=ft.ScrollMode.AUTO),
                                height=430,
                                padding=10,
                                bgcolor=COLORS["bg"],
                                border_radius=SPACING["radius"],
                            ),
                        ],
                    ),
                    card_panel(
                        "Saved Fingerprints",
                        [
                            ft.Container(
                                content=self.fingerprint_list,
                                height=260,
                                padding=10,
                                bgcolor=COLORS["bg"],
                                border_radius=SPACING["radius"],
                            ),
                            ft.Row(
                                [
                                    ft.Container(expand=True),
                                    ft.Button("Refresh", on_click=self._refresh_and_update),
                                    self.clear_button,
                                ],
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
