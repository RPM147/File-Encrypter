"""Vault Info / Inspect screen for the Flet UI."""
import asyncio
import shutil
import tempfile
from pathlib import Path

import flet as ft

from crypto_core import mnemonic_to_entropy
from recovery_dialog_copy import INSPECT_RECOVERY_LABEL
from ui_flet.controllers.inspect_controller import InspectController
from ui_flet.tokens import COLORS, SPACING, TYPE


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
        self._clipboard_token = 0
        self._clipboard_clear_seconds = 30
        self._selective_output_field = None
        self._diff_path_a_field = None
        self._diff_path_b_field = None

        self.vault_picker = ft.FilePicker()
        self.selective_output_picker = ft.FilePicker()
        self.diff_vault_a_picker = ft.FilePicker()
        self.diff_vault_b_picker = ft.FilePicker()
        self.clipboard = ft.Clipboard()

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

    def _ensure_services(self) -> None:
        services = self.page.services
        for service in (
            self.vault_picker,
            self.selective_output_picker,
            self.diff_vault_a_picker,
            self.diff_vault_b_picker,
            self.clipboard,
        ):
            if not any(existing is service for existing in services):
                services.append(service)

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

    # --- status / results helpers ---
    def _set_status(self, text: str, is_error=False) -> None:
        if hasattr(self.shell, "show_snackbar"):
            self.shell.show_snackbar(text, is_error=is_error)
            return
        self.shell.status_text.value = text
        self.shell.safe_update()

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

    def _finish_operation(self, status_text: str) -> None:
        self.services.is_processing = False
        self.shell.status_text.value = status_text
        self.shell.progress_bar.value = 0
        self.shell.progress_pct.value = "0%"
        if self.shell.busy_control is not None:
            self.shell.busy_control.disabled = False
            self.shell.busy_control = None
        self.shell.safe_update()

    # --- validation ---
    def _selected_path(self):
        raw = (self.path_field.value or "").strip().strip('"')
        if not raw:
            self._set_status("Select a .vault file", is_error=True)
            return None
        if not raw.lower().endswith(".vault"):
            self._set_status("Only .vault files can be inspected", is_error=True)
            return None
        path = Path(raw)
        if not path.is_file():
            self._set_status("Vault file does not exist", is_error=True)
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
            self._set_status("Inspect Vault first", is_error=True)
            return False
        if path.resolve() != self.current_path.resolve():
            self._set_status("Path changed. Inspect Vault again.", is_error=True)
            return False
        if self.current_auth_password is None and self.current_auth_recovery_key is None:
            self._set_status("Inspect Vault again before extracting", is_error=True)
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
                self._set_status("Enter your 24-word recovery phrase", is_error=True)
                return
            try:
                recovery_key = mnemonic_to_entropy(phrase)
            except ValueError as exc:
                self._set_status(f"Invalid recovery phrase: {exc}", is_error=True)
                return
        else:
            locked, secs = self.services.limiter.is_locked()
            if locked:
                self._set_attempt_status(self.services.limiter.attempts_remaining(), secs)
                self._set_status(f"Locked out - {secs}s", is_error=True)
                return
            password = self.password_field.value or ""
            if not password:
                self._set_status("Enter the vault password", is_error=True)
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
            self._set_status("Run Integrity Check first", is_error=True)
            return
        try:
            await self.clipboard.set(rec["sha256"])
        except Exception as exc:
            self._set_status(f"Clipboard failed: {exc}", is_error=True)
            return
        self._clipboard_token += 1
        token = self._clipboard_token
        self._set_status(f"SHA-256 copied: {rec['sha256'][:16]}...")
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
            self._set_status(f"File picker failed: {exc}", is_error=True)

    async def _pick_selective_output(self):
        try:
            folder = await self.selective_output_picker.get_directory_path()
            if folder and self._selective_output_field is not None:
                self._selective_output_field.value = folder
            self.shell.safe_update()
        except Exception as exc:
            self._set_status(f"Output picker failed: {exc}", is_error=True)

    async def _pick_diff_vault(self, target: str):
        picker = self.diff_vault_a_picker if target == "a" else self.diff_vault_b_picker
        field = self._diff_path_a_field if target == "a" else self._diff_path_b_field
        try:
            files = await picker.pick_files(allow_multiple=False)
            if files and field is not None:
                item = files[0]
                field.value = getattr(item, "path", "") or getattr(item, "name", "")
            self.shell.safe_update()
        except Exception as exc:
            self._set_status(f"Vault picker failed: {exc}", is_error=True)

    # --- dialogs ---
    def _open_selective_extract(self, _event=None):
        if self.services.is_processing:
            return
        if not self._has_current_context():
            return
        files = self.current_metadata.get("files", [])
        if not files:
            self._set_status("No files available for Selective Extract", is_error=True)
            return

        checks = []
        for item in files:
            path = item.get("path", "")
            size = int(item.get("size", 0) or 0)
            checks.append(
                ft.Checkbox(
                    label=f"{path} ({size:,} bytes)",
                    value=False,
                    data=path,
                    active_color=COLORS["accent"],
                    label_style=ft.TextStyle(size=TYPE["body"]["size"], color=COLORS["text_primary"]),
                )
            )

        self._selective_output_field = ft.TextField(
            label="Output directory",
            expand=True,
            color=COLORS["text_primary"],
            border_color=COLORS["border"],
            focused_border_color=COLORS["accent"],
        )

        def _cancel(_e=None):
            if hasattr(self.page, "pop_dialog"):
                self.page.pop_dialog()
            self.shell.safe_update()

        def _extract(_e=None):
            selected = [c.data for c in checks if c.value]
            if not selected:
                self._set_status("Select at least one file", is_error=True)
                return
            out_raw = (self._selective_output_field.value or "").strip()
            out_dir = Path(out_raw)
            if not out_raw or not out_dir.is_dir():
                self._set_status("Select a valid output directory", is_error=True)
                return
            try:
                if InspectController.temp_space_warning_needed(
                    self.current_metadata,
                    shutil.disk_usage(tempfile.gettempdir()).free,
                ):
                    self._set_status("Temp drive may not have enough free space", is_error=True)
                    return
                selected_size = InspectController.estimate_selected_size(self.current_metadata, selected)
                if shutil.disk_usage(out_dir).free < selected_size:
                    self._set_status("Output drive does not have enough free space", is_error=True)
                    return
            except Exception:
                pass

            if hasattr(self.page, "pop_dialog"):
                self.page.pop_dialog()
            self.services.is_processing = True
            self.services.cancel_requested = False
            self.shell.set_busy(self.selective_button)
            self.shell.status_text.value = "Extracting selected files..."
            self.shell.safe_update()
            InspectController(self.services).start_selective_extract(
                self.current_path,
                self.current_auth_password,
                self.current_auth_recovery_key,
                selected,
                out_dir,
            )

        dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text("Selective Extract"),
            content=ft.Container(
                width=620,
                height=430,
                content=ft.Column(
                    [
                        ft.Text(
                            "Full decrypt to a secure temporary archive is required first.",
                            size=TYPE["caption"]["size"],
                            color=COLORS["text_secondary"],
                        ),
                        ft.Container(
                            content=ft.Column(checks, scroll=ft.ScrollMode.AUTO),
                            height=260,
                            padding=10,
                            bgcolor=COLORS["bg"],
                            border_radius=SPACING["radius"],
                        ),
                        ft.Row(
                            [
                                self._selective_output_field,
                                ft.Button("Browse", on_click=lambda _e: self.page.run_task(self._pick_selective_output)),
                            ],
                            spacing=10,
                        ),
                    ],
                    spacing=12,
                ),
            ),
            actions=[
                ft.Button("Cancel", on_click=_cancel),
                ft.Button("Extract", on_click=_extract),
            ],
        )
        if hasattr(self.page, "show_dialog"):
            self.page.show_dialog(dialog)
            self.shell.safe_update()
        else:
            self._set_status("Dialog unavailable", is_error=True)

    def _open_vault_diff(self, _event=None):
        if self.services.is_processing:
            return

        self._diff_path_a_field = ft.TextField(label="Vault A path", expand=True)
        self._diff_path_b_field = ft.TextField(label="Vault B path", expand=True)
        pw_a_field = ft.TextField(label="Vault A password", password=True, can_reveal_password=True)
        pw_b_field = ft.TextField(label="Vault B password", password=True, can_reveal_password=True)

        def _cancel(_e=None):
            if hasattr(self.page, "pop_dialog"):
                self.page.pop_dialog()
            self.shell.safe_update()

        def _compare(_e=None):
            path_a = Path((self._diff_path_a_field.value or "").strip().strip('"'))
            path_b = Path((self._diff_path_b_field.value or "").strip().strip('"'))
            pw_a = pw_a_field.value or ""
            pw_b = pw_b_field.value or ""
            if not path_a.is_file() or not path_b.is_file() or not pw_a or not pw_b:
                self._set_status("Vault paths and passwords are required", is_error=True)
                return
            if hasattr(self.page, "pop_dialog"):
                self.page.pop_dialog()
            self.services.is_processing = True
            self.services.cancel_requested = False
            self.shell.set_busy(self.diff_button)
            self.shell.status_text.value = "Computing Vault Diff..."
            self.shell.safe_update()
            InspectController(self.services).start_vault_diff(path_a, pw_a, path_b, pw_b)

        dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text("Vault Diff"),
            content=ft.Container(
                width=620,
                content=ft.Column(
                    [
                        ft.Row(
                            [
                                self._diff_path_a_field,
                                ft.Button("Browse", on_click=lambda _e: self.page.run_task(self._pick_diff_vault, "a")),
                            ],
                            spacing=10,
                        ),
                        pw_a_field,
                        ft.Row(
                            [
                                self._diff_path_b_field,
                                ft.Button("Browse", on_click=lambda _e: self.page.run_task(self._pick_diff_vault, "b")),
                            ],
                            spacing=10,
                        ),
                        pw_b_field,
                    ],
                    spacing=12,
                ),
            ),
            actions=[
                ft.Button("Cancel", on_click=_cancel),
                ft.Button("Compare", on_click=_compare),
            ],
        )
        if hasattr(self.page, "show_dialog"):
            self.page.show_dialog(dialog)
            self.shell.safe_update()
        else:
            self._set_status("Dialog unavailable", is_error=True)

    # --- result handlers (called by AppShell on the poll loop) ---
    def on_inspect_result(self, msg):
        error = msg.get("error", "")
        if error:
            self.current_metadata = {}
            self.current_path = None
            self.current_auth_password = None
            self.current_auth_recovery_key = None
            self._set_results(error)
            self._finish_operation(error)
            return
        self.current_metadata = msg.get("metadata", {})
        path_str = msg.get("path", "")
        self.current_path = Path(path_str) if path_str else self._pending_auth_path
        self.current_auth_password = self._pending_auth_password
        self.current_auth_recovery_key = self._pending_auth_recovery_key
        self._pending_auth_path = None
        self._pending_auth_password = None
        self._pending_auth_recovery_key = None
        self.attempts_text.value = ""
        self._set_results(self._format_metadata(self.current_metadata))
        self._finish_operation("Vault inspection complete")

    def on_integrity_result(self, msg):
        ok = bool(msg.get("ok", False))
        if ok:
            self.last_sha = msg.get("sha", "")
        self._set_results(msg.get("msg", ""))
        if ok:
            self._refresh_fingerprint_panel()
        self._finish_operation("Integrity check complete" if ok else "Integrity check failed")

    def on_verify_result(self, msg):
        status = msg.get("status", "")
        current_sha = msg.get("current_sha", "")
        saved_sha = msg.get("saved_sha", "")
        recorded = msg.get("recorded", "")
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
            text = msg.get("error", "Verification error")
            status_line = "Verification error"
        self._set_results(text)
        self._finish_operation(status_line)

    def on_selective_extract_result(self, msg):
        if msg.get("error"):
            self._set_results(f"Selective Extract failed: {msg.get('error')}")
        else:
            self._set_results(
                f"Selective Extract complete\n\nCopied {msg.get('count', 0)} file(s) to:\n{msg.get('output_dir', '')}"
            )

    def on_vault_diff_result(self, msg):
        self._set_results(msg.get("text", "No diff results."))

    # --- rendering ---
    def _format_metadata(self, metadata):
        mb = metadata.get("total_size", metadata.get("original_size", 0)) / (1024 * 1024)
        lines = [
            "=" * 55,
            "VAULT METADATA",
            "=" * 55,
            "",
            f"Original Name   : {metadata.get('filename', 'N/A')}",
            f"Original Size   : {metadata.get('original_size', 0):,} bytes ({mb:.2f} MiB)",
            f"File Count      : {metadata.get('file_count', 'N/A')}",
            f"Created         : {metadata.get('created_at', 'N/A')}",
            f"Source Type     : {metadata.get('source_type', 'N/A')}",
            "",
            "-" * 55,
            "CRYPTOGRAPHIC PARAMETERS",
            "-" * 55,
            "",
            f"KDF Algorithm   : {metadata.get('kdf_algorithm', 'N/A')}",
            f"Envelope Cipher : {metadata.get('encryption', 'N/A')}",
            f"Payload Cipher  : {metadata.get('payload_encryption', 'N/A')}",
            "",
            f"Argon2 Memory   : {metadata.get('argon_memory', 'N/A')} KiB",
            f"Argon2 Iters    : {metadata.get('argon_iterations', 'N/A')}",
            f"Argon2 Parallel : {metadata.get('argon_parallelism', 'N/A')}",
            "",
            "=" * 55,
        ]
        files = metadata.get("files", [])
        if files:
            lines += ["", "FILE MANIFEST", "-" * 55, ""]
            for fi in files[:100]:
                lines.append(f"- {fi.get('path', '')} ({fi.get('size', 0):,} bytes)")
            if len(files) > 100:
                lines.append(f"... and {len(files) - 100} more files")
            lines += ["", "=" * 55]
        return "\n".join(lines)

    def _refresh_fingerprint_panel(self) -> None:
        fps = InspectController.load_fingerprints()
        if not fps:
            self.fingerprint_list.controls = [
                ft.Text(
                    "No fingerprints saved yet.",
                    size=TYPE["body"]["size"],
                    color=COLORS["text_secondary"],
                )
            ]
            return

        rows = []
        for key, rec in sorted(
            fps.items(), key=lambda kv: kv[1].get("recorded", ""), reverse=True
        ):
            sz_mb = rec.get("size", 0) / (1024 * 1024)
            sha16 = rec.get("sha256", "")[:16]
            rows.append(
                ft.Container(
                    content=ft.Column(
                        [
                            ft.Text(
                                f"{rec.get('filename', '?')}  ({sz_mb:.1f} MiB)  recorded {rec.get('recorded', '')}",
                                size=TYPE["body"]["size"],
                                color=COLORS["text_primary"],
                            ),
                            ft.Text(
                                f"SHA-256: {sha16}...  |  {key}",
                                size=TYPE["caption"]["size"],
                                color=COLORS["text_secondary"],
                            ),
                        ],
                        spacing=2,
                    ),
                    padding=ft.Padding.symmetric(horizontal=10, vertical=6),
                    bgcolor=COLORS["bg"],
                    border_radius=SPACING["radius"],
                )
            )
        self.fingerprint_list.controls = rows

    def _refresh_and_update(self, _event=None):
        self._refresh_fingerprint_panel()
        self.shell.safe_update()

    def build(self) -> ft.Control:
        self._ensure_services()
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
                    self._panel(
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
                    self._panel(
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
                    self._panel(
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
