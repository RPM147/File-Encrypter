"""Re-Key Vault view (with version history) for RPM Encrypter.

Phase 26 (ARCH-01) Stage 6: moved verbatim out of RPMEncrypterApp into this
mixin so no single class owns every feature. Uses shared self (self.crypto,
self.versioner, self.stats, self.msg_queue, self.progress_bar, self._qlog,
self._set_status, self._log_activity, ...) plus the Stage-0 widgets/helpers and
the Stage-4 constants, so behavior is unchanged.
"""
import queue
import logging
import threading
from pathlib import Path
from typing import List, Optional

import customtkinter as ctk
from tkinter import filedialog, messagebox

import versioning
from widgets import RecentBar, PasswordEntry, LogBox
from app_config import push_recent
from app_constants import ZXCVBN_AVAILABLE, zxcvbn
from crypto_core import OperationCancelledError, AuthenticationError, CryptoError

logger = logging.getLogger("RPM_GUI")


class RekeyViewMixin:
    def _create_rekey_frame(self) -> ctk.CTkFrame:
        page_frame = ctk.CTkFrame(self.main_frame, fg_color="#0d1117", corner_radius=0)
        page_frame.grid_columnconfigure(0, weight=1)
        page_frame.grid_rowconfigure(0, weight=1)
        frame = ctk.CTkScrollableFrame(page_frame, fg_color="transparent", corner_radius=0)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(5, weight=1)

        ctk.CTkLabel(frame, text="Re-Key Vault", font=ctk.CTkFont(size=22, weight="bold"), text_color="#e6edf3").grid(row=0, column=0, pady=(0, 6), sticky="w")
        ctk.CTkLabel(
            frame,
            text=(
                "Change the vault password without decrypting the payload.\n"
                "Only the small DEK envelope (~200 bytes) is re-encrypted — "
                "instant even for multi-gigabyte vaults."
            ),
            font=ctk.CTkFont(size=12),
            justify="left",

        text_color="#7d8590").grid(row=1, column=0, pady=(0, 14), sticky="w")

        form = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        form.grid(row=2, column=0, sticky="ew", pady=(0, 8))
        form.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(form, text="Vault:", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=0, column=0, padx=(0, 10), pady=5, sticky="w")
        vault_row = ctk.CTkFrame(form, fg_color="transparent", corner_radius=0)
        vault_row.grid(row=0, column=1, sticky="ew")
        vault_row.grid_columnconfigure(0, weight=1)
        self.rekey_path = ctk.CTkEntry(vault_row, font=ctk.CTkFont(size=14), fg_color="#161b22", text_color="#e6edf3", border_color="#30363d", placeholder_text_color="#7d8590", height=36, corner_radius=6)
        self.rekey_path.grid(row=0, column=0, sticky="ew", padx=(0, 6))
        ctk.CTkButton(vault_row, text="Browse",
                      command=self._browse_rekey_vault, width=80, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).grid(row=0, column=1)

        self._rk_recent = RecentBar(frame, "rekey_vaults",
                                    on_select=lambda p: (self.rekey_path.delete(0, "end"),
                                                         self.rekey_path.insert(0, p)))
        self._rk_recent.grid(row=3, column=0, sticky="w", pady=(0, 6))

        ctk.CTkLabel(form, text="Current Password:", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=1, column=0, padx=(0, 10), pady=5, sticky="w")
        self.rekey_old_pw = PasswordEntry(form, height=36, corner_radius=6)
        self.rekey_old_pw.grid(row=1, column=1, sticky="ew")

        ctk.CTkLabel(form, text="New Password:", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=2, column=0, padx=(0, 10), pady=5, sticky="w")
        self.rekey_new_pw = PasswordEntry(form, placeholder="New password", height=36, corner_radius=6)
        self.rekey_new_pw.grid(row=2, column=1, sticky="ew")
        self.rekey_new_pw.bind_change(self._on_rekey_pw_change)

        self.rekey_strength_lbl = ctk.CTkLabel(
            frame, text="", font=ctk.CTkFont(size=14), text_color="#e6edf3")
        self.rekey_strength_lbl.grid(row=4, column=0, sticky="w", pady=(0, 4))

        ctk.CTkLabel(form, text="Confirm New:", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=3, column=0, padx=(0, 10), pady=5, sticky="w")
        self.rekey_confirm_pw = PasswordEntry(form, placeholder="Confirm new password", height=36, corner_radius=6)
        self.rekey_confirm_pw.grid(row=3, column=1, sticky="ew")

        self.rekey_btn = ctk.CTkButton(
            frame, text="⟳  Re-Key Vault",
            command=self._do_rekey, width=120, fg_color="#00d4aa", text_color="#0d1117", hover_color="#00ffcc", font=ctk.CTkFont(size=14, weight="bold"), height=42, corner_radius=8)
        self.rekey_btn.grid(row=5, column=0, pady=(8, 6), sticky="w")

        self.rekey_log = LogBox(frame, height=120)
        self.rekey_log.grid(row=6, column=0, sticky="nsew", pady=(6, 0))
        frame.grid_rowconfigure(6, weight=1)

        # --- VERSION HISTORY PANEL ---
        ctk.CTkLabel(frame, text="Version History", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=7, column=0, sticky="w", pady=(18, 4))

        ctk.CTkLabel(
            frame,
            text="Automatically saved before each Re-Key. Select a vault above, then click Refresh.",
            justify="left", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=8, column=0, sticky="w", pady=(0, 6))

        vh_container = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        vh_container.grid(row=9, column=0, sticky="nsew", pady=(0, 0))
        vh_container.grid_columnconfigure(0, weight=1)
        vh_container.grid_rowconfigure(0, weight=1)
        frame.grid_rowconfigure(9, weight=2)

        self._version_list_box = ctk.CTkTextbox(
            vh_container,
            font=ctk.CTkFont(size=12, family="Courier New"),
            state="disabled",
            wrap="none",

        fg_color="#161b22", text_color="#e6edf3", corner_radius=6)
        self._version_list_box.grid(row=0, column=0, sticky="nsew", padx=6, pady=(6, 0))

        # Store version entries for action buttons
        self._version_entries: List[versioning.VersionEntry] = []
        self._selected_version_idx: Optional[int] = None

        def on_version_click(event):
            """Highlight clicked line and record selection index."""
            widget = event.widget
            idx_str = widget.index(f"@{event.x},{event.y}")
            line_num = int(idx_str.split(".")[0]) - 1  # 0-indexed
            if 0 <= line_num < len(self._version_entries):
                self._selected_version_idx = line_num
                # Highlight selection
                widget.tag_remove("selected", "1.0", "end")
                widget.tag_add("selected", f"{line_num+1}.0", f"{line_num+2}.0")
                widget.tag_config("selected", background="#204060")

        self._version_list_box._textbox.bind("<Button-1>", on_version_click)

        vh_btn_row = ctk.CTkFrame(vh_container, fg_color="#0d1117", corner_radius=0)
        vh_btn_row.grid(row=1, column=0, sticky="w", padx=6, pady=6)
        ctk.CTkButton(vh_btn_row, text="Refresh",
                      command=self._refresh_version_list, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="left", padx=(0, 6))
        ctk.CTkButton(vh_btn_row, text="Restore as Copy",
                      command=self._do_restore_copy, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="left", padx=(0, 6))
        ctk.CTkButton(vh_btn_row, text="Replace Current",
                      command=self._do_replace_current, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="left", padx=(0, 6))
        ctk.CTkButton(vh_btn_row, text="Delete Version",
                      command=self._do_delete_version, width=120, fg_color="#f85149", text_color="#0d1117", hover_color="#ff6e6e", font=ctk.CTkFont(size=14, weight="bold"), height=42, corner_radius=8).pack(side="left")

        return page_frame
    def _refresh_version_list(self) -> None:
        """Populate the version history list for the current vault path in the Re-Key field."""
        if not hasattr(self, '_version_list_box'):
            return
        path_str = self.rekey_path.get().strip()
        if not path_str:
            self._version_list_box.configure(state="normal")
            self._version_list_box.delete("0.0", "end")
            self._version_list_box.insert("end", "  Select a vault in the Vault field above, then click Refresh.")
            self._version_list_box.configure(state="disabled")
            self._version_entries = []
            return

        vault = Path(path_str)
        entries = self.versioner.list_versions(vault)
        entries_reversed = list(reversed(entries))  # Show newest first
        self._version_entries = entries_reversed
        self._selected_version_idx = None

        self._version_list_box.configure(state="normal")
        self._version_list_box.delete("0.0", "end")
        if not entries_reversed:
            if not self.versioner.enabled:
                self._version_list_box.insert("end", "  Versioning is disabled. Enable it in Settings → Vault Versioning.")
            else:
                self._version_list_box.insert("end", "  No versions found for this vault.")
        else:
            for entry in entries_reversed:
                line = f"  {entry.display_timestamp}    {entry.display_size:>10}    {entry.path.name}\n"
                self._version_list_box.insert("end", line)
        self._version_list_box.configure(state="disabled")

    def _get_selected_version(self) -> Optional["versioning.VersionEntry"]:
        """Return the selected VersionEntry, or show a warning and return None."""
        if not self._version_entries:
            messagebox.showwarning("No Versions", "No version history found for this vault.\nRun a Re-Key first to create a version.")
            return None
        if self._selected_version_idx is None or self._selected_version_idx >= len(self._version_entries):
            messagebox.showwarning("No Selection", "Please click on a version entry in the list to select it.")
            return None
        return self._version_entries[self._selected_version_idx]

    def _do_restore_copy(self) -> None:
        """Restore selected version as a new copy beside the original vault."""
        path_str = self.rekey_path.get().strip()
        if not path_str:
            messagebox.showwarning("No Vault", "Please select a vault in the Vault field above.")
            return
        entry = self._get_selected_version()
        if entry is None:
            return
        vault = Path(path_str)
        try:
            copy_path = self.versioner.restore_as_copy(entry, vault)
            self._set_status(f"Restored copy: {copy_path.name}")
            messagebox.showinfo("Restored", f"Version restored as a new copy:\n{copy_path.name}\n\nThe original vault was not modified.")
            self._log_activity("Version Restore", vault.name, "Success", f"Copy: {copy_path.name}")
        except OSError as exc:
            messagebox.showerror("Restore Failed", f"Could not restore version:\n{exc}")

    def _do_replace_current(self) -> None:
        """Atomically replace the current vault with the selected version."""
        path_str = self.rekey_path.get().strip()
        if not path_str:
            messagebox.showwarning("No Vault", "Please select a vault in the Vault field above.")
            return
        entry = self._get_selected_version()
        if entry is None:
            return
        vault = Path(path_str)
        if not messagebox.askyesno(
            "Replace Current Vault?",
            f"This will REPLACE the current vault file with the selected version:\n\n"            f"  Version:  {entry.display_timestamp}\n"            f"  Size:     {entry.display_size}\n\n"            f"The current vault will be overwritten. This cannot be undone.\n"            f"Proceed?",
            icon="warning",
        ):
            return
        try:
            self.versioner.replace_current(entry, vault)
            self._set_status(f"Vault restored from version {entry.display_timestamp}")
            messagebox.showinfo("Restored", f"Vault successfully replaced with version from {entry.display_timestamp}.")
            self._log_activity("Version Replace", vault.name, "Success", f"From: {entry.path.name}")
            self._refresh_version_list()
        except OSError as exc:
            messagebox.showerror("Replace Failed", f"Could not replace vault:\n{exc}")

    def _do_delete_version(self) -> None:
        """Permanently delete the selected version file."""
        entry = self._get_selected_version()
        if entry is None:
            return
        if not messagebox.askyesno(
            "Delete Version?",
            f"Permanently delete this version?\n\n"            f"  {entry.display_timestamp}  ({entry.display_size})\n\n"            f"This cannot be undone.",
        ):
            return
        try:
            self.versioner.delete_version(entry)
            self._refresh_version_list()
            self._set_status("Version deleted")
        except OSError as exc:
            messagebox.showerror("Delete Failed", f"Could not delete version:\n{exc}")

    def _browse_rekey_vault(self) -> None:
        path = filedialog.askopenfilename(
            title="Select Vault to Re-Key",
            filetypes=[("RPM Vault", "*.vault"), ("All Files", "*.*")],
        )
        if path:
            self.rekey_path.delete(0, "end")
            self.rekey_path.insert(0, path)
            push_recent("rekey_vaults", path)
            self._rk_recent.refresh()
            self._refresh_version_list()

    def _on_rekey_pw_change(self, _=None) -> None:
        """Debounced password strength for rekey."""
        pw = self.rekey_new_pw.get()
        if not pw:
            self.rekey_strength_lbl.configure(text="")
            return
        
        if hasattr(self, '_rekey_strength_timer'):
            self.after_cancel(self._rekey_strength_timer)
        
        self._rekey_strength_timer = self.after(300,
            lambda: self._compute_rekey_strength_async(pw))

    def _compute_rekey_strength_async(self, password: str):
        """Background password strength for rekey."""
        def compute():
            if ZXCVBN_AVAILABLE:
                try:
                    res = zxcvbn(password)
                    self.msg_queue.put({
                        "type": "rekey_password_strength",
                        "score": res["score"],
                        "crack_time": res["crack_times_display"]["offline_slow_hashing_1e4_per_second"]
                    }, timeout=0.1)
                except queue.Full:
                    pass
        
        threading.Thread(target=compute, daemon=True).start()

    def _do_rekey(self) -> None:
        if self.is_processing:
            messagebox.showinfo("Busy", "An operation is already in progress.")
            return
        path_str  = self.rekey_path.get().strip()
        old_pw    = self.rekey_old_pw.get()
        new_pw    = self.rekey_new_pw.get()
        confirm   = self.rekey_confirm_pw.get()

        if not path_str:
            messagebox.showwarning("No Vault", "Please select a vault file.")
            return
        if not old_pw:
            messagebox.showwarning("Password Required", "Please enter the current password.")
            return
        if not new_pw:
            messagebox.showwarning("Password Required", "Please enter the new password.")
            return
        if new_pw != confirm:
            messagebox.showerror("Mismatch", "New password and confirmation do not match.")
            return
        if new_pw == old_pw:
            messagebox.showwarning("Same Password",
                                   "New password is the same as the current one.")
            return

        vault = Path(path_str)
        if not vault.is_file():
            messagebox.showwarning("File Not Found", f"Vault not found:\n{vault}")
            return

        self.is_processing = True
        self._cancel_requested = False
        self._active_log = self.rekey_log
        self.rekey_btn.configure(state="disabled", text="Re-Keying…")
        self.rekey_log.clear()
        self.progress_bar.configure(mode="indeterminate")
        self.progress_bar.start()
        self._progress_pct.configure(text="KDF…")
        self._set_status("Deriving key (Argon2id)…")

        self.worker_thread = threading.Thread(
            target=self._rekey_worker,
            args=(vault, old_pw, new_pw),
            daemon=True,
        )
        self.worker_thread.start()

    def _rekey_worker(self, vault: Path, old_pw: str, new_pw: str) -> None:
        cancel_check = lambda: self._cancel_requested
        try:
            self._qlog(f"Re-keying  →  {vault.name}")

            # --- Vault Versioning: save a copy before any modification ---
            if self.versioner.enabled:
                self._qlog("Saving version before re-key…")
                saved = self.versioner.save_version(vault)
                if saved:
                    self._qlog(f"✓ Version saved: {saved.name}")
                    self.after(0, self._refresh_version_list)
                else:
                    self._qlog("⚠ Versioning skipped (disk full or disabled)")
            # ---

            tmp = vault.with_suffix(".rekey.tmp")
            self.crypto.rekey_vault(vault, tmp, old_pw, new_pw, cancel_check=cancel_check)
            tmp.replace(vault)

            self.stats.add_rekeyed()
            self._qlog(f"✓ Re-key complete  →  {vault.name}")
            self._log_activity("Re-Key", vault.name, "Success")
            push_recent("rekey_vaults", str(vault))
            try:
                self.msg_queue.put({
                    "type": "batch_done",
                    "text": f"Re-key complete: {vault.name}",
                }, timeout=1.0)
            except queue.Full:
                pass
        except OperationCancelledError:
            self._qlog("Cancelling and cleaning up…")
            try:
                self.msg_queue.put({
                    "type": "batch_done",
                    "text": "Cancelled — 0/1 done",
                }, timeout=1.0)
            except queue.Full:
                pass
        except AuthenticationError:
            self._qlog("✗ Wrong current password")
            self._log_activity("Re-Key", vault.name, "Failed", "Wrong current password")
            try:
                self.msg_queue.put({
                    "type": "batch_done",
                    "text": "Re-key failed: wrong current password",
                }, timeout=1.0)
            except queue.Full:
                pass
        except CryptoError as exc:
            # F2 FIX: Surface the hidden-compartment re-key guard (and any other
            # CryptoError) with a clear, truthful message instead of a confusing
            # generic failure. Routed through "batch_done" — like the other
            # terminal outcomes in this worker — so the Re-Key button is
            # re-enabled and the UI never looks frozen/broken to the user.
            if "Re-Key is not supported for vaults containing a hidden compartment" in str(exc):
                # Specific, clear error for the F2 guard.
                self._qlog(f"✗ {exc}")
                self._log_activity("Re-Key", vault.name, "Blocked", "Hidden compartment present")
                text = str(exc)
            else:
                logger.exception("Re-key failed for %s", vault)
                self._qlog(f"✗ FAILED: {exc}")
                self._log_activity("Re-Key", vault.name, "Failed", str(exc))
                text = f"Re-key failed: {exc}"
            try:
                self.msg_queue.put({
                    "type": "batch_done",
                    "text": text,
                }, timeout=1.0)
            except queue.Full:
                pass
        except Exception as exc:
            logger.exception("Re-key failed for %s", vault)
            self._qlog(f"✗ FAILED: {exc}")
            self._log_activity("Re-Key", vault.name, "Failed", str(exc))
            try:
                self.msg_queue.put({
                    "type": "batch_done",
                    "text": f"Re-key failed: {exc}",
                }, timeout=1.0)
            except queue.Full:
                pass
        finally:
            tmp = vault.with_suffix(".rekey.tmp")
            if tmp.exists():
                try:
                    tmp.unlink()
                except Exception:
                    pass
