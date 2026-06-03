"""Decrypt Vault view for RPM Encrypter.

Phase 26 (ARCH-01) Stage 7: moved verbatim out of RPMEncrypterApp into this
mixin so no single class owns every feature. Uses shared self (self.crypto,
self.packager, self.wiper, self.limiter, self.stats, self.msg_queue, the
progress bars, self._qlog, self._set_status, self._log_activity,
self._lockout_check, self._parse_drop_paths, ...) plus the Stage-0 widgets and
helpers, so behavior is unchanged.
"""
import os
import queue
import shutil
import secrets
import logging
import tempfile
import threading
from pathlib import Path
from datetime import datetime
from typing import List, Optional

import customtkinter as ctk
from tkinter import filedialog, messagebox
from tkinterdnd2 import DND_FILES

from widgets import RecentBar, PasswordEntry, LogBox
from app_config import push_recent
from recovery_dialog_copy import DECRYPT_RECOVERY_LABEL
from crypto_core import OperationCancelledError, AuthenticationError, mnemonic_to_entropy
from log_hygiene import redact_path

logger = logging.getLogger("RPM_GUI")


class DecryptViewMixin:
    def _create_decrypt_frame(self) -> ctk.CTkFrame:
        page_frame = ctk.CTkFrame(self.main_frame, fg_color="#0d1117", corner_radius=0)
        page_frame.grid_columnconfigure(0, weight=1)
        page_frame.grid_rowconfigure(0, weight=1)
        frame = ctk.CTkScrollableFrame(page_frame, fg_color="transparent", corner_radius=0)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(6, weight=1)

        ctk.CTkLabel(frame, text="Decrypt Vault", font=ctk.CTkFont(size=22, weight="bold"), text_color="#e6edf3").grid(row=0, column=0, pady=(0, 12), sticky="w")

        # Drop zone
        self.decrypt_drop_zone = ctk.CTkFrame(
            frame, height=90,

        fg_color="transparent", corner_radius=0)
        self.decrypt_drop_zone.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        self.decrypt_drop_zone.grid_columnconfigure(0, weight=1)
        self.decrypt_drop_zone.grid_rowconfigure(0, weight=1)

        dec_drop_lbl = ctk.CTkLabel(
            self.decrypt_drop_zone,
            text="🔒  Drop .vault files here  (or click to browse)  [Ctrl+D]", font=ctk.CTkFont(size=14), text_color="#e6edf3")
        dec_drop_lbl.grid(row=0, column=0, pady=22)

        self.decrypt_drop_zone.drop_target_register(DND_FILES)
        self.decrypt_drop_zone.dnd_bind("<<Drop>>", self._on_decrypt_drop)
        self.decrypt_drop_zone.bind("<Button-1>", lambda _: self._browse_decrypt_source())
        dec_drop_lbl.bind("<Button-1>", lambda _: self._browse_decrypt_source())

        # File list
        self.decrypt_sources = ctk.CTkTextbox(frame, font=ctk.CTkFont(size=12), fg_color="#161b22", text_color="#e6edf3", corner_radius=6)
        self.decrypt_sources.grid(row=2, column=0, sticky="ew", pady=(0, 4))
        self.decrypt_sources.insert("0.0", "No vault files selected")
        self.decrypt_sources.configure(state="disabled")

        # Recent decrypt sources
        self._dec_recent = RecentBar(frame, "dec_sources",
                                     on_select=self._set_decrypt_sources_from_path)
        self._dec_recent.grid(row=3, column=0, sticky="w", pady=(0, 6))

        # Password + output
        form = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        form.grid(row=4, column=0, sticky="ew", pady=(0, 8))
        form.grid_columnconfigure(1, weight=1)

        self.use_recovery_var = ctk.BooleanVar(value=False)
        def toggle_recovery():
            if self.use_recovery_var.get():
                self.decrypt_pw.grid_remove()
                self.recovery_text.grid(row=0, column=1, sticky="ew")
                self._dec_pw_lbl.configure(text="Recovery:")
            else:
                self.recovery_text.grid_remove()
                self.decrypt_pw.grid(row=0, column=1, sticky="ew")
                self._dec_pw_lbl.configure(text="Password:")

        self._dec_pw_lbl = ctk.CTkLabel(form, text="Password:", font=ctk.CTkFont(size=14), text_color="#e6edf3")
        self._dec_pw_lbl.grid(row=0, column=0, padx=(0, 10), pady=4, sticky="nw")
        
        self.decrypt_pw = PasswordEntry(form, height=36, corner_radius=6)
        self.decrypt_pw.grid(row=0, column=1, sticky="ew")
        self.decrypt_pw.bind_key("<Return>", lambda _: self._do_decrypt())
        
        self.recovery_text = ctk.CTkTextbox(form, font=ctk.CTkFont(size=13), wrap="word", fg_color="#161b22", text_color="#e6edf3", corner_radius=6)
        
        ctk.CTkCheckBox(form, text=DECRYPT_RECOVERY_LABEL, variable=self.use_recovery_var, command=toggle_recovery, fg_color="#00d4aa", text_color="#e6edf3", border_color="#30363d", checkmark_color="#0d1117").grid(row=1, column=1, sticky="w", pady=(2, 6))

        ctk.CTkLabel(form, text="Output dir:", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=2, column=0, padx=(0, 10), pady=4, sticky="w")
        dec_out_row = ctk.CTkFrame(form, fg_color="transparent", corner_radius=0)
        dec_out_row.grid(row=2, column=1, sticky="ew")
        dec_out_row.grid_columnconfigure(0, weight=1)
        self.decrypt_output = ctk.CTkEntry(dec_out_row, font=ctk.CTkFont(size=14), fg_color="#161b22", text_color="#e6edf3", border_color="#30363d", placeholder_text_color="#7d8590", height=36, corner_radius=6)
        self.decrypt_output.grid(row=0, column=0, sticky="ew", padx=(0, 6))
        ctk.CTkButton(dec_out_row, text="Browse",
                      command=self._browse_decrypt_output, width=80, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).grid(row=0, column=1)

        # Attempt counter label
        self._dec_attempts_lbl = ctk.CTkLabel(
            frame, text="", font=ctk.CTkFont(size=14), text_color="#e6edf3")
        self._dec_attempts_lbl.grid(row=5, column=0, sticky="w", pady=(0, 4))

        self.decrypt_btn = ctk.CTkButton(
            frame, text="🔓  Decrypt",
            command=self._do_decrypt, width=120, fg_color="#00d4aa", text_color="#0d1117", hover_color="#00ffcc", font=ctk.CTkFont(size=14, weight="bold"), height=42, corner_radius=8)
        self.decrypt_btn.grid(row=6, column=0, pady=(0, 4), sticky="w")

        dec_prog_row = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        dec_prog_row.grid(row=7, column=0, sticky="ew", pady=(0, 4))
        dec_prog_row.grid_columnconfigure(0, weight=1)
        self._dec_progress = ctk.CTkProgressBar(dec_prog_row, height=14, corner_radius=6, fg_color="#21262d", progress_color="#00d4aa")
        self._dec_progress.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self._dec_progress.set(0)
        self._dec_pct_lbl = ctk.CTkLabel(dec_prog_row, text="", width=42, anchor="e", font=ctk.CTkFont(size=14), text_color="#e6edf3")
        self._dec_pct_lbl.grid(row=0, column=1)

        self.dec_log = LogBox(frame, height=140)
        self.dec_log.grid(row=8, column=0, sticky="nsew", pady=(4, 0))
        frame.grid_rowconfigure(8, weight=1)

        return page_frame
    def _on_decrypt_drop(self, event) -> None:
        all_paths = self._parse_drop_paths(event.data)
        vaults = [p for p in all_paths if str(p).lower().endswith(".vault")]
        
        ignored = len(all_paths) - len(vaults)
        if ignored > 0:
            messagebox.showinfo(
                "File Filter",
                f"Added {len(vaults)} vault(s).\nIgnored {ignored} non-vault file(s)."
            )
        
        if vaults:
            self._set_decrypt_sources(vaults)
        elif all_paths:
            messagebox.showwarning("No Vaults", "Please drop .vault files.")

    def _browse_decrypt_source(self) -> None:
        files = filedialog.askopenfilenames(
            title="Select Vault Files",
            filetypes=[("RPM Vault", "*.vault"), ("All Files", "*.*")],
        )
        self._set_decrypt_sources(list(files))

    def _set_decrypt_sources_from_path(self, path: str) -> None:
        self._set_decrypt_sources([path])

    def _set_decrypt_sources(self, paths: List[str]) -> None:
        self.decrypt_paths = paths
        self.decrypt_sources.configure(state="normal")
        self.decrypt_sources.delete("0.0", "end")
        for p in paths:
            self.decrypt_sources.insert("end", f"🔒  {p}\n")
        self.decrypt_sources.configure(state="disabled")
        if paths:
            self.decrypt_output.delete(0, "end")
            self.decrypt_output.insert(0, str(Path(paths[0]).parent))
            for p in paths:
                push_recent("dec_sources", p)
            self._dec_recent.refresh()

    def _browse_decrypt_output(self) -> None:
        path = filedialog.askdirectory(title="Select Output Directory")
        if path:
            self.decrypt_output.delete(0, "end")
            self.decrypt_output.insert(0, path)

    def _clear_decrypt_form(self) -> None:
        self.decrypt_paths = []
        self.decrypt_sources.configure(state="normal")
        self.decrypt_sources.delete("0.0", "end")
        self.decrypt_sources.insert("0.0", "No vault files selected")
        self.decrypt_sources.configure(state="disabled")
        
        self.decrypt_pw.clear()
        self.recovery_text.delete("0.0", "end")
        self.decrypt_output.delete(0, "end")
        
        if self.use_recovery_var.get():
            self.use_recovery_var.set(False)
            self.recovery_text.grid_remove()
            self.decrypt_pw.grid(row=0, column=1, sticky="ew")
            if hasattr(self, '_dec_pw_lbl'):
                self._dec_pw_lbl.configure(text="Password:")

    def _do_decrypt(self) -> None:
        if not self.use_recovery_var.get() and self._lockout_check(self.decrypt_pw):
            return
        if not self.decrypt_paths:
            messagebox.showwarning("No Selection", "Please select vault files to decrypt.")
            return
            
        password = None
        recovery_key = None
        
        if self.use_recovery_var.get():
            phrase = self.recovery_text.get("1.0", "end").strip()
            if not phrase:
                messagebox.showwarning("Phrase Required", "Please enter your 24-word recovery phrase.")
                return
            try:
                recovery_key = mnemonic_to_entropy(phrase)
            except ValueError as e:
                messagebox.showwarning("Invalid Phrase", str(e))
                return
        else:
            password = self.decrypt_pw.get()
            if not password:
                messagebox.showwarning("Password Required", "Please enter the vault password.")
                return
        
        output_dir = Path(self.decrypt_output.get())
        
        # Validate output directory
        if not output_dir.is_dir():
            messagebox.showwarning("Invalid Path", "Output directory does not exist.")
            return
        
        # Check write permission
        test_file = output_dir / f".rpm_test_{secrets.token_hex(4)}"
        try:
            test_file.touch()
            test_file.unlink()
        except PermissionError:
            messagebox.showerror("Permission Denied", 
                                f"Cannot write to directory:\n{output_dir}")
            return
        except Exception as exc:
            messagebox.showerror("Error", f"Directory access failed:\n{exc}")
            return
        
        # Check disk space
        total_vault_size = sum(Path(p).stat().st_size for p in self.decrypt_paths)
        free_space = shutil.disk_usage(output_dir).free
        
        if free_space < total_vault_size * 1.5:
            if not messagebox.askyesno(
                "Low Disk Space",
                f"Available: {free_space / 1024**3:.1f} GB\n"
                f"Required (est.): {total_vault_size * 1.5 / 1024**3:.1f} GB\n\n"
                "Continue anyway?"
            ):
                return

        self.is_processing = True
        self._cancel_requested = False
        self._active_log = self.dec_log
        self.decrypt_btn.configure(state="disabled", text="Decrypting…")
        self.dec_log.clear()
        self._dec_attempts_lbl.configure(text="")
        self.progress_bar.configure(mode="indeterminate")
        self.progress_bar.start()
        self._progress_pct.configure(text="KDF…")
        if hasattr(self, "_dec_progress"):
            self._dec_progress.configure(mode="indeterminate")
            self._dec_progress.start()
        if hasattr(self, "_dec_pct_lbl"):
            self._dec_pct_lbl.configure(text="KDF…")
        self._set_status("Deriving key (Argon2id)…")

        self.worker_thread = threading.Thread(
            target=self._batch_decrypt_worker,
            args=(self.decrypt_paths.copy(), password, output_dir, recovery_key),
            daemon=True,
        )
        self.worker_thread.start()

    def _batch_decrypt_worker(
        self,
        paths: List[str],
        password: Optional[str],
        output_dir: Path,
        recovery_key: Optional[bytes] = None
    ) -> None:
        total = len(paths)
        success = 0
        total_orig_size = 0
        total_vault_size = 0
        auth_error = False
        cancelled = False
        cancel_check = lambda: self._cancel_requested

        for idx, path in enumerate(paths, 1):
            if self._cancel_requested:
                cancelled = True
                self._qlog("Operation cancelled by user")
                break
            
            path = Path(path)
            temp_zip: Optional[Path] = None
            extract_dir: Optional[Path] = None
            
            try:
                temp_fd, temp_name = tempfile.mkstemp(prefix=".rpm_pack_", suffix=".zip", dir=tempfile.gettempdir())
                os.close(temp_fd)
                temp_zip = Path(temp_name)
                
                with self._temp_files_lock:
                    self._active_temp_files.append(temp_zip)

                self._qlog(f"[{idx}/{total}] Decrypting →  {path.name}")
                try:
                    self.msg_queue.put({"type": "progress_start"}, timeout=0.1)
                except queue.Full:
                    pass

                def prog(done: int, total_b: int):
                    try:
                        self.msg_queue.put({"type": "progress", "done": done, "total": total_b}, timeout=0.01)
                    except queue.Full:
                        pass

                # PERF-01 (Phase 12): single KDF pass. decrypt_file derives the
                # keys via the unchanged M2 constant-work pass (exactly two
                # Argon2 derivations: main then hidden, unconditional) and returns
                # the populated header. Calling the metadata verifier first
                # repeated the same two derivations, turning decrypt into four
                # Argon2 calls per password-protected file.
                header = self.crypto.decrypt_file(
                    path,
                    temp_zip,
                    password,
                    progress_callback=prog,
                    recovery_key=recovery_key,
                    cancel_check=cancel_check,
                )

                self._qlog(f"[{idx}/{total}] Extracting →  {header.payload.filename}")
                _fname = header.payload.filename
                _stem  = Path(_fname).stem if Path(_fname).suffix else _fname
                extract_dir = output_dir / _stem
                _counter = 1
                while extract_dir.exists():
                    extract_dir = output_dir / f"{_stem}_{_counter}"
                    _counter += 1

                self.packager.extract_archive(temp_zip, extract_dir, cancel_check=cancel_check)

                self.stats.add_decrypted(byte_count=header.payload.original_size)

                self._qlog(f"[{idx}/{total}] ✓ Restored →  {extract_dir.name}")
                success += 1
                self.limiter.record_success()
                self._log_activity("Decrypt", path.name, "Success", f"Output: {extract_dir.name}")

            except OperationCancelledError:
                cancelled = True
                self._qlog("Cancelling and cleaning up…")
                if extract_dir is not None and extract_dir.exists():
                    try:
                        self.wiper.wipe_folder(extract_dir)
                    except Exception:
                        shutil.rmtree(extract_dir, ignore_errors=True)
                break
            except AuthenticationError:
                auth_error = True
                self.limiter.record_failure()
                self._log_activity("Decrypt", path.name, "Failed", "Authentication Error")
                _, secs = self.limiter.is_locked()
                rem = self.limiter.attempts_remaining()
                if secs:
                    self._qlog(f"[{idx}/{total}] ✗ Wrong password — locked for {secs}s")
                else:
                    self._qlog(f"[{idx}/{total}] ✗ Wrong password — {rem} attempts remaining")
                try:
                    self.msg_queue.put({"type": "auth_error",
                                        "remaining": rem, "lockout": secs}, timeout=0.1)
                except queue.Full:
                    pass
                break

            except Exception as exc:
                logger.exception("Decryption failed for %s", redact_path(path))
                # Partial plaintext may have been written before the failure; shred it.
                if extract_dir is not None and extract_dir.exists():
                    try:
                        self.wiper.wipe_folder(extract_dir)
                    except Exception:
                        shutil.rmtree(extract_dir, ignore_errors=True)
                self._qlog(f"[{idx}/{total}] ✗ FAILED: {exc}")
                self._log_activity("Decrypt", path.name, "Failed", str(exc))

            finally:
                if temp_zip:
                    with self._temp_files_lock:
                        try:
                            self._active_temp_files.remove(temp_zip)
                        except ValueError:
                            pass

                    # H4 FIX: temp_zip is the fully decrypted PLAINTEXT archive. A
                    # bare unlink() leaves a recoverable copy in the output folder's
                    # free space. Route removal through the secure wiper (chunked +
                    # truthful-failure, Phase 17). Failures are logged, not silently
                    # swallowed, but must not break the per-file decrypt loop.
                    try:
                        if temp_zip.exists():
                            self.wiper.wipe_file(temp_zip)
                    except Exception as wipe_exc:
                        logger.warning("Failed to securely wipe temp file %s: %s", redact_path(temp_zip), wipe_exc)

        text = (
            f"Cancelled — {success}/{total} done"
            if cancelled
            else (
                f"Wrong password or corrupted vault — {self.limiter.attempts_remaining()} "
                f"attempts remaining"
                if auth_error
                else f"Batch complete: {success}/{total} decrypted"
            )
        )
        
        try:
            self.msg_queue.put({"type": "batch_done", "text": text}, timeout=1.0)
        except queue.Full:
            logger.warning("Message queue full, batch_done notification dropped")
