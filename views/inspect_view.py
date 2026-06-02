"""Vault Info / Inspect view for RPM Encrypter (inspect, integrity + SHA-256
fingerprints, selective extract, vault diff).

Phase 26 (ARCH-01) Stage 11 (final view): moved verbatim out of RPMEncrypterApp
into this mixin so no single class owns every feature. Uses shared self
(self.inspector, self.crypto, self.packager, self.wiper, self.limiter,
self.msg_queue, self.progress_bar, self._qlog, self._set_status, the shell's
self._log_activity, self._lockout_check) plus the Stage-0 widgets/helpers, so
behavior is unchanged.
"""
import os
import queue
import struct
import shutil
import hashlib
import logging
import tempfile
import threading
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Dict, Any, Tuple

import customtkinter as ctk
from tkinter import filedialog, messagebox

from widgets import PasswordEntry
from app_config import _load_cfg, _save_cfg
from recovery_dialog_copy import INSPECT_RECOVERY_LABEL
from crypto_core import (
    AuthenticationError, OperationCancelledError, mnemonic_to_entropy,
    VAULT_MAGIC, AES_TAG_SIZE, is_supported_vault_version,
)

logger = logging.getLogger("RPM_GUI")


class InspectViewMixin:
    def _create_inspect_frame(self) -> ctk.CTkFrame:
        page_frame = ctk.CTkFrame(self.main_frame, fg_color="#0d1117", corner_radius=0)
        page_frame.grid_columnconfigure(0, weight=1)
        page_frame.grid_rowconfigure(0, weight=1)
        frame = ctk.CTkScrollableFrame(page_frame, fg_color="transparent", corner_radius=0)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(6, weight=1)
        frame.grid_rowconfigure(4, weight=1)

        ctk.CTkLabel(frame, text="Vault Information", font=ctk.CTkFont(size=22, weight="bold"), text_color="#e6edf3").grid(row=0, column=0, pady=(0, 12), sticky="w")

        # --- File + password form ---
        form = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        form.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        form.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(form, text="Vault:", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=0, column=0, padx=(0, 10), pady=4, sticky="w")
        vault_row = ctk.CTkFrame(form, fg_color="transparent", corner_radius=0)
        vault_row.grid(row=0, column=1, sticky="ew")
        vault_row.grid_columnconfigure(0, weight=1)
        self.inspect_path = ctk.CTkEntry(vault_row, font=ctk.CTkFont(size=14), fg_color="#161b22", text_color="#e6edf3", border_color="#30363d", placeholder_text_color="#7d8590", height=36, corner_radius=6)
        self.inspect_path.grid(row=0, column=0, sticky="ew", padx=(0, 6))
        ctk.CTkButton(vault_row, text="Browse",
                      command=self._browse_inspect, width=80, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).grid(row=0, column=1)

        self.ins_use_recovery_var = ctk.BooleanVar(value=False)
        def toggle_ins_recovery():
            if self.ins_use_recovery_var.get():
                self.inspect_pw.grid_remove()
                self.ins_recovery_text.grid(row=1, column=1, sticky="ew")
                pw_lbl.configure(text="Recovery:")
            else:
                self.ins_recovery_text.grid_remove()
                self.inspect_pw.grid(row=1, column=1, sticky="ew")
                pw_lbl.configure(text="Password:")

        pw_lbl = ctk.CTkLabel(form, text="Password:", font=ctk.CTkFont(size=14), text_color="#e6edf3")
        pw_lbl.grid(row=1, column=0, padx=(0, 10), pady=4, sticky="nw")
        
        self.inspect_pw = PasswordEntry(form, height=36, corner_radius=6)
        self.inspect_pw.grid(row=1, column=1, sticky="ew")
        self.inspect_pw.bind_key("<Return>", lambda _: self._do_inspect())
        
        self.ins_recovery_text = ctk.CTkTextbox(form, font=ctk.CTkFont(size=13), wrap="word", fg_color="#161b22", text_color="#e6edf3", corner_radius=6)
        
        ctk.CTkCheckBox(form, text=INSPECT_RECOVERY_LABEL, variable=self.ins_use_recovery_var, command=toggle_ins_recovery, fg_color="#00d4aa", text_color="#e6edf3", border_color="#30363d", checkmark_color="#0d1117").grid(row=2, column=1, sticky="w", pady=(2, 6))

        # --- Action buttons ---
        btn_row = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        btn_row.grid(row=2, column=0, sticky="w", pady=(0, 4))

        btn_row_top = ctk.CTkFrame(btn_row, fg_color="transparent", corner_radius=0)
        btn_row_top.pack(fill="x")
        btn_row_bottom = ctk.CTkFrame(btn_row, fg_color="transparent", corner_radius=0)
        btn_row_bottom.pack(fill="x", pady=(6, 0))

        ctk.CTkButton(btn_row_top, text="📋  Inspect Vault",
                      command=self._do_inspect, width=120, fg_color="#00d4aa", text_color="#0d1117", hover_color="#00ffcc", font=ctk.CTkFont(size=14, weight="bold"), height=42, corner_radius=8).pack(side="left", padx=(0, 8))

        self.integrity_btn = ctk.CTkButton(btn_row_top, text="🔍  Integrity Check",
                      command=self._do_integrity_check, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8)
        self.integrity_btn.pack(side="left", padx=(0, 8))

        ctk.CTkButton(btn_row_top, text="✂️ Selective Extract",
                      command=self._open_selective_extract, width=120, fg_color="#00d4aa", text_color="#0d1117", hover_color="#00ffcc", font=ctk.CTkFont(size=14, weight="bold"), height=42, corner_radius=8).pack(side="left", padx=(0, 8))

        ctk.CTkButton(btn_row_bottom, text="⚖️ Vault Diff",
                      command=self._open_vault_diff, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="left", padx=(0, 8))

        self.verify_btn = ctk.CTkButton(btn_row_bottom, text="🛡  Verify vs Saved",
                      command=self._verify_against_saved, width=120, fg_color="#00d4aa", text_color="#0d1117", hover_color="#00ffcc", font=ctk.CTkFont(size=14, weight="bold"), height=42, corner_radius=8)
        self.verify_btn.pack(side="left", padx=(0, 8))

        ctk.CTkButton(btn_row_bottom, text="📋 Copy SHA-256",
                      command=self._copy_last_sha, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="left")

        # --- Attempt counter ---
        self._ins_attempts_lbl = ctk.CTkLabel(
            frame, text="", font=ctk.CTkFont(size=14), text_color="#e6edf3")
        self._ins_attempts_lbl.grid(row=3, column=0, sticky="w")

        # --- Main results textbox ---
        self.inspect_results = ctk.CTkTextbox(
            frame,
            font=ctk.CTkFont(size=12, family="Courier New"),
            wrap="none",

        fg_color="#161b22", text_color="#e6edf3", corner_radius=6)
        self.inspect_results.grid(row=4, column=0, sticky="nsew", pady=(8, 0))
        self.inspect_results.insert("0.0",
            "Vault metadata appears here after Inspect Vault.\n\n"
            "Use Integrity Check to verify structure without a password.\n"
            "Use Verify vs Saved to compare against a previously saved fingerprint.")
        self.inspect_results.configure(state="disabled")

        # --- Saved fingerprints panel ---
        ctk.CTkLabel(frame,
                     text="Saved Fingerprints", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=5, column=0, sticky="w", pady=(14, 4))

        fp_container = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        fp_container.grid(row=6, column=0, sticky="nsew")
        fp_container.grid_columnconfigure(0, weight=1)
        fp_container.grid_rowconfigure(0, weight=1)

        self._fp_listbox = ctk.CTkTextbox(
            fp_container,
            font=ctk.CTkFont(size=11, family="Courier New"),
            wrap="none",
            state="disabled",

        fg_color="#161b22", text_color="#e6edf3", corner_radius=6)
        self._fp_listbox.grid(row=0, column=0, sticky="nsew", padx=6, pady=(6, 0))

        fp_btn_row = ctk.CTkFrame(fp_container, fg_color="#0d1117", corner_radius=0)
        fp_btn_row.grid(row=1, column=0, sticky="e", padx=6, pady=6)
        ctk.CTkButton(fp_btn_row, text="Refresh",
                      command=self._refresh_fingerprint_panel, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="left", padx=(0, 6))
        ctk.CTkButton(fp_btn_row, text="Clear All",
                      command=self._clear_all_fingerprints, width=80, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="left")

        self._refresh_fingerprint_panel()

        return page_frame

    def _set_inspect_hash_buttons(self, enabled: bool) -> None:
        state = "normal" if enabled else "disabled"
        for attr in ("integrity_btn", "verify_btn"):
            btn = getattr(self, attr, None)
            if btn:
                btn.configure(state=state)

    def _clear_all_fingerprints(self) -> None:
        if not messagebox.askyesno("Clear All Fingerprints",
                                   "Delete all saved SHA-256 fingerprint records?"):
            return
        cfg = _load_cfg()
        cfg["fingerprints"] = {}
        _save_cfg(cfg)
        self._refresh_fingerprint_panel()
        self._set_status("All fingerprints cleared")

    def _browse_inspect(self) -> None:
        path = filedialog.askopenfilename(
            title="Select Vault File",
            filetypes=[("RPM Vault", "*.vault"), ("All Files", "*.*")],
        )
        if path:
            self.inspect_path.delete(0, "end")
            self.inspect_path.insert(0, path)

    def _do_inspect(self) -> None:
        if not self.ins_use_recovery_var.get() and self._lockout_check(self.inspect_pw):
            return
        path_str = self.inspect_path.get().strip()
        
        password = None
        recovery_key = None
        
        if self.ins_use_recovery_var.get():
            phrase = self.ins_recovery_text.get("1.0", "end").strip()
            if not phrase:
                messagebox.showwarning("Required", "Please enter recovery phrase.")
                return
            try:
                recovery_key = mnemonic_to_entropy(phrase)
            except ValueError as e:
                messagebox.showwarning("Invalid", str(e))
                return
        else:
            password = self.inspect_pw.get()
            if not password:
                messagebox.showwarning("Required", "Please select a vault file and enter the password.")
                return
                
        try:
            metadata = self.inspector.inspect(Path(path_str), password=password, recovery_key=recovery_key)
            self._current_inspect_metadata = metadata
            self._current_inspect_path = Path(path_str)
            self._current_inspect_password = password
            self._current_inspect_recovery_key = recovery_key
            
            self.limiter.record_success()
            self._ins_attempts_lbl.configure(text="")
            self._render_inspect_results(metadata)
            self._set_status("Vault inspection complete")
            self._log_activity("Inspect", Path(path_str).name, "Success")
        except AuthenticationError:
            self.limiter.record_failure()
            self._log_activity("Inspect", Path(path_str).name, "Failed", "Authentication Error")
            _, secs = self.limiter.is_locked()
            rem = self.limiter.attempts_remaining()
            if secs:
                self._ins_attempts_lbl.configure(
                    text=f"Wrong password — locked for {secs}s")
            else:
                self._ins_attempts_lbl.configure(
                    text=f"Wrong password — {rem} attempts remaining")
            messagebox.showerror("Access Denied", "Invalid password or corrupted vault envelope.")
        except Exception as exc:
            self._log_activity("Inspect", Path(path_str).name, "Failed", str(exc))
            messagebox.showerror("Error", f"Inspection failed: {exc}")

    def _open_selective_extract(self) -> None:
        if not hasattr(self, '_current_inspect_metadata') or not self._current_inspect_metadata:
            messagebox.showwarning("Inspect First", "Please inspect a vault first to load its manifest.")
            return
            
        metadata = self._current_inspect_metadata
        files = metadata.get("files", [])
        if not files:
            messagebox.showinfo("No Files", "This vault does not contain any individual files to extract.")
            return

        dialog = ctk.CTkToplevel(self)
        dialog.title("Selective Extraction")
        dialog.geometry("600x500")
        dialog.transient(self)
        dialog.grab_set()
        dialog.configure(fg_color="#0d1117")

        scroll_wrapper = ctk.CTkScrollableFrame(dialog, fg_color="transparent", corner_radius=0)
        scroll_wrapper.pack(fill="both", expand=True, padx=20, pady=5)
        
        ctk.CTkLabel(scroll_wrapper, text="Select Files to Extract", font=ctk.CTkFont(size=14), text_color="#e6edf3").pack(pady=(15, 5))
        ctk.CTkLabel(scroll_wrapper, text="Note: AES-GCM requires full decryption to a secure temporary directory first.", font=ctk.CTkFont(size=12), text_color="#7d8590").pack(pady=(0, 10))

        scroll = ctk.CTkFrame(scroll_wrapper, fg_color="transparent", corner_radius=0)
        scroll.pack(fill="both", expand=True)

        file_vars = {}
        for fi in files:
            var = ctk.BooleanVar(value=False)
            file_vars[fi["path"]] = var
            cb = ctk.CTkCheckBox(scroll, text=f"{fi['path']} ({fi['size']:,} bytes)", variable=var, fg_color="#00d4aa", text_color="#e6edf3", border_color="#30363d", checkmark_color="#0d1117")
            cb.pack(anchor="w", pady=2)

        bottom_frame = ctk.CTkFrame(dialog, fg_color="transparent", corner_radius=0)
        bottom_frame.pack(fill="x", side="bottom", padx=20, pady=10)

        out_frame = ctk.CTkFrame(bottom_frame, fg_color="transparent", corner_radius=0)
        out_frame.pack(fill="x", pady=(0, 10))
        ctk.CTkLabel(out_frame, text="Output Directory:", font=ctk.CTkFont(size=14), text_color="#e6edf3").pack(side="left")
        out_entry = ctk.CTkEntry(out_frame, width=250, fg_color="#161b22", text_color="#e6edf3", border_color="#30363d", placeholder_text_color="#7d8590", height=36, corner_radius=6)
        out_entry.pack(side="left", padx=10)
        
        def browse_out():
            d = filedialog.askdirectory()
            if d:
                out_entry.delete(0, "end")
                out_entry.insert(0, d)
                
        ctk.CTkButton(out_frame, text="Browse", command=browse_out, width=80, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="left")

        def do_extract():
            selected = [path for path, var in file_vars.items() if var.get()]
            if not selected:
                messagebox.showwarning("No Selection", "Please select at least one file.", parent=dialog)
                return
            out_dir = out_entry.get().strip()
            if not out_dir or not Path(out_dir).is_dir():
                messagebox.showwarning("Invalid Output", "Please select a valid output directory.", parent=dialog)
                return
                
            orig_size = metadata.get("original_size", 0)
            req_space = orig_size * 1.5
            try:
                free_space_temp = shutil.disk_usage(tempfile.gettempdir()).free
                free_space_out = shutil.disk_usage(out_dir).free
                
                if free_space_temp < req_space:
                    if not messagebox.askyesno("Low Disk Space", "Your system Temp drive may not have enough space for the full extraction. Continue?", parent=dialog):
                        return
                        
                req_out_space = sum([fi["size"] for fi in files if file_vars[fi["path"]].get()])
                if free_space_out < req_out_space:
                    messagebox.showwarning("Low Disk Space", "Your output drive does not have enough space for the selected files.", parent=dialog)
                    return
            except:
                pass
                
            dialog.destroy()
            
            self.is_processing = True
            self.progress_bar.configure(mode="indeterminate")
            self.progress_bar.start()
            self._set_status("Extracting selected files...")
            
            threading.Thread(
                target=self._selective_extract_worker,
                args=(self._current_inspect_path, self._current_inspect_password, self._current_inspect_recovery_key, selected, Path(out_dir)),
                daemon=True
            ).start()

        btn_frame = ctk.CTkFrame(bottom_frame, fg_color="transparent", corner_radius=0)
        btn_frame.pack(pady=10)
        ctk.CTkButton(btn_frame, text="Cancel", command=dialog.destroy, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="left", padx=10)
        ctk.CTkButton(btn_frame, text="Extract", command=do_extract, width=120, fg_color="#00d4aa", text_color="#0d1117", hover_color="#00ffcc", font=ctk.CTkFont(size=14, weight="bold"), height=42, corner_radius=8).pack(side="right", padx=10)

    def _selective_extract_worker(self, vault_path: Path, password: Optional[str], recovery_key: Optional[bytes], selected_files: List[str], output_dir: Path) -> None:
        temp_zip: Optional[Path] = None
        temp_extract_dir: Optional[Path] = None
        success = False
        cancel_check = lambda: self._cancel_requested
        try:
            temp_fd, temp_name = tempfile.mkstemp(suffix=".zip", prefix=".rpm_extract_")
            os.close(temp_fd)
            temp_zip = Path(temp_name)
            
            with self._temp_files_lock:
                self._active_temp_files.append(temp_zip)

            # 1. Full Decryption
            self.crypto.decrypt_file(
                vault_path, temp_zip, password=password, recovery_key=recovery_key,
                cancel_check=cancel_check
            )
            
            # 2. Extract ZIP to temp folder
            temp_extract_dir = Path(tempfile.mkdtemp(prefix=".rpm_extract_dir_"))
            self.packager.extract_archive(temp_zip, temp_extract_dir, cancel_check=cancel_check)
            
            # 3. Copy selected files
            extracted_count = 0
            for sel in selected_files:
                src_path = temp_extract_dir / sel
                if src_path.is_file():
                    dst_path = output_dir / Path(sel).name
                    # Handle name collisions
                    counter = 1
                    orig_dst = dst_path
                    while dst_path.exists():
                        dst_path = orig_dst.with_name(f"{orig_dst.stem}_{counter}{orig_dst.suffix}")
                        counter += 1
                    shutil.copy2(src_path, dst_path)
                    extracted_count += 1
                    
            success = True
            msg = f"Successfully extracted {extracted_count} file(s)."
        except OperationCancelledError:
            self._qlog("Cancelling and cleaning up…")
            msg = "Cancelled — 0/1 done"
        except Exception as e:
            logger.exception("Selective extraction failed")
            msg = f"Extraction failed: {e}"
        finally:
            # 4. Secure Wipe
            if temp_zip:
                with self._temp_files_lock:
                    try:
                        self._active_temp_files.remove(temp_zip)
                    except ValueError:
                        pass
                try:
                    if temp_zip.exists():
                        self.wiper.wipe_file(temp_zip)
                except Exception:
                    pass
            if temp_extract_dir and temp_extract_dir.exists():
                try:
                    self.wiper.wipe_folder(temp_extract_dir)
                except Exception:
                    shutil.rmtree(temp_extract_dir, ignore_errors=True)
                    
            try:
                self.msg_queue.put({"type": "batch_done", "text": msg}, timeout=1.0)
            except queue.Full:
                pass

    def _open_vault_diff(self) -> None:
        dialog = ctk.CTkToplevel(self)
        dialog.title("Vault Diff Tool")
        dialog.geometry("500x350")
        dialog.transient(self)
        dialog.grab_set()
        dialog.configure(fg_color="#0d1117")

        scroll = ctk.CTkScrollableFrame(dialog, fg_color="transparent", corner_radius=0)
        scroll.pack(fill="both", expand=True, padx=20, pady=5)

        ctk.CTkLabel(scroll, text="Compare Vaults", font=ctk.CTkFont(size=14), text_color="#e6edf3").pack(pady=(15, 10))

        # Vault A
        frame_a = ctk.CTkFrame(scroll, fg_color="transparent", corner_radius=0)
        frame_a.pack(fill="x", pady=5)
        ctk.CTkLabel(frame_a, text="Vault A:", width=60, anchor="w", font=ctk.CTkFont(size=14), text_color="#e6edf3").pack(side="left")
        entry_a = ctk.CTkEntry(frame_a, width=200, fg_color="#161b22", text_color="#e6edf3", border_color="#30363d", placeholder_text_color="#7d8590", height=36, corner_radius=6)
        entry_a.pack(side="left", padx=5)
        ctk.CTkButton(frame_a, text="Browse", command=lambda: [entry_a.delete(0, 'end'), entry_a.insert(0, filedialog.askopenfilename())], width=80, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="left")
        
        pw_a = PasswordEntry(frame_a, placeholder="Password A", height=36, corner_radius=6)
        pw_a.pack(side="left", padx=5, fill="x", expand=True)

        # Vault B
        frame_b = ctk.CTkFrame(scroll, fg_color="transparent", corner_radius=0)
        frame_b.pack(fill="x", pady=10)
        ctk.CTkLabel(frame_b, text="Vault B:", width=60, anchor="w", font=ctk.CTkFont(size=14), text_color="#e6edf3").pack(side="left")
        entry_b = ctk.CTkEntry(frame_b, width=200, fg_color="#161b22", text_color="#e6edf3", border_color="#30363d", placeholder_text_color="#7d8590", height=36, corner_radius=6)
        entry_b.pack(side="left", padx=5)
        ctk.CTkButton(frame_b, text="Browse", command=lambda: [entry_b.delete(0, 'end'), entry_b.insert(0, filedialog.askopenfilename())], width=80, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="left")
        
        pw_b = PasswordEntry(frame_b, placeholder="Password B", height=36, corner_radius=6)
        pw_b.pack(side="left", padx=5, fill="x", expand=True)

        def do_diff():
            path_a = entry_a.get().strip()
            path_b = entry_b.get().strip()
            pwa = pw_a.get()
            pwb = pw_b.get()
            if not path_a or not path_b or not pwa or not pwb:
                messagebox.showwarning("Required", "All fields are required.", parent=dialog)
                return
            
            dialog.destroy()
            self.is_processing = True
            self.progress_bar.configure(mode="indeterminate")
            self.progress_bar.start()
            self._set_status("Computing Vault Diff...")
            
            threading.Thread(
                target=self._vault_diff_worker,
                args=(Path(path_a), Path(path_b), pwa, pwb),
                daemon=True
            ).start()

        ctk.CTkButton(dialog, text="Compare", command=do_diff, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(pady=(16, 0))

    def _vault_diff_worker(self, path_a: Path, path_b: Path, pw_a: str, pw_b: str) -> None:
        try:
            with open(path_a, "rb") as f:
                header_a = self.crypto.verify_password_and_get_header(f, pw_a)
            with open(path_b, "rb") as f:
                header_b = self.crypto.verify_password_and_get_header(f, pw_b)
                
            files_a = {f["path"]: f for f in (header_a.payload.metadata.get("files", []) if header_a.payload.metadata else [])}
            files_b = {f["path"]: f for f in (header_b.payload.metadata.get("files", []) if header_b.payload.metadata else [])}
            
            all_paths = set(files_a.keys()).union(set(files_b.keys()))
            
            added = []
            removed = []
            modified = []
            
            for p in sorted(all_paths):
                if p in files_b and p not in files_a:
                    added.append(f"+ {p} ({files_b[p]['size']} bytes)")
                elif p in files_a and p not in files_b:
                    removed.append(f"- {p} ({files_a[p]['size']} bytes)")
                else:
                    fa = files_a[p]
                    fb = files_b[p]
                    if fa['size'] != fb['size'] or fa.get('mtime') != fb.get('mtime'):
                        modified.append(f"~ {p} (Size: {fa['size']} -> {fb['size']})")
                        
            # Format output uses update_ui
            
            def update_ui():
                self.inspect_results.configure(state="normal")
                self.inspect_results.delete("0.0", "end")
                self.inspect_results.insert("end", "═" * 55 + "\n           VAULT DIFF RESULTS\n" + "═" * 55 + "\n")
                self.inspect_results.insert("end", f"  Vault A: {path_a.name}\n  Vault B: {path_b.name}\n" + "─" * 55 + "\n")
                
                self.inspect_results.tag_config("diff_added", foreground="#44ff44")
                self.inspect_results.tag_config("diff_removed", foreground="#ff4444")
                self.inspect_results.tag_config("diff_modified", foreground="#ffcc00")
                
                if not added and not removed and not modified:
                    self.inspect_results.insert("end", "  No differences found in manifests.\n")
                else:
                    if added:
                        self.inspect_results.insert("end", "  ADDED:\n")
                        for x in added: self.inspect_results.insert("end", f"    {x}\n", "diff_added")
                    if removed:
                        self.inspect_results.insert("end", "\n  REMOVED:\n")
                        for x in removed: self.inspect_results.insert("end", f"    {x}\n", "diff_removed")
                    if modified:
                        self.inspect_results.insert("end", "\n  MODIFIED:\n")
                        for x in modified: self.inspect_results.insert("end", f"    {x}\n", "diff_modified")
                self.inspect_results.insert("end", "═" * 55 + "\n")
                self.inspect_results.configure(state="disabled")
            
            self.after(0, update_ui)
            msg = "Vault Diff complete."
            
        except Exception as e:
            logger.exception("Vault Diff failed")
            msg = f"Diff failed: {e}"
        finally:
            try:
                self.msg_queue.put({"type": "batch_done", "text": msg}, timeout=1.0)
            except queue.Full:
                pass

    def _do_integrity_check(self) -> None:
        """Check vault structure, compute SHA-256, save fingerprint record."""
        path_str = self.inspect_path.get().strip()
        if not path_str:
            messagebox.showwarning("No File", "Please select a vault file first.")
            return
        path = Path(path_str).resolve()
        self._set_inspect_hash_buttons(False)
        self.inspect_results.configure(state="normal")
        self.inspect_results.delete("0.0", "end")
        self.inspect_results.insert("0.0", "⏳  Verifying integrity (hashing file)…")
        self.inspect_results.configure(state="disabled")
        self._set_status("Hashing vault… (large files may take a while)")

        def worker():
            try:
                ok, msg, sha = self._check_vault_integrity(path)
                payload = {
                    "type": "integrity_result",
                    "path": str(path),
                    "ok": ok,
                    "msg": msg,
                    "sha": sha,
                }
            except Exception as exc:
                logger.exception("Integrity check failed")
                payload = {
                    "type": "integrity_result",
                    "path": str(path),
                    "ok": False,
                    "msg": str(exc),
                    "sha": "",
                }
            try:
                self.msg_queue.put(payload, timeout=1.0)
            except queue.Full:
                logger.warning("Message queue full, integrity_result dropped")

        threading.Thread(target=worker, daemon=True).start()

    @staticmethod
    def _save_fingerprint(path: Path, sha: str) -> None:
        """Append or update a fingerprint entry in config."""
        cfg = _load_cfg()
        fps = cfg.setdefault("fingerprints", {})
        key = str(path.resolve())
        fps[key] = {
            "filename": path.name,
            "sha256":   sha,
            "size":     path.stat().st_size,
            "recorded": datetime.now().isoformat(timespec="seconds"),
        }
        if len(fps) > 50:
            oldest = sorted(fps, key=lambda k: fps[k]["recorded"])
            for k in oldest[:len(fps) - 50]:
                del fps[k]
        _save_cfg(cfg)

    @staticmethod
    def _load_fingerprints() -> Dict[str, Any]:
        return _load_cfg().get("fingerprints", {})

    def _refresh_fingerprint_panel(self) -> None:
        """Rebuild the saved-fingerprints listbox with background hash verification."""
        if not hasattr(self, "_fp_listbox"):
            return
        
        self._fp_listbox.configure(state="normal")
        self._fp_listbox.delete("0.0", "end")
        fps = self._load_fingerprints()
        
        if not fps:
            self._fp_listbox.insert("0.0", "No fingerprints saved yet.")
            self._fp_listbox.configure(state="disabled")
            return
        
        # Show loading message
        for key, rec in sorted(fps.items(), key=lambda kv: kv[1]["recorded"], reverse=True):
            sz_mb = rec["size"] / (1024 * 1024)
            self._fp_listbox.insert("end", 
                f"⏳  {rec['filename']}  ({sz_mb:.1f} MB)  recorded {rec['recorded']}\n"
                f"      SHA-256: {rec['sha256']}\n"
                f"      Verifying...\n\n")
        
        self._fp_listbox.configure(state="disabled")
        
        # Compute hashes in background
        def verify_fingerprints():
            results = {}
            for key, rec in fps.items():
                p = Path(key)
                if not p.exists():
                    results[key] = ("⚠️ missing", None)
                    continue
                
                try:
                    if p.stat().st_size != rec["size"]:
                        results[key] = ("❌ SIZE MISMATCH", None)
                        continue
                    
                    h = hashlib.sha256()
                    with open(p, "rb") as f:
                        while chunk := f.read(65536):
                            h.update(chunk)
                    
                    match = "✅" if h.hexdigest() == rec["sha256"] else "❌ MISMATCH"
                    results[key] = (match, h.hexdigest())
                except Exception:
                    results[key] = ("⚠️ ERROR", None)
            
            try:
                self.msg_queue.put({"type": "fingerprint_results", "data": results}, timeout=1.0)
            except queue.Full:
                logger.warning("Message queue full, fingerprint results dropped")
        
        threading.Thread(target=verify_fingerprints, daemon=True).start()

    def _copy_last_sha(self) -> None:
        """Copy the SHA-256 of the currently selected vault to clipboard."""
        path_str = self.inspect_path.get().strip()
        if not path_str:
            messagebox.showwarning("No File", "Please run an integrity check first.")
            return
        fps = self._load_fingerprints()
        rec = fps.get(str(Path(path_str).resolve()))
        if not rec:
            messagebox.showwarning("Not Found",
                                   "No saved fingerprint for this vault.\n"
                                   "Run Integrity Check first.")
            return
        self.clipboard_clear()
        self.clipboard_append(rec["sha256"])
        self._set_status(f"SHA-256 copied: {rec['sha256'][:16]}…")

    def _verify_against_saved(self) -> None:
        """Re-hash the current file and compare with its saved fingerprint."""
        path_str = self.inspect_path.get().strip()
        if not path_str:
            messagebox.showwarning("No File", "Please select a vault file first.")
            return
        fps = self._load_fingerprints()
        rec = fps.get(str(Path(path_str).resolve()))
        if not rec:
            messagebox.showwarning("No Record",
                                   "No saved fingerprint for this vault.\n"
                                   "Run Integrity Check first to create one.")
            return
        path = Path(path_str)
        self._set_inspect_hash_buttons(False)
        self._set_status("Hashing vault… (large files may take a while)")

        def worker():
            try:
                _, _, current_sha = self._check_vault_integrity(path)
                payload = {
                    "type": "verify_result",
                    "rec": rec,
                    "current_sha": current_sha,
                }
            except Exception as exc:
                logger.exception("Verify-vs-saved failed")
                payload = {
                    "type": "verify_result",
                    "rec": rec,
                    "current_sha": "",
                    "error": str(exc),
                }
            try:
                self.msg_queue.put(payload, timeout=1.0)
            except queue.Full:
                logger.warning("Message queue full, verify_result dropped")

        threading.Thread(target=worker, daemon=True).start()

    @staticmethod
    def _check_vault_integrity(path: Path) -> Tuple[bool, str, str]:
        """Structural + hash check without password. Returns (ok, message, sha256_hex)."""
        try:
            sz = path.stat().st_size
            min_sz = len(VAULT_MAGIC) + 1 + 4 + 1 + AES_TAG_SIZE
            if sz < min_sz:
                return False, f"File too small ({sz} bytes < {min_sz} minimum)", ""
            
            with open(path, "rb") as f:
                magic = f.read(len(VAULT_MAGIC))
                if magic != VAULT_MAGIC:
                    return False, f"Invalid magic bytes: {magic!r}", ""
                (version,) = struct.unpack("!B", f.read(1))
                if not is_supported_vault_version(version):
                    return False, f"Unsupported version: {version}", ""
                (hlen,) = struct.unpack("!I", f.read(4))
                if hlen > sz:
                    return False, f"Header length field ({hlen}) exceeds file size", ""
            
            h = hashlib.sha256()
            with open(path, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            sha = h.hexdigest()
            msg = (f"Structure valid  ·  Size: {sz:,} bytes\n"
                   f"  SHA-256: {sha}")
            return True, msg, sha
        except Exception as exc:
            return False, str(exc), ""

    def _render_inspect_results(self, metadata: Dict[str, Any]) -> None:
        mb = metadata.get("total_size", metadata.get("original_size", 0)) / (1024 * 1024)
        lines = [
            "═" * 55,
            "           VAULT METADATA",
            "═" * 55,
            "",
            f"  Original Name   : {metadata.get('filename', 'N/A')}",
            f"  Original Size   : {metadata.get('original_size', 0):,} bytes"
            f"  ({mb:.2f} MiB)",
            f"  File Count      : {metadata.get('file_count', 'N/A')}",
            f"  Created         : {metadata.get('created_at', 'N/A')}",
            f"  Source Type     : {metadata.get('source_type', 'N/A')}",
            "",
            "─" * 55,
            "           CRYPTOGRAPHIC PARAMETERS",
            "─" * 55,
            "",
            f"  KDF Algorithm   : {metadata.get('kdf_algorithm', 'N/A')}",
            f"  Envelope Cipher : {metadata.get('encryption', 'N/A')}",
            f"  Payload Cipher  : {metadata.get('payload_encryption', 'N/A')}",
            "",
            f"  Argon2 Memory   : {metadata.get('argon_memory', 'N/A')} KiB",
            f"  Argon2 Iters    : {metadata.get('argon_iterations', 'N/A')}",
            f"  Argon2 Parallel : {metadata.get('argon_parallelism', 'N/A')}",
            "",
            "═" * 55,
        ]
        files = metadata.get("files", [])
        if files:
            lines += ["", "           FILE MANIFEST", "─" * 55, ""]
            for fi in files[:100]:
                lines.append(f"  • {fi['path']}  ({fi['size']:,} bytes)")
            if len(files) > 100:
                lines.append(f"  … and {len(files) - 100} more files")
            lines += ["", "═" * 55]

        self.inspect_results.configure(state="normal")
        self.inspect_results.delete("0.0", "end")
        self.inspect_results.insert("0.0", "\n".join(lines))
        self.inspect_results.configure(state="disabled")

    # ==========================================================================
    # RE-KEY VIEW
    # ==========================================================================

    # ==========================================================================
    # PASSWORD GENERATOR VIEW
    # ==========================================================================

    # ==========================================================================
    # LIBRARY VIEW
    # ==========================================================================

    # ==========================================================================
    # NOTES VIEW
    # ==========================================================================

    # ==========================================================================
    # ACTIVITY VIEW
    # ==========================================================================

    # ==========================================================================
    # SETTINGS VIEW
    # ==========================================================================

