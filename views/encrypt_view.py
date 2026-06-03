"""Encrypt view for RPM Encrypter (normal + hidden vaults, recovery-phrase modal,
batch encrypt worker).

Phase 26 (ARCH-01) Stage 10: moved verbatim out of RPMEncrypterApp into this mixin
so no single class owns every feature. Uses shared self (self.crypto, self.packager,
self.wiper, self.stats, self.msg_queue, the progress bars, self.batch_queue,
self._qlog, self._set_status, self._log_activity, self._parse_drop_paths, and the
SettingsViewMixin's self._apply_profile) plus the Stage-0/4/8 widgets/helpers/
constants, so behavior is unchanged.
"""
import os
import queue
import logging
import threading
from pathlib import Path
from typing import List, Optional

import customtkinter as ctk
from tkinter import filedialog, messagebox
from tkinterdnd2 import DND_FILES

from widgets import DragDropArea, RecentBar, PasswordEntry, LogBox
from app_config import push_recent
from app_constants import CONTAINER_SIZE_CHOICES, container_label_to_mb, ZXCVBN_AVAILABLE, zxcvbn
from recovery_dialog_copy import get_recovery_dialog_copy
from crypto_core import (
    generate_recovery_entropy, entropy_to_mnemonic,
    MAX_PAYLOAD_SIZE, PayloadTooLargeError, OperationCancelledError,
)
from file_handler import atomic_output
from log_hygiene import redact_path

logger = logging.getLogger("RPM_GUI")


class EncryptViewMixin:
    def _create_encrypt_frame(self) -> ctk.CTkFrame:
        page_frame = ctk.CTkFrame(self.main_frame, fg_color="#0d1117", corner_radius=0)
        page_frame.grid_columnconfigure(0, weight=1)
        page_frame.grid_rowconfigure(0, weight=1)
        frame = ctk.CTkScrollableFrame(page_frame, fg_color="transparent", corner_radius=0)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(12, weight=1)

        ctk.CTkLabel(frame, text="Encrypt Folders & Files", font=ctk.CTkFont(size=22, weight="bold"), text_color="#e6edf3").grid(row=0, column=0, pady=(0, 12), sticky="w")

        # --- Drop Zone ---
        dz_container = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        dz_container.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        dz_container.grid_columnconfigure(0, weight=1)

        self.encrypt_drop_zone = DragDropArea(dz_container, browse_command=self._add_encrypt_files)
        self.encrypt_drop_zone.grid(row=0, column=0, sticky="ew")
        self.encrypt_drop_zone.drop_target_register(DND_FILES)
        self.encrypt_drop_zone.dnd_bind("<<Drop>>", self._on_encrypt_drop)

        add_btn_row = ctk.CTkFrame(dz_container, fg_color="transparent", corner_radius=0)
        add_btn_row.grid(row=1, column=0, sticky="w", pady=(8, 0))
        ctk.CTkButton(add_btn_row, text="📄  Add File(s)", command=self._add_encrypt_files,
                      fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d",
                      font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="left", padx=(0, 8))
        ctk.CTkButton(add_btn_row, text="📁  Add Folder", command=self._add_encrypt_folder,
                      fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d",
                      font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="left")

        # --- Source list ---
        self.encrypt_sources_row = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        self.encrypt_sources_row.grid(row=2, column=0, sticky="ew", pady=(0, 8))
        self.encrypt_sources_row.grid_columnconfigure(0, weight=1)
        self.encrypt_sources_row.grid_remove() # Hidden by default
        list_row = self.encrypt_sources_row

        self.encrypt_sources = ctk.CTkTextbox(list_row, font=ctk.CTkFont(size=12), fg_color="#161b22", text_color="#e6edf3", corner_radius=6)
        self.encrypt_sources.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self.encrypt_sources.insert("0.0", "No sources selected")
        self.encrypt_sources.configure(state="disabled")

        ctk.CTkButton(list_row, text="Clear",
                      command=self._clear_batch, width=80, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).grid(row=0, column=1)

        # Recent encrypt sources
        self._enc_recent = RecentBar(frame, "enc_sources",
                                     on_select=lambda p: self._add_encrypt_source(p))
        self._enc_recent.grid(row=3, column=0, sticky="w", pady=(0, 6))

        # --- Password ---
        pw_frame = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        pw_frame.grid(row=4, column=0, sticky="ew", pady=(0, 6))
        pw_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(pw_frame, text="Password:", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=0, column=0, padx=(0, 10), sticky="w")
        self.encrypt_pw = PasswordEntry(pw_frame, height=36, corner_radius=6)
        self.encrypt_pw.grid(row=0, column=1, sticky="ew")
        self.encrypt_pw.bind_change(self._on_enc_pw_change)

        # --- Confirm Password ---
        ctk.CTkLabel(pw_frame, text="Confirm Password", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=1, column=1, pady=(0, 6), sticky="w")
        self.encrypt_pw_confirm = PasswordEntry(pw_frame, placeholder="Confirm Password", height=36, corner_radius=6)
        self.encrypt_pw_confirm.grid(row=2, column=1, sticky="ew", pady=(0, 12))

        # --- Strength meter ---
        meter_row = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        meter_row.grid(row=5, column=0, sticky="ew", pady=(0, 8))
        meter_row.grid_columnconfigure(1, weight=1)

        self.strength_bar = ctk.CTkProgressBar(
            meter_row, width=200, height=10, corner_radius=5,

        fg_color="#21262d", progress_color="#00d4aa")
        self.strength_bar.grid(row=0, column=0, sticky="w")
        self.strength_bar.set(0)

        self.strength_label = ctk.CTkLabel(
            meter_row, text="Enter a password", font=ctk.CTkFont(size=14), text_color="#e6edf3")
        self.strength_label.grid(row=0, column=1, padx=(12, 0), sticky="w")

        # --- Hidden Vault Mode ---
        self.hidden_mode_var = ctk.BooleanVar(value=False)
        self.hidden_mode_switch = ctk.CTkSwitch(
            frame, text="Enable Hidden Vault Mode (Plausible Deniability)",
            variable=self.hidden_mode_var,
            font=ctk.CTkFont(size=14, weight="bold"),
            command=self._toggle_hidden_mode,

        fg_color="#30363d", progress_color="#00d4aa", text_color="#e6edf3", button_color="#ffffff")
        self.hidden_mode_switch.grid(row=6, column=0, sticky="w", pady=(8, 8), padx=4)

        # --- Hidden Vault Controls (hidden by default) ---
        self.hidden_frame = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        self.hidden_frame.grid_columnconfigure(1, weight=1)

        # Hidden Password
        ctk.CTkLabel(self.hidden_frame, text="Hidden Password:", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=0, column=0, padx=(10, 10), pady=(10, 6), sticky="w")
        self.hidden_pw = PasswordEntry(self.hidden_frame, height=36, corner_radius=6)
        self.hidden_pw.grid(row=0, column=1, sticky="ew", padx=(0, 10), pady=(10, 6))

        # Confirm Hidden Password
        ctk.CTkLabel(self.hidden_frame, text="Confirm Hidden Password", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=1, column=1, pady=(0, 6), sticky="w")
        self.hidden_pw_confirm = PasswordEntry(self.hidden_frame, placeholder="Confirm Hidden Password", height=36, corner_radius=6)
        self.hidden_pw_confirm.grid(row=2, column=1, sticky="ew", padx=(0, 10), pady=(0, 12))

        # Hidden Files Drop Zone & List
        hd_row = ctk.CTkFrame(self.hidden_frame, fg_color="transparent", corner_radius=0)
        hd_row.grid(row=3, column=0, columnspan=2, sticky="ew", padx=10, pady=(0, 6))
        hd_row.grid_columnconfigure(0, weight=1)
        
        self.hidden_sources_box = ctk.CTkTextbox(hd_row, font=ctk.CTkFont(size=12), fg_color="#161b22", text_color="#e6edf3", corner_radius=6)
        self.hidden_sources_box.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self.hidden_sources_box.insert("0.0", "No hidden sources selected")
        self.hidden_sources_box.configure(state="disabled")
        self._hidden_sources_list = []
        
        hb_col = ctk.CTkFrame(hd_row, fg_color="#0d1117", corner_radius=0)
        hb_col.grid(row=0, column=1)
        ctk.CTkButton(hb_col, text="Browse", command=self._browse_hidden_source, width=80, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(pady=(16, 0))
        ctk.CTkButton(hb_col, text="Clear", command=self._clear_hidden, width=80, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack()

        # Target Size
        ts_row = ctk.CTkFrame(self.hidden_frame, fg_color="transparent", corner_radius=0)
        ts_row.grid(row=4, column=0, columnspan=2, sticky="ew", padx=10, pady=(0, 10))
        ctk.CTkLabel(ts_row, text="Container Size:", font=ctk.CTkFont(size=14), text_color="#e6edf3").pack(side="left", padx=(0, 8))
        # C2/Phase 24: hidden vaults require an EXPLICIT container size (no "Auto")
        # so a small decoy is never auto-placed in a minimal bucket that would
        # betray the hidden compartment.
        self.hidden_size_var = ctk.StringVar(value="100 MB")
        ctk.CTkOptionMenu(ts_row, variable=self.hidden_size_var, values=["10 MB", "100 MB", "500 MB", "1 GB", "5 GB", "10 GB"], fg_color="#161b22", text_color="#e6edf3", button_color="#30363d", height=36, corner_radius=6).pack(side="left")
        ctk.CTkLabel(ts_row, text="(pick a size larger than your data — a larger container is a normal choice)",
                     font=ctk.CTkFont(size=12), text_color="#7d8590").pack(side="left", padx=(8, 0))

        ctk.CTkLabel(
            self.hidden_frame,
            text="Hidden data has no recovery phrase; it requires the hidden password.",
            font=ctk.CTkFont(size=12),
            text_color="#7d8590"
        ).grid(row=5, column=0, columnspan=2, sticky="w", padx=10, pady=(0, 10))

        # --- Options row ---
        opts = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        opts.grid(row=8, column=0, sticky="w", pady=(0, 8))

        ctk.CTkLabel(opts, text="Profile:", font=ctk.CTkFont(size=14), text_color="#e6edf3").pack(side="left", padx=(0, 8))
        self.enc_profile_var = ctk.StringVar(value="Custom")
        self.enc_profile_menu = ctk.CTkOptionMenu(opts, variable=self.enc_profile_var, values=["Custom"], command=self._apply_profile, fg_color="#161b22", text_color="#e6edf3", button_color="#30363d", height=36, corner_radius=6)
        self.enc_profile_menu.pack(side="left", padx=(0, 20))

        self.enc_wipe_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(opts, text="Securely delete originals after encryption",
                        variable=self.enc_wipe_var,
                        font=ctk.CTkFont(size=14),

                        fg_color="#00d4aa", text_color="#e6edf3", border_color="#30363d", checkmark_color="#0d1117").pack(side="left", padx=(0, 20))

        self.enc_same_dir_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(opts, text="Save .vault next to source",
                        variable=self.enc_same_dir_var,
                        font=ctk.CTkFont(size=14),
                        command=self._toggle_enc_outdir,

                        fg_color="#00d4aa", text_color="#e6edf3", border_color="#30363d", checkmark_color="#0d1117").pack(side="left", padx=(0, 10))

        self.compress_var = ctk.BooleanVar(value=False)
        ctk.CTkSwitch(opts, text="Compress Files",
                        variable=self.compress_var,
                        font=ctk.CTkFont(size=14),
                        fg_color="#30363d", progress_color="#00d4aa", button_color="#ffffff", text_color="#e6edf3").pack(side="left", padx=(0, 10))

        # C2 (Phase 24): Container Size selector. "Auto" pads to the smallest
        # 1.25x ladder bucket; an explicit choice sets a larger floor so the
        # on-disk size reveals nothing about the true payload size.
        ctk.CTkLabel(opts, text="Container Size:", font=ctk.CTkFont(size=14), text_color="#e6edf3").pack(side="left", padx=(0, 8))
        self.enc_container_var = ctk.StringVar(value="Auto")
        ctk.CTkOptionMenu(opts, variable=self.enc_container_var, values=CONTAINER_SIZE_CHOICES,
                          fg_color="#161b22", text_color="#e6edf3", button_color="#30363d", height=36, corner_radius=6).pack(side="left", padx=(0, 10))

        # Output directory override
        self._enc_outdir_row = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        self._enc_outdir_row.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(self._enc_outdir_row, text="Output dir:", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=0, column=0, padx=(0, 8), sticky="w")
        self._enc_outdir_entry = ctk.CTkEntry(
            self._enc_outdir_row, font=ctk.CTkFont(size=14),

        fg_color="#161b22", text_color="#e6edf3", border_color="#30363d", placeholder_text_color="#7d8590", height=36, corner_radius=6)
        self._enc_outdir_entry.grid(row=0, column=1, sticky="ew", padx=(0, 6))
        ctk.CTkButton(self._enc_outdir_row, text="Browse",
                      command=self._browse_enc_outdir, width=80, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).grid(row=0, column=2)

        # --- Action button ---
        self.encrypt_btn = ctk.CTkButton(
            frame, text="🔐  Encrypt Batch",
            command=self._process_batch, width=120, fg_color="#00d4aa", text_color="#0d1117", hover_color="#00ffcc", font=ctk.CTkFont(size=14, weight="bold"), height=42, corner_radius=8)
        self.encrypt_btn.grid(row=10, column=0, pady=(8, 4), sticky="w")

        # --- Inline progress row ---
        enc_prog_row = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        enc_prog_row.grid(row=11, column=0, sticky="ew", pady=(0, 4))
        enc_prog_row.grid_columnconfigure(0, weight=1)
        self._enc_progress = ctk.CTkProgressBar(enc_prog_row, height=14, corner_radius=6, fg_color="#21262d", progress_color="#00d4aa")
        self._enc_progress.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self._enc_progress.set(0)
        self._enc_pct_lbl = ctk.CTkLabel(enc_prog_row, text="", width=42, anchor="e", font=ctk.CTkFont(size=14), text_color="#e6edf3")
        self._enc_pct_lbl.grid(row=0, column=1)

        # --- Log ---
        self.enc_log = LogBox(frame, height=140)
        self.enc_log.grid(row=12, column=0, sticky="nsew", pady=(4, 0))
        frame.grid_rowconfigure(12, weight=1)

        return page_frame
    def _toggle_enc_outdir(self) -> None:
        if self.enc_same_dir_var.get():
            self._enc_outdir_row.grid_forget()
        else:
            self._enc_outdir_row.grid(row=9, column=0, sticky="ew", pady=(0, 6))

    def _browse_enc_outdir(self) -> None:
        path = filedialog.askdirectory(title="Select Output Directory")
        if path:
            self._enc_outdir_entry.delete(0, "end")
            self._enc_outdir_entry.insert(0, path)

    def _add_encrypt_files(self) -> None:
        paths = filedialog.askopenfilenames(title="Select File(s) to Encrypt")
        for p in paths:
            self._add_encrypt_source(p)

    def _add_encrypt_folder(self) -> None:
        path = filedialog.askdirectory(title="Select Folder to Encrypt")
        if path:
            self._add_encrypt_source(path)

    def _on_encrypt_drop(self, event) -> None:
        for p in self._parse_drop_paths(event.data):
            self._add_encrypt_source(p)

    def _add_encrypt_source(self, path: str) -> None:
        p = Path(path)
        if not p.exists():
            return
        if any(str(item["path"]) == str(p) for item in self.batch_queue):
            self._set_status(f"Already in queue: {p.name}")
            return
        self.batch_queue.append({"path": p, "type": "folder" if p.is_dir() else "file"})
        push_recent("enc_sources", str(p))
        self._update_enc_source_display()
        self._enc_recent.refresh()
        self._set_status(f"Added: {p.name}")

    def _update_enc_source_display(self) -> None:
        self.encrypt_sources.configure(state="normal")
        self.encrypt_sources.delete("0.0", "end")
        
        total_size = 0
        if self.batch_queue:
            for item in self.batch_queue:
                icon = "" if item["type"] == "folder" else ""
                self.encrypt_sources.insert("end", f"{icon}  {item['path']}\\n")
                try:
                    p = item["path"]
                    if p.is_file(): total_size += p.stat().st_size
                    elif p.is_dir(): total_size += sum(f.stat().st_size for f in p.rglob('*') if f.is_file())
                except: pass
            self.encrypt_drop_zone.update_state(len(self.batch_queue), total_size / (1024*1024))
            self.encrypt_sources_row.grid()
        else:
            self.encrypt_sources.insert("0.0", "No sources selected")
            self.encrypt_drop_zone.update_state(0, 0)
            self.encrypt_sources_row.grid_remove()
        
        self.encrypt_sources.configure(state="disabled")

    def _clear_batch(self) -> None:
        self.batch_queue.clear()
        self._update_enc_source_display()
        
        self.encrypt_pw.clear()
        self.encrypt_pw_confirm.clear()
        if hasattr(self, 'hidden_pw'):
            self.hidden_pw.clear()
        if hasattr(self, 'hidden_pw_confirm'):
            self.hidden_pw_confirm.clear()
            
        if hasattr(self, '_enc_outdir_entry'):
            self._enc_outdir_entry.delete(0, "end")
            
        self._set_status("Queue cleared")

    def _on_enc_pw_change(self, _=None) -> None:
        """Debounced password strength calculation."""
        password = self.encrypt_pw.get()
        if not password:
            self.strength_bar.set(0)
            self.strength_bar.configure(progress_color="#7d8590")
            self.strength_label.configure(text="Enter a password",
                                          text_color="#7d8590")
            return
        
        # Cancel previous timer
        if hasattr(self, '_enc_strength_timer'):
            self.after_cancel(self._enc_strength_timer)
        
        # Schedule strength calculation after 300ms
        self._enc_strength_timer = self.after(300, 
            lambda: self._compute_enc_strength_async(password))

    def _compute_enc_strength_async(self, password: str):
        """Compute password strength in background thread."""
        def compute():
            if ZXCVBN_AVAILABLE:
                try:
                    res = zxcvbn(password)
                    self.msg_queue.put({
                        "type": "enc_password_strength",
                        "score": res["score"],
                        "crack_time": res["crack_times_display"]["offline_slow_hashing_1e4_per_second"]
                    }, timeout=0.1)
                except queue.Full:
                    pass
            else:
                # Simple length-based estimation
                ln = len(password)
                idx = 0 if ln < 8 else 1 if ln < 12 else 2 if ln < 16 else 3 if ln < 20 else 4
                self.msg_queue.put({
                    "type": "enc_password_strength",
                    "score": idx,
                    "crack_time": None
                }, timeout=0.1)
        
        threading.Thread(target=compute, daemon=True).start()


    def _toggle_hidden_mode(self):
        if self.hidden_mode_var.get():
            self.hidden_frame.grid(row=7, column=0, sticky="ew", pady=(0, 8))
        else:
            self.hidden_frame.grid_forget()

    def _browse_hidden_source(self):
        paths = filedialog.askopenfilenames(title="Select Hidden Files")
        for p in paths:
            if p not in self._hidden_sources_list:
                self._hidden_sources_list.append(p)
        self._update_hidden_box()

    def _clear_hidden(self):
        self._hidden_sources_list.clear()
        self._update_hidden_box()

    def _update_hidden_box(self):
        self.hidden_sources_box.configure(state="normal")
        self.hidden_sources_box.delete("0.0", "end")
        if not self._hidden_sources_list:
            self.hidden_sources_box.insert("0.0", "No hidden sources selected")
        else:
            for p in self._hidden_sources_list:
                self.hidden_sources_box.insert("end", f"{Path(p).name}\n")
        self.hidden_sources_box.configure(state="disabled")

    def _process_batch(self) -> None:
        if self.is_processing:
            messagebox.showinfo("Busy", "An operation is already in progress.")
            return
        if not self.batch_queue:
            messagebox.showwarning("Empty Queue", "Please add files or folders to encrypt.")
            return

        password = self.encrypt_pw.get()
        password_confirm = self.encrypt_pw_confirm.get()
        if password != password_confirm:
            messagebox.showwarning("Password Mismatch", "Passwords do not match. Please try again.")
            return

        if not password:
            messagebox.showwarning("Password Required", "Please enter a password.")
            return

        hidden_mode_on = bool(self.hidden_mode_var.get())
        if hidden_mode_on:
            hidden_password = self.hidden_pw.get()
            hidden_password_confirm = self.hidden_pw_confirm.get()
            if hidden_password != hidden_password_confirm:
                messagebox.showwarning("Password Mismatch", "Hidden passwords do not match. Please try again.")
                return

            if not hidden_password:
                messagebox.showwarning("Hidden Password Required", "Please enter a hidden password.")
                return
            if password == hidden_password:
                messagebox.showwarning("Password Error", "Decoy and Hidden passwords must be different.")
                return
            if not self._hidden_sources_list:
                messagebox.showwarning("Hidden Files Required", "Please add files to the hidden vault.")
                return

        # Resolve output directory
        if self.enc_same_dir_var.get():
            out_dir_override = None
        else:
            d = self._enc_outdir_entry.get().strip()
            if not d or not Path(d).is_dir():
                messagebox.showwarning("Invalid Output", "Please select a valid output directory.")
                return
            out_dir_override = Path(d)

        self.is_processing = True
        self._cancel_requested = False
        
        # --- Phase 3: Recovery Key Modal ---
        recovery_key = generate_recovery_entropy()
        mnemonic = entropy_to_mnemonic(recovery_key)
        recovery_copy = get_recovery_dialog_copy(hidden_mode_on)
        
        dialog = ctk.CTkToplevel(self)
        dialog.title(recovery_copy.title)
        dialog.geometry("550x350")
        dialog.configure(fg_color="#0d1117")
        dialog.resizable(False, False)
        dialog.attributes("-topmost", True)
        dialog.grab_set()
        
        scroll = ctk.CTkScrollableFrame(dialog, fg_color="transparent", corner_radius=0)
        scroll.pack(fill="both", expand=True, padx=20, pady=5)
        
        ctk.CTkLabel(scroll, text=recovery_copy.heading, font=ctk.CTkFont(size=14), text_color="#e6edf3").pack(pady=(20, 5))
        ctk.CTkLabel(
            scroll,
            text=recovery_copy.description,
            font=ctk.CTkFont(size=14),
            text_color="#e6edf3",
            wraplength=490,
            justify="left"
        ).pack(pady=(0, 15))
        
        textbox = ctk.CTkTextbox(scroll, wrap="word", font=ctk.CTkFont(size=14), fg_color="#161b22", text_color="#e6edf3", corner_radius=6)
        textbox.pack(padx=10, fill="x")
        textbox.insert("0.0", mnemonic)
        textbox.configure(state="disabled")
        
        confirmed = ctk.BooleanVar(value=False)
        check = ctk.CTkCheckBox(scroll, text=recovery_copy.checkbox_text, variable=confirmed, fg_color="#00d4aa", text_color="#e6edf3", border_color="#30363d", checkmark_color="#0d1117")
        check.pack(pady=20)
        
        btn_frame = ctk.CTkFrame(dialog, fg_color="transparent", corner_radius=0)
        btn_frame.pack(fill="x", side="bottom", pady=10)
        
        result_key = []
        
        def on_continue():
            if not confirmed.get():
                messagebox.showwarning("Confirm", "You must confirm you have saved the phrase.", parent=dialog)
                return
            result_key.append(recovery_key)
            dialog.destroy()
            
        def on_cancel():
            dialog.destroy()
            
        ctk.CTkButton(btn_frame, text="Cancel", command=on_cancel, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="left", padx=10)
        ctk.CTkButton(btn_frame, text="Continue", command=on_continue, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="right", padx=10)
        
        self.wait_window(dialog)
        
        if not result_key:
            self.is_processing = False
            return  # User cancelled the modal
        # -----------------------------------

        self._active_log = self.enc_log
        self.encrypt_btn.configure(state="disabled", text="Encrypting…")
        self.enc_log.clear()
        self.progress_bar.configure(mode="indeterminate")
        self.progress_bar.start()
        self._progress_pct.configure(text="KDF…")
        if hasattr(self, "_enc_progress"):
            self._enc_progress.configure(mode="indeterminate")
            self._enc_progress.start()
        if hasattr(self, "_enc_pct_lbl"):
            self._enc_pct_lbl.configure(text="KDF…")
        self._set_status("Deriving key (Argon2id)…")

        paths = [item["path"] for item in self.batch_queue]

        # F5 FIX: Tkinter is not thread-safe. Snapshot every hidden-mode Tk
        # variable here on the main thread and hand the worker plain Python
        # values. The worker must never call .get() on a Tk variable.
        hidden_password = self.hidden_pw.get() if hidden_mode_on else None
        hidden_size_str = self.hidden_size_var.get()
        hidden_sources = list(self._hidden_sources_list)
        # C2 (Phase 24): snapshot the "Container Size" choice on the main thread
        # (F5 pattern — never call .get() on a Tk var inside the worker).
        container_mb = container_label_to_mb(self.enc_container_var.get())

        self.worker_thread = threading.Thread(
            target=self._batch_encrypt_worker,
            args=(paths, password, self.enc_wipe_var.get(), out_dir_override, result_key[0], getattr(self, "compress_var", None) and self.compress_var.get()),
            kwargs=dict(
                hidden_mode=hidden_mode_on,
                hidden_password=hidden_password,
                hidden_size_str=hidden_size_str,
                hidden_sources=hidden_sources,
                container_mb=container_mb,
            ),
            daemon=True,
        )
        self.worker_thread.start()

    def _batch_encrypt_worker(
        self,
        paths: List[Path],
        password: str,
        secure_wipe: bool,
        out_dir_override: Optional[Path],
        recovery_key: Optional[bytes] = None,
        compress: bool = False,
        hidden_mode: bool = False,
        hidden_password: Optional[str] = None,
        hidden_size_str: Optional[str] = None,
        hidden_sources: Optional[List[str]] = None,
        container_mb: int = 0
    ) -> None:
        total = len(paths)
        success = 0
        total_orig_size = 0
        total_vault_size = 0
        cancelled = False
        
        # F6 FIX: Initialize cleanup/reporting handles up front so control flow
        # tests `is not None` instead of brittle runtime name introspection.
        decoy_tmp = None
        hidden_tmp = None
        out_path = None
        final_vault = None

        # F5 FIX: hidden_mode and the hidden inputs were snapshotted on the main
        # thread and passed in. hidden_sources is a plain list, never a Tk var.
        hidden_sources = list(hidden_sources) if hidden_sources else []
        cancel_check = lambda: self._cancel_requested

        if hidden_mode:
            self._qlog("--- CREATING HIDDEN VAULT ---")
            try:
                # Target size parsing
                size_str = hidden_size_str or "100 MB"
                multiplier = 1024*1024
                if "GB" in size_str: multiplier = 1024*1024*1024
                target_size = int(size_str.split()[0]) * multiplier
                # C2 (Phase 24): the hidden vault's final on-disk size is snapped
                # to a 1.25x ladder bucket with this explicit container as the
                # floor, so it is size-indistinguishable from a normal vault.
                hidden_container_mb = container_label_to_mb(size_str)
                
                h_paths = [Path(p) for p in hidden_sources]

                if len(paths) == 1 and Path(paths[0]).is_dir():
                    dec_meta = self.packager.get_manifest(paths[0], exclude_paths=h_paths)
                elif len(paths) == 1:
                    dec_meta = self.packager.get_manifest(paths[0])
                else:
                    dec_meta = self.packager.get_manifest_multiple(paths, exclude_paths=h_paths)
                if len(h_paths) == 1 and h_paths[0].is_dir():
                    hid_meta = self.packager.get_manifest(h_paths[0])
                elif len(h_paths) == 1:
                    hid_meta = self.packager.get_manifest(h_paths[0])
                else:
                    hid_meta = self.packager.get_manifest_multiple(h_paths)
                dec_meta["type"] = "archive"
                hid_meta["type"] = "archive"

                decoy_total_size = int(dec_meta.get("total_size", 0) or 0)
                hidden_total_size = int(hid_meta.get("total_size", 0) or 0)
                total_orig_size += decoy_total_size + hidden_total_size

                if decoy_total_size > MAX_PAYLOAD_SIZE or hidden_total_size > MAX_PAYLOAD_SIZE:
                    detail = (
                        f"Hidden-vault payload too large (> 32 GiB): "
                        f"decoy={decoy_total_size:,} bytes, hidden={hidden_total_size:,} bytes. "
                        f"Split the data or select smaller sources."
                    )
                    raise PayloadTooLargeError(detail)
                
                self._qlog("Packaging Decoy files...")
                if len(paths) == 1 and Path(paths[0]).is_dir():
                    decoy_tmp = self.packager.package_folder(paths[0], exclude_paths=h_paths, compress=compress, on_skip=lambda m: self._qlog(f"⚠ {m}"), cancel_check=cancel_check)
                else:
                    decoy_tmp = self.packager.package_files(paths, exclude_paths=h_paths, compress=compress, on_skip=lambda m: self._qlog(f"⚠ {m}"), cancel_check=cancel_check)

                self._qlog("Packaging Hidden files...")
                if len(h_paths) == 1 and h_paths[0].is_dir():
                    hidden_tmp = self.packager.package_folder(h_paths[0], compress=compress, on_skip=lambda m: self._qlog(f"⚠ {m}"), cancel_check=cancel_check)
                else:
                    hidden_tmp = self.packager.package_files(h_paths, compress=compress, on_skip=lambda m: self._qlog(f"⚠ {m}"), cancel_check=cancel_check)
                
                # Output path
                out_name = paths[0].name + ".vault"
                if len(paths) > 1:
                    out_name = f"HiddenArchive.vault"
                
                base_dir = out_dir_override if out_dir_override else paths[0].parent
                final_vault = base_dir / out_name
                counter = 1
                orig_out = final_vault
                while final_vault.exists():
                    final_vault = orig_out.with_name(f"{orig_out.stem}_{counter}{orig_out.suffix}")
                    counter += 1
                
                self._qlog(f"Encrypting Hidden Vault -> {final_vault.name}")
                self.msg_queue.put({"type": "progress_start"}, timeout=0.1)

                def prog(done: int, total_b: int):
                    try:
                        self.msg_queue.put({"type": "progress", "done": done, "total": total_b}, timeout=0.01)
                    except:
                        pass
                
                # Determine original filenames for headers
                decoy_filename = paths[0].name if len(paths) == 1 else "DecoyArchive"
                hidden_filename = h_paths[0].name if len(h_paths) == 1 else h_paths[0].parent.name

                # Phase 6 (SEC-04): route the OUTPUT write through atomic_output so a
                # failed hidden-vault creation never leaves a partial under the final
                # .vault name. The two PLAINTEXT input temps are still read as before
                # (and still secure-wiped in `finally`). Capture the returned header.
                captured = {}
                def _write_hidden_vault(p):
                    with open(decoy_tmp, 'rb') as dec_in, open(hidden_tmp, 'rb') as hid_in, open(p, 'wb') as v_out:
                        captured['header'] = self.crypto.encrypt_hidden_vault(
                            dec_in, hid_in, v_out,
                            password_a=password, password_b=hidden_password,
                            target_total_size=target_size,
                            decoy_filename=decoy_filename,
                            hidden_filename=hidden_filename,
                            decoy_metadata=dec_meta,
                            hidden_metadata=hid_meta,
                            progress_callback=prog,
                            recovery_key=recovery_key,
                            target_container_mb=hidden_container_mb,
                            cancel_check=cancel_check
                        )
                atomic_output(final_vault, _write_hidden_vault)
                header = captured.get('header')
                
                self._qlog("Hidden Vault Creation Complete!")
                
                if secure_wipe:
                    self._qlog("Securely wiping original sources...")
                    for s in paths + [Path(p) for p in hidden_sources]:
                        if s.is_dir(): self.wiper.wipe_folder(s, on_skip=lambda m: self._qlog(f"⚠ {m}"))
                        else: self.wiper.wipe_file(s, on_skip=lambda m: self._qlog(f"⚠ {m}"))
                        
                success += 1
                
            except OperationCancelledError:
                cancelled = True
                self._qlog("Cancelling and cleaning up…")
            except Exception as exc:
                self._qlog(f"✗ FAILED: {exc}")
                self._log_activity("Encrypt", "HiddenArchive", "Failed", str(exc))
            finally:
                if decoy_tmp is not None and decoy_tmp.exists(): self.wiper.wipe_file(decoy_tmp)
                if hidden_tmp is not None and hidden_tmp.exists(): self.wiper.wipe_file(hidden_tmp)
                
        else:
            for idx, path in enumerate(paths, 1):
                # Accumulate original size
                try:
                    if Path(path).is_file():
                        total_orig_size += os.path.getsize(path)
                    elif Path(path).is_dir():
                        total_orig_size += sum(os.path.getsize(f) for f in Path(path).rglob('*') if f.is_file())
                except Exception:
                    pass

                # Check cancel flag
                if self._cancel_requested:
                    cancelled = True
                    self._qlog("Operation cancelled by user")
                    break
            
                path = Path(path)
                temp_zip: Optional[Path] = None
            
                try:
                    self._qlog(f"[{idx}/{total}] Packaging  →  {path.name}")
                    manifest = self.packager.get_manifest(path)
                    manifest_size = int(manifest.get("total_size", 0) or 0)
                    if manifest_size > MAX_PAYLOAD_SIZE:
                        detail = (
                            f"Payload too large (> 32 GiB): {manifest_size:,} bytes. "
                            f"Split the data or select a smaller source."
                        )
                        self._qlog(f"[{idx}/{total}] ✗ FAILED: {detail}")
                        self._log_activity("Encrypt", path.name, "Failed", detail)
                        continue

                    temp_zip = (self.packager.package_folder(path, compress=compress, on_skip=lambda m: self._qlog(f"⚠ {m}"), cancel_check=cancel_check)
                                if path.is_dir()
                                else self.packager.package_files([path], compress=compress, on_skip=lambda m: self._qlog(f"⚠ {m}"), cancel_check=cancel_check))
                
                    # Track temp file for cleanup
                    with self._temp_files_lock:
                        self._active_temp_files.append(temp_zip)

                    base_dir = out_dir_override if out_dir_override else path.parent
                    out_path = base_dir / f"{path.name}.vault"
                    counter  = 1
                    orig_out = out_path
                    while out_path.exists():
                        out_path = orig_out.with_name(f"{orig_out.stem}_{counter}{orig_out.suffix}")
                        counter += 1

                    self._qlog(f"[{idx}/{total}] Encrypting →  {path.name}")
                    self.msg_queue.put({"type": "progress_start"}, timeout=0.1)

                    def prog(done: int, total_b: int):
                        try:
                            self.msg_queue.put({"type": "progress", "done": done, "total": total_b}, timeout=0.01)
                        except queue.Full:
                            pass  # Skip progress update if queue full

                    # Phase 6 (SEC-04): write to a same-dir temp, os.replace onto
                    # out_path only on full success → never a partial under the
                    # final .vault name. The lambda runs synchronously inside
                    # atomic_output, so the loop var `path` is bound, not deferred.
                    atomic_output(out_path, lambda p: self.crypto.encrypt_file(
                        temp_zip, p, password,
                        original_filename=path.name,
                        metadata=manifest,
                        progress_callback=prog,
                        recovery_key=recovery_key,
                        target_container_mb=container_mb,
                        cancel_check=cancel_check
                    ))

                    if secure_wipe:
                        self._qlog(f"[{idx}/{total}] Wiping     →  {path.name}")
                        if path.is_dir():
                            self.wiper.wipe_folder(path, on_skip=lambda m: self._qlog(f"⚠ {m}"))
                        else:
                            self.wiper.wipe_file(path, on_skip=lambda m: self._qlog(f"⚠ {m}"))

                    self.stats.add_encrypted(
                        file_count=manifest.get("file_count", 1),
                        byte_count=manifest.get("total_size", 0),
                    )

                    self._qlog(f"[{idx}/{total}] ✓ Done     →  {out_path.name}")
                    success += 1
                    self._log_activity("Encrypt", path.name, "Success", f"Output: {out_path.name}")

                except OperationCancelledError:
                    cancelled = True
                    self._qlog("Cancelling and cleaning up…")
                    break
                except Exception as exc:
                    logger.exception("Encryption failed for %s", redact_path(path))
                    self._qlog(f"[{idx}/{total}] ✗ FAILED: {exc}")
                    self._log_activity("Encrypt", path.name, "Failed", str(exc))
                    try:
                        self.msg_queue.put({"type": "error", "text": f"✗ {path.name}: {exc}"}, timeout=0.1)
                    except queue.Full:
                        pass
            
                finally:
                    # Always remove from tracking list first
                    if temp_zip:
                        with self._temp_files_lock:
                            try:
                                self._active_temp_files.remove(temp_zip)
                            except ValueError:
                                pass
                    
                        # Then try to wipe/delete
                        try:
                            if temp_zip.exists():
                                self.wiper.wipe_file(temp_zip)
                        except Exception as wipe_exc:
                            logger.warning("Failed to wipe temp file %s: %s", redact_path(temp_zip), wipe_exc)
                            try:
                                temp_zip.unlink(missing_ok=True)
                            except Exception:
                                pass

        # After all files are encrypted successfully, before the final batch_done message:
        extra_msg = ""
        if compress:
            try:
                vault_size = os.path.getsize(out_path) if out_path is not None else (os.path.getsize(final_vault) if final_vault is not None else 0)
                if total_orig_size > 0 and vault_size > 0 and vault_size < total_orig_size:
                    ratio = round((1 - vault_size / total_orig_size) * 100)
                    vault_mb = vault_size / (1024 * 1024)
                    extra_msg = f" — Vault created: {vault_mb:.1f} MB ({ratio}% smaller)"
            except Exception:
                pass

        try:
            done_text = (
                f"Cancelled — {success}/{total} done"
                if cancelled
                else f"Batch complete: {success}/{total} encrypted" + extra_msg
            )
            self.msg_queue.put({
                "type": "batch_done",
                "text": done_text,
            }, timeout=1.0)
        except queue.Full:
            logger.warning("Message queue full, batch_done notification dropped")

    # ==========================================================================
    # DECRYPT VIEW
