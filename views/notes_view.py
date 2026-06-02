"""Encrypted Notes view for RPM Encrypter.

Phase 26 (ARCH-01) Stage 2: moved verbatim out of RPMEncrypterApp into this
mixin so no single class owns every feature. Uses shared self (self.crypto,
self.msg_queue, self.is_processing, self._set_status, self._log_activity,
self.main_frame) plus the Stage-0 widgets/helpers, so behavior is unchanged.
"""
import threading
from pathlib import Path

import customtkinter as ctk
from tkinter import filedialog, messagebox

from widgets import PasswordEntry, EmptyStateContainer
from file_handler import atomic_output
from crypto_core import AuthenticationError


class NotesViewMixin:
    def _create_notes_frame(self) -> ctk.CTkFrame:
        page_frame = ctk.CTkFrame(self.main_frame, fg_color="#0d1117", corner_radius=0)
        page_frame.grid_columnconfigure(0, weight=1)
        page_frame.grid_rowconfigure(0, weight=1)
        frame = ctk.CTkScrollableFrame(page_frame, fg_color="transparent", corner_radius=0)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)

        ctk.CTkLabel(frame, text="Encrypted Notes", font=ctk.CTkFont(size=22, weight="bold"), text_color="#e6edf3").grid(row=0, column=0, pady=(0, 10), sticky="w")
                     
        ctrl_row = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        ctrl_row.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        
        self.note_pw = PasswordEntry(ctrl_row, placeholder="Note Password", height=36, corner_radius=6)
        self.note_pw.pack(side="left", padx=(0, 10))
        
        ctk.CTkButton(ctrl_row, text="Save Note",
                      command=self._save_note, width=120, fg_color="#00d4aa", text_color="#0d1117", hover_color="#00ffcc", font=ctk.CTkFont(size=14, weight="bold"), height=42, corner_radius=8).pack(side="left", padx=(0, 8))
        ctk.CTkButton(ctrl_row, text="Load Note",
                      command=self._load_note, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="left", padx=(0, 8))
        
        self.note_textbox = ctk.CTkTextbox(
            frame, font=ctk.CTkFont(size=14), wrap="word",

        fg_color="#161b22", text_color="#e6edf3", corner_radius=6)
        self.note_textbox.grid(row=2, column=0, sticky="nsew")
        
        
        self.notes_empty = EmptyStateContainer(frame, "📝", "You don't have your encrypted note yet.")
        self.notes_empty.show()
        
        def _on_note_interaction(*args):
            self.notes_empty.hide()
            
        self.note_textbox.bind("<Button-1>", _on_note_interaction)
        self.note_textbox.bind("<Key>", _on_note_interaction)
        self.note_textbox.bind("<FocusIn>", _on_note_interaction)
        
        def _hide_and_focus(*args):
            self.notes_empty.hide()
            self.note_textbox.focus()
            
        self.notes_empty.bind("<Button-1>", _hide_and_focus)
        self.notes_empty.icon_label.bind("<Button-1>", _hide_and_focus)
        self.notes_empty.msg_label.bind("<Button-1>", _hide_and_focus)
        
        # Hook load event to hide empty state
        original_insert = self.note_textbox.insert
        def _hooked_insert(*args, **kwargs):
            self.notes_empty.hide()
            return original_insert(*args, **kwargs)
        self.note_textbox.insert = _hooked_insert
        
        return page_frame

    def _save_note(self):
        pw = self.note_pw.get()
        if not pw:
            messagebox.showwarning("Password Required", "Please enter a password to encrypt the note.")
            return
            
        text = self.note_textbox.get("0.0", "end-1c")
        if not text:
            messagebox.showwarning("Empty Note", "Please write something to encrypt.")
            return
            
        path = filedialog.asksaveasfilename(
            title="Save Encrypted Note",
            defaultextension=".vault",
            filetypes=[("RPM Vault", "*.vault"), ("All Files", "*.*")]
        )
        if not path: return
        
        self.is_processing = True
        self._set_status("Encrypting note...")
        threading.Thread(target=self._notes_encrypt_worker, args=(text, Path(path), pw), daemon=True).start()

    def _notes_encrypt_worker(self, text, path, pw):
        try:
            # Phase 6 (SEC-04): a note is a .vault too — write atomically so a
            # failure never leaves a partial under the final name. Title is taken
            # from the FINAL path; the bytes are written into the temp.
            atomic_output(path, lambda p: self.crypto.encrypt_note(text, p, pw, note_title=path.name))
            self._log_activity("Note Encrypt", path.name, "Success")
            self.msg_queue.put({"type": "batch_done", "text": f"Note saved to {path.name}"}, timeout=1.0)
        except Exception as e:
            self._log_activity("Note Encrypt", path.name, "Failed", str(e))
            self.msg_queue.put({"type": "batch_done", "text": f"Note save failed: {e}"}, timeout=1.0)

    def _load_note(self):
        pw = self.note_pw.get()
        if not pw:
            messagebox.showwarning("Password Required", "Please enter the password to decrypt.")
            return
            
        path = filedialog.askopenfilename(
            title="Load Encrypted Note",
            filetypes=[("RPM Vault", "*.vault"), ("All Files", "*.*")]
        )
        if not path: return
        
        self.is_processing = True
        self._set_status("Decrypting note...")
        self.note_textbox.configure(state="normal")
        self.note_textbox.delete("0.0", "end")
        threading.Thread(target=self._notes_decrypt_worker, args=(Path(path), pw), daemon=True).start()

    def _notes_decrypt_worker(self, path, pw):
        try:
            text = self.crypto.decrypt_note(path, pw)
            self._log_activity("Note Decrypt", path.name, "Success")
            self.msg_queue.put({"type": "note_decrypted", "text": text}, timeout=1.0)
            self.msg_queue.put({"type": "batch_done", "text": f"Note loaded: {path.name}"}, timeout=1.0)
        except AuthenticationError:
            self._log_activity("Note Decrypt", path.name, "Failed", "Auth Error")
            self.msg_queue.put({"type": "batch_done", "text": "Note load failed: Wrong Password"}, timeout=1.0)
        except Exception as e:
            self._log_activity("Note Decrypt", path.name, "Failed", str(e))
            self.msg_queue.put({"type": "batch_done", "text": f"Note load failed: {e}"}, timeout=1.0)
