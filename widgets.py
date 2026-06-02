"""Reusable CustomTkinter widgets for RPM Encrypter.

Phase 26 (ARCH-01) Stage 0: extracted verbatim from gui_app.py. gui_app
re-imports these names. RecentBar uses get_recent from app_config.
"""
import customtkinter as ctk
from datetime import datetime
from functools import partial
from pathlib import Path
from tkinter import filedialog, messagebox

from app_config import get_recent


class PasswordEntry(ctk.CTkFrame):
    """
    A CTkEntry with a show/hide toggle button bundled beside it.
    """

    def __init__(self, master, placeholder: str = "Password", **kw):
        super().__init__(master, fg_color="transparent", **kw)
        self.grid_columnconfigure(0, weight=1)

        self._entry = ctk.CTkEntry(
            self,
            show="•",
            placeholder_text=placeholder,
            font=ctk.CTkFont(size=14),

        fg_color="#161b22", text_color="#e6edf3", border_color="#30363d", placeholder_text_color="#7d8590", height=36, corner_radius=6)
        self._entry.grid(row=0, column=0, sticky="ew", padx=(0, 6))

        self._visible = False
        self._toggle_btn = ctk.CTkButton(
            self,
            text="👁",
            command=self._toggle, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8)
        self._toggle_btn.grid(row=0, column=1)

    def _toggle(self):
        self._visible = not self._visible
        self._entry.configure(show="" if self._visible else "•")

    def get(self) -> str:
        return self._entry.get()

    def set(self, value: str) -> None:
        self._entry.delete(0, "end")
        self._entry.insert(0, value)

    def clear(self) -> None:
        self._entry.delete(0, "end")
        self._visible = False
        self._entry.configure(show="•")

    def bind_key(self, sequence: str, callback) -> None:
        self._entry.bind(sequence, callback)

    def bind_change(self, callback) -> None:
        self._entry.bind("<KeyRelease>", callback)


class LogBox(ctk.CTkFrame):
    """
    A read-only, auto-scrolling log display backed by a CTkTextbox.
    """

    def __init__(self, master, height: int = 180, **kw):
        super().__init__(master, fg_color="transparent", **kw)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._box = ctk.CTkTextbox(
            self,
            font=ctk.CTkFont(size=12, family="Courier New"),
            wrap="word",
            state="disabled",

        fg_color="#161b22", text_color="#e6edf3", corner_radius=6)
        self._box.grid(row=0, column=0, sticky="nsew")

        btn_row = ctk.CTkFrame(self, fg_color="transparent", corner_radius=0)
        btn_row.grid(row=1, column=0, sticky="e", pady=(4, 0))
        ctk.CTkButton(
            btn_row, text="Clear Log",
            command=self.clear, width=80, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="left", padx=(0, 6))
        ctk.CTkButton(
            btn_row, text="Export Log",
            command=self.export_to_file, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="left")

    def write(self, msg: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self._box.configure(state="normal")
        self._box.insert("end", f"[{ts}]  {msg}\n")
        self._box.see("end")
        self._box.configure(state="disabled")

    def clear(self) -> None:
        self._box.configure(state="normal")
        self._box.delete("0.0", "end")
        self._box.configure(state="disabled")

    def export_to_file(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Export Log",
            defaultextension=".txt",
            filetypes=[("Text file", "*.txt"), ("All files", "*.*")],
        )
        if not path:
            return
        content = self._box.get("0.0", "end")
        try:
            Path(path).write_text(content, "utf-8")
        except Exception as exc:
            messagebox.showerror("Export Failed", str(exc))


class RecentBar(ctk.CTkFrame):
    """
    A compact horizontal strip of clickable recent-path buttons.
    Fixed memory leak by using partial() instead of lambda closures.
    """

    def __init__(self, master, recent_key: str, on_select, **kw):
        super().__init__(master, fg_color="transparent", **kw)
        self._key       = recent_key
        self._on_select = on_select
        self._buttons   = []  # Track buttons for proper cleanup
        self.refresh()

    def refresh(self) -> None:
        # Clear command callbacks first to break closure references
        for btn in self._buttons:
            btn.configure(command=None)
            btn.destroy()
        self._buttons.clear()
        
        recent = get_recent(self._key)[:5]
        if not recent:
            return
        
        ctk.CTkLabel(self, text="Recent:", font=ctk.CTkFont(size=14), text_color="#e6edf3").pack(side="left", padx=(0, 6))
        
        for p in recent:
            name = Path(p).name
            btn = ctk.CTkButton(
                self, text=name,
                command=partial(self._on_select, p), fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8)  # Use partial instead of lambda
            btn.pack(side="left", padx=2)
            self._buttons.append(btn)


class DragDropArea(ctk.CTkFrame):
    def __init__(self, master, browse_command, **kwargs):
        super().__init__(master, fg_color="#0d1117", corner_radius=8, border_width=2, border_color="#30363d", **kwargs)
        self.pack_propagate(False)
        self.grid_propagate(False)
        self.browse_command = browse_command

        self.content_frame = ctk.CTkFrame(self, fg_color="transparent", corner_radius=0)
        self.content_frame.place(relx=0.5, rely=0.5, anchor="center")

        self.icon_label = ctk.CTkLabel(self.content_frame, text="📁", font=ctk.CTkFont(size=48), text_color="#7d8590")
        self.text_label = ctk.CTkLabel(self.content_frame, text="Drag and Drop or Select Files", font=ctk.CTkFont(size=12), text_color="#7d8590")
        
        for w in (self, self.content_frame, self.icon_label, self.text_label):
            w.bind("<Button-1>", lambda e: self.browse_command())
            w.bind("<Enter>", lambda e: self.configure(cursor="hand2"))
            w.bind("<Leave>", lambda e: self.configure(cursor=""))

        self.is_empty = True
        self._update_ui()

    def _update_ui(self):
        if self.is_empty:
            self.configure(height=200, border_color="#30363d")
            self.icon_label.pack(pady=(0, 12))
            self.text_label.pack()
            self.text_label.configure(text="Drag and Drop or Select Files", text_color="#7d8590")
        else:
            self.configure(height=60, border_color="#00d4aa")
            self.icon_label.pack_forget()
            self.text_label.pack()

    def update_state(self, file_count, total_mb):
        if file_count == 0:
            self.is_empty = True
            self._update_ui()
        else:
            self.is_empty = False
            self.text_label.configure(text=f"{file_count} files selected | Total: {total_mb:.1f} MB", text_color="#e6edf3")
            self._update_ui()


class EmptyStateContainer(ctk.CTkFrame):
    def __init__(self, master, icon, message):
        super().__init__(master, fg_color="transparent")
        
        self.icon_label = ctk.CTkLabel(self, text=icon, font=ctk.CTkFont(size=48), text_color="#7d8590")
        self.icon_label.pack(pady=(0, 12))
        
        self.msg_label = ctk.CTkLabel(self, text=message, font=ctk.CTkFont(size=14), text_color="#7d8590")
        self.msg_label.pack()
        
    def show(self):
        self.place(relx=0.5, rely=0.5, anchor="center")
        
    def hide(self):
        self.place_forget()


class SidebarItem(ctk.CTkFrame):
    def __init__(self, master, text, command, **kwargs):
        super().__init__(master, height=44, fg_color="transparent", corner_radius=0, **kwargs)
        self.pack_propagate(False)
        self.command = command
        self._active = False
        
        self.inner = ctk.CTkFrame(self, fg_color="#010409", corner_radius=0)
        self.inner.pack(fill="both", expand=True, padx=(2, 0))
        
        self.label = ctk.CTkLabel(self.inner, text=text, font=ctk.CTkFont(size=14), text_color="#7d8590", anchor="w")
        self.label.pack(fill="both", expand=True, padx=18)
        
        for w in (self, self.inner, self.label):
            w.bind("<Enter>", self._on_enter)
            w.bind("<Leave>", self._on_leave)
            w.bind("<Button-1>", self._on_click)

    def _on_enter(self, e):
        self.label.configure(cursor="hand2")
        self.inner.configure(cursor="hand2")
        self.configure(cursor="hand2")
        if not self._active:
            self.label.configure(text_color="#e6edf3")

    def _on_leave(self, e):
        if not self._active:
            self.label.configure(text_color="#7d8590")

    def _on_click(self, e):
        if self.command:
            self.command()

    def set_active(self, active: bool):
        self._active = active
        if active:
            self.configure(fg_color="#00d4aa")
            self.label.configure(text_color="#00d4aa")
        else:
            self.configure(fg_color="transparent")
            self.label.configure(text_color="#7d8590")
