"""Vault Library view for RPM Encrypter.

Phase 26 (ARCH-01) Stage 3: moved verbatim out of RPMEncrypterApp into this
mixin so no single class owns every feature. Uses shared self (self.main_frame,
self.scanner, self.msg_queue, self.is_processing) plus the Stage-0 config
helpers, so behavior is unchanged.
"""
import threading

import customtkinter as ctk
from tkinter import filedialog

from app_config import _load_cfg, _save_cfg


class LibraryViewMixin:
    def _create_library_frame(self) -> ctk.CTkFrame:
        page_frame = ctk.CTkFrame(self.main_frame, fg_color="#0d1117", corner_radius=0)
        page_frame.grid_columnconfigure(0, weight=1)
        page_frame.grid_rowconfigure(0, weight=1)
        frame = ctk.CTkScrollableFrame(page_frame, fg_color="transparent", corner_radius=0)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(3, weight=1)

        ctk.CTkLabel(frame, text="Vault Library", font=ctk.CTkFont(size=22, weight="bold"), text_color="#e6edf3").grid(row=0, column=0, pady=(0, 20), sticky="w")

        # M5 FIX: The Library list is built from UNVERIFIED vault headers (read
        # without a password). Warn the user that these fields can be spoofed so
        # header-derived strings are never mistaken for authenticated data.
        ctk.CTkLabel(
            frame,
            text="⚠️ Vault metadata is read without authentication and may be spoofed.",
            font=ctk.CTkFont(size=12),
            text_color="#7d8590"
        ).grid(row=1, column=0, sticky="w", pady=(0, 6))

        search_container = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        search_container.grid(row=2, column=0, sticky="ew", pady=(0, 12))
        
        self.library_search_entry = ctk.CTkEntry(search_container, placeholder_text="Search vaults...", fg_color="#161b22", text_color="#e6edf3", border_color="#30363d", placeholder_text_color="#7d8590", height=36, corner_radius=6)
        self.library_search_entry.pack(fill="x", side="left", expand=True)
        self.library_search_entry.bind("<KeyRelease>", self._filter_library)
        
        self.library_search_clear = ctk.CTkButton(search_container, text="✕", width=36, height=36, fg_color="#21262d", text_color="#7d8590", hover_color="#30363d", corner_radius=6, font=ctk.CTkFont(size=14))
        self.library_search_clear.pack(side="right", padx=(8, 0))
        self.library_search_clear.configure(command=self._clear_library_search)
        self.library_search_clear.pack_forget()
        
        btn_row = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        btn_row.grid(row=3, column=0, sticky="ew", pady=(0, 8))

        ctk.CTkButton(btn_row, text="Add Directory",
                      command=self._add_library_dir, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="left", padx=(0, 8))
        ctk.CTkButton(btn_row, text="Scan Now",
                      command=self._scan_library, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="left", padx=(0, 8))
        
        # Display area
        self.library_textbox = ctk.CTkTextbox(
            frame,
            font=ctk.CTkFont(size=12, family="Courier New"),
            wrap="none",

        fg_color="#161b22", text_color="#e6edf3", corner_radius=6)
        self.library_textbox.grid(row=4, column=0, sticky="nsew")
        
        self.after(500, self._scan_library)
        return page_frame
    def _add_library_dir(self):
        path = filedialog.askdirectory(title="Select Directory to Monitor")
        if not path: return
        cfg = _load_cfg()
        dirs = cfg.get("library_dirs", [])
        if path not in dirs:
            dirs.append(path)
            cfg["library_dirs"] = dirs
            _save_cfg(cfg)
            self._scan_library()

    def _scan_library(self):
        if self.is_processing: return
        cfg = _load_cfg()
        dirs = cfg.get("library_dirs", [])
        if not dirs:
            self.library_textbox.configure(state="normal")
            self.library_textbox.delete("0.0", "end")
            self.library_textbox.insert("end", "No directories monitored. Click 'Add Directory' to start.")
            self.library_textbox.configure(state="disabled")
            return
            
        self.library_textbox.configure(state="normal")
        self.library_textbox.delete("0.0", "end")
        self.library_textbox.insert("end", "Scanning directories...\n")
        self.library_textbox.configure(state="disabled")
        
        threading.Thread(target=self._scan_worker, args=(dirs,), daemon=True).start()

    def _scan_worker(self, dirs):
        try:
            results = self.scanner.scan_directories(dirs)
            self.msg_queue.put({"type": "library_results", "data": results}, timeout=1.0)
        except Exception as e:
            self.msg_queue.put({"type": "error", "text": f"Scan failed: {e}"}, timeout=1.0)


    def _clear_library_search(self):
        self.library_search_entry.delete(0, "end")
        self._filter_library()

    def _filter_library(self, event=None):
        if not hasattr(self, "last_library_results"):
            return
            
        query = self.library_search_entry.get().strip().lower()
        if not query:
            self.library_search_clear.pack_forget()
            filtered = self.last_library_results
        else:
            self.library_search_clear.pack(side="right", padx=(8, 0))
            filtered = [
                r for r in self.last_library_results
                if query in r.get("filename", "").lower() or query in r.get("path", "").lower()
            ]
            
        self.library_textbox.configure(state="normal")
        self.library_textbox.delete("0.0", "end")
        
        if not filtered:
            self.library_textbox.insert("end", "No .vault files found matching the search.")
            if hasattr(self, "library_empty"): self.library_empty.show()
        else:
            if hasattr(self, "library_empty"): self.library_empty.hide()
            
            # Sort by created_at or path
            filtered.sort(key=lambda x: x.get("created_at", ""), reverse=True)
            
            header = f"{'FILENAME':<40} | {'CONTAINER SIZE':<15} | {'SOURCE TYPE':<15} | {'CREATED AT':<25}\n"
            self.library_textbox.insert("end", header)
            self.library_textbox.insert("end", "-" * 100 + "\n")
            
            for r in filtered:
                fname = r.get("filename", "Unknown")[:38]
                sz = r.get("container_size", r.get("original_size", 0))
                sz_str = f"{sz / 1024 / 1024:.2f} MB" if sz > 1024*1024 else f"{sz / 1024:.1f} KB"
                stype = r.get("source_type", "Unknown")[:13]
                cat = r.get("created_at", "Unknown")[:23]
                
                line = f"{fname:<40} | {sz_str:<15} | {stype:<15} | {cat:<25}\n"
                self.library_textbox.insert("end", line)
                
        self.library_textbox.configure(state="disabled")
