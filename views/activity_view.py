"""Activity Feed & Statistics view for RPM Encrypter.

Phase 26 (ARCH-01) Stage 1: these methods were moved verbatim out of
RPMEncrypterApp into this mixin so no single class owns every feature. The mixin
is composed into RPMEncrypterApp and uses its shared `self` (self.main_frame,
self.activity_logger, self.activity_textbox), so behavior is unchanged.
"""
import customtkinter as ctk
from tkinter import messagebox


class ActivityViewMixin:
    def _create_activity_frame(self) -> ctk.CTkFrame:
        page_frame = ctk.CTkFrame(self.main_frame, fg_color="#0d1117", corner_radius=0)
        page_frame.grid_columnconfigure(0, weight=1)
        page_frame.grid_rowconfigure(0, weight=1)
        frame = ctk.CTkScrollableFrame(page_frame, fg_color="transparent", corner_radius=0)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)

        ctk.CTkLabel(frame, text="Activity Feed & Statistics", font=ctk.CTkFont(size=22, weight="bold"), text_color="#e6edf3").grid(row=0, column=0, pady=(0, 20), sticky="w")
        
        btn_row = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        btn_row.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        
        ctk.CTkButton(btn_row, text="Refresh",
                      command=self._refresh_activity, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="left", padx=(0, 8))
        ctk.CTkButton(btn_row, text="Clear Log",
                      command=self._clear_activity, width=80, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="left")

        self.activity_textbox = ctk.CTkTextbox(
            frame,
            font=ctk.CTkFont(size=12, family="Courier New"),
            wrap="word",

        fg_color="#161b22", text_color="#e6edf3", corner_radius=6)
        self.activity_textbox.grid(row=2, column=0, sticky="nsew")
        self._refresh_activity()
        return page_frame
    def _refresh_activity(self) -> None:
        if not hasattr(self, "activity_textbox"): return
        self.activity_textbox.configure(state="normal")
        self.activity_textbox.delete("0.0", "end")
        logs = self.activity_logger.get_logs(limit=200)
        if not logs:
            self.activity_textbox.insert("end", "No activity recorded yet.")
        else:
            for log in logs:
                line = f"[{log['timestamp']}] {log['action']:<10} | {log['status']:<8} | {log['filename']}\n"
                if log['details']:
                    line += f"    -> {log['details']}\n"
                self.activity_textbox.insert("end", line)
        self.activity_textbox.configure(state="disabled")

    def _clear_activity(self) -> None:
        if messagebox.askyesno("Clear Activity Log", "Are you sure you want to delete all activity logs?"):
            self.activity_logger.clear_logs()
            self._refresh_activity()
