"""Password Generator view for RPM Encrypter.

Phase 26 (ARCH-01) Stage 5: moved verbatim out of RPMEncrypterApp into this
mixin so no single class owns every feature. Uses shared self (self.main_frame,
the self.pwgen_* widgets, self._set_status, and — for the '→ Encrypt' button —
the shell's self.encrypt_pw / self._on_enc_pw_change) plus the Stage-4 constants,
so behavior is unchanged.
"""
import string
import secrets
from typing import List

import customtkinter as ctk
from tkinter import messagebox

from app_constants import DEFAULT_PW_LEN, STRENGTH_COLORS, ZXCVBN_AVAILABLE, zxcvbn


class PasswordViewMixin:
    def _create_password_frame(self) -> ctk.CTkFrame:
        page_frame = ctk.CTkFrame(self.main_frame, fg_color="#0d1117", corner_radius=0)
        page_frame.grid_columnconfigure(0, weight=1)
        page_frame.grid_rowconfigure(0, weight=1)
        frame = ctk.CTkScrollableFrame(page_frame, fg_color="transparent", corner_radius=0)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(frame, text="Password Generator", font=ctk.CTkFont(size=22, weight="bold"), text_color="#e6edf3").grid(row=0, column=0, pady=(0, 20), sticky="w")

        len_row = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        len_row.grid(row=1, column=0, sticky="w", pady=(0, 14))

        ctk.CTkLabel(len_row, text="Length:", font=ctk.CTkFont(size=14), text_color="#e6edf3").pack(side="left", padx=(0, 12))
        self.pwgen_length = ctk.CTkSlider(
            len_row, from_=8, to=64, number_of_steps=56, width=240,
            command=self._update_length_label,
            fg_color="#21262d", progress_color="#00d4aa", button_color="#00d4aa",
        )
        self.pwgen_length.set(DEFAULT_PW_LEN)
        self.pwgen_length.pack(side="left", padx=(0, 10))
        self.pwgen_length_label = ctk.CTkLabel(
            len_row, text=str(DEFAULT_PW_LEN),
            font=ctk.CTkFont(size=14), width=30,

        text_color="#e6edf3")
        self.pwgen_length_label.pack(side="left")

        opts = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        opts.grid(row=2, column=0, sticky="w", pady=(0, 14))

        self.pwgen_upper   = ctk.BooleanVar(value=True)
        self.pwgen_lower   = ctk.BooleanVar(value=True)
        self.pwgen_digits  = ctk.BooleanVar(value=True)
        self.pwgen_symbols = ctk.BooleanVar(value=True)
        self.pwgen_no_ambig = ctk.BooleanVar(value=False)

        for text, var in [
            ("A-Z", self.pwgen_upper),
            ("a-z", self.pwgen_lower),
            ("0-9", self.pwgen_digits),
            ("!@#$%", self.pwgen_symbols),
            ("Exclude ambiguous (0Ol1I|`)", self.pwgen_no_ambig),
        ]:
            ctk.CTkCheckBox(opts, text=text, variable=var,
                            font=ctk.CTkFont(size=14), fg_color="#00d4aa", text_color="#e6edf3", border_color="#30363d", checkmark_color="#0d1117").pack(side="left", padx=8)

        res_row = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        res_row.grid(row=3, column=0, sticky="ew", pady=(0, 12))
        res_row.grid_columnconfigure(0, weight=1)

        self.pwgen_result = ctk.CTkEntry(
            res_row,
            font=ctk.CTkFont(size=16, family="Courier New", weight="bold"),

        fg_color="#161b22", text_color="#e6edf3", border_color="#30363d", placeholder_text_color="#7d8590", height=36, corner_radius=6)
        self.pwgen_result.grid(row=0, column=0, sticky="ew", padx=(0, 8))

        ctk.CTkButton(res_row, text="Copy",
                      command=self._copy_generated_pw, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).grid(row=0, column=1, padx=(0, 6))
        ctk.CTkButton(res_row, text="→ Encrypt",
                      command=self._use_generated_pw, width=120, fg_color="#00d4aa", text_color="#0d1117", hover_color="#00ffcc", font=ctk.CTkFont(size=14, weight="bold"), height=42, corner_radius=8).grid(row=0, column=2)

        self.pwgen_strength_lbl = ctk.CTkLabel(
            frame, text="", font=ctk.CTkFont(size=14), text_color="#e6edf3")
        self.pwgen_strength_lbl.grid(row=4, column=0, sticky="w", pady=(0, 10))

        ctk.CTkButton(
            frame, text="🔑  Generate Password",
            command=self._generate_password, width=120, fg_color="#00d4aa", text_color="#0d1117", hover_color="#00ffcc", font=ctk.CTkFont(size=14, weight="bold"), height=42, corner_radius=8).grid(row=5, column=0, pady=(0, 0), sticky="w")

        return page_frame
    def _update_length_label(self, value) -> None:
        self.pwgen_length_label.configure(text=str(int(value)))

    def _generate_password(self) -> None:
        chars = ""
        if self.pwgen_upper.get():   chars += string.ascii_uppercase
        if self.pwgen_lower.get():   chars += string.ascii_lowercase
        if self.pwgen_digits.get():  chars += string.digits
        if self.pwgen_symbols.get(): chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        if self.pwgen_no_ambig.get():
            for ch in "0O1lI|`":
                chars = chars.replace(ch, "")
        if not chars:
            messagebox.showwarning("Options", "Select at least one character type.")
            return

        length = int(self.pwgen_length.get())
        required: List[str] = []
        pools = []
        if self.pwgen_upper.get():
            p = string.ascii_uppercase
            if self.pwgen_no_ambig.get():
                p = "".join(c for c in p if c not in "OI")
            pools.append(p)
        if self.pwgen_lower.get():
            p = string.ascii_lowercase
            if self.pwgen_no_ambig.get():
                p = "".join(c for c in p if c not in "l")
            pools.append(p)
        if self.pwgen_digits.get():
            p = string.digits
            if self.pwgen_no_ambig.get():
                p = "".join(c for c in p if c not in "01")
            pools.append(p)
        if self.pwgen_symbols.get():
            pools.append("!@#$%^&*()_+-=[]{}|;:,.<>?")

        for pool in pools:
            if pool:
                required.append(secrets.choice(pool))

        remainder = [secrets.choice(chars) for _ in range(max(0, length - len(required)))]
        password_list = required + remainder
        secrets.SystemRandom().shuffle(password_list)
        password = "".join(password_list)

        self.pwgen_result.delete(0, "end")
        self.pwgen_result.insert(0, password)

        if ZXCVBN_AVAILABLE:
            res   = zxcvbn(password)
            score = res["score"]
            color, label = STRENGTH_COLORS.get(score, ("gray", "Unknown"))
            crack = res["crack_times_display"]["offline_slow_hashing_1e4_per_second"]
            self.pwgen_strength_lbl.configure(
                text=f"Strength: {label}  •  Est. crack time: {crack}",
                text_color=color,
            )
        else:
            self.pwgen_strength_lbl.configure(
                text=f"Length: {length} chars  (install zxcvbn for strength analysis)"
            )

    def _clear_clipboard(self) -> None:
        try:
            self.clipboard_clear()
            self.clipboard_append("")
            self.update()
        except Exception:
            pass

    def _start_clipboard_timer(self) -> None:
        if hasattr(self, '_clipboard_timer') and self._clipboard_timer is not None:
            self.after_cancel(self._clipboard_timer)
        self._clipboard_timer = self.after(30000, self._clear_clipboard)

    def _copy_generated_pw(self) -> None:
        pw = self.pwgen_result.get()
        if pw:
            self.clipboard_clear()
            self.clipboard_append(pw)
            self._start_clipboard_timer()
            self._set_status("Copied! Clipboard will be cleared in 30s.")
            if hasattr(self, '_clipboard_hint_timer') and self._clipboard_hint_timer is not None:
                self.after_cancel(self._clipboard_hint_timer)
            self._clipboard_hint_timer = self.after(3000, lambda: self._set_status("Ready"))

    def _use_generated_pw(self) -> None:
        pw = self.pwgen_result.get()
        if pw:
            self.encrypt_pw.set(pw)
            self.encrypt_pw_confirm.set(pw)
            self._on_enc_pw_change()
            self._show_frame("encrypt")
            self._set_status("Password transferred to Encrypt tab")
