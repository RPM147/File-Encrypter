"""Settings view for RPM Encrypter (appearance, updates, profiles, Argon2id KDF,
secure wipe, vault versioning, privacy, health check, about).

Phase 26 (ARCH-01) Stage 9: moved verbatim out of RPMEncrypterApp into this mixin
so no single class owns every feature. Uses shared self (self.is_processing,
self._build_crypto, self._build_versioner, the rebuilt self.crypto/packager/wiper/
inspector/versioner, self._set_status, and the shell's self._save_logging_setting /
self._clear_all_traces) plus the Stage-0/4/8 helpers and constants, so behavior is
unchanged.
"""
from pathlib import Path
from typing import Dict, Any

import customtkinter as ctk
from tkinter import filedialog, messagebox

import versioning
from app_config import _load_cfg, _mutate_cfg, get_setting, save_setting
from file_handler import FolderPackager, SecureWiper, VaultInspector
from crypto_core import ARGON2_MEMORY_COST, ARGON2_TIME_COST, ARGON2_PARALLELISM
from app_constants import APP_NAME, APP_VERSION


class SettingsViewMixin:
    def _create_settings_frame(self) -> ctk.CTkFrame:
        page_frame = ctk.CTkFrame(self.main_frame, fg_color="#0d1117", corner_radius=0)
        page_frame.grid_columnconfigure(0, weight=1)
        page_frame.grid_rowconfigure(0, weight=1)
        frame = ctk.CTkScrollableFrame(page_frame, fg_color="transparent", corner_radius=0)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(frame, text="Settings", font=ctk.CTkFont(size=22, weight="bold"), text_color="#e6edf3").grid(row=0, column=0, pady=(0, 20), sticky="w")

        row = 1

        # --- APPEARANCE ---
        ctk.CTkLabel(frame, text="Appearance", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=row, column=0, sticky="w", pady=(0, 6))
        row += 1

        app_frame = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        app_frame.grid(row=row, column=0, sticky="w", pady=(0, 16))
        row += 1

        ctk.CTkLabel(app_frame, text="Theme:", font=ctk.CTkFont(size=14), text_color="#e6edf3").pack(side="left", padx=(0, 12))
        self.theme_var = ctk.StringVar(value=get_setting("theme", "Dark"))
        ctk.CTkOptionMenu(
            app_frame, values=["Dark", "Light", "System"],
            variable=self.theme_var,
            command=self._change_theme,
            width=130, font=ctk.CTkFont(size=14),

        fg_color="#161b22", text_color="#e6edf3", button_color="#30363d", height=36, corner_radius=6).pack(side="left", padx=(0, 20))

        ctk.CTkLabel(app_frame, text="UI Scale:", font=ctk.CTkFont(size=14), text_color="#e6edf3").pack(side="left", padx=(0, 12))
        self.scale_var = ctk.StringVar(value="100%")
        ctk.CTkOptionMenu(
            app_frame, values=["80%", "90%", "100%", "110%", "120%"],
            variable=self.scale_var,
            command=self._change_scaling,
            width=110, font=ctk.CTkFont(size=14),

        fg_color="#161b22", text_color="#e6edf3", button_color="#30363d", height=36, corner_radius=6).pack(side="left")

        # --- UPDATES ---
        ctk.CTkLabel(frame, text="Updates", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=row, column=0, sticky="w", pady=(0, 6))
        row += 1

        upd_frame = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        upd_frame.grid(row=row, column=0, sticky="w", pady=(0, 16))
        row += 1

        self.updates_var = ctk.BooleanVar(value=get_setting("check_updates", False))
        ctk.CTkSwitch(
            upd_frame, text="Check for updates on startup",
            variable=self.updates_var,
            command=lambda: save_setting("check_updates", self.updates_var.get()),
            font=ctk.CTkFont(size=14),
            fg_color="#30363d", progress_color="#00d4aa", button_color="#ffffff", text_color="#e6edf3"
        ).pack(side="left")

        # --- PROFILES ---
        ctk.CTkLabel(frame, text="Smart Encryption Profiles", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=row, column=0, sticky="w", pady=(0, 6))
        row += 1

        prof_frame = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        prof_frame.grid(row=row, column=0, sticky="ew", pady=(0, 20))
        prof_frame.grid_columnconfigure(0, weight=1)
        row += 1
        
        prof_entry_row = ctk.CTkFrame(prof_frame, fg_color="#0d1117", corner_radius=0)
        prof_entry_row.grid(row=0, column=0, sticky="w", pady=(0, 6))
        self.profile_name_var = ctk.StringVar()
        ctk.CTkEntry(prof_entry_row, textvariable=self.profile_name_var, placeholder_text="Profile Name", width=200, fg_color="#161b22", text_color="#e6edf3", border_color="#30363d", placeholder_text_color="#7d8590", height=36, corner_radius=6).pack(side="left", padx=(0, 8))
        ctk.CTkButton(prof_entry_row, text="Save Current as Profile", command=self._save_profile, width=120, fg_color="#00d4aa", text_color="#0d1117", hover_color="#00ffcc", font=ctk.CTkFont(size=14, weight="bold"), height=42, corner_radius=8).pack(side="left", padx=(0, 8))
        ctk.CTkButton(prof_entry_row, text="Delete Selected", command=self._delete_profile, width=120, fg_color="#f85149", text_color="#0d1117", hover_color="#ff6e6e", font=ctk.CTkFont(size=14, weight="bold"), height=42, corner_radius=8).pack(side="left")
        
        self.profile_select_var = ctk.StringVar(value="Select Profile")
        self.profile_delete_menu = ctk.CTkOptionMenu(prof_entry_row, variable=self.profile_select_var, values=["Select Profile"], fg_color="#161b22", text_color="#e6edf3", button_color="#30363d", height=36, corner_radius=6)
        self.profile_delete_menu.pack(side="left", padx=(8, 0))
        
        self.after(100, self._update_profile_dropdowns)

        # --- ARGON2 KDF ---
        ctk.CTkLabel(frame, text="Argon2id Key Derivation (applied to new vaults)", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=row, column=0, sticky="w", pady=(0, 6))
        row += 1

        kdf_frame = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        kdf_frame.grid(row=row, column=0, sticky="ew", pady=(0, 6), ipadx=10, ipady=8)
        kdf_frame.grid_columnconfigure(1, weight=1)
        row += 1

        self._kdf_widgets: Dict[str, Any] = {}
        kdf_params = [
            ("Memory (KiB)", "argon2_memory", ARGON2_MEMORY_COST,
             [16384, 32768, 65536, 131072, 262144, 524288],
             {16384: "16 MiB", 32768: "32 MiB", 65536: "64 MiB (default)",
              131072: "128 MiB", 262144: "256 MiB", 524288: "512 MiB"}),
            ("Iterations", "argon2_time", ARGON2_TIME_COST,
             [1, 2, 3, 4, 5, 6, 8, 10],
             {}),
            ("Parallelism", "argon2_par", ARGON2_PARALLELISM,
             [1, 2, 4, 8, 16],
             {}),
        ]

        for kdf_row, (label, key, default, values, label_map) in enumerate(kdf_params):
            current = get_setting(key, default)
            ctk.CTkLabel(kdf_frame, text=f"{label}:",
                         font=ctk.CTkFont(size=14),

                         text_color="#e6edf3").grid(row=kdf_row, column=0, padx=(12, 10), pady=4, sticky="w")
            str_values = [label_map.get(v, str(v)) for v in values]
            rev_map = {label_map.get(v, str(v)): v for v in values}
            cur_disp = label_map.get(current, str(current))
            var = ctk.StringVar(value=cur_disp)
            self._kdf_widgets[key] = (var, rev_map, default)
            ctk.CTkOptionMenu(
                kdf_frame, values=str_values, variable=var,
                width=200, font=ctk.CTkFont(size=13),

            fg_color="#161b22", text_color="#e6edf3", button_color="#30363d", height=36, corner_radius=6).grid(row=kdf_row, column=1, padx=(0, 12), pady=4, sticky="w")

        ctk.CTkButton(
            frame, text="💾  Save KDF Settings & Restart Crypto Engine",
            command=self._save_kdf_settings, width=120, fg_color="#00d4aa", text_color="#0d1117", hover_color="#00ffcc", font=ctk.CTkFont(size=14, weight="bold"), height=42, corner_radius=8).grid(row=row, column=0, sticky="w", pady=(0, 20))
        row += 1

        # --- SECURITY HEALTH CHECK ---
        ctk.CTkLabel(frame, text="Security Health Check", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=row, column=0, sticky="w", pady=(0, 6))
        row += 1
        
        ctk.CTkButton(
            frame, text="🛡️  Run Security Health Check",
            command=self._run_health_check, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).grid(row=row, column=0, sticky="w", pady=(0, 20))
        row += 1

        # --- SECURE WIPE ---
        ctk.CTkLabel(frame, text="Secure Wipe", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=row, column=0, sticky="w", pady=(0, 6))
        row += 1

        wipe_frame = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        wipe_frame.grid(row=row, column=0, sticky="w", pady=(0, 20))
        row += 1

        ctk.CTkLabel(wipe_frame, text="Overwrite passes:", font=ctk.CTkFont(size=14), text_color="#e6edf3").pack(side="left", padx=(0, 10))
        self.wipe_passes_var = ctk.StringVar(
            value=str(get_setting("wipe_passes", 1)))
        ctk.CTkOptionMenu(
            wipe_frame, values=["1", "3", "7"],
            variable=self.wipe_passes_var,
            width=80, font=ctk.CTkFont(size=14),
            command=self._save_wipe_setting,

        fg_color="#161b22", text_color="#e6edf3", button_color="#30363d", height=36, corner_radius=6).pack(side="left")
        ctk.CTkLabel(wipe_frame,
                     text="  (1 pass is sufficient for SSDs; 3+ for HDDs)", font=ctk.CTkFont(size=14), text_color="#e6edf3").pack(side="left", padx=(8, 0))

        # --- VAULT VERSIONING ---
        ctk.CTkLabel(frame, text="Vault Versioning", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=row, column=0, sticky="w", pady=(0, 6))
        row += 1

        ver_frame = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        ver_frame.grid(row=row, column=0, sticky="ew", pady=(0, 20), ipadx=10, ipady=10)
        ver_frame.grid_columnconfigure(1, weight=1)
        row += 1

        # Enable toggle
        self._ver_enabled_var = ctk.BooleanVar(value=bool(get_setting("versioning_enabled", False)))
        ctk.CTkLabel(ver_frame, text="Enable Versioning:", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=0, column=0, padx=(12, 10), pady=6, sticky="w")
        ver_toggle = ctk.CTkSwitch(
            ver_frame, text="",
            variable=self._ver_enabled_var,
            command=self._save_versioning_settings,

        fg_color="#30363d", progress_color="#00d4aa", text_color="#e6edf3", button_color="#ffffff")
        ver_toggle.grid(row=0, column=1, padx=(0, 12), pady=6, sticky="w")

        # Max versions per vault
        ctk.CTkLabel(ver_frame, text="Max versions per vault:", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=1, column=0, padx=(12, 10), pady=6, sticky="w")
        self._ver_max_count_var = ctk.StringVar(value=str(get_setting("versioning_max_per_vault", 5)))
        ctk.CTkOptionMenu(
            ver_frame, values=["1", "2", "3", "5", "10", "20"],
            variable=self._ver_max_count_var,
            width=100, font=ctk.CTkFont(size=13),
            command=lambda _: self._save_versioning_settings(),

        fg_color="#161b22", text_color="#e6edf3", button_color="#30363d", height=36, corner_radius=6).grid(row=1, column=1, padx=(0, 12), pady=6, sticky="w")

        # Max total size
        ctk.CTkLabel(ver_frame, text="Max total size (MiB):", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=2, column=0, padx=(12, 10), pady=6, sticky="w")
        self._ver_max_size_var = ctk.StringVar(value=str(get_setting("versioning_max_total_mb", 2048)))
        ctk.CTkOptionMenu(
            ver_frame, values=["256", "512", "1024", "2048", "4096", "8192"],
            variable=self._ver_max_size_var,
            width=120, font=ctk.CTkFont(size=13),
            command=lambda _: self._save_versioning_settings(),

        fg_color="#161b22", text_color="#e6edf3", button_color="#30363d", height=36, corner_radius=6).grid(row=2, column=1, padx=(0, 12), pady=6, sticky="w")

        # Versions directory
        ctk.CTkLabel(ver_frame, text="Versions directory:", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=3, column=0, padx=(12, 10), pady=6, sticky="w")
        ver_dir_row = ctk.CTkFrame(ver_frame, fg_color="transparent", corner_radius=0)
        ver_dir_row.grid(row=3, column=1, sticky="ew", padx=(0, 12), pady=6)
        ver_dir_row.grid_columnconfigure(0, weight=1)
        default_ver_dir = str(versioning.VERSIONS_ROOT_DEFAULT)
        self._ver_dir_entry = ctk.CTkEntry(
            ver_dir_row,
            font=ctk.CTkFont(size=12),
            placeholder_text=default_ver_dir,

        fg_color="#161b22", text_color="#e6edf3", border_color="#30363d", placeholder_text_color="#7d8590", height=36, corner_radius=6)
        self._ver_dir_entry.grid(row=0, column=0, sticky="ew", padx=(0, 6))
        saved_dir = get_setting("versioning_dir", "")
        if saved_dir:
            self._ver_dir_entry.insert(0, saved_dir)

        def browse_ver_dir():
            d = filedialog.askdirectory(title="Select Versions Directory")
            if d:
                self._ver_dir_entry.delete(0, "end")
                self._ver_dir_entry.insert(0, d)
                self._save_versioning_settings()
        ctk.CTkButton(ver_dir_row, text="Browse",
                      command=browse_ver_dir, width=80, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).grid(row=0, column=1)

        ctk.CTkLabel(
            ver_frame,
            text="  Versioning is opt-in. Large vaults (>1 GiB) will be fully copied before each Re-Key.",
            justify="left", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=4, column=0, columnspan=2, padx=12, pady=(4, 6), sticky="w")

        # --- PRIVACY & LOCAL TRACES ---
        ctk.CTkLabel(frame, text="Privacy & Local Traces", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=row, column=0, sticky="w", pady=(0, 6))
        row += 1

        privacy_frame = ctk.CTkFrame(frame, fg_color="transparent", corner_radius=0)
        privacy_frame.grid(row=row, column=0, sticky="w", pady=(0, 10))
        row += 1

        self.logging_enabled_var = ctk.BooleanVar(value=bool(get_setting("logging_enabled", False)))
        ctk.CTkSwitch(
            privacy_frame, text="Enable Activity Logging",
            variable=self.logging_enabled_var,
            command=self._save_logging_setting,
            font=ctk.CTkFont(size=14),
            fg_color="#30363d", progress_color="#00d4aa", button_color="#ffffff", text_color="#e6edf3"
        ).pack(side="left")

        ctk.CTkLabel(
            frame,
            text="  Records each operation (action, status, and the file's NAME) to a local activity log on this device. Off by default; vault contents are never logged.",
            justify="left", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=row, column=0, sticky="w", pady=(0, 10))
        row += 1

        ctk.CTkButton(
            frame, text="⚠️  Clear All Local Traces",
            command=self._clear_all_traces, fg_color="#f85149", text_color="#0d1117", hover_color="#ff6e6e", font=ctk.CTkFont(size=14, weight="bold"), height=42, corner_radius=8).grid(row=row, column=0, sticky="w", pady=(0, 6))
        row += 1

        ctk.CTkLabel(
            frame,
            text="  Erases the activity log, Library cache, saved fingerprints, and recent-file lists from this device. Vault files are not affected.",
            justify="left", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=row, column=0, sticky="w", pady=(0, 20))
        row += 1

        # --- ABOUT ---
        ctk.CTkLabel(frame, text="About", font=ctk.CTkFont(size=14), text_color="#e6edf3").grid(row=row, column=0, sticky="w", pady=(0, 6))
        row += 1

        about = (
            f"{APP_NAME}  v{APP_VERSION}\n"
            "Envelope Encryption: AES-256-GCM  ·  Argon2id KDF\n"
            "\n"
            "Shortcuts:  Ctrl+E Encrypt  ·  Ctrl+D Decrypt  ·  Ctrl+I Inspect\n"
            "            Ctrl+R Re-Key   ·  Ctrl+P Password  ·  Alt+S Settings"
        )
        ctk.CTkLabel(
            frame, text=about,
            font=ctk.CTkFont(size=12),
            justify="left",

        text_color="#7d8590").grid(row=row, column=0, sticky="w")

        return page_frame
    def _change_theme(self, choice: str) -> None:
        ctk.set_appearance_mode(choice)
        save_setting("theme", choice)
        self._set_status(f"Theme: {choice}")

    def _change_scaling(self, choice: str) -> None:
        scale = int(choice.replace("%", "")) / 100
        ctk.set_widget_scaling(scale)
        self._set_status(f"UI scale: {choice}")

    def _save_kdf_settings(self) -> None:
        if self.is_processing:
            messagebox.showwarning(
                "Operation in Progress",
                "Cannot change KDF settings while encrypting/decrypting.\n"
                "Please wait for the current operation to finish."
            )
            return
        
        for key, (var, rev_map, default) in self._kdf_widgets.items():
            raw = rev_map.get(var.get(), default)
            save_setting(key, raw)
        
        # Rebuild all crypto services
        self._build_crypto()
        self.packager = FolderPackager()
        self.wiper = SecureWiper(passes=get_setting("wipe_passes", 1))
        self.inspector = VaultInspector(self.crypto)
        
        self._set_status("Crypto engine reloaded with new KDF parameters")
        messagebox.showinfo("Saved",
                            "Argon2id parameters updated.\n"
                            "New vaults will use these settings.\n"
                            "Existing vaults remain accessible with their original parameters.")

    def _save_wipe_setting(self, choice: str) -> None:
        passes = int(choice)
        save_setting("wipe_passes", passes)
        self.wiper = SecureWiper(passes=passes)
        self._set_status(f"Wipe passes set to {passes}")

    def _save_versioning_settings(self) -> None:
        """Persist versioning settings and rebuild the versioner instance."""
        save_setting("versioning_enabled", self._ver_enabled_var.get())
        try:
            save_setting("versioning_max_per_vault", int(self._ver_max_count_var.get()))
        except ValueError:
            pass
        try:
            save_setting("versioning_max_total_mb", int(self._ver_max_size_var.get()))
        except ValueError:
            pass
        ver_dir = self._ver_dir_entry.get().strip()
        save_setting("versioning_dir", ver_dir)
        self.versioner = self._build_versioner()
        self._set_status(
            f"Versioning {'enabled' if self.versioner.enabled else 'disabled'} — "            f"max {self.versioner.max_versions_per_vault} versions, "            f"{self.versioner.max_total_size_bytes // (1024*1024)} MiB limit"
        )

    def _update_profile_dropdowns(self):
        cfg = _load_cfg()
        profiles = cfg.get("profiles", {})
        profile_names = list(profiles.keys())
        if not profile_names:
            profile_names = ["No Profiles Saved"]
            
        if hasattr(self, "profile_delete_menu"):
            self.profile_delete_menu.configure(values=profile_names)
            self.profile_select_var.set(profile_names[0])
            
        if hasattr(self, "enc_profile_menu"):
            self.enc_profile_menu.configure(values=["Custom"] + (list(profiles.keys()) if profiles else []))

    def _save_profile(self):
        name = self.profile_name_var.get().strip()
        if not name:
            messagebox.showwarning("Name Required", "Please enter a profile name.")
            return
        if name.lower() in ["custom", "no profiles saved"]:
            messagebox.showwarning("Reserved Name", "That profile name is reserved. Please choose another name.")
            return
        
        def _save(cfg):
            profiles = cfg.setdefault("profiles", {})
            settings = cfg.get("settings", {})
            profiles[name] = {
                "argon2_memory": settings.get("argon2_memory", ARGON2_MEMORY_COST),
                "argon2_time": settings.get("argon2_time", ARGON2_TIME_COST),
                "argon2_par": settings.get("argon2_par", ARGON2_PARALLELISM),
                "wipe_passes": settings.get("wipe_passes", 1),
            }
        _mutate_cfg(_save)
        self.profile_name_var.set("")
        self._update_profile_dropdowns()
        self._set_status(f"Profile '{name}' saved.")

    def _delete_profile(self):
        name = self.profile_select_var.get()
        deleted = False
        def _delete(cfg):
            nonlocal deleted
            profiles = cfg.get("profiles", {})
            if name in profiles:
                del profiles[name]
                deleted = True
        _mutate_cfg(_delete)
        if deleted:
            self._update_profile_dropdowns()
            self._set_status(f"Profile '{name}' deleted.")

    def _apply_profile(self, profile_name: str):
        if profile_name == "Custom" or profile_name == "No Profiles Saved": return
        cfg = _load_cfg()
        profiles = cfg.get("profiles", {})
        profile = profiles.get(profile_name)
        if not profile: return
        
        save_setting("argon2_memory", profile.get("argon2_memory"))
        save_setting("argon2_time", profile.get("argon2_time"))
        save_setting("argon2_par", profile.get("argon2_par"))
        save_setting("wipe_passes", profile.get("wipe_passes", 1))
        
        if hasattr(self, "_kdf_widgets"):
            for key, (var, rev_map, default) in self._kdf_widgets.items():
                val = profile.get(key, default)
                for k, v in rev_map.items():
                    if v == val:
                        var.set(k)
                        break
        if hasattr(self, "wipe_passes_var"):
            self.wipe_passes_var.set(str(profile.get("wipe_passes", 1)))
            
        self._build_crypto()
        self.wiper = SecureWiper(passes=profile.get("wipe_passes", 1))
        self._set_status(f"Profile '{profile_name}' applied.")

    def _run_health_check(self):
        import platform
        
        settings = _load_cfg().get("settings", {})
        mem = settings.get("argon2_memory", ARGON2_MEMORY_COST)
        iters = settings.get("argon2_time", ARGON2_TIME_COST)
        wipe = settings.get("wipe_passes", 1)
        
        issues = []
        passes = []
        
        if mem >= 65536 and iters >= 3:
            passes.append("✅ Argon2id parameters meet or exceed OWASP baselines.")
        else:
            issues.append("⚠️ Argon2id parameters are below OWASP baselines (recommend >= 64 MiB memory, >= 3 iterations).")
            
        if wipe >= 1:
            passes.append("✅ Secure Wipe is configured (passes >= 1).")
        else:
            issues.append("⚠️ Secure Wipe passes is 0. Original files will not be securely deleted.")
            
        is_ssd = False
        try:
            if platform.system() == "Windows":
                import subprocess
                # LOW-02: use the modern Windows Storage module. Any failure
                # falls through to the safe "assume HDD" advice below.
                res = subprocess.run(
                    ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                     "Get-PhysicalDisk | Select-Object -ExpandProperty MediaType"],
                    capture_output=True, text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW, timeout=8)
                if "SSD" in res.stdout:
                    is_ssd = True
            elif platform.system() == "Linux":
                for p in Path("/sys/block").glob("*/queue/rotational"):
                    if p.read_text().strip() == "0":
                        is_ssd = True
                        break
        except Exception:
            pass

        if is_ssd:
            passes.append("ℹ️ SSD detected. 1 wipe pass is sufficient due to wear-leveling.")
        else:
            passes.append("ℹ️ Storage medium: Assuming HDD or indeterminate. 3+ wipe passes recommended for HDDs.")
            
        msg = "SECURITY HEALTH CHECK RESULTS\n\n"
        if issues:
            msg += "Needs Attention:\n" + "\n".join(issues) + "\n\n"
        msg += "Good:\n" + "\n".join(passes)
        
        messagebox.showinfo("Security Health Check", msg)

    # ==========================================================================
    # THREAD COMMUNICATION
    # ==========================================================================

