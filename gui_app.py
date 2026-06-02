#!/usr/bin/env python3
"""
RPM Encrypter - Main GUI Application  (v3.0 - Vault Format v2)
==============================================================
Version is defined once as APP_VERSION below (single source of truth).
The "Major Fixes in v2.1" list is retained as historical changelog.

Major Fixes in v2.1:
  - Thread lifecycle management (graceful shutdown, cancel support)
  - Window close race condition fixed
  - Temp file memory leak resolved
  - Config file atomic writes
  - Message queue bounded to prevent overflow
  - Fingerprint panel performance optimization (background hashing)
  - Password strength calculation debounced
  - RecentBar widget memory leak fixed
  - Decrypt output directory validation enhanced
  - Progress feedback during KDF phase
  - Better error handling in worker threads

Architecture:
  - All long-running ops run in daemon threads
  - Thread-safe queue relays progress/log/completion back to main thread
  - AttemptLimiter shared across Decrypt and Inspect tabs
  - Cancel flag for graceful worker termination

Dependencies:
    pip install customtkinter tkinterdnd2 cryptography argon2-cffi zxcvbn
"""

import os
import sys
import json
import queue
import threading
import secrets
import string
import logging
import tempfile
import hashlib
import struct
import time
import webbrowser
from updater import check_for_update
import shutil
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Dict, Any, Tuple
from functools import partial

# ------------------------------------------------------------------------------
# Third-Party Imports
# ------------------------------------------------------------------------------

import tkinterdnd2
from tkinterdnd2 import DND_FILES, TkinterDnD

import customtkinter as ctk
from tkinter import filedialog, messagebox, Entry, Text

# ------------------------------------------------------------------------------
# Local Modules
# ------------------------------------------------------------------------------

from crypto_core import (
    VaultCrypto, AuthenticationError, VaultFormatError, CryptoError,
    PayloadTooLargeError, OperationCancelledError,
    VAULT_MAGIC, is_supported_vault_version, AES_TAG_SIZE,
    MAX_PAYLOAD_SIZE,
    ARGON2_MEMORY_COST, ARGON2_TIME_COST, ARGON2_PARALLELISM,
    generate_recovery_entropy, entropy_to_mnemonic, mnemonic_to_entropy
)
from file_handler import FolderPackager, SecureWiper, VaultInspector, atomic_output
from recovery_dialog_copy import (
    DECRYPT_RECOVERY_LABEL,
    INSPECT_RECOVERY_LABEL,
    get_recovery_dialog_copy,
)
import activity_log
import vault_scanner
import versioning

# Phase 26 (ARCH-01) Stage 0: these were extracted into dedicated modules;
# re-import them so existing call sites and tests keep working unchanged.
from app_config import (
    CONFIG_FILE, MAX_RECENT, _load_cfg, _save_cfg, get_recent, push_recent,
    get_setting, save_setting, resource_path,
)
from app_state import (
    assert_main_thread, MAX_ATTEMPTS, LOCKOUT_SECS, AttemptLimiter, SessionStats,
)
from app_constants import (
    DEFAULT_PW_LEN, STRENGTH_COLORS, ZXCVBN_AVAILABLE, zxcvbn,
    APP_NAME, APP_VERSION, CONTAINER_SIZE_CHOICES, container_label_to_mb,
)
from widgets import (
    PasswordEntry, LogBox, RecentBar, DragDropArea, EmptyStateContainer, SidebarItem,
)
from views.activity_view import ActivityViewMixin
from views.notes_view import NotesViewMixin
from views.library_view import LibraryViewMixin
from views.password_view import PasswordViewMixin
from views.rekey_view import RekeyViewMixin
from views.decrypt_view import DecryptViewMixin
from views.settings_view import SettingsViewMixin
from views.encrypt_view import EncryptViewMixin
from views.inspect_view import InspectViewMixin


# ------------------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("RPM_GUI")


# ------------------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------------------

MSG_QUEUE_SIZE  = 1000  # Bounded queue to prevent memory overflow


# ==============================================================================
# MAIN APPLICATION
# ==============================================================================

class RPMEncrypterApp(ctk.CTk, TkinterDnD.DnDWrapper, ActivityViewMixin, NotesViewMixin, LibraryViewMixin, PasswordViewMixin, RekeyViewMixin, DecryptViewMixin, SettingsViewMixin, EncryptViewMixin, InspectViewMixin):
    """
    Primary application window.

    Tab layout:
        Encrypt | Decrypt | Vault Info | Re-Key | Password Gen | Settings
    """

    def __init__(self):
        super().__init__()

        # --- Window ---
        self.title(f"{APP_NAME} v{APP_VERSION}")
        try:
            self.iconbitmap(resource_path("icon.ico"))
        except Exception:
            pass
        self.geometry("1180x820")
        self.minsize(width=1024, height=600)

        # --- Threading ---
        self.msg_queue: queue.Queue = queue.Queue(maxsize=MSG_QUEUE_SIZE)  # Bounded queue
        self.worker_thread: Optional[threading.Thread] = None
        self.is_processing: bool = False
        self._clipboard_timer = None
        self._clipboard_hint_timer = None
        self._cancel_requested: bool = False  # Flag for graceful shutdown
        self._active_log:  Optional[LogBox] = None
        self._active_temp_files: List[Path] = []
        self._temp_files_lock = threading.Lock()

        # --- DnD ---
        try:
            self.TkdndVersion = TkinterDnD._require(self)
            logger.info("DnD initialised (tkdnd %s)", self.TkdndVersion)
        except Exception as exc:
            logger.warning("DnD unavailable: %s", exc)

        # --- Back-end services ---
        self._build_crypto()
        self.packager  = FolderPackager()
        self.wiper     = SecureWiper(passes=get_setting("wipe_passes", 1))
        self.inspector = VaultInspector(self.crypto)
        self.limiter   = AttemptLimiter()
        self.stats     = SessionStats()
        self.activity_logger = activity_log.ActivityLogger(enabled=get_setting("logging_enabled", False))
        self.scanner = vault_scanner.VaultScanner()
        self.versioner = self._build_versioner()

        # Clean up orphaned temp extraction directories
        self._cleanup_orphaned_temp_files()

        # Prune version history on startup (background thread, non-blocking)
        threading.Thread(target=self.versioner.prune_all, daemon=True).start()
        
        # --- State ---
        self.batch_queue:   List[Dict[str, Any]] = []
        self.decrypt_paths: List[str] = []

        # --- UI ---
        self._setup_appearance()
        self._setup_layout()
        self._setup_sidebar()
        self._setup_main_frames()
        self._setup_status_bar()
        self._show_encrypt()
        self._bind_shortcuts()
        self.bind("<Configure>", self._on_window_resize)

        self._show_frame("encrypt")
        self._poll_queue()
        
        if get_setting("check_updates", False):
            threading.Thread(target=self._check_update_background, daemon=True).start()
        if not get_setting("privacy_notice_shown", False):
            self.after(800, self._show_privacy_notice)
        self._tick_clock()

        # Guard against closing mid-operation
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        logger.info("Application started")

    
    def _on_window_resize(self, event):
        if event.widget == self:
            if hasattr(self, '_resize_timer'):
                self.after_cancel(self._resize_timer)
            self._resize_timer = self.after(150, self._handle_resize_done)

    def _handle_resize_done(self):
        self.update_idletasks()

    def _cleanup_orphaned_temp_files(self) -> None:
        import glob
        temp_dir = tempfile.gettempdir()
        
        # H4 FIX: orphaned temporaries are decrypted PLAINTEXT left behind by a
        # previous run that crashed/was killed before its own cleanup. Securely
        # wipe them instead of using a bare os.remove()/rmtree() that would leave
        # recoverable plaintext in free space. If a secure wipe fails, fall back to
        # a plain delete so startup cleanup still makes a best effort.
        # Cleanup temp zips
        for p in glob.glob(os.path.join(temp_dir, '.rpm_extract_*.zip')):
            try:
                self.wiper.wipe_file(Path(p))
            except Exception:
                try:
                    os.remove(p)
                except Exception:
                    pass

        # Cleanup temp extraction dirs
        for p in glob.glob(os.path.join(temp_dir, '.rpm_extract_dir_*')):
            if os.path.isdir(p):
                try:
                    self.wiper.wipe_folder(Path(p))
                except Exception:
                    shutil.rmtree(p, ignore_errors=True)

        # Cleanup temp packaging + decrypt zips (Phase 4)
        for p in glob.glob(os.path.join(temp_dir, '.rpm_pack_*.zip')):
            try:
                self.wiper.wipe_file(Path(p))
            except Exception:
                try:
                    os.remove(p)
                except Exception:
                    pass

    # ==========================================================================
    # VERSIONING INITIALISATION
    # ==========================================================================

    def _build_versioner(self) -> "versioning.VaultVersionManager":
        """Build a VaultVersionManager from the current config settings."""
        cfg = _load_cfg().get("settings", {})
        versions_root_str = cfg.get("versioning_dir", "")
        versions_root = Path(versions_root_str) if versions_root_str else None
        return versioning.VaultVersionManager(
            versions_root=versions_root,
            max_versions_per_vault=int(cfg.get("versioning_max_per_vault", 5)),
            max_total_size_bytes=int(cfg.get("versioning_max_total_mb", 2048)) * 1024 * 1024,
            enabled=bool(cfg.get("versioning_enabled", False)),
        )

    # ==========================================================================
    # CRYPTO INITIALISATION
    # ==========================================================================

    def _build_crypto(self) -> None:
        self.crypto = VaultCrypto(
            argon_memory      = get_setting("argon2_memory", ARGON2_MEMORY_COST),
            argon_iterations  = get_setting("argon2_time",   ARGON2_TIME_COST),
            argon_parallelism = get_setting("argon2_par",    ARGON2_PARALLELISM),
        )

    # ==========================================================================
    # UI SETUP
    # ==========================================================================

    def _setup_appearance(self) -> None:
        theme = get_setting("theme", "Dark")
        ctk.set_appearance_mode(theme)
        ctk.set_default_color_theme("dark-blue")
        self.configure(fg_color="#0d1117")

    def _setup_layout(self) -> None:
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.sidebar = ctk.CTkFrame(self, width=180, fg_color="#010409", corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="ns")
        self.sidebar.grid_rowconfigure(8, weight=1)
        self.sidebar.grid_propagate(False)

        self.main_frame = ctk.CTkFrame(self, fg_color="#0d1117", corner_radius=0)
        self.main_frame.grid(row=0, column=1, sticky="nsew")
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(0, weight=1)

        self.status_bar = ctk.CTkFrame(self, height=32, fg_color="transparent", corner_radius=0)
        self.status_bar.grid(row=1, column=0, columnspan=2, sticky="ew", padx=20, pady=(0, 10))

    def _setup_sidebar(self) -> None:
        ctk.CTkLabel(
            self.sidebar,
            text="RPM Encrypter"
        , font=ctk.CTkFont(size=14), text_color="#e6edf3").pack(pady=(25, 5), padx=20, anchor="w")

        ctk.CTkLabel(
            self.sidebar,
            text=f"v{APP_VERSION}    AES-256-GCM",
            font=ctk.CTkFont(size=12),
            text_color="#7d8590"
        ).pack(pady=(0, 20), padx=20, anchor="w")

        self.nav_buttons = {}
        nav_items = [
            ("encrypt",  "Encrypt",       self._show_encrypt),
            ("decrypt",  "Decrypt",       self._show_decrypt),
            ("inspect",  "Vault Info",    self._show_inspect),
            ("library",  "Library",       self._show_library),
            ("notes",    "Notes",         self._show_notes),
            ("rekey",    "Re-Key",        self._show_rekey),
            ("password", "Password Gen",  self._show_password),
            ("activity", "Activity",      self._show_activity),
        ]

        # Sidebar scrollable container
        self.sidebar_scroll = ctk.CTkScrollableFrame(self.sidebar, fg_color="transparent", corner_radius=0)
        self.sidebar_scroll.pack(fill="both", expand=True)

        # Container for top nav items
        self._nav_top = ctk.CTkFrame(self.sidebar_scroll, fg_color="transparent", corner_radius=0)
        self._nav_top.pack(fill="x")

        for key, text, cmd in nav_items:
            item = SidebarItem(self._nav_top, text=text, command=cmd)
            item.pack(fill="x")
            self.nav_buttons[key] = item

        # Bottom spacer
        spacer = ctk.CTkFrame(self.sidebar_scroll, fg_color="transparent", corner_radius=0)
        spacer.pack(fill="both", expand=True)

        # Settings at bottom
        self._nav_bottom = ctk.CTkFrame(self.sidebar_scroll, fg_color="transparent", corner_radius=0)
        self._nav_bottom.pack(fill="x", side="bottom", pady=(0, 20))
        
        # Live statistics panel above settings
        self._stats_frame = ctk.CTkFrame(self._nav_bottom, fg_color="#0d1117", corner_radius=0)
        self._stats_frame.pack(fill="x", padx=12, pady=(0, 10))
        self._stats_lbl = ctk.CTkLabel(
            self._stats_frame,
            text=self._stats_text(),
            font=ctk.CTkFont(size=14),
            justify="left",
            text_color="#e6edf3"
        )
        self._stats_lbl.pack(padx=10, pady=8, anchor="w")

        settings_item = SidebarItem(self._nav_bottom, text="Settings", command=self._show_settings)
        settings_item.pack(fill="x")
        self.nav_buttons["settings"] = settings_item

    def _stats_text(self) -> str:
        if not hasattr(self, "stats"):
            return ""
        snap = self.stats.snapshot()
        kb = snap["bytes_total"] // 1024
        return (
            f"⬡ Encrypted : {snap['encrypted']}\n"
            f"⬢ Decrypted : {snap['decrypted']}\n"
            f"⟳ Re-Keyed  : {snap['rekeyed']}\n"
            f"📦 Files     : {snap['files_total']}\n"
            f"💾 Data      : {kb:,} KB\n"
            f"⏱ Uptime    : {snap['uptime']}"
        )

    def _tick_clock(self) -> None:
        """Single unified 1-second ticker: updates stats panel + status-bar clock."""
        if hasattr(self, "_stats_lbl"):
            self._stats_lbl.configure(text=self._stats_text())
        if hasattr(self, "_clock_lbl"):
            self._clock_lbl.configure(text=datetime.now().strftime("%H:%M:%S"))
        self.after(1000, self._tick_clock)

    def _setup_main_frames(self) -> None:
        self.frames: Dict[str, ctk.CTkFrame] = {}
        builders = {
            "encrypt":  self._create_encrypt_frame,
            "decrypt":  self._create_decrypt_frame,
            "inspect":  self._create_inspect_frame,
            "library":  self._create_library_frame,
            "notes":    self._create_notes_frame,
            "rekey":    self._create_rekey_frame,
            "password": self._create_password_frame,
            "activity": self._create_activity_frame,
            "settings": self._create_settings_frame,
        }
        for name, builder in builders.items():
            frame = builder()
            self.frames[name] = frame

    def _setup_status_bar(self) -> None:
        # Pack order: right items first (to prevent truncation on resize)
        
        # Clock (rightmost)
        self._clock_lbl = ctk.CTkLabel(
            self.status_bar, text="",
            width=65, anchor="e", font=ctk.CTkFont(size=14), text_color="#e6edf3")
        self._clock_lbl.pack(side="right", padx=(0, 12))

        # Percentage label
        self._progress_pct = ctk.CTkLabel(
            self.status_bar, text="",
            width=38, anchor="e", font=ctk.CTkFont(size=14), text_color="#e6edf3")
        self._progress_pct.pack(side="right", padx=(0, 4))

        # Progress bar
        self.progress_bar = ctk.CTkProgressBar(
            self.status_bar, width=200, height=8, corner_radius=4,
            fg_color="#21262d", progress_color="#00d4aa")
        self.progress_bar.pack(side="right", padx=(0, 6))
        self.progress_bar.set(0)

        # Status text (left side)
        self.status_label = ctk.CTkLabel(
            self.status_bar, text="Ready", font=ctk.CTkFont(size=12), text_color="#7d8590")
        self.status_label.pack(side="left", padx=15)

    def _bind_shortcuts(self) -> None:
        self.bind("<Control-e>", lambda e: self._nav_shortcut(self._show_encrypt))
        self.bind("<Control-d>", lambda e: self._nav_shortcut(self._show_decrypt))
        self.bind("<Control-i>", lambda e: self._nav_shortcut(self._show_inspect))
        self.bind("<Control-l>", lambda e: self._nav_shortcut(self._show_library))
        self.bind("<Control-n>", lambda e: self._nav_shortcut(self._show_notes))
        self.bind("<Control-r>", lambda e: self._nav_shortcut(self._show_rekey))
        self.bind("<Control-p>", lambda e: self._nav_shortcut(self._show_password))
        self.bind("<Control-s>", lambda e: self._nav_shortcut(self._show_activity))
        self.bind("<Alt-s>", lambda e: self._nav_shortcut(self._show_settings))  # Changed from Ctrl+S

    def _nav_shortcut(self, action) -> None:
        """
        UI-05: ignore global navigation shortcuts while the user is typing in a
        text field. CTk entries/textboxes wrap tkinter Entry/Text widgets, and
        those inner widgets hold focus during input.
        """
        try:
            focused = self.focus_get()
        except Exception:
            focused = None
        if isinstance(focused, (Entry, Text)):
            return
        action()

    # ==========================================================================
    # NAVIGATION
    # ==========================================================================

    def _show_frame(self, name: str) -> None:
        # Hide all pages first
        for key, f in self.frames.items():
            f.grid_remove()
            
        # Show only the target page
        target_frame = self.frames.get(name)
        if target_frame:
            target_frame.grid(row=0, column=0, sticky="nsew", padx=24, pady=24)
            
        # Force immediate redraw to prevent flicker
        self.update_idletasks()
        
        for key, btn in self.nav_buttons.items():
            btn.set_active(key == name)
        self._set_status(
            {"encrypt": "Encrypt", "decrypt": "Decrypt", "inspect": "Vault Info",
             "rekey": "Re-Key Vault", "password": "Password Generator",
             "settings": "Settings"}.get(name, "")
        )

    def _show_encrypt(self):  self._show_frame("encrypt")
    def _show_decrypt(self):  self._show_frame("decrypt")
    def _show_inspect(self):  self._show_frame("inspect")
    def _show_library(self):  self._show_frame("library")
    def _show_notes(self):    self._show_frame("notes")
    def _show_rekey(self):    self._show_frame("rekey")
    def _show_password(self): self._show_frame("password")
    def _show_activity(self): self._show_frame("activity")
    def _show_settings(self): self._show_frame("settings")

    # ==========================================================================
    # WINDOW CLOSE GUARD (FIXED)
    # ==========================================================================

    def _on_close(self) -> None:
        self._clear_clipboard()
        if self.is_processing:
            if not messagebox.askyesno(
                "Operation in Progress",
                "An encryption/decryption operation is running.\n"
                "Closing now may leave temporary files on disk.\n\n"
                "Exit anyway?",
            ):
                return
            
            # Send cancel signal to worker
            self._cancel_requested = True
            
            # Wait for worker to finish (max 3 seconds)
            if self.worker_thread and self.worker_thread.is_alive():
                logger.info("Waiting for worker thread to finish...")
                self.worker_thread.join(timeout=3.0)
                if self.worker_thread.is_alive():
                    logger.warning("Worker thread did not stop gracefully")
        
        # Best-effort cleanup of temp files
        with self._temp_files_lock:
            files_to_clean = list(self._active_temp_files)
        
        for p in files_to_clean:
            try:
                if p.exists():
                    # H4 FIX: these are decrypted PLAINTEXT temporaries. Securely
                    # wipe them rather than merely unlinking so no recoverable copy
                    # is left behind on exit. Wrapped in try/except so a wipe
                    # failure (or a slow/hung wipe surfacing as OSError) can never
                    # stop the app from closing.
                    self.wiper.wipe_file(p)
                    logger.info("Securely wiped temp file on exit: %s", p)
            except Exception as exc:
                logger.warning("Failed to wipe temp file %s: %s", p, exc)

        self.destroy()

    # ==========================================================================
    # COMMON HELPERS
    # ==========================================================================

    def _set_status(self, text: str) -> None:
        assert_main_thread("_set_status")
        self.status_label.configure(text=text)

    def _lockout_check(self, entry_widget) -> bool:
        """Return True if locked out (shows error message)."""
        locked, secs = self.limiter.is_locked()
        if locked:
            entry_widget.clear()
            messagebox.showerror(
                "Too Many Attempts",
                f"Too many failed attempts.\nPlease wait {secs} seconds before trying again.",
            )
            return True
        return False

    def _parse_drop_paths(self, data: str) -> List[str]:
        """Parse tkinterdnd2 drop data (handles paths with spaces in braces)."""
        data = data.strip()
        paths, current, in_braces = [], "", False
        for ch in data:
            if ch == "{":
                in_braces = True
            elif ch == "}":
                in_braces = False
                if current:
                    paths.append(current)
                    current = ""
            elif ch == " " and not in_braces:
                if current:
                    paths.append(current)
                    current = ""
            else:
                current += ch
        if current:
            paths.append(current)
        return paths

    def _section_label(self, master, text: str) -> ctk.CTkLabel:
        lbl = ctk.CTkLabel(master, text=text, font=ctk.CTkFont(size=16, weight="bold"), text_color="#e6edf3")
        return lbl

    # ==========================================================================
    # ENCRYPT VIEW
    # ==========================================================================


    # ==========================================================================

    def _log_activity(self, action: str, filename: str, status: str, details: str = "") -> None:
        """
        F4 FIX: Single choke point for activity logging. Writes an event only
        when the user has left 'Enable Activity Logging' on (default OFF — PRIV-01). The
        setting is read live, so toggling it takes effect immediately; the
        ActivityLogger is also gated via its own `enabled` flag (defence in depth).
        """
        if get_setting("logging_enabled", False):
            self.activity_logger.log_event(action, filename, status, details)

    def _save_logging_setting(self) -> None:
        """Persist the activity-logging toggle and apply it to the live logger."""
        enabled = bool(self.logging_enabled_var.get())
        save_setting("logging_enabled", enabled)
        try:
            self.activity_logger.enabled = enabled
        except Exception:
            pass
        self._set_status("Activity logging " + ("enabled" if enabled else "disabled"))

    def _clear_all_traces(self) -> None:
        """
        F4 FIX: One-click erasure of every local forensic trace this app keeps on
        disk — the activity-log database, the Library cache, saved fingerprints,
        and the recent-file lists. Encrypted .vault files are never touched.
        Missing DB/cache files are handled gracefully.
        """
        if not messagebox.askyesno(
            "Clear All Local Traces",
            "This permanently erases local traces kept by this app:\n\n"
            "  •  Activity log database\n"
            "  •  Library cache\n"
            "  •  Saved fingerprints\n"
            "  •  Recent encrypt / decrypt / re-key lists\n\n"
            "Your encrypted .vault files are NOT affected.\n\nContinue?"
        ):
            return

        errors = []

        # 1. Activity log database (clear_logs no-ops gracefully if the DB is absent).
        try:
            self.activity_logger.clear_logs()
        except Exception as exc:
            errors.append(f"activity log: {exc}")

        # 2. Library cache file on disk + the in-memory copy so it is not re-saved.
        try:
            vault_scanner.CACHE_FILE.unlink(missing_ok=True)
        except Exception as exc:
            errors.append(f"library cache: {exc}")
        try:
            self.scanner.cache = {}
        except Exception:
            pass

        # 3 & 4. Fingerprints and recent-file lists stored in the config.
        try:
            cfg = _load_cfg()
            cfg["fingerprints"] = {}
            cfg["enc_sources"] = []
            cfg["dec_sources"] = []
            cfg["rekey_vaults"] = []
            _save_cfg(cfg)
        except Exception as exc:
            errors.append(f"config: {exc}")

        # Refresh any visible panels so the UI reflects the cleared state.
        fp_refresh = getattr(self, "_refresh_fingerprint_panel", None)
        if callable(fp_refresh):
            try:
                fp_refresh()
            except Exception:
                pass
        for bar_attr in ("_enc_recent", "_dec_recent", "_rk_recent"):
            bar = getattr(self, bar_attr, None)
            if bar is not None:
                try:
                    bar.refresh()
                except Exception:
                    pass

        if errors:
            messagebox.showwarning(
                "Clear All Local Traces",
                "Completed with some issues:\n\n" + "\n".join(errors))
        else:
            messagebox.showinfo(
                "Clear All Local Traces",
                "All local traces have been cleared from this device.")
        self._set_status("Local traces cleared")

    def _qlog(self, msg: str) -> None:
        """Send a log message from worker thread to the active log box."""
        try:
            self.msg_queue.put({"type": "log", "text": msg}, timeout=0.1)
        except queue.Full:
            logger.warning("Message queue full, log message dropped: %s", msg)


    def _check_update_background(self):
        update_info = check_for_update(APP_VERSION)
        if update_info is not None:
            self.after(0, self._show_update_notification, update_info)

    def _show_update_notification(self, update_info: dict):
        if hasattr(self, "_update_frame") and self._update_frame.winfo_exists():
            return
            
        self._update_frame = ctk.CTkFrame(self._nav_bottom, fg_color="transparent")
        self._update_frame.pack(side="top", fill="x", pady=(0, 8))
        
        # Clickable event wrapper
        def click_handler(event=None):
            self._download_update(update_info["url"])
            
        # Left container for text
        text_container = ctk.CTkFrame(self._update_frame, fg_color="transparent")
        text_container.pack(side="left", fill="x", expand=True)
        text_container.bind("<Button-1>", click_handler)
            
        # Banner layout
        lbl_new = ctk.CTkLabel(text_container, text=f"🔄 New version: v{update_info['version']}", text_color="#00d4aa", font=ctk.CTkFont(size=14), cursor="hand2")
        lbl_new.pack(side="top", anchor="w", padx=(12, 0))
        lbl_new.bind("<Button-1>", click_handler)
        
        lbl_dl = ctk.CTkLabel(text_container, text="Click to download", text_color="#7d8590", font=ctk.CTkFont(size=14), cursor="hand2")
        lbl_dl.pack(side="top", anchor="w", padx=(12, 0))
        lbl_dl.bind("<Button-1>", click_handler)
        
        self._update_frame.bind("<Button-1>", click_handler)
        
        # Close button on the right
        btn_close = ctk.CTkButton(self._update_frame, text="✕", width=20, height=20, fg_color="transparent", text_color="#7d8590", hover_color="#30363d", corner_radius=4)
        btn_close.pack(side="right", padx=(0, 4))
        
        def destroy_banner():
            if self._update_frame.winfo_exists():
                self._update_frame.destroy()
        
        btn_close.configure(command=destroy_banner)

    def _show_privacy_notice(self) -> None:
        # PRIV-01: one-time, NON-blocking first-run privacy notice. Both features
        # are already OFF by default; this only tells the user where to enable
        # them. The flag is saved on show, so it never reappears.
        save_setting("privacy_notice_shown", True)
        if hasattr(self, "_privacy_notice_frame") and self._privacy_notice_frame.winfo_exists():
            return

        self._privacy_notice_frame = ctk.CTkFrame(self._nav_bottom, fg_color="transparent")
        self._privacy_notice_frame.pack(side="top", fill="x", pady=(0, 8))

        def open_settings(event=None):
            self._show_settings()

        text_container = ctk.CTkFrame(self._privacy_notice_frame, fg_color="transparent")
        text_container.pack(side="left", fill="x", expand=True)
        text_container.bind("<Button-1>", open_settings)

        lbl1 = ctk.CTkLabel(text_container, text="🔒 Update checks & activity logging are OFF",
                            text_color="#00d4aa", font=ctk.CTkFont(size=14), cursor="hand2")
        lbl1.pack(side="top", anchor="w", padx=(12, 0))
        lbl1.bind("<Button-1>", open_settings)

        lbl2 = ctk.CTkLabel(text_container, text="Enable them in Settings if you want",
                            text_color="#7d8590", font=ctk.CTkFont(size=14), cursor="hand2")
        lbl2.pack(side="top", anchor="w", padx=(12, 0))
        lbl2.bind("<Button-1>", open_settings)

        self._privacy_notice_frame.bind("<Button-1>", open_settings)

        btn_close = ctk.CTkButton(self._privacy_notice_frame, text="✕", width=20, height=20,
                                  fg_color="transparent", text_color="#7d8590", hover_color="#30363d", corner_radius=4)
        btn_close.pack(side="right", padx=(0, 4))

        def destroy_banner():
            if self._privacy_notice_frame.winfo_exists():
                self._privacy_notice_frame.destroy()

        btn_close.configure(command=destroy_banner)

    def _download_update(self, url: str):
        webbrowser.open(url)

    def _poll_queue(self) -> None:
        try:
            while True:
                msg = self.msg_queue.get_nowait()
                self._handle_message(msg)
        except queue.Empty:
            pass
        self.after(100, self._poll_queue)

    def _handle_message(self, msg: Dict[str, Any]) -> None:
        mtype = msg.get("type")

        if mtype == "log":
            if self._active_log is not None:
                self._active_log.write(msg["text"])
            self._set_status(msg["text"])

        elif mtype == "progress_start":
            try:
                self.progress_bar.stop()
                self.progress_bar.configure(mode="determinate")
            except Exception:
                pass
            self.progress_bar.set(0)
            self._progress_pct.configure(text="0%")
            
            for attr in ("_enc_progress", "_dec_progress"):
                bar = getattr(self, attr, None)
                if bar:
                    try:
                        bar.stop()
                        bar.configure(mode="determinate")
                    except Exception:
                        pass
                    bar.set(0)
            for attr in ("_enc_pct_lbl", "_dec_pct_lbl"):
                lbl = getattr(self, attr, None)
                if lbl:
                    lbl.configure(text="0%")

        elif mtype == "progress":
            done  = msg.get("done", 0)
            total = msg.get("total", 0)
            if total > 0:
                pct = min(done / total, 1.0)
                pct_text = f"{int(pct * 100)}%"
                self.progress_bar.set(pct)
                self._progress_pct.configure(text=pct_text)
                
                for bar_attr, lbl_attr in (("_enc_progress", "_enc_pct_lbl"),
                                            ("_dec_progress", "_dec_pct_lbl")):
                    bar = getattr(self, bar_attr, None)
                    lbl = getattr(self, lbl_attr, None)
                    if bar:
                        bar.set(pct)
                    if lbl:
                        lbl.configure(text=pct_text)

        elif mtype == "error":
            self._set_status(msg.get("text", "Error"))
            self._reset_progress_bars()

        elif mtype == "auth_error":
            rem = msg.get("remaining", 0)
            secs = msg.get("lockout", 0)
            text = (f"Locked out — wait {secs}s" if secs
                    else f"Wrong password — {rem} attempts remaining")
            if hasattr(self, "_dec_attempts_lbl"):
                self._dec_attempts_lbl.configure(text=text)
            if hasattr(self, "_ins_attempts_lbl"):
                self._ins_attempts_lbl.configure(text=text)

        elif mtype == "batch_done":
            self.is_processing = False
            self._reset_progress_bars(success=True)
            self._set_status(msg.get("text", "Done"))
            
            # Re-enable buttons
            for attr, label in [
                ("encrypt_btn", "🔐  Encrypt Batch"),
                ("decrypt_btn", "🔓  Decrypt"),
                ("rekey_btn",   "⟳  Re-Key Vault"),
            ]:
                btn = getattr(self, attr, None)
                if btn:
                    btn.configure(state="normal", text=label)
            
            if hasattr(self, "_rk_recent"):
                self._rk_recent.refresh()
                
            msg_text = msg.get("text", "").lower()
            if "encrypt" in msg_text and "fail" not in msg_text and "error" not in msg_text:
                self.after(2000, self._clear_batch)
            elif "decrypt" in msg_text and "fail" not in msg_text and "error" not in msg_text:
                self.after(2000, self._clear_decrypt_form)

        elif mtype == "enc_password_strength":
            score = msg.get("score", 0)
            crack_time = msg.get("crack_time")
            color, label = STRENGTH_COLORS.get(score, ("gray", "Unknown"))
            self.strength_bar.set((score + 1) / 5.0)
            self.strength_bar.configure(progress_color=color)
            if crack_time:
                self.strength_label.configure(
                    text=f"{label}  •  Est. crack time: {crack_time}",
                    text_color=color)
            else:
                self.strength_label.configure(
                    text=f"{label}  (install zxcvbn for accurate analysis)",
                    text_color=color)

        elif mtype == "rekey_password_strength":
            score = msg.get("score", 0)
            crack_time = msg.get("crack_time")
            color, label = STRENGTH_COLORS.get(score, ("gray", "Unknown"))
            if crack_time:
                self.rekey_strength_lbl.configure(
                    text=f"New password strength: {label}  •  Est. crack time: {crack_time}",
                    text_color=color)

        elif mtype == "integrity_result":
            try:
                ok = msg.get("ok", False)
                sha = msg.get("sha", "")
                text = msg.get("msg", "")
                path = Path(msg.get("path", ""))
                icon = "✅" if ok else "❌"
                if ok:
                    self._save_fingerprint(path, sha)
                result_text = (
                    "═" * 55 + "\n"
                    "       INTEGRITY CHECK  (password-free)\n"
                    + "═" * 55 + f"\n\n  {icon}  {text}\n"
                )
                self.inspect_results.configure(state="normal")
                self.inspect_results.delete("0.0", "end")
                self.inspect_results.insert("0.0", result_text)
                self.inspect_results.configure(state="disabled")
                self._refresh_fingerprint_panel()
                self._set_status("Integrity check complete — fingerprint saved" if ok else "Integrity check failed")
                self._log_activity(
                    "Integrity",
                    path.name,
                    "Success" if ok else "Failed",
                    f"SHA: {sha[:16]}" if ok else text,
                )
            finally:
                self._set_inspect_hash_buttons(True)

        elif mtype == "verify_result":
            try:
                rec = msg.get("rec", {})
                current_sha = msg.get("current_sha", "")
                if not current_sha:
                    messagebox.showerror("Error", "Could not read vault file.")
                    self._set_status("Verify failed")
                elif current_sha == rec.get("sha256"):
                    messagebox.showinfo("Match ✅",
                                        f"Fingerprint matches the saved record.\n\n"
                                        f"Recorded : {rec.get('recorded')}\n"
                                        f"SHA-256  : {current_sha}")
                    self._set_status("✅ Fingerprint verified — file unchanged")
                else:
                    messagebox.showerror("Mismatch ❌",
                                         f"Fingerprint does NOT match!\n\n"
                                         f"Saved    : {rec.get('sha256')}\n"
                                         f"Current  : {current_sha}\n\n"
                                         "The vault file may have been tampered with or corrupted.")
                    self._set_status("❌ Fingerprint mismatch — file changed!")
            finally:
                self._set_inspect_hash_buttons(True)

        elif mtype == "fingerprint_results":
            # Update fingerprint panel with hash verification results
            data = msg.get("data", {})
            fps = self._load_fingerprints()
            
            self._fp_listbox.configure(state="normal")
            self._fp_listbox.delete("0.0", "end")
            
            for key, rec in sorted(fps.items(), key=lambda kv: kv[1]["recorded"], reverse=True):
                status, current_hash = data.get(key, ("⏳", None))
                sz_mb = rec["size"] / (1024 * 1024)
                line = (f"{status}  {rec['filename']}  "
                        f"({sz_mb:.1f} MB)  recorded {rec['recorded']}\n"
                        f"      SHA-256: {rec['sha256']}\n\n")
                self._fp_listbox.insert("end", line)
            
            self._fp_listbox.configure(state="disabled")

        elif mtype == "library_results":
            if hasattr(self, "library_textbox"):
                self.last_library_results = msg.get("data", [])
                self._filter_library()
                self._set_status(f"Library scan complete. Found {len(self.last_library_results)} vaults.")

        elif mtype == "note_decrypted":
            if hasattr(self, "note_textbox"):
                self.note_textbox.configure(state="normal")
                self.note_textbox.insert("end", msg.get("text", ""))

        elif mtype == "recovery_phrase":
            # Phase 3: recovery phrases are shown exactly once before encryption.
            # Worker-sent recovery_phrase messages are intentionally ignored to
            # prevent a duplicate hidden-mode dialog.
            return
            # H5 FIX: The hidden-vault worker (running off the main thread) cannot
            # build a dialog itself, so it enqueues the DECOY recovery phrase here.
            # Previously there was no branch for this message type, so the phrase
            # was silently discarded — a user who later lost the decoy password
            # could be permanently locked out. _handle_message runs on the main
            # thread, so displaying the dialog from here is thread-safe.

    def _show_recovery_dialog(self, phrase: str) -> None:
        """
        H5 FIX: Display an already-generated recovery phrase (e.g. the decoy
        recovery phrase produced by the hidden-vault worker) and force the user
        to acknowledge it before it disappears.

        This mirrors the read-only recovery-phrase modal the normal encrypt path
        shows synchronously, reusing the same widgets and styling. It is
        display-only — the phrase is generated elsewhere — so unlike the encrypt
        modal it returns no key and gates no operation. Invoked from
        _handle_message (main thread); the nested wait_window blocks the main
        window until dismissed so the user cannot miss it.
        """
        if not phrase:
            return

        dialog = ctk.CTkToplevel(self)
        dialog.title("Recovery Phrase")
        dialog.geometry("550x350")
        dialog.configure(fg_color="#0d1117")
        dialog.resizable(False, False)
        dialog.attributes("-topmost", True)
        dialog.grab_set()

        scroll = ctk.CTkScrollableFrame(dialog, fg_color="transparent", corner_radius=0)
        scroll.pack(fill="both", expand=True, padx=20, pady=5)

        ctk.CTkLabel(scroll, text="Your Recovery Phrase", font=ctk.CTkFont(size=14), text_color="#e6edf3").pack(pady=(20, 5))
        ctk.CTkLabel(scroll, text="Write this down and keep it safe. It will never be shown again.", font=ctk.CTkFont(size=14), text_color="#e6edf3").pack(pady=(0, 15))

        textbox = ctk.CTkTextbox(scroll, wrap="word", font=ctk.CTkFont(size=14), fg_color="#161b22", text_color="#e6edf3", corner_radius=6)
        textbox.pack(padx=10, fill="x")
        textbox.insert("0.0", phrase)
        textbox.configure(state="disabled")

        confirmed = ctk.BooleanVar(value=False)
        check = ctk.CTkCheckBox(scroll, text="I have securely saved this 24-word phrase.", variable=confirmed, fg_color="#00d4aa", text_color="#e6edf3", border_color="#30363d", checkmark_color="#0d1117")
        check.pack(pady=20)

        btn_frame = ctk.CTkFrame(dialog, fg_color="transparent", corner_radius=0)
        btn_frame.pack(fill="x", side="bottom", pady=10)

        def on_done():
            if not confirmed.get():
                messagebox.showwarning("Confirm", "You must confirm you have saved the phrase.", parent=dialog)
                return
            dialog.destroy()

        ctk.CTkButton(btn_frame, text="Done", command=on_done, fg_color="#21262d", text_color="#e6edf3", hover_color="#30363d", font=ctk.CTkFont(size=14), height=42, corner_radius=8).pack(side="right", padx=10)

        # Force acknowledgment: closing via the window's X button must also pass
        # through on_done() so the phrase cannot be dismissed without confirming.
        dialog.protocol("WM_DELETE_WINDOW", on_done)

        self.wait_window(dialog)

    def _reset_progress_bars(self, success=False):
        """Reset all progress bars to initial state."""
        assert_main_thread("_reset_progress_bars")

        def revert_color(bar, lbl):
            if bar.winfo_exists():
                bar.configure(progress_color="#00d4aa")
                bar.set(0)
            if lbl and lbl.winfo_exists():
                lbl.configure(text="0%")

        for bar_attr, lbl_attr in (
            ("progress_bar", "_progress_pct"),
            ("_enc_progress", "_enc_pct_lbl"),
            ("_dec_progress", "_dec_pct_lbl"),
        ):
            bar = getattr(self, bar_attr, None)
            lbl = getattr(self, lbl_attr, None)
            if bar:
                try:
                    bar.stop()
                    bar.configure(mode="determinate")
                except Exception:
                    pass
                if success:
                    bar.configure(progress_color="#3fb950")
                    bar.set(1.0)
                    if lbl: lbl.configure(text="100%")
                    self.after(2000, lambda b=bar, l=lbl: revert_color(b, l))
                else:
                    bar.set(0)
                    if lbl: lbl.configure(text="0%")
            if lbl:
                lbl.configure(text="")

    # ==========================================================================
    # ENTRY POINT
    # ==========================================================================

    def run(self) -> None:
        self.stats.mark_start()
        self.mainloop()


def main() -> None:
    app = RPMEncrypterApp()
    app.run()


if __name__ == "__main__":
    main()
