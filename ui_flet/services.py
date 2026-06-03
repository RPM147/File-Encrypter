"""Backend service wiring for the Flet UI.

This module intentionally imports no Flet symbols. It mirrors the backend object
graph built by the legacy CustomTkinter shell so Stage-1 bridge tests can run in
a headless environment.
"""
import glob
import os
import queue
import shutil
import tempfile
import threading
from pathlib import Path

from crypto_core import (
    VaultCrypto, ARGON2_MEMORY_COST, ARGON2_TIME_COST, ARGON2_PARALLELISM,
)
from file_handler import SecureWiper, FolderPackager, VaultInspector
from app_state import AttemptLimiter, SessionStats
from app_config import get_setting, _load_cfg
from ui_flet.controllers.settings_controller import ensure_modern_settings_defaults
import activity_log
import vault_scanner
import versioning


MSG_QUEUE_SIZE = 1000


class AppServices:
    """Builds and owns the backend services exactly as RPMEncrypterApp.__init__
    does. FLET-FREE on purpose -> unit-testable without a display. The Flet shell
        drives this; this module must remain Flet-free."""

    def __init__(self):
        ensure_modern_settings_defaults()
        self.msg_queue: "queue.Queue" = queue.Queue(maxsize=MSG_QUEUE_SIZE)
        self.is_processing = False
        self.cancel_requested = False
        self.shutdown_requested = False
        self._active_temp_files = []
        self._temp_files_lock = threading.Lock()

        self.crypto = self._build_crypto()
        self.packager = FolderPackager()
        self.wiper = SecureWiper(passes=get_setting("wipe_passes", 1))
        self.inspector = VaultInspector(self.crypto)
        self.limiter = AttemptLimiter()
        self.stats = SessionStats()
        self.activity_logger = activity_log.ActivityLogger(
            enabled=get_setting("logging_enabled", False)
        )
        self.scanner = vault_scanner.VaultScanner()
        self.versioner = self._build_versioner()

    def _build_crypto(self):
        return VaultCrypto(
            argon_memory=get_setting("argon2_memory", ARGON2_MEMORY_COST),
            argon_iterations=get_setting("argon2_time", ARGON2_TIME_COST),
            argon_parallelism=get_setting("argon2_par", ARGON2_PARALLELISM),
        )

    def _build_versioner(self):
        cfg = _load_cfg().get("settings", {})
        versions_root_str = cfg.get("versioning_dir", "")
        versions_root = Path(versions_root_str) if versions_root_str else None
        return versioning.VaultVersionManager(
            versions_root=versions_root,
            max_versions_per_vault=int(cfg.get("versioning_max_per_vault", 5)),
            max_total_size_bytes=int(cfg.get("versioning_max_total_mb", 2048)) * 1024 * 1024,
            enabled=bool(cfg.get("versioning_enabled", False)),
        )

    def rebuild_crypto(self):
        """Call after KDF settings change (mirrors gui_app._build_crypto)."""
        self.crypto = self._build_crypto()
        self.inspector = VaultInspector(self.crypto)

    def start_background_prune(self):
        """Non-blocking version-history prune on startup (mirrors gui_app)."""
        threading.Thread(target=self.versioner.prune_all, daemon=True).start()

    def cleanup_orphaned_temp_files(self):
        """Securely wipe decrypted PLAINTEXT left by a crashed previous run.
        Mirrors gui_app._cleanup_orphaned_temp_files (H4 FIX): secure-wipe first,
        fall back to plain delete. Patterns are the app's temp prefixes."""
        temp_dir = tempfile.gettempdir()
        for pattern, is_dir in (
            (".rpm_extract_*.zip", False),
            (".rpm_extract_dir_*", True),
            (".rpm_pack_*.zip", False),
        ):
            for p in glob.glob(os.path.join(temp_dir, pattern)):
                try:
                    if is_dir:
                        if os.path.isdir(p):
                            self.wiper.wipe_folder(Path(p))
                    else:
                        self.wiper.wipe_file(Path(p))
                except Exception:
                    try:
                        if os.path.isdir(p):
                            shutil.rmtree(p, ignore_errors=True)
                        else:
                            os.remove(p)
                    except Exception:
                        pass
