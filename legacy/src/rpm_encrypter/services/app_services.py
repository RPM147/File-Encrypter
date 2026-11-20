"""Backend service wiring for RPM Encrypter (Flet-free on purpose)."""

import glob
import os
import queue
import shutil
import tempfile
import threading
from pathlib import Path

from rpm_encrypter.core import (
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    ARGON2_TIME_COST,
    VaultCrypto,
)
from rpm_encrypter.storage import (
    ActivityLogger,
    FolderPackager,
    SecureWiper,
    VaultInspector,
    VaultScanner,
    VaultVersionManager,
    _load_cfg,
    get_setting,
)
from . import updater
from .controllers.settings_controller import ensure_modern_settings_defaults
from .events import UpdateAvailableEvent
from .state import AttemptLimiter, SessionStats

MSG_QUEUE_SIZE = 1000


class AppServices:
    """Builds and owns the backend services cleanly separated from the Flet UI."""

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
        self.activity_logger = ActivityLogger(
            enabled=get_setting("logging_enabled", False)
        )
        self.scanner = VaultScanner()
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
        return VaultVersionManager(
            versions_root=versions_root,
            max_versions_per_vault=int(cfg.get("versioning_max_per_vault", 5)),
            max_total_size_bytes=int(cfg.get("versioning_max_total_mb", 2048)) * 1024 * 1024,
            enabled=bool(cfg.get("versioning_enabled", False)),
        )

    def rebuild_crypto(self):
        """Rebuild VaultCrypto and VaultInspector after KDF settings change."""
        self.crypto = self._build_crypto()
        self.inspector = VaultInspector(self.crypto)

    def start_background_prune(self):
        """Non-blocking version-history prune on startup."""
        threading.Thread(target=self.versioner.prune_all, daemon=True).start()

    def start_update_check(self, current_version: str) -> bool:
        """Start an opt-in background update check if enabled in settings."""
        if not get_setting("check_updates", False):
            return False

        def _worker():
            info = updater.check_for_update(current_version)
            if info is not None:
                try:
                    self.msg_queue.put(
                        UpdateAvailableEvent(info=info),
                        timeout=0.5,
                    )
                except queue.Full:
                    pass

        threading.Thread(target=_worker, daemon=True).start()
        return True

    def cleanup_orphaned_temp_files(self):
        """Securely wipe decrypted plaintext left by a crashed previous run."""
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
