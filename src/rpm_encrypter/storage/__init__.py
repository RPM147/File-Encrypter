"""Storage layer exports for RPM Encrypter."""

from .activity_log import DB_PATH, ActivityLogger
from .config import (
    CONFIG_FILE,
    MAX_RECENT,
    _CONFIG_LOCK,
    _load_cfg,
    _mutate_cfg,
    _save_cfg,
    get_recent,
    get_setting,
    push_recent,
    save_setting,
)
from .file_handler import (
    MAX_EXTRACT_SIZE,
    WIPE_CHUNK_SIZE,
    FolderPackager,
    SecureWiper,
    VaultInspector,
    atomic_output,
)
from .log_hygiene import redact_path
from .scanner import CACHE_FILE, VaultScanner
from .versioning import VERSIONS_ROOT_DEFAULT, VaultVersionManager, VersionEntry

__all__ = [
    "DB_PATH",
    "ActivityLogger",
    "CONFIG_FILE",
    "MAX_RECENT",
    "_CONFIG_LOCK",
    "_load_cfg",
    "_mutate_cfg",
    "_save_cfg",
    "get_recent",
    "get_setting",
    "push_recent",
    "save_setting",
    "MAX_EXTRACT_SIZE",
    "WIPE_CHUNK_SIZE",
    "FolderPackager",
    "SecureWiper",
    "VaultInspector",
    "atomic_output",
    "redact_path",
    "CACHE_FILE",
    "VaultScanner",
    "VERSIONS_ROOT_DEFAULT",
    "VaultVersionManager",
    "VersionEntry",
]
