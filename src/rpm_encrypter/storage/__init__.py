"""Storage layer exports for RPM Encrypter."""

from .activity_log import DB_PATH, ActivityLogger
from .atomic import atomic_output
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
from .inspector import VaultInspector
from .log_hygiene import redact_path
from .packager import MAX_EXTRACT_SIZE, FolderPackager, assign_unique_arcnames
from .scanner import CACHE_FILE, VaultScanner
from .versioning import VERSIONS_ROOT_DEFAULT, VaultVersionManager, VersionEntry
from .wiper import WIPE_CHUNK_SIZE, SecureWiper

__all__ = [
    "DB_PATH",
    "ActivityLogger",
    "atomic_output",
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
    "VaultInspector",
    "redact_path",
    "MAX_EXTRACT_SIZE",
    "assign_unique_arcnames",
    "FolderPackager",
    "CACHE_FILE",
    "VaultScanner",
    "VERSIONS_ROOT_DEFAULT",
    "VaultVersionManager",
    "VersionEntry",
    "WIPE_CHUNK_SIZE",
    "SecureWiper",
]
