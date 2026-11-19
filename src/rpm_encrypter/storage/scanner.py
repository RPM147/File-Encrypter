"""Monitored-directory vault scanner and metadata cache."""

import json
import logging
import struct
from pathlib import Path
from typing import Any, Dict, List

from rpm_encrypter.core import (
    MAX_HEADER_SIZE,
    VAULT_MAGIC,
    VaultFormatError,
    is_supported_vault_version,
)
from .log_hygiene import redact_path

logger = logging.getLogger(__name__)

CACHE_FILE = Path.home() / ".rpm_encrypter_library.json"


class VaultScanner:
    def __init__(self):
        self.cache: Dict[str, Dict[str, Any]] = self._load_cache()

    def _load_cache(self) -> Dict[str, Dict[str, Any]]:
        if CACHE_FILE.exists():
            try:
                with open(CACHE_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning("Failed to load library cache: %s", e)
        return {}

    def _save_cache(self) -> None:
        try:
            with open(CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(self.cache, f)
        except Exception as e:
            logger.error("Failed to save library cache: %s", e)

    def _extract_metadata(self, path: Path) -> Dict[str, Any]:
        """
        Extract the limited, non-sensitive metadata available from a vault header
        WITHOUT a password.
        """
        with open(path, "rb") as f:
            magic = f.read(len(VAULT_MAGIC))
            if magic != VAULT_MAGIC:
                raise VaultFormatError("Invalid vault magic bytes")

            version_data = f.read(1)
            if len(version_data) != 1:
                raise VaultFormatError("Vault file truncated: missing version byte.")
            (version,) = struct.unpack("!B", version_data)
            if not is_supported_vault_version(version):
                raise VaultFormatError(f"Unsupported vault version: {version}")

            header_len_data = f.read(4)
            if len(header_len_data) != 4:
                raise VaultFormatError("Vault file truncated: missing header length.")
            (header_len,) = struct.unpack("!I", header_len_data)
            if header_len > MAX_HEADER_SIZE:
                raise VaultFormatError(
                    f"Vault header length ({header_len}) exceeds maximum allowed size"
                )
            header_json_bytes = f.read(header_len)
            if len(header_json_bytes) != header_len:
                raise VaultFormatError("Vault file truncated: header block incomplete.")

            try:
                header_dict = json.loads(header_json_bytes.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise VaultFormatError(f"Invalid vault header JSON: {exc}") from exc
            payload = header_dict.get("payload", {})

            try:
                container_size = int(payload.get("container_size", 0))
            except (TypeError, ValueError):
                container_size = 0
            return {
                "filename": path.name,
                "container_size": container_size,
                "source_type": "Encrypted Metadata",
                "created_at": "Requires Password",
            }

    def scan_directories(self, directories: List[str]) -> List[Dict[str, Any]]:
        """
        Scan directories for .vault files.
        Uses cache to skip extracting metadata from unmodified files.
        """
        results = []
        cache_updated = False
        seen_paths = set()

        for dir_str in directories:
            dir_path = Path(dir_str)
            if not dir_path.is_dir():
                continue

            for vault_file in dir_path.rglob("*.vault"):
                if not vault_file.is_file():
                    continue

                path_str = str(vault_file.resolve())
                seen_paths.add(path_str)

                try:
                    stat = vault_file.stat()
                    mtime = stat.st_mtime
                    size = stat.st_size

                    cached = self.cache.get(path_str)

                    if cached and cached.get("mtime") == mtime:
                        results.append(cached)
                    else:
                        meta = self._extract_metadata(vault_file)
                        entry = {
                            "path": path_str,
                            "mtime": mtime,
                            "encrypted_size": size,
                            "filename": meta.get("filename"),
                            "container_size": meta.get("container_size"),
                            "source_type": meta.get("source_type"),
                            "created_at": meta.get("created_at"),
                        }
                        self.cache[path_str] = entry
                        results.append(entry)
                        cache_updated = True
                except Exception as e:
                    logger.warning("Skipping unreadable vault %s: %s", redact_path(path_str), e)

        resolved_dirs = [Path(d).resolve() for d in directories]
        keys_to_remove = [
            p
            for p in self.cache.keys()
            if p not in seen_paths
            and any(Path(p).resolve() == d or d in Path(p).resolve().parents for d in resolved_dirs)
        ]
        for k in keys_to_remove:
            del self.cache[k]
            cache_updated = True

        if cache_updated:
            self._save_cache()

        return results
