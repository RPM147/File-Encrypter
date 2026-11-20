"""Best-effort secure deletion utility (chunked overwrite + symlink safety)."""

import logging
import os
import secrets
from pathlib import Path
from typing import Callable, Optional

from .log_hygiene import redact_path

logger = logging.getLogger(__name__)

# Overwrite random data in bounded 1 MiB chunks to bound memory usage.
WIPE_CHUNK_SIZE = 1 * 1024 * 1024  # 1 MiB


class SecureWiper:
    """
    Best-effort secure deletion utility.

    Overwrites file contents with CSPRNG bytes in bounded chunks before unlinking.
    Does not follow symlinks: symlink handles are unlinked without touching targets.
    """

    def __init__(self, passes: int = 1):
        self.passes = passes

    def wipe_file(self, path: Path, on_skip: Optional[Callable[[str], None]] = None) -> None:
        """Overwrite a single file with random bytes, then unlink it."""
        path = Path(path)
        if path.is_symlink():
            try:
                path.unlink()
                logger.warning(
                    "Secure-wipe skipped symlink (removed link, target kept): %s",
                    redact_path(path),
                )
                if on_skip:
                    on_skip(f"Skipped symlink (removed link, target kept): {redact_path(path)}")
            except OSError as exc:
                logger.error("Failed to unlink symlink %s: %s", redact_path(path), exc)
            return
        if not path.exists() or not path.is_file():
            logger.warning("Wipe target does not exist or is not a file: %s", redact_path(path))
            return

        success = False
        try:
            with open(path, "r+b") as f:
                size = os.fstat(f.fileno()).st_size
                if size > 0:
                    for _ in range(self.passes):
                        f.seek(0)
                        bytes_written = 0
                        while bytes_written < size:
                            chunk_size = min(WIPE_CHUNK_SIZE, size - bytes_written)
                            f.write(secrets.token_bytes(chunk_size))
                            bytes_written += chunk_size
                        f.flush()
                        os.fsync(f.fileno())
            success = True
            logger.info("Overwrite successful: %s", redact_path(path))
        except OSError as exc:
            logger.error("Failed to overwrite %s: %s", redact_path(path), exc)
        finally:
            if success:
                try:
                    path.unlink()
                    logger.info("Securely wiped file: %s", redact_path(path))
                except Exception as del_exc:
                    logger.critical(
                        "Wiped file could not be deleted: %s - %s",
                        redact_path(path),
                        del_exc,
                    )
                    raise
            else:
                logger.critical(
                    "Failed to overwrite %s. File was NOT deleted to prevent plaintext recovery.",
                    redact_path(path),
                )
                raise OSError(f"Secure wipe failed for {redact_path(path)}. File remains on disk.")

    def wipe_folder(self, path: Path, on_skip: Optional[Callable[[str], None]] = None) -> None:
        """Recursively wipe files in a directory tree bottom-up without following symlinks."""
        path = Path(path)
        if path.is_symlink():
            try:
                path.unlink()
            except OSError:
                pass
            logger.warning(
                "Secure-wipe skipped symlink folder (removed link, target kept): %s",
                redact_path(path),
            )
            if on_skip:
                on_skip(f"Skipped symlink folder (removed link, target kept): {redact_path(path)}")
            return
        if not path.exists():
            return
        if not path.is_dir():
            self.wipe_file(path, on_skip=on_skip)
            return

        for root, dirs, files in os.walk(path, topdown=False, followlinks=False):
            for fname in files:
                full = Path(root) / fname
                if full.is_symlink():
                    try:
                        full.unlink()
                    except OSError:
                        pass
                    logger.warning(
                        "Secure-wipe skipped symlink file (removed link, target kept): %s",
                        redact_path(full),
                    )
                    if on_skip:
                        on_skip(
                            f"Skipped symlink file (removed link, target kept): {redact_path(full)}"
                        )
                else:
                    self.wipe_file(full, on_skip=on_skip)
            for dname in dirs:
                full = os.path.join(root, dname)
                if os.path.islink(full):
                    try:
                        os.unlink(full)
                    except OSError:
                        try:
                            os.rmdir(full)
                        except OSError:
                            pass
                    logger.warning(
                        "Secure-wipe skipped symlink dir (removed link, target kept): %s",
                        redact_path(full),
                    )
                    if on_skip:
                        on_skip(
                            f"Skipped symlink dir (removed link, target kept): {redact_path(full)}"
                        )
                else:
                    try:
                        os.rmdir(full)
                    except OSError:
                        pass

        try:
            os.rmdir(path)
        except OSError:
            pass

        logger.info("Securely wiped folder: %s", redact_path(path))
