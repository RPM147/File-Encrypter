"""
RPM Encrypter - File Handling Module
=====================================

Handles secure file operations including folder packaging into zip archives,
secure file wiping (multi-pass overwrite), vault metadata inspection,
and archive extraction. All operations are designed to integrate cleanly
with the GUI's background worker threads.

Security Notes:
---------------
- Secure wipe overwrites file sectors with CSPRNG bytes before unlinking.
- Folder packaging preserves directory structure and file metadata in zip.
- Vault inspection leverages envelope encryption to read metadata without
  decrypting the potentially massive payload.
"""

import os
import zipfile
import tempfile
import shutil
import secrets
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Callable, Any

from crypto_core import (
    VaultCrypto, VaultHeader, AuthenticationError, VaultFormatError,
    OperationCancelledError,
)
from log_hygiene import redact_path

logger = logging.getLogger(__name__)

# H3 FIX: Overwrite random data in bounded chunks so wiping a multi-gigabyte
# file uses constant memory instead of allocating the whole file at once.
WIPE_CHUNK_SIZE = 1 * 1024 * 1024  # 1 MiB

# M4 FIX: Hard ceiling on total uncompressed size during extraction to defeat
# zip bombs (a small archive that expands to fill the disk).
MAX_EXTRACT_SIZE = 10 * 1024 * 1024 * 1024  # 10 GiB


def _raise_if_cancelled(cancel_check):
    if cancel_check is not None and cancel_check():
        raise OperationCancelledError("Operation cancelled by user.")


# ------------------------------------------------------------------------------
# ATOMIC VAULT OUTPUT (Phase 6 / SEC-04)
# ------------------------------------------------------------------------------

def atomic_output(final_path: Path, write_fn: Callable[[Path], None]) -> None:
    """
    Phase 6 (SEC-04): write a vault atomically.

    Creates a recognizable temp file IN THE SAME DIRECTORY as ``final_path`` (so the
    final rename is atomic — ``os.replace`` is only atomic within one filesystem),
    invokes ``write_fn(temp_path)`` to produce the complete vault, then atomically
    swaps it onto ``final_path``. If ``write_fn`` raises for ANY reason, the partial
    temp is removed so nothing is ever left under the real ``.vault`` name.

    The temp is CIPHERTEXT, so a plain unlink is the correct cleanup (no secure wipe).
    """
    final_path = Path(final_path)
    fd, tmp_name = tempfile.mkstemp(
        prefix=".rpm_vaulttmp_", suffix=".part", dir=str(final_path.parent)
    )
    os.close(fd)
    tmp_path = Path(tmp_name)
    try:
        write_fn(tmp_path)                 # caller writes the full vault into tmp_path
        os.replace(tmp_path, final_path)   # atomic swap on the same volume
    except BaseException:
        # Never leave a partial output. The temp is ciphertext → plain unlink
        # (do NOT secure-wipe and do NOT route through SecureWiper / .rpm_pack_).
        try:
            tmp_path.unlink()
        except OSError:
            pass
        raise


# DATA-01 (Phase 11): map a flat list of selected files to collision-safe zip
# arcnames. Unique basenames are kept; colliding ones are prefixed with their
# sanitized parent-folder name; a numeric suffix is the final guaranteed-unique
# fallback. Loss-proof: every input maps to a distinct arcname.
_UNSAFE_NAME_CHARS = set('<>:"/\\|?*') | {chr(c) for c in range(0x20)}


def _safe_component(name: str) -> str:
    """Reduce a folder/file name to one safe path component."""
    cleaned = "".join("_" if ch in _UNSAFE_NAME_CHARS else ch for ch in (name or ""))
    return cleaned.strip(" .")


def assign_unique_arcnames(paths):
    """
    Return a list of (Path, arcname) in the same order as ``paths``.

    Guarantees all arcnames are distinct, preventing zip entry overwrite and
    data loss when selected files share a basename.
    """
    from collections import Counter

    paths = [Path(p) for p in paths]
    counts = Counter(p.name for p in paths)
    used = set()
    result = []

    for p in paths:
        if counts[p.name] == 1:
            arc = p.name
        else:
            parent = _safe_component(p.parent.name) or "root"
            arc = f"{parent}_{p.name}"

        candidate = arc
        i = 1
        while candidate in used:
            candidate = f"{Path(arc).stem}_{i}{Path(arc).suffix}"
            i += 1
        used.add(candidate)
        result.append((p, candidate))

    return result


# ------------------------------------------------------------------------------
# SECURE FILE WIPER
# ------------------------------------------------------------------------------

class SecureWiper:
    """
    Best-effort secure deletion utility.

    Instead of calling `os.remove()` directly (which only unlinks the inode
    and leaves data recoverable via undelete tools), this class overwrites
    the file's allocated sectors with cryptographically random bytes before
    deletion. For directories, it walks the tree bottom-up, wiping every file
    and then removing empty folders.

    Limitations (inherent to the OS / storage layer — not a bug):
    - SSDs with wear leveling may not overwrite the original physical sectors.
    - Copy-on-write filesystems (ZFS, Btrfs, APFS) may retain old data blocks.
    - Cloud-backed or network volumes offer no overwrite guarantees.
    - Filename and directory structure remain in the filesystem journal until
      the journal entries are overwritten by subsequent activity.
    For maximum assurance, use full-disk encryption on the source volume.
    """

    def __init__(self, passes: int = 1):
        """
        Args:
            passes: Number of overwrite iterations. OWASP recommends 1 pass
                of random data for modern media (SSD/HDD) as multi-pass
                patterns are largely obsolete for flash-based storage.
        """
        self.passes = passes

    def wipe_file(self, path: Path, on_skip: Optional[Callable[[str], None]] = None) -> None:
        """
        Overwrite a single file with random bytes, then delete it.

        Steps:
            1. Determine exact file size.
            2. Open in read+write binary mode ('r+b') to preserve the inode.
            3. For each pass, seek to start and write `secrets.token_bytes(size)`.
            4. Call `os.fsync()` to force flush to physical media.
            5. Close and `unlink()` the file.
        """
        path = Path(path)
        # Phase 5 (SEC-03): never follow a symlink. Opening it 'r+b' would scribble
        # random bytes over the TARGET (possibly a file outside the selected folder).
        # Remove the link itself only; leave the target untouched. is_symlink() uses
        # lstat, so a broken/dangling link is handled too — do NOT gate this behind
        # exists() (which follows the link and is False for a broken one).
        if path.is_symlink():
            try:
                path.unlink()
                logger.warning("Secure-wipe skipped symlink (removed link, target kept): %s", redact_path(path))
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
            with open(path, 'r+b') as f:
                size = os.fstat(f.fileno()).st_size
                if size > 0:
                    for _ in range(self.passes):
                        # H3 FIX: write random data in bounded chunks instead of
                        # allocating `size` bytes at once (prevents MemoryError on
                        # multi-gigabyte files).
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
            # H2 FIX: Only delete the file if the overwrite actually succeeded.
            # Unlinking after a failed overwrite would leave recoverable plaintext
            # while falsely reporting a secure wipe. On failure, keep the file and
            # raise so the caller learns the wipe did not happen.
            if success:
                try:
                    path.unlink()
                    logger.info("Securely wiped file: %s", redact_path(path))
                except Exception as del_exc:
                    logger.critical("Wiped file could not be deleted: %s - %s", redact_path(path), del_exc)
                    raise
            else:
                logger.critical(
                    "Failed to overwrite %s. File was NOT deleted to prevent plaintext recovery.",
                    redact_path(path)
                )
                raise OSError(f"Secure wipe failed for {redact_path(path)}. File remains on disk.")

    def wipe_folder(self, path: Path, on_skip: Optional[Callable[[str], None]] = None) -> None:
        """
        Recursively wipe all files in a directory tree, then remove directories.

        Uses a bottom-up walk to ensure we never attempt to delete a directory
        that still contains files.
        """
        path = Path(path)
        # Phase 5 (SEC-03): if the folder handle itself is a symlink, remove only the
        # link and return — never walk into / wipe the target tree (it may live
        # outside the selected folder). is_symlink() uses lstat, so a broken link is
        # handled too; do NOT gate behind exists() (which follows the link).
        if path.is_symlink():
            try:
                path.unlink()
            except OSError:
                pass
            logger.warning("Secure-wipe skipped symlink folder (removed link, target kept): %s", redact_path(path))
            if on_skip:
                on_skip(f"Skipped symlink folder (removed link, target kept): {redact_path(path)}")
            return
        if not path.exists():
            return
        if not path.is_dir():
            self.wipe_file(path, on_skip=on_skip)
            return

        # Phase 5 (SEC-03): walk bottom-up WITHOUT following symlinks. os.walk with
        # followlinks=False never descends into symlinked subdirs; pathlib.rglob WOULD
        # descend into them on Python 3.12 (recurse_symlinks=False is 3.13+). Wipe real
        # files, unlink symlinks (file or dir) without touching their targets, and
        # rmdir emptied real dirs.
        for root, dirs, files in os.walk(path, topdown=False, followlinks=False):
            for fname in files:
                full = Path(root) / fname
                if full.is_symlink():
                    try: full.unlink()
                    except OSError: pass
                    logger.warning("Secure-wipe skipped symlink file (removed link, target kept): %s", redact_path(full))
                    if on_skip:
                        on_skip(f"Skipped symlink file (removed link, target kept): {redact_path(full)}")
                else:
                    self.wipe_file(full, on_skip=on_skip)
            for dname in dirs:
                full = os.path.join(root, dname)
                if os.path.islink(full):
                    # Remove the link only, never the target. POSIX: os.unlink removes
                    # a symlink-to-dir. Windows: os.unlink raises OSError on a directory
                    # symlink and os.rmdir is required (it STILL removes only the reparse
                    # point, not the target's contents) — try unlink first, then rmdir.
                    try:
                        os.unlink(full)
                    except OSError:
                        try: os.rmdir(full)
                        except OSError: pass
                    logger.warning("Secure-wipe skipped symlink dir (removed link, target kept): %s", redact_path(full))
                    if on_skip:
                        on_skip(f"Skipped symlink dir (removed link, target kept): {redact_path(full)}")
                else:
                    try: os.rmdir(full)
                    except OSError: pass

        try:
            os.rmdir(path)
        except OSError:
            pass

        logger.info("Securely wiped folder: %s", redact_path(path))


# ------------------------------------------------------------------------------
# FOLDER PACKAGER
# ------------------------------------------------------------------------------

class FolderPackager:
    """
    Creates compressed zip archives from folders or file lists.

    The resulting zip is written to a temporary file that the caller is
    responsible for deleting after encryption. Using `zipfile.ZIP_STORED`
    provides maximum speed since encrypted data doesn't compress well anyway.
    """

    def package_folder(
        self,
        source_path: Path,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        exclude_paths: Optional[List[Path]] = None,
        compress: bool = False,
        on_skip: Optional[Callable[[str], None]] = None,
        cancel_check: Optional[Callable[[], bool]] = None
    ) -> Path:
        """
        Recursively zip a folder into a temporary archive.

        Args:
            source_path: Directory to archive.
            progress_callback: (bytes_processed, total_bytes) -> None

        Returns:
            Path to the temporary zip file.
        """
        source_path = Path(source_path).resolve()
        if not source_path.is_dir():
            raise ValueError(f"Source must be a directory: {source_path}")

        temp_fd, temp_name = tempfile.mkstemp(prefix='.rpm_pack_', suffix='.zip', dir=tempfile.gettempdir())
        temp_path = Path(temp_name)

        exclude_set = set(Path(p).resolve() for p in (exclude_paths or []))
        
        def is_excluded(p: Path) -> bool:
            res = p.resolve()
            return any(res == ex or ex in res.parents for ex in exclude_set)

        # Phase 5 (SEC-03): build the real-file list ONCE with os.walk(followlinks=
        # False) so the size total and the zip contents can never disagree, and so we
        # never follow symlinks. rglob would descend into symlinked dirs on Python
        # 3.12, and is_file() follows a symlinked file. Symlinked files are skipped
        # and symlinked subdirs are pruned (never recursed into); both are reported.
        skipped_symlinks: List[Path] = []
        real_files: List[Path] = []
        for root, dirs, files in os.walk(source_path, followlinks=False):
            kept_dirs = []
            for dname in dirs:
                full = os.path.join(root, dname)
                if os.path.islink(full):
                    skipped_symlinks.append(Path(full))
                else:
                    kept_dirs.append(dname)
            dirs[:] = kept_dirs  # do not descend into symlinked dirs
            for fname in files:
                full = Path(root) / fname
                if full.is_symlink():
                    skipped_symlinks.append(full)
                    continue
                if not is_excluded(full):
                    real_files.append(full)
        total_size = sum(f.stat().st_size for f in real_files)
        processed = 0

        try:
            with os.fdopen(temp_fd, 'wb') as temp_file:
                compression = zipfile.ZIP_DEFLATED if compress else zipfile.ZIP_STORED
                with zipfile.ZipFile(temp_file, 'w', compression) as zf:
                    for file_path in real_files:
                        _raise_if_cancelled(cancel_check)
                        arcname = str(file_path.relative_to(source_path))
                        zf.write(file_path, arcname)
                        processed += file_path.stat().st_size
                        if progress_callback:
                            try:
                                progress_callback(processed, total_size)
                            except Exception as exc:
                                logger.warning("Progress callback failed: %s", exc)
        except Exception:
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except Exception:
                    pass
            raise

        # Phase 5 (SEC-03): report any skipped symlinks — their targets were NOT
        # archived (they may point outside the selected folder).
        for s in skipped_symlinks:
            logger.warning("Packaging skipped symlink (target NOT archived): %s", redact_path(s))
            if on_skip:
                on_skip(f"Skipped symlink (not archived): {redact_path(s)}")

        logger.info("Packaged folder '%s' -> '%s' (%d bytes)", redact_path(source_path), redact_path(temp_path), total_size)
        return temp_path

    def package_files(
        self,
        file_paths: List[Path],
        progress_callback: Optional[Callable[[int, int], None]] = None,
        exclude_paths: Optional[List[Path]] = None,
        compress: bool = False,
        on_skip: Optional[Callable[[str], None]] = None,
        cancel_check: Optional[Callable[[], bool]] = None
    ) -> Path:
        """
        Create a zip archive containing multiple individual files.

        Args:
            file_paths: List of file paths to include.
            progress_callback: (bytes_processed, total_bytes) -> None

        Returns:
            Path to the temporary zip file.
        """
        if not file_paths:
            raise ValueError("file_paths cannot be empty")

        temp_fd, temp_name = tempfile.mkstemp(prefix='.rpm_pack_', suffix='.zip', dir=tempfile.gettempdir())
        temp_path = Path(temp_name)

        # Phase 5 (SEC-03): detect symlinks BEFORE resolve()/exclude (resolve() follows
        # the link, defeating detection). These are explicit user selections, but we
        # still must not silently archive an out-of-tree symlink target. DATA-01
        # (Phase 11): build one ordered real-file list, then assign loss-proof
        # flat arcnames so duplicate basenames cannot overwrite each other in zip.
        exclude_set = set(Path(p).resolve() for p in (exclude_paths or []))
        skipped_symlinks: List[Path] = []
        selected: List[Path] = []
        for f in file_paths:
            f = Path(f)
            if f.is_symlink():
                skipped_symlinks.append(f)
                continue
            if f.is_file() and f.resolve() not in exclude_set:
                selected.append(f)

        pairs = assign_unique_arcnames(selected)
        total_size = sum(f.stat().st_size for f in selected)
        processed = 0

        try:
            with os.fdopen(temp_fd, 'wb') as temp_file:
                compression = zipfile.ZIP_DEFLATED if compress else zipfile.ZIP_STORED
                with zipfile.ZipFile(temp_file, 'w', compression) as zf:
                    for file_path, arcname in pairs:
                        _raise_if_cancelled(cancel_check)
                        if file_path.exists() and file_path.is_file():
                            zf.write(file_path, arcname)
                            processed += file_path.stat().st_size
                            if progress_callback:
                                try:
                                    progress_callback(processed, total_size)
                                except Exception as exc:
                                    logger.warning("Progress callback failed: %s", exc)
        except Exception:
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except Exception:
                    pass
            raise

        # Phase 5 (SEC-03): report any skipped symlinks — their targets were NOT archived.
        for s in skipped_symlinks:
            logger.warning("Packaging skipped symlink (target NOT archived): %s", redact_path(s))
            if on_skip:
                on_skip(f"Skipped symlink (not archived): {redact_path(s)}")

        logger.info("Packaged %d files -> '%s' (%d bytes)", len(file_paths), redact_path(temp_path), total_size)
        return temp_path

    def get_manifest(self, source_path: Path, exclude_paths: list = None) -> dict:
        """
        Build a JSON-serializable manifest of the source for vault header metadata.

        Returns:
            Dict with keys: file_count, total_size, files[], created_at, source_type
        """
        source_path = Path(source_path)
        files = []
        total_size = 0

        exclude_set = set(Path(p).resolve() for p in (exclude_paths or []))
        def is_excluded(p: Path) -> bool:
            res = p.resolve()
            return any(res == ex or ex in res.parents for ex in exclude_set)

        if source_path.is_file():
            if not is_excluded(source_path):
                files.append({
                    "path": source_path.name,
                    "size": source_path.stat().st_size,
                    "mtime": datetime.fromtimestamp(source_path.stat().st_mtime).isoformat()
                })
                total_size = source_path.stat().st_size
            source_type = "file"
        elif source_path.is_dir():
            # Phase 5 (SEC-03): walk WITHOUT following symlinks and skip symlinked
            # files / prune symlinked dirs, so the manifest matches EXACTLY what
            # package_folder() archives. The manifest lives in the encrypted metadata
            # block and is read by the Vault Info / Vault Diff tools; if it listed a
            # skipped symlink it would describe a file that is not in the archive.
            for root, dirs, files_in in os.walk(source_path, followlinks=False):
                dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
                for fname in files_in:
                    file_path = Path(root) / fname
                    if file_path.is_symlink():
                        continue
                    if not is_excluded(file_path):
                        rel_path = str(file_path.relative_to(source_path))
                        files.append({
                            "path": rel_path,
                            "size": file_path.stat().st_size,
                            "mtime": datetime.fromtimestamp(file_path.stat().st_mtime).isoformat()
                        })
                        total_size += file_path.stat().st_size
            source_type = "folder"
        else:
            raise ValueError(f"Source does not exist: {source_path}")

        return {
            "file_count": len(files),
            "total_size": total_size,
            "files": files,
            "created_at": datetime.now().isoformat(),
            "source_type": source_type
        }

    def get_manifest_multiple(self, file_paths: list, exclude_paths: list = None) -> dict:
        exclude_set = set(Path(p).resolve() for p in (exclude_paths or []))
        selected: List[Path] = []
        for fp in file_paths:
            fp = Path(fp)
            # Phase 5 (SEC-03): skip symlinks so the manifest matches what
            # package_files() archives (it also skips symlinked selections).
            # DATA-01 (Phase 11): use the same ordered real-file selection as
            # package_files(), then store the assigned arcname under "path".
            if fp.is_symlink():
                continue
            if fp.is_file() and fp.resolve() not in exclude_set:
                selected.append(fp)

        pairs = assign_unique_arcnames(selected)
        files = []
        total_size = 0
        for fp, arcname in pairs:
            files.append({
                "path": arcname,
                "size": fp.stat().st_size,
                "mtime": datetime.fromtimestamp(fp.stat().st_mtime).isoformat(),
                "original_name": fp.name,
            })
            total_size += fp.stat().st_size
        return {
            "file_count": len(files),
            "total_size": total_size,
            "files": files,
            "created_at": datetime.now().isoformat(),
            "source_type": "archive"
        }

    def extract_archive(
        self,
        archive_path: Path,
        output_dir: Path,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        cancel_check: Optional[Callable[[], bool]] = None
    ) -> None:
        """
        Extract a zip archive to the specified output directory.

        Args:
            archive_path: Path to the zip file.
            output_dir: Destination directory.
            progress_callback: Optional progress callback.
        """
        archive_path = Path(archive_path)
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        output_dir_resolved = output_dir.resolve()

        # M4 FIX: Track cumulative uncompressed size to abort on zip bombs.
        cumulative_size = 0

        with zipfile.ZipFile(archive_path, 'r') as zf:
            total = len(zf.namelist())
            for idx, member in enumerate(zf.namelist(), 1):
                _raise_if_cancelled(cancel_check)
                info = zf.getinfo(member)

                # M4 FIX: Reject archives whose declared uncompressed size exceeds
                # the safety ceiling before extracting the offending member.
                member_size = info.file_size
                cumulative_size += member_size
                if cumulative_size > MAX_EXTRACT_SIZE:
                    logger.error(
                        "Zip Bomb detected! Extracted size exceeds %d bytes.",
                        MAX_EXTRACT_SIZE
                    )
                    raise VaultFormatError(
                        "Archive extraction aborted: decompressed size exceeds safety limit."
                    )

                unix_mode = (info.external_attr >> 16) & 0xFFFF
                if unix_mode and (unix_mode & 0o170000) == 0o120000:
                    logger.error(
                        "Symlink entry blocked: %r in archive %s",
                        member, redact_path(archive_path)
                    )
                    raise VaultFormatError(
                        f"Archive contains a symlink entry: {member!r}. "
                        f"Symlinks are not permitted in RPM vaults."
                    )

                member_path = output_dir_resolved / member
                try:
                    member_resolved = member_path.resolve()
                    member_resolved.relative_to(output_dir_resolved)
                except (ValueError, RuntimeError):
                    logger.error(
                        "Zip Slip attempt blocked: member %r would escape output dir %s",
                        member, redact_path(output_dir_resolved)
                    )
                    raise VaultFormatError(
                        f"Archive contains a path-traversal entry: {member!r}. "
                        f"The vault may have been tampered with."
                    )

                zf.extract(member, output_dir)
                if progress_callback:
                    try:
                        progress_callback(idx, total)
                    except Exception as exc:
                        logger.warning("Progress callback failed: %s", exc)

        logger.info("Extracted '%s' -> '%s'", redact_path(archive_path), redact_path(output_dir))


# ------------------------------------------------------------------------------
# VAULT INSPECTOR
# ------------------------------------------------------------------------------

class VaultInspector:
    """
    Provides metadata extraction from vault headers without full decryption.

    This is the backend for the GUI's "Vault Info Panel". It leverages the
    Envelope Encryption architecture: only the small DEK header is decrypted
    to prove password correctness, while the massive payload stream is never
    touched.
    """

    def __init__(self, crypto: VaultCrypto):
        self.crypto = crypto

    def inspect(self, vault_path: Path, password: Optional[str] = None, recovery_key: Optional[bytes] = None) -> Dict[str, Any]:
        """
        Verify password or recovery key and return vault metadata.

        Args:
            vault_path: Path to the .vault file.
            password: User's password.
            recovery_key: Optional recovery phrase entropy.

        Returns:
            Dictionary containing all metadata fields.

        Raises:
            AuthenticationError: Wrong password/key.
            VaultFormatError: Corrupted or invalid vault.
        """
        vault_path = Path(vault_path)
        if not vault_path.exists():
            raise VaultFormatError(f"Vault file not found: {vault_path}")

        try:
            with open(vault_path, 'rb') as f:
                header = self.crypto.verify_password_and_get_header(f, password=password, recovery_key=recovery_key)
        except AuthenticationError:
            raise
        except Exception as exc:
            raise VaultFormatError(f"Failed to read vault header: {exc}") from exc

        metadata = {
            "filename": header.payload.filename,
            "original_size": header.payload.original_size,
            "kdf_algorithm": header.kdf.algorithm,
            "encryption": header.envelope.algorithm,
            "payload_encryption": header.payload.algorithm,
            "argon_memory": header.kdf.memory,
            "argon_iterations": header.kdf.iterations,
            "argon_parallelism": header.kdf.parallelism,
        }

        if header.payload.metadata:
            metadata.update(header.payload.metadata)

        return metadata
