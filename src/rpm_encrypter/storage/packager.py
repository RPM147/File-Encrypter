"""Zip packaging, manifest generation, and zip-slip/zip-bomb safe extraction."""

from collections import Counter
from datetime import datetime
import logging
import os
from pathlib import Path
import tempfile
from typing import Callable, List, Optional
import zipfile

from rpm_encrypter.core import VaultFormatError, _raise_if_cancelled
from .log_hygiene import redact_path

logger = logging.getLogger(__name__)

# Hard ceiling on total uncompressed size during extraction to defeat zip bombs.
MAX_EXTRACT_SIZE = 10 * 1024 * 1024 * 1024  # 10 GiB

_UNSAFE_NAME_CHARS = set('<>:"/\\|?*') | {chr(c) for c in range(0x20)}


def _safe_component(name: str) -> str:
    """Reduce a folder/file name to one safe path component."""
    cleaned = "".join("_" if ch in _UNSAFE_NAME_CHARS else ch for ch in (name or ""))
    return cleaned.strip(" .")


def assign_unique_arcnames(paths):
    """
    Return a list of (Path, arcname) in the same order as ``paths``.

    Guarantees all arcnames are distinct, preventing zip entry overwrite when
    selected files share a basename.
    """
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


class FolderPackager:
    """Creates and extracts zip archives with symlink, zip-slip, and zip-bomb defenses."""

    def package_folder(
        self,
        source_path: Path,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        exclude_paths: Optional[List[Path]] = None,
        compress: bool = False,
        on_skip: Optional[Callable[[str], None]] = None,
        cancel_check: Optional[Callable[[], bool]] = None,
    ) -> Path:
        """Recursively zip a folder into a temporary archive without following symlinks."""
        source_path = Path(source_path).resolve()
        if not source_path.is_dir():
            raise ValueError(f"Source must be a directory: {source_path}")

        temp_fd, temp_name = tempfile.mkstemp(
            prefix=".rpm_pack_", suffix=".zip", dir=tempfile.gettempdir()
        )
        temp_path = Path(temp_name)

        exclude_set = set(Path(p).resolve() for p in (exclude_paths or []))

        def is_excluded(p: Path) -> bool:
            res = p.resolve()
            return any(res == ex or ex in res.parents for ex in exclude_set)

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
            dirs[:] = kept_dirs
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
            with os.fdopen(temp_fd, "wb") as temp_file:
                compression = zipfile.ZIP_DEFLATED if compress else zipfile.ZIP_STORED
                with zipfile.ZipFile(temp_file, "w", compression) as zf:
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

        for s in skipped_symlinks:
            logger.warning("Packaging skipped symlink (target NOT archived): %s", redact_path(s))
            if on_skip:
                on_skip(f"Skipped symlink (not archived): {redact_path(s)}")

        logger.info(
            "Packaged folder '%s' -> '%s' (%d bytes)",
            redact_path(source_path),
            redact_path(temp_path),
            total_size,
        )
        return temp_path

    def package_files(
        self,
        file_paths: List[Path],
        progress_callback: Optional[Callable[[int, int], None]] = None,
        exclude_paths: Optional[List[Path]] = None,
        compress: bool = False,
        on_skip: Optional[Callable[[str], None]] = None,
        cancel_check: Optional[Callable[[], bool]] = None,
    ) -> Path:
        """Create a zip archive containing multiple individual files."""
        if not file_paths:
            raise ValueError("file_paths cannot be empty")

        temp_fd, temp_name = tempfile.mkstemp(
            prefix=".rpm_pack_", suffix=".zip", dir=tempfile.gettempdir()
        )
        temp_path = Path(temp_name)

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
            with os.fdopen(temp_fd, "wb") as temp_file:
                compression = zipfile.ZIP_DEFLATED if compress else zipfile.ZIP_STORED
                with zipfile.ZipFile(temp_file, "w", compression) as zf:
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

        for s in skipped_symlinks:
            logger.warning("Packaging skipped symlink (target NOT archived): %s", redact_path(s))
            if on_skip:
                on_skip(f"Skipped symlink (not archived): {redact_path(s)}")

        logger.info(
            "Packaged %d files -> '%s' (%d bytes)",
            len(file_paths),
            redact_path(temp_path),
            total_size,
        )
        return temp_path

    def get_manifest(self, source_path: Path, exclude_paths: list = None) -> dict:
        """Build a JSON-serializable manifest of the source for encrypted metadata."""
        source_path = Path(source_path)
        files = []
        total_size = 0

        exclude_set = set(Path(p).resolve() for p in (exclude_paths or []))

        def is_excluded(p: Path) -> bool:
            res = p.resolve()
            return any(res == ex or ex in res.parents for ex in exclude_set)

        if source_path.is_file():
            if not is_excluded(source_path):
                files.append(
                    {
                        "path": source_path.name,
                        "size": source_path.stat().st_size,
                        "mtime": datetime.fromtimestamp(source_path.stat().st_mtime).isoformat(),
                    }
                )
                total_size = source_path.stat().st_size
            source_type = "file"
        elif source_path.is_dir():
            for root, dirs, files_in in os.walk(source_path, followlinks=False):
                dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
                for fname in files_in:
                    file_path = Path(root) / fname
                    if file_path.is_symlink():
                        continue
                    if not is_excluded(file_path):
                        rel_path = str(file_path.relative_to(source_path))
                        files.append(
                            {
                                "path": rel_path,
                                "size": file_path.stat().st_size,
                                "mtime": datetime.fromtimestamp(
                                    file_path.stat().st_mtime
                                ).isoformat(),
                            }
                        )
                        total_size += file_path.stat().st_size
            source_type = "folder"
        else:
            raise ValueError(f"Source does not exist: {source_path}")

        return {
            "file_count": len(files),
            "total_size": total_size,
            "files": files,
            "created_at": datetime.now().isoformat(),
            "source_type": source_type,
        }

    def get_manifest_multiple(self, file_paths: list, exclude_paths: list = None) -> dict:
        exclude_set = set(Path(p).resolve() for p in (exclude_paths or []))
        selected: List[Path] = []
        for fp in file_paths:
            fp = Path(fp)
            if fp.is_symlink():
                continue
            if fp.is_file() and fp.resolve() not in exclude_set:
                selected.append(fp)

        pairs = assign_unique_arcnames(selected)
        files = []
        total_size = 0
        for fp, arcname in pairs:
            files.append(
                {
                    "path": arcname,
                    "size": fp.stat().st_size,
                    "mtime": datetime.fromtimestamp(fp.stat().st_mtime).isoformat(),
                    "original_name": fp.name,
                }
            )
            total_size += fp.stat().st_size
        return {
            "file_count": len(files),
            "total_size": total_size,
            "files": files,
            "created_at": datetime.now().isoformat(),
            "source_type": "archive",
        }

    def extract_archive(
        self,
        archive_path: Path,
        output_dir: Path,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        cancel_check: Optional[Callable[[], bool]] = None,
    ) -> None:
        """Extract a zip archive while enforcing symlink, path-traversal, and size limits."""
        archive_path = Path(archive_path)
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        output_dir_resolved = output_dir.resolve()
        cumulative_size = 0

        with zipfile.ZipFile(archive_path, "r") as zf:
            total = len(zf.namelist())
            for idx, member in enumerate(zf.namelist(), 1):
                _raise_if_cancelled(cancel_check)
                info = zf.getinfo(member)

                member_size = info.file_size
                cumulative_size += member_size
                if cumulative_size > MAX_EXTRACT_SIZE:
                    logger.error(
                        "Zip Bomb detected! Extracted size exceeds %d bytes.",
                        MAX_EXTRACT_SIZE,
                    )
                    raise VaultFormatError(
                        "Archive extraction aborted: decompressed size exceeds safety limit."
                    )

                unix_mode = (info.external_attr >> 16) & 0xFFFF
                if unix_mode and (unix_mode & 0o170000) == 0o120000:
                    logger.error(
                        "Symlink entry blocked: %r in archive %s",
                        member,
                        redact_path(archive_path),
                    )
                    raise VaultFormatError(
                        f"Archive contains a symlink entry: {member!r}. "
                        f"Symlinks are not permitted in RPM vaults."
                    )

                member_path = output_dir_resolved / member
                try:
                    member_resolved = member_path.resolve()
                    member_resolved.relative_to(output_dir_resolved)
                except (ValueError, RuntimeError) as exc:
                    logger.error(
                        "Zip Slip attempt blocked: member %r would escape output dir %s",
                        member,
                        redact_path(output_dir_resolved),
                    )
                    raise VaultFormatError(
                        f"Archive contains a path-traversal entry: {member!r}. "
                        f"The vault may have been tampered with."
                    ) from exc

                zf.extract(member, output_dir)
                if progress_callback:
                    try:
                        progress_callback(idx, total)
                    except Exception as exc:
                        logger.warning("Progress callback failed: %s", exc)

        logger.info("Extracted '%s' -> '%s'", redact_path(archive_path), redact_path(output_dir))
