"""
Phase 5 (SEC-03) regression tests: symlink-safe secure wipe and packaging.

Threat model: "secure delete originals" and "package folder" must operate on the
LINK itself, never the target. Following a symlink would let a folder that
contains a link (a) overwrite a file OUTSIDE the selected folder during a secure
wipe, or (b) archive content from outside the selected root into the vault.

These tests are GUI-free (they import only `file_handler`).

NOTE: creating a symlink on Windows raises OSError [WinError 1314] unless
Developer Mode / admin is enabled. Every test detects this and skips cleanly
instead of failing.
"""

import os
import zipfile
from pathlib import Path

import pytest

from file_handler import SecureWiper, FolderPackager


SKIP_REASON = (
    "Symlink creation not permitted on this machine "
    "(needs Developer Mode / admin on Windows)."
)


def _symlinks_supported(tmp_path: Path) -> bool:
    """Probe whether this process may create symlinks in `tmp_path`."""
    target = tmp_path / "_probe_target"
    target.write_text("probe")
    link = tmp_path / "_probe_link"
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        return False
    finally:
        try:
            link.unlink()
        except OSError:
            pass
    return True


# ---------------------------------------------------------------------------
# SecureWiper
# ---------------------------------------------------------------------------

def test_wipe_file_on_symlink_keeps_target(tmp_path):
    """1. wipe_file on a symlink-to-file removes only the LINK; target survives."""
    if not _symlinks_supported(tmp_path):
        pytest.skip(SKIP_REASON)

    target = tmp_path / "real_target.txt"
    target.write_text("SECRET-OUTSIDE-DATA")
    link = tmp_path / "link_to_target.txt"
    os.symlink(target, link)

    skipped = []
    SecureWiper(passes=1).wipe_file(link, on_skip=skipped.append)

    assert not link.is_symlink()                       # the link is gone
    assert not link.exists()
    assert target.exists()                             # the target survived
    assert target.read_text() == "SECRET-OUTSIDE-DATA"  # bytes untouched
    assert skipped                                     # reported via on_skip


def test_wipe_file_on_broken_symlink_removes_link(tmp_path):
    """Edge case #1: a broken/dangling link is handled (is_symlink uses lstat),
    proving the symlink branch runs BEFORE the exists()/is_file() guard."""
    if not _symlinks_supported(tmp_path):
        pytest.skip(SKIP_REASON)

    missing = tmp_path / "does_not_exist.txt"
    link = tmp_path / "broken_link.txt"
    os.symlink(missing, link)
    assert link.is_symlink()
    assert not link.exists()  # broken: target is missing

    SecureWiper(passes=1).wipe_file(link)  # must not raise
    assert not link.is_symlink()           # link removed


def test_wipe_folder_skips_symlink_file_keeps_external_target(tmp_path):
    """2. wipe_folder removes a contained symlink-to-file (link only) and wipes
    the folder's real files; the EXTERNAL target survives intact."""
    if not _symlinks_supported(tmp_path):
        pytest.skip(SKIP_REASON)

    external = tmp_path / "external_target.txt"
    external.write_text("EXTERNAL-SECRET")

    folder = tmp_path / "to_wipe"
    folder.mkdir()
    (folder / "inside.txt").write_text("inside-data")
    os.symlink(external, folder / "link.txt")

    skipped = []
    SecureWiper(passes=1).wipe_folder(folder, on_skip=skipped.append)

    assert not folder.exists()                       # whole folder removed
    assert external.exists()                          # external target survived
    assert external.read_text() == "EXTERNAL-SECRET"  # bytes untouched
    assert skipped


def test_wipe_folder_does_not_recurse_symlinked_dir(tmp_path):
    """3. wipe_folder does NOT descend into a symlink-to-DIR: the external
    directory and its files are untouched; only the link is removed."""
    if not _symlinks_supported(tmp_path):
        pytest.skip(SKIP_REASON)

    external_dir = tmp_path / "external_dir"
    external_dir.mkdir()
    (external_dir / "keep1.txt").write_text("KEEP-1")
    (external_dir / "keep2.txt").write_text("KEEP-2")

    folder = tmp_path / "to_wipe"
    folder.mkdir()
    (folder / "inside.txt").write_text("inside-data")
    os.symlink(external_dir, folder / "dlink", target_is_directory=True)

    skipped = []
    SecureWiper(passes=1).wipe_folder(folder, on_skip=skipped.append)

    assert not folder.exists()                            # folder removed
    assert external_dir.exists() and external_dir.is_dir()
    assert (external_dir / "keep1.txt").read_text() == "KEEP-1"
    assert (external_dir / "keep2.txt").read_text() == "KEEP-2"
    assert skipped


# ---------------------------------------------------------------------------
# FolderPackager
# ---------------------------------------------------------------------------

def test_package_folder_skips_symlink_file(tmp_path):
    """4. package_folder does not archive a symlinked file's target; normal
    in-folder files ARE archived, and on_skip receives a message."""
    if not _symlinks_supported(tmp_path):
        pytest.skip(SKIP_REASON)

    external = tmp_path / "external_secret.txt"
    external.write_text("EXTERNAL-CONTENT")

    folder = tmp_path / "src"
    folder.mkdir()
    (folder / "normal.txt").write_text("normal-content")
    os.symlink(external, folder / "linked.txt")

    skipped = []
    packager = FolderPackager()
    zip_path = packager.package_folder(folder, on_skip=skipped.append)
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            names = zf.namelist()
            assert any(Path(n).name == "normal.txt" for n in names)
            assert not any(Path(n).name == "linked.txt" for n in names)
            for n in names:
                assert zf.read(n) != b"EXTERNAL-CONTENT"
        assert skipped  # on_skip fired for the skipped symlink
    finally:
        zip_path.unlink(missing_ok=True)


def test_package_folder_does_not_recurse_symlinked_dir(tmp_path):
    """5. package_folder does not recurse into a symlinked subdirectory:
    nothing from the link target appears in the zip."""
    if not _symlinks_supported(tmp_path):
        pytest.skip(SKIP_REASON)

    external_dir = tmp_path / "ext"
    external_dir.mkdir()
    (external_dir / "ext_file.txt").write_text("EXT-DIR-CONTENT")

    folder = tmp_path / "src"
    folder.mkdir()
    (folder / "keep.txt").write_text("keep")
    os.symlink(external_dir, folder / "linkdir", target_is_directory=True)

    packager = FolderPackager()
    zip_path = packager.package_folder(folder)
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            names = zf.namelist()
            assert any(Path(n).name == "keep.txt" for n in names)
            assert not any(Path(n).name == "ext_file.txt" for n in names)
            assert not any("linkdir" in n for n in names)
    finally:
        zip_path.unlink(missing_ok=True)


def test_package_files_skips_symlink_selection(tmp_path):
    """package_files skips a symlinked selection (target not archived) while a
    normal selected file is archived; on_skip receives a message."""
    if not _symlinks_supported(tmp_path):
        pytest.skip(SKIP_REASON)

    external = tmp_path / "ext.txt"
    external.write_text("EXTERNAL-FILE-CONTENT")
    link = tmp_path / "link.txt"
    os.symlink(external, link)

    normal = tmp_path / "normal.txt"
    normal.write_text("normal")

    skipped = []
    packager = FolderPackager()
    zip_path = packager.package_files([normal, link], on_skip=skipped.append)
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            names = zf.namelist()
            assert "normal.txt" in names
            assert "link.txt" not in names
            for n in names:
                assert zf.read(n) != b"EXTERNAL-FILE-CONTENT"
        assert skipped
    finally:
        zip_path.unlink(missing_ok=True)


def test_manifest_matches_archive_skips_symlinks(tmp_path):
    """get_manifest / get_manifest_multiple apply the SAME symlink-skip policy,
    so the (encrypted) manifest stays byte-consistent with the archive."""
    if not _symlinks_supported(tmp_path):
        pytest.skip(SKIP_REASON)

    external = tmp_path / "ext.txt"
    external.write_text("EXTERNAL")

    folder = tmp_path / "src"
    folder.mkdir()
    (folder / "real.txt").write_text("real")
    os.symlink(external, folder / "linked.txt")

    packager = FolderPackager()
    manifest = packager.get_manifest(folder)
    listed = {Path(e["path"]).name for e in manifest["files"]}
    assert "real.txt" in listed
    assert "linked.txt" not in listed

    normal = tmp_path / "n.txt"
    normal.write_text("n")
    link2 = tmp_path / "l.txt"
    os.symlink(external, link2)
    mm = packager.get_manifest_multiple([normal, link2])
    listed_m = {e["path"] for e in mm["files"]}
    assert "n.txt" in listed_m
    assert "l.txt" not in listed_m


# ---------------------------------------------------------------------------
# Regression: no behavior change when there are no symlinks
# ---------------------------------------------------------------------------

def test_regression_normal_wipe_and_package_no_symlinks(tmp_path):
    """6. Normal files and nested folders still package and wipe exactly as
    before (no symlinks involved)."""
    # --- packaging a nested folder ---
    src = tmp_path / "proj"
    (src / "sub").mkdir(parents=True)
    (src / "a.txt").write_text("AAA")
    (src / "sub" / "b.txt").write_text("BBB")

    packager = FolderPackager()
    zip_path = packager.package_folder(src)
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            names = zf.namelist()
            assert any(Path(n).name == "a.txt" for n in names)
            assert any(Path(n).name == "b.txt" for n in names)  # nested preserved
            a_name = next(n for n in names if Path(n).name == "a.txt")
            assert zf.read(a_name) == b"AAA"
    finally:
        zip_path.unlink(missing_ok=True)

    # --- wiping a normal nested folder ---
    wipe_root = tmp_path / "wipe_me"
    (wipe_root / "deep").mkdir(parents=True)
    (wipe_root / "f1.txt").write_text("x")
    (wipe_root / "deep" / "f2.txt").write_text("y")
    SecureWiper(passes=1).wipe_folder(wipe_root)
    assert not wipe_root.exists()

    # --- wiping a single normal file ---
    f = tmp_path / "single.txt"
    f.write_text("data")
    SecureWiper(passes=1).wipe_file(f)
    assert not f.exists()
