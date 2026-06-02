import zipfile
from pathlib import Path

from file_handler import FolderPackager, assign_unique_arcnames


def _write(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def _zip_names(zip_path: Path) -> set[str]:
    with zipfile.ZipFile(zip_path, "r") as zf:
        return set(zf.namelist())


def _zip_contents(zip_path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(zip_path, "r") as zf:
        return {name: zf.read(name) for name in zf.namelist()}


def test_package_files_duplicate_basenames_round_trip_without_data_loss(tmp_path):
    dir_a_report = _write(tmp_path / "dirA" / "report.pdf", b"AAA")
    dir_b_report = _write(tmp_path / "dirB" / "report.pdf", b"BBB")
    out = tmp_path / "out"

    packager = FolderPackager()
    zip_path = packager.package_files([dir_a_report, dir_b_report])
    try:
        packager.extract_archive(zip_path, out)

        contents = {p.read_bytes() for p in out.rglob("*") if p.is_file()}
        assert {b"AAA", b"BBB"} <= contents
    finally:
        zip_path.unlink(missing_ok=True)


def test_parent_prefix_scheme_only_applies_to_colliding_basenames(tmp_path):
    dir_a_report = _write(tmp_path / "dirA" / "report.pdf", b"AAA")
    dir_b_report = _write(tmp_path / "dirB" / "report.pdf", b"BBB")
    notes = _write(tmp_path / "dirA" / "notes.txt", b"CCC")

    packager = FolderPackager()
    zip_path = packager.package_files([dir_a_report, dir_b_report, notes])
    try:
        assert _zip_names(zip_path) == {
            "dirA_report.pdf",
            "dirB_report.pdf",
            "notes.txt",
        }
        contents = _zip_contents(zip_path)
        assert contents["dirA_report.pdf"] == b"AAA"
        assert contents["dirB_report.pdf"] == b"BBB"
        assert contents["notes.txt"] == b"CCC"
    finally:
        zip_path.unlink(missing_ok=True)


def test_manifest_multiple_paths_match_zip_arcnames(tmp_path):
    dir_a_report = _write(tmp_path / "dirA" / "report.pdf", b"AAA")
    dir_b_report = _write(tmp_path / "dirB" / "report.pdf", b"BBB")
    notes = _write(tmp_path / "dirA" / "notes.txt", b"CCC")
    selection = [dir_a_report, dir_b_report, notes]

    packager = FolderPackager()
    zip_path = packager.package_files(selection)
    try:
        manifest = packager.get_manifest_multiple(selection)
        assert {entry["path"] for entry in manifest["files"]} == _zip_names(zip_path)
    finally:
        zip_path.unlink(missing_ok=True)


def test_same_parent_name_collision_falls_back_to_numeric_suffix_and_preserves_both(tmp_path):
    first = _write(tmp_path / "X" / "sub" / "a.txt", b"FIRST")
    second = _write(tmp_path / "Y" / "sub" / "a.txt", b"SECOND")
    out = tmp_path / "out"

    packager = FolderPackager()
    zip_path = packager.package_files([first, second])
    try:
        assert _zip_names(zip_path) == {"sub_a.txt", "sub_a_1.txt"}
        packager.extract_archive(zip_path, out)
        contents = {p.read_bytes() for p in out.rglob("*") if p.is_file()}
        assert {b"FIRST", b"SECOND"} <= contents
    finally:
        zip_path.unlink(missing_ok=True)


def test_assign_unique_arcnames_keeps_unique_basenames_clean(tmp_path):
    paths = [
        tmp_path / "one" / "alpha.txt",
        tmp_path / "two" / "beta.txt",
        tmp_path / "three" / "gamma.bin",
    ]

    pairs = assign_unique_arcnames(paths)

    assert [arc for _, arc in pairs] == ["alpha.txt", "beta.txt", "gamma.bin"]


def test_assign_unique_arcnames_never_returns_duplicate_arcnames(tmp_path):
    paths = [
        tmp_path / "A" / "same.txt",
        tmp_path / "B" / "same.txt",
        tmp_path / "A_same.txt",
        tmp_path / "C" / "same.txt",
    ]

    arcs = [arc for _, arc in assign_unique_arcnames(paths)]

    assert len(set(arcs)) == len(arcs)
    assert "A_same.txt" in arcs
    assert "B_same.txt" in arcs
