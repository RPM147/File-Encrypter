from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _method_slice(source: str, method_name: str) -> str:
    marker = f"    def {method_name}"
    start = source.index(marker)
    next_def = source.find("\n    def ", start + len(marker))
    return source[start:] if next_def == -1 else source[start:next_def]


def test_separate_add_files_and_add_folder_methods_exist():
    source = (ROOT / "views" / "encrypt_view.py").read_text(encoding="utf-8")
    files_body = _method_slice(source, "_add_encrypt_files")
    folder_body = _method_slice(source, "_add_encrypt_folder")
    assert "askopenfilenames(" in files_body
    assert "self._add_encrypt_source(" in files_body
    assert "askdirectory(" in folder_body
    assert "self._add_encrypt_source(" in folder_body


def test_old_folder_first_browse_is_gone():
    source = (ROOT / "views" / "encrypt_view.py").read_text(encoding="utf-8")
    # The folder-first method and its tell-tale single-file fallback are removed.
    assert "def _browse_encrypt_source" not in source
    assert 'askopenfilename(title="Select File to Encrypt")' not in source


def test_encrypt_frame_has_two_explicit_add_buttons():
    body = _method_slice((ROOT / "views" / "encrypt_view.py").read_text(encoding="utf-8"), "_create_encrypt_frame")
    assert "Add File(s)" in body
    assert "Add Folder" in body
    assert "command=self._add_encrypt_files" in body
    assert "command=self._add_encrypt_folder" in body
