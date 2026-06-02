from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _method_slice(source: str, method_name: str) -> str:
    marker = f"    def {method_name}"
    start = source.index(marker)
    next_def = source.find("\n    def ", start + len(marker))
    return source[start:] if next_def == -1 else source[start:next_def]


def test_notes_page_has_no_dead_search_control():
    source = (ROOT / "views" / "notes_view.py").read_text(encoding="utf-8")
    notes_body = _method_slice(source, "_create_notes_frame")

    # The dead search widgets are gone from the Notes page.
    assert "notes_search_entry" not in notes_body
    assert "notes_search_clear" not in notes_body
    assert "Search notes" not in notes_body

    # The control row + textbox keep their grid rows.
    assert "ctrl_row.grid(row=1, column=0" in notes_body
    assert "self.note_textbox.grid(row=2, column=0" in notes_body
    assert "grid_rowconfigure(2, weight=1)" in notes_body


def test_no_dangling_notes_search_helpers_anywhere():
    gui_src = (ROOT / "gui_app.py").read_text(encoding="utf-8")
    notes_src = (ROOT / "views" / "notes_view.py").read_text(encoding="utf-8")
    for src in (gui_src, notes_src):
        assert "def _filter_notes" not in src
        assert "def _clear_notes_search" not in src
        assert "notes_search_entry" not in src
        assert "notes_search_clear" not in src
