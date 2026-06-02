from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _method_slice(source: str, method_name: str) -> str:
    marker = f"    def {method_name}"
    start = source.index(marker)
    next_def = source.find("\n    def ", start + len(marker))
    return source[start:] if next_def == -1 else source[start:next_def]


def test_activity_button_row_and_textbox_are_on_separate_grid_rows():
    body = _method_slice((ROOT / "views" / "activity_view.py").read_text(encoding="utf-8"), "_create_activity_frame")
    # The button row no longer shares row 2 with the textbox.
    assert "btn_row.grid(row=1, column=0" in body
    assert "self.activity_textbox.grid(row=2, column=0" in body
    # Row weight stays only on the textbox's row (row 2), so only it expands.
    assert "grid_rowconfigure(2, weight=1)" in body
    assert "grid_rowconfigure(1, weight=1)" not in body
