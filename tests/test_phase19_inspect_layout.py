from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _method_slice(source: str, method_name: str) -> str:
    marker = f"    def {method_name}"
    start = source.index(marker)
    next_def = source.find("\n    def ", start + len(marker))
    return source[start:] if next_def == -1 else source[start:next_def]


def test_inspect_results_box_expands_vertically():
    body = _method_slice((ROOT / "views" / "inspect_view.py").read_text(encoding="utf-8"), "_create_inspect_frame")
    assert 'self.inspect_results.grid(row=4, column=0, sticky="nsew"' in body
    assert "frame.grid_rowconfigure(4, weight=1)" in body
    assert "frame.grid_rowconfigure(6, weight=1)" in body


def test_inspect_toolbar_is_split_into_two_rows():
    body = _method_slice((ROOT / "views" / "inspect_view.py").read_text(encoding="utf-8"), "_create_inspect_frame")
    assert "btn_row_top" in body and "btn_row_bottom" in body
    # 3 buttons per sub-row -> 6 total still present, none dropped.
    assert body.count("btn_row_top") >= 4
    assert body.count("btn_row_bottom") >= 4
    for label in ("Inspect Vault", "Integrity Check", "Selective Extract",
                  "Vault Diff", "Verify vs Saved", "Copy SHA-256"):
        assert label in body
