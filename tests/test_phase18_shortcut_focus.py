from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _method_slice(source: str, method_name: str) -> str:
    marker = f"    def {method_name}"
    start = source.index(marker)
    next_def = source.find("\n    def ", start + len(marker))
    return source[start:] if next_def == -1 else source[start:next_def]


def test_nav_shortcuts_go_through_the_focus_guard():
    source = (ROOT / "gui_app.py").read_text(encoding="utf-8")
    bind_body = _method_slice(source, "_bind_shortcuts")
    # Every nav binding now routes through the guard, not a direct _show_* call.
    assert bind_body.count("self._nav_shortcut(") == 9
    assert "lambda _: self._show_" not in bind_body


def test_focus_guard_checks_text_widget_focus():
    source = (ROOT / "gui_app.py").read_text(encoding="utf-8")
    guard_body = _method_slice(source, "_nav_shortcut")
    assert "self.focus_get()" in guard_body
    assert "isinstance(focused, (Entry, Text))" in guard_body
    assert "from tkinter import filedialog, messagebox, Entry, Text" in source
