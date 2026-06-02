from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _method_slice(source: str, method_name: str) -> str:
    marker = f"    def {method_name}"
    start = source.index(marker)
    next_def = source.find("\n    def ", start + len(marker))
    return source[start:] if next_def == -1 else source[start:next_def]


def _class_method_slice(source: str, class_name: str, method_name: str) -> str:
    class_start = source.index(f"class {class_name}")
    marker = f"    def {method_name}"
    start = source.index(marker, class_start)
    next_def = source.find("\n    def ", start + len(marker))
    return source[start:] if next_def == -1 else source[start:next_def]


def test_update_and_logging_default_to_off():
    src = (ROOT / "gui_app.py").read_text(encoding="utf-8")
    # No remaining default-ON reads of either setting.
    assert 'get_setting("check_updates", True)' not in src
    assert 'get_setting("logging_enabled", True)' not in src
    # Both are read with default False at least where they gate behaviour.
    assert 'get_setting("check_updates", False)' in src
    assert 'get_setting("logging_enabled", False)' in src


def test_one_time_nonblocking_privacy_notice_exists():
    src = (ROOT / "gui_app.py").read_text(encoding="utf-8")
    notice = _method_slice(src, "_show_privacy_notice")
    assert 'save_setting("privacy_notice_shown", True)' in notice
    assert "self._nav_bottom" in notice
    assert "grab_set" not in notice
    # Shown once, gated on the flag, in __init__.
    init_body = _class_method_slice(src, "RPMEncrypterApp", "__init__")
    assert 'get_setting("privacy_notice_shown", False)' in init_body
    assert "self._show_privacy_notice" in init_body


def test_settings_label_states_filenames_are_logged():
    src = (ROOT / "views" / "settings_view.py").read_text(encoding="utf-8")
    assert "file's NAME" in src or "filename" in src.lower()
    assert "Off by default" in src
