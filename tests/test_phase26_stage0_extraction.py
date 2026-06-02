from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_support_modules_define_the_moved_symbols():
    import widgets, app_config, app_state
    for name in ("PasswordEntry", "LogBox", "RecentBar", "DragDropArea",
                 "EmptyStateContainer", "SidebarItem"):
        assert hasattr(widgets, name), name
    for name in ("get_setting", "save_setting", "get_recent", "push_recent",
                 "_load_cfg", "_save_cfg", "resource_path", "CONFIG_FILE"):
        assert hasattr(app_config, name), name
    for name in ("assert_main_thread", "AttemptLimiter", "SessionStats",
                 "MAX_ATTEMPTS", "LOCKOUT_SECS"):
        assert hasattr(app_state, name), name


def test_gui_app_reexports_for_backward_compatibility():
    import gui_app
    for name in ("assert_main_thread", "RPMEncrypterApp", "get_setting",
                 "save_setting", "PasswordEntry", "AttemptLimiter", "SessionStats"):
        assert hasattr(gui_app, name), name


def test_moved_definitions_are_gone_from_gui_app_but_shell_remains():
    src = (ROOT / "gui_app.py").read_text(encoding="utf-8")
    for marker in ("class PasswordEntry(", "class LogBox(", "class RecentBar(",
                   "class DragDropArea(", "class EmptyStateContainer(", "class SidebarItem(",
                   "class AttemptLimiter", "class SessionStats",
                   "def _load_cfg(", "def get_setting(", "def assert_main_thread("):
        assert marker not in src, f"{marker} should have moved out of gui_app.py"
    assert "class RPMEncrypterApp(" in src
    assert "def _setup_main_frames(" in src
    assert "def _handle_message(" in src
