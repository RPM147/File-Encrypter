from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_activity_mixin_module_defines_the_three_methods():
    from views.activity_view import ActivityViewMixin
    for name in ("_create_activity_frame", "_refresh_activity", "_clear_activity"):
        assert callable(getattr(ActivityViewMixin, name, None)), name


def test_app_composes_the_activity_mixin_and_keeps_the_methods():
    import gui_app
    from views.activity_view import ActivityViewMixin
    assert issubclass(gui_app.RPMEncrypterApp, ActivityViewMixin)
    # Methods are still reachable on the app class (via the mixin).
    for name in ("_create_activity_frame", "_refresh_activity", "_clear_activity"):
        assert hasattr(gui_app.RPMEncrypterApp, name), name
    # The shared logging choke point STAYED in the shell.
    assert hasattr(gui_app.RPMEncrypterApp, "_log_activity")


def test_activity_view_methods_moved_out_of_gui_app():
    src = (ROOT / "gui_app.py").read_text(encoding="utf-8")
    for marker in ("def _create_activity_frame(", "def _refresh_activity(", "def _clear_activity("):
        assert marker not in src, f"{marker} should now live in views/activity_view.py"
    # _log_activity and the app shell remain.
    assert "def _log_activity(" in src
    assert "class RPMEncrypterApp(" in src
