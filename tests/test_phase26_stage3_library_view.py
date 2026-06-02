from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

LIBRARY_METHODS = ("_create_library_frame", "_add_library_dir", "_scan_library",
                   "_scan_worker", "_clear_library_search", "_filter_library")


def test_library_mixin_module_defines_the_six_methods():
    from views.library_view import LibraryViewMixin
    for name in LIBRARY_METHODS:
        assert callable(getattr(LibraryViewMixin, name, None)), name


def test_app_composes_the_library_mixin_and_keeps_shared_methods():
    import gui_app
    from views.library_view import LibraryViewMixin
    assert issubclass(gui_app.RPMEncrypterApp, LibraryViewMixin)
    for name in LIBRARY_METHODS:
        assert hasattr(gui_app.RPMEncrypterApp, name), name
    # Shared shell methods stay in the app class.
    assert hasattr(gui_app.RPMEncrypterApp, "_handle_message")
    assert hasattr(gui_app.RPMEncrypterApp, "_show_library")


def test_library_methods_moved_out_of_gui_app():
    src = (ROOT / "gui_app.py").read_text(encoding="utf-8")
    for name in LIBRARY_METHODS:
        assert f"def {name}(" not in src, f"{name} should now live in views/library_view.py"
    assert "class RPMEncrypterApp(" in src
    assert "def _handle_message(" in src
