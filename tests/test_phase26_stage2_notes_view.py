from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

NOTES_METHODS = ("_create_notes_frame", "_save_note", "_notes_encrypt_worker",
                 "_load_note", "_notes_decrypt_worker")


def test_notes_mixin_module_defines_the_five_methods():
    from views.notes_view import NotesViewMixin
    for name in NOTES_METHODS:
        assert callable(getattr(NotesViewMixin, name, None)), name


def test_app_composes_the_notes_mixin_and_keeps_shared_methods():
    import gui_app
    from views.notes_view import NotesViewMixin
    assert issubclass(gui_app.RPMEncrypterApp, NotesViewMixin)
    for name in NOTES_METHODS:
        assert hasattr(gui_app.RPMEncrypterApp, name), name
    # Shared shell methods stay in the app class.
    assert hasattr(gui_app.RPMEncrypterApp, "_handle_message")
    assert hasattr(gui_app.RPMEncrypterApp, "_log_activity")


def test_notes_methods_moved_out_of_gui_app():
    src = (ROOT / "gui_app.py").read_text(encoding="utf-8")
    for name in NOTES_METHODS:
        assert f"def {name}(" not in src, f"{name} should now live in views/notes_view.py"
    assert "class RPMEncrypterApp(" in src
    assert "def _handle_message(" in src
