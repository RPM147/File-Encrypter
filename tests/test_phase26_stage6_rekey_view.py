from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REKEY_METHODS = ("_create_rekey_frame", "_refresh_version_list", "_get_selected_version",
                 "_do_restore_copy", "_do_replace_current", "_do_delete_version",
                 "_browse_rekey_vault", "_on_rekey_pw_change", "_compute_rekey_strength_async",
                 "_do_rekey", "_rekey_worker")


def test_rekey_mixin_module_defines_all_methods():
    from views.rekey_view import RekeyViewMixin
    for name in REKEY_METHODS:
        assert callable(getattr(RekeyViewMixin, name, None)), name


def test_app_composes_the_rekey_mixin_and_keeps_shared_methods():
    import gui_app
    from views.rekey_view import RekeyViewMixin
    assert issubclass(gui_app.RPMEncrypterApp, RekeyViewMixin)
    for name in REKEY_METHODS:
        assert hasattr(gui_app.RPMEncrypterApp, name), name
    assert hasattr(gui_app.RPMEncrypterApp, "_handle_message")
    assert hasattr(gui_app.RPMEncrypterApp, "_show_rekey")


def test_rekey_methods_moved_out_of_gui_app():
    src = (ROOT / "gui_app.py").read_text(encoding="utf-8")
    for name in REKEY_METHODS:
        assert f"def {name}(" not in src, f"{name} should now live in views/rekey_view.py"
    assert "class RPMEncrypterApp(" in src
    assert "def _handle_message(" in src
