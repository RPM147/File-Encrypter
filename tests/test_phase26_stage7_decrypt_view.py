from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

DECRYPT_METHODS = (
    "_create_decrypt_frame",
    "_on_decrypt_drop",
    "_browse_decrypt_source",
    "_set_decrypt_sources_from_path",
    "_set_decrypt_sources",
    "_browse_decrypt_output",
    "_clear_decrypt_form",
    "_do_decrypt",
    "_batch_decrypt_worker",
)


def test_decrypt_mixin_module_defines_all_methods():
    from views.decrypt_view import DecryptViewMixin

    for name in DECRYPT_METHODS:
        assert callable(getattr(DecryptViewMixin, name, None)), name


def test_app_composes_the_decrypt_mixin_and_keeps_shared_methods():
    import gui_app
    from views.decrypt_view import DecryptViewMixin

    assert issubclass(gui_app.RPMEncrypterApp, DecryptViewMixin)
    for name in DECRYPT_METHODS:
        assert hasattr(gui_app.RPMEncrypterApp, name), name
    for shared in ("_handle_message", "_show_decrypt", "_lockout_check", "_parse_drop_paths"):
        assert hasattr(gui_app.RPMEncrypterApp, shared), shared


def test_decrypt_methods_moved_out_of_gui_app():
    src = (ROOT / "gui_app.py").read_text(encoding="utf-8")
    for name in DECRYPT_METHODS:
        assert f"def {name}(" not in src, f"{name} should now live in views/decrypt_view.py"
    assert "class RPMEncrypterApp(" in src
    assert "def _handle_message(" in src
