from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

ENCRYPT_METHODS = (
    "_create_encrypt_frame",
    "_toggle_enc_outdir",
    "_browse_enc_outdir",
    "_add_encrypt_files",
    "_add_encrypt_folder",
    "_on_encrypt_drop",
    "_add_encrypt_source",
    "_update_enc_source_display",
    "_clear_batch",
    "_on_enc_pw_change",
    "_compute_enc_strength_async",
    "_toggle_hidden_mode",
    "_browse_hidden_source",
    "_clear_hidden",
    "_update_hidden_box",
    "_process_batch",
    "_batch_encrypt_worker",
)


def test_encrypt_mixin_module_defines_all_methods():
    from views.encrypt_view import EncryptViewMixin

    for name in ENCRYPT_METHODS:
        assert callable(getattr(EncryptViewMixin, name, None)), name


def test_app_composes_encrypt_mixin_and_keeps_shared_methods():
    import gui_app
    from views.encrypt_view import EncryptViewMixin

    assert issubclass(gui_app.RPMEncrypterApp, EncryptViewMixin)
    for name in ENCRYPT_METHODS:
        assert hasattr(gui_app.RPMEncrypterApp, name), name
    for shared in ("_handle_message", "_show_encrypt", "_parse_drop_paths", "_apply_profile", "_use_generated_pw"):
        assert hasattr(gui_app.RPMEncrypterApp, shared), shared


def test_encrypt_methods_moved_out_of_gui_app():
    src = (ROOT / "gui_app.py").read_text(encoding="utf-8")
    for name in ENCRYPT_METHODS:
        assert f"def {name}(" not in src, f"{name} should now live in views/encrypt_view.py"
    assert "class RPMEncrypterApp(" in src
    assert "def _handle_message(" in src
