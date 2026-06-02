from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PASSWORD_METHODS = ("_create_password_frame", "_update_length_label", "_generate_password",
                    "_clear_clipboard", "_start_clipboard_timer", "_copy_generated_pw",
                    "_use_generated_pw")


def test_password_mixin_module_defines_the_seven_methods():
    from views.password_view import PasswordViewMixin
    for name in PASSWORD_METHODS:
        assert callable(getattr(PasswordViewMixin, name, None)), name


def test_app_composes_the_password_mixin_and_keeps_shared_methods():
    import gui_app
    from views.password_view import PasswordViewMixin
    assert issubclass(gui_app.RPMEncrypterApp, PasswordViewMixin)
    for name in PASSWORD_METHODS:
        assert hasattr(gui_app.RPMEncrypterApp, name), name
    # The encrypt handler the '→ Encrypt' button calls stays in the shell.
    assert hasattr(gui_app.RPMEncrypterApp, "_on_enc_pw_change")
    assert hasattr(gui_app.RPMEncrypterApp, "_show_password")


def test_password_methods_moved_out_of_gui_app():
    src = (ROOT / "gui_app.py").read_text(encoding="utf-8")
    for name in PASSWORD_METHODS:
        assert f"def {name}(" not in src, f"{name} should now live in views/password_view.py"
    assert "class RPMEncrypterApp(" in src
    assert "def _show_password(" in src
