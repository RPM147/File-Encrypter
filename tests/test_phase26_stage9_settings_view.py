from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SETTINGS_METHODS = (
    "_create_settings_frame",
    "_change_theme",
    "_change_scaling",
    "_save_kdf_settings",
    "_save_wipe_setting",
    "_save_versioning_settings",
    "_update_profile_dropdowns",
    "_save_profile",
    "_delete_profile",
    "_apply_profile",
    "_run_health_check",
)


def test_settings_mixin_module_defines_all_methods():
    from views.settings_view import SettingsViewMixin

    for name in SETTINGS_METHODS:
        assert callable(getattr(SettingsViewMixin, name, None)), name


def test_app_composes_settings_mixin_and_keeps_shell_handlers():
    import gui_app
    from views.settings_view import SettingsViewMixin

    assert issubclass(gui_app.RPMEncrypterApp, SettingsViewMixin)
    for name in SETTINGS_METHODS:
        assert hasattr(gui_app.RPMEncrypterApp, name), name
    # The two scattered settings handlers + shell helpers stay reachable.
    for shared in (
        "_save_logging_setting",
        "_clear_all_traces",
        "_show_settings",
        "_build_crypto",
        "_build_versioner",
    ):
        assert hasattr(gui_app.RPMEncrypterApp, shared), shared


def test_settings_methods_moved_out_of_gui_app():
    src = (ROOT / "gui_app.py").read_text(encoding="utf-8")
    for name in SETTINGS_METHODS:
        assert f"def {name}(" not in src, f"{name} should now live in views/settings_view.py"
    # The two handlers that intentionally stayed:
    assert "def _save_logging_setting(" in src
    assert "def _clear_all_traces(" in src
    assert "class RPMEncrypterApp(" in src
