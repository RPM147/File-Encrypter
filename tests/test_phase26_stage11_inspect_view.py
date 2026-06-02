from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

INSPECT_METHODS = (
    "_create_inspect_frame",
    "_set_inspect_hash_buttons",
    "_clear_all_fingerprints",
    "_browse_inspect",
    "_do_inspect",
    "_open_selective_extract",
    "_selective_extract_worker",
    "_open_vault_diff",
    "_vault_diff_worker",
    "_do_integrity_check",
    "_save_fingerprint",
    "_load_fingerprints",
    "_refresh_fingerprint_panel",
    "_copy_last_sha",
    "_verify_against_saved",
    "_check_vault_integrity",
    "_render_inspect_results",
)


def test_inspect_mixin_module_defines_all_methods():
    from views.inspect_view import InspectViewMixin

    for name in INSPECT_METHODS:
        assert callable(getattr(InspectViewMixin, name, None)), name


def test_app_composes_inspect_mixin_and_keeps_shared_methods():
    import gui_app
    from views.inspect_view import InspectViewMixin

    assert issubclass(gui_app.RPMEncrypterApp, InspectViewMixin)
    for name in INSPECT_METHODS:
        assert hasattr(gui_app.RPMEncrypterApp, name), name
    # The interleaved methods that MUST stay in the shell:
    for shared in ("_log_activity", "_save_logging_setting", "_clear_all_traces",
                   "_show_inspect", "_handle_message"):
        assert hasattr(gui_app.RPMEncrypterApp, shared), shared


def test_inspect_methods_moved_but_log_activity_stayed():
    src = (ROOT / "gui_app.py").read_text(encoding="utf-8")
    for name in INSPECT_METHODS:
        assert f"def {name}(" not in src, f"{name} should now live in views/inspect_view.py"
    # The shared logging choke point and the two settings handlers stayed in the shell:
    assert "def _log_activity(" in src
    assert "def _save_logging_setting(" in src
    assert "def _clear_all_traces(" in src
    assert "class RPMEncrypterApp(" in src


def test_no_create_frame_views_remain_in_gui_app():
    # ARCH-01 endpoint: the shell owns no page builder anymore.
    src = (ROOT / "gui_app.py").read_text(encoding="utf-8")
    assert "def _create_" not in src or "_create_inspect_frame" not in src
    for builder in ("_create_encrypt_frame", "_create_decrypt_frame", "_create_inspect_frame",
                    "_create_settings_frame", "_create_rekey_frame", "_create_password_frame",
                    "_create_library_frame", "_create_notes_frame", "_create_activity_frame"):
        assert f"def {builder}(" not in src, f"{builder} should have moved to a view module"
