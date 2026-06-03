"""Stage 11 cross-cutting parity tests for the Flet UI."""
import asyncio
import json
import queue
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def fast_services(tmp_path, monkeypatch):
    import activity_log
    import app_config
    import vault_scanner
    import versioning

    cfg = tmp_path / "cfg.json"
    cfg.write_text(
        json.dumps(
            {
                "settings": {
                    "argon2_memory": 8192,
                    "argon2_time": 1,
                    "argon2_par": 1,
                    "wipe_passes": 1,
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(app_config, "CONFIG_FILE", cfg)
    monkeypatch.setattr(activity_log, "DB_PATH", tmp_path / "activity.db")
    monkeypatch.setattr(vault_scanner, "CACHE_FILE", tmp_path / "lib.json")
    monkeypatch.setattr(versioning, "VERSIONS_ROOT_DEFAULT", tmp_path / "versions", raising=False)

    from ui_flet.services import AppServices

    return AppServices()


def _drain(q):
    out = []
    while not q.empty():
        out.append(q.get_nowait())
    return out


def _run(coro):
    return asyncio.run(coro)


class _FakePage:
    def __init__(self):
        self.services = []
        self.overlay = []
        self.update_calls = 0
        self.tasks = []
        self.dialogs = []
        self.snack_bar = None
        self.web = False

    def update(self):
        self.update_calls += 1

    def run_task(self, handler, *args):
        self.tasks.append((handler, args))
        return None

    def show_dialog(self, dialog):
        self.dialogs.append(dialog)

    def pop_dialog(self):
        if self.dialogs:
            self.dialogs.pop()


class _FakeShell:
    def __init__(self, page):
        self.page = page
        self.status_text = SimpleNamespace(value="Ready")
        self.progress_bar = SimpleNamespace(value=0, color=None)
        self.progress_pct = SimpleNamespace(value="0%")
        self.busy_control = None

    def set_busy(self, control):
        self.busy_control = control
        control.disabled = True

    def safe_update(self):
        self.page.update()
        return True

    def show_snackbar(self, text, is_error=False):
        self.status_text.value = text
        self.page.snack_bar = SimpleNamespace(text=text, is_error=is_error)
        self.safe_update()


class _FakeClipboard:
    def __init__(self):
        self.values = []

    async def set(self, value):
        self.values.append(value)


def _make_encrypt_screen(fast_services):
    pytest.importorskip("flet")
    from ui_flet.screens.encrypt_screen import EncryptScreen

    page = _FakePage()
    shell = _FakeShell(page)
    screen = EncryptScreen(page, fast_services, shell)
    screen.build()
    return screen, page, shell


def _make_inspect_screen(fast_services):
    pytest.importorskip("flet")
    from ui_flet.screens.inspect_screen import InspectScreen

    page = _FakePage()
    shell = _FakeShell(page)
    screen = InspectScreen(page, fast_services, shell)
    screen.build()
    return screen, page, shell


def _make_vault(services, files, vault_path, password="Stage11Pw!", recovery_key=None):
    temp_zip = services.packager.package_files([Path(p) for p in files], compress=True)
    try:
        manifest = services.packager.get_manifest_multiple([Path(p) for p in files])
        services.crypto.encrypt_file(
            temp_zip,
            vault_path,
            password,
            original_filename="archive",
            metadata=manifest,
            recovery_key=recovery_key,
            target_container_mb=0,
        )
    finally:
        if temp_zip.exists():
            try:
                services.wiper.wipe_file(temp_zip)
            except Exception:
                temp_zip.unlink(missing_ok=True)
    return vault_path


def _extract_zip(services, zip_path, output_dir):
    services.packager.extract_archive(zip_path, output_dir)
    return {p.name: p.read_bytes() for p in output_dir.rglob("*") if p.is_file()}


def test_encrypt_screen_validation_blocks_invalid_starts(fast_services, tmp_path):
    screen, _page, shell = _make_encrypt_screen(fast_services)
    src = tmp_path / "src.txt"
    src.write_text("payload", encoding="utf-8")
    screen.sources = [str(src)]
    screen.password_field.value = "A-password-1"
    screen.confirm_password_field.value = "different"

    screen._start_encrypt()
    assert shell.status_text.value == "Passwords do not match"
    assert not fast_services.is_processing

    screen.confirm_password_field.value = "A-password-1"
    screen.save_next_checkbox.value = True
    screen.output_field.value = str(tmp_path / "missing")
    args, error = screen._validate_start()
    assert error == ""
    assert args["out_dir"] is None

    screen.save_next_checkbox.value = False
    args, error = screen._validate_start()
    assert args is None
    assert error == "Select a valid output directory"


def test_encrypt_screen_hidden_validation_blocks_bad_inputs(fast_services, tmp_path):
    screen, _page, _shell = _make_encrypt_screen(fast_services)
    src = tmp_path / "decoy.txt"
    hidden = tmp_path / "hidden.txt"
    src.write_text("decoy", encoding="utf-8")
    hidden.write_text("hidden", encoding="utf-8")
    screen.sources = [str(src)]
    screen.password_field.value = "Decoy-password-1"
    screen.confirm_password_field.value = "Decoy-password-1"
    screen.hidden_toggle.value = True
    screen.hidden_password_field.value = "hidden-a"
    screen.hidden_confirm_password_field.value = "hidden-b"

    _args, error = screen._validate_start()
    assert error == "Hidden passwords do not match"

    screen.hidden_confirm_password_field.value = "Decoy-password-1"
    screen.hidden_password_field.value = "Decoy-password-1"
    _args, error = screen._validate_start()
    assert error == "Decoy and hidden passwords must be different"

    screen.hidden_password_field.value = "Hidden-password-1"
    screen.hidden_confirm_password_field.value = "Hidden-password-1"
    _args, error = screen._validate_start()
    assert error == "Add at least one hidden source"

    screen.hidden_sources = [str(hidden)]
    args, error = screen._validate_start()
    assert error == ""
    assert args["hidden_mode"] is True


def test_encrypt_controller_recovery_key_and_output_paths(fast_services, tmp_path):
    from crypto_core import generate_recovery_entropy
    from ui_flet.controllers.encrypt_controller import EncryptController

    src = tmp_path / "secret.txt"
    src.write_bytes(b"stage11 recovery payload" * 50)
    recovery_key = generate_recovery_entropy()

    EncryptController(fast_services)._worker(
        [str(src)],
        "Password-1",
        0,
        True,
        False,
        None,
        recovery_key=recovery_key,
    )
    vault = tmp_path / "secret.txt.vault"
    assert vault.exists()
    restored = tmp_path / "restored.zip"
    fast_services.crypto.decrypt_file(vault, restored, password=None, recovery_key=recovery_key)
    assert restored.exists()

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    EncryptController(fast_services)._worker(
        [str(src)],
        "Password-1",
        0,
        True,
        False,
        str(out_dir),
        recovery_key=recovery_key,
    )
    assert (out_dir / "secret.txt.vault").exists()


def test_hidden_vault_controller_round_trips_decoy_and_hidden(fast_services, tmp_path):
    from crypto_core import generate_recovery_entropy
    from ui_flet.controllers.encrypt_controller import EncryptController

    decoy = tmp_path / "decoy.txt"
    hidden = tmp_path / "hidden.txt"
    decoy.write_bytes(b"decoy payload")
    hidden.write_bytes(b"hidden payload")
    recovery_key = generate_recovery_entropy()

    EncryptController(fast_services)._worker(
        [str(decoy)],
        "Decoy-password-1",
        0,
        True,
        False,
        None,
        recovery_key=recovery_key,
        hidden_mode=True,
        hidden_password="Hidden-password-1",
        hidden_size_label="10 MB",
        hidden_sources=[str(hidden)],
    )

    vault = tmp_path / "decoy.txt.vault"
    assert vault.exists()

    decoy_zip = tmp_path / "decoy.zip"
    hidden_zip = tmp_path / "hidden.zip"
    fast_services.crypto.decrypt_file(vault, decoy_zip, "Decoy-password-1")
    fast_services.crypto.decrypt_file(vault, hidden_zip, "Hidden-password-1")

    decoy_files = _extract_zip(fast_services, decoy_zip, tmp_path / "decoy_out")
    hidden_files = _extract_zip(fast_services, hidden_zip, tmp_path / "hidden_out")
    assert decoy_files["decoy.txt"] == b"decoy payload"
    assert hidden_files["hidden.txt"] == b"hidden payload"


def test_encrypt_controller_never_emits_worker_recovery_phrase_event():
    root = Path(__file__).resolve().parents[1]
    src = (root / "ui_flet" / "controllers" / "encrypt_controller.py").read_text(encoding="utf-8")
    assert "recovery_phrase" not in src


def test_encrypt_and_inspect_services_registered_without_overlay(fast_services):
    ft = pytest.importorskip("flet")
    encrypt_screen, encrypt_page, _ = _make_encrypt_screen(fast_services)
    inspect_screen, inspect_page, _ = _make_inspect_screen(fast_services)

    assert encrypt_page.overlay == []
    assert encrypt_page.services == [
        encrypt_screen.file_picker,
        encrypt_screen.folder_picker,
        encrypt_screen.output_picker,
        encrypt_screen.hidden_file_picker,
        encrypt_screen.hidden_folder_picker,
    ]
    assert all(isinstance(item, ft.FilePicker) for item in encrypt_page.services)

    assert inspect_page.overlay == []
    assert inspect_page.services[:4] == [
        inspect_screen.vault_picker,
        inspect_screen.selective_output_picker,
        inspect_screen.diff_vault_a_picker,
        inspect_screen.diff_vault_b_picker,
    ]
    assert all(isinstance(item, ft.FilePicker) for item in inspect_page.services[:4])
    assert isinstance(inspect_page.services[4], ft.Clipboard)


def test_copy_sha_uses_saved_fingerprint_and_token_clear(fast_services, tmp_path):
    from ui_flet.controllers.inspect_controller import InspectController

    screen, _page, shell = _make_inspect_screen(fast_services)
    fake = _FakeClipboard()
    screen.clipboard = fake
    vault = tmp_path / "copy.vault"
    vault.write_bytes(b"not a real vault; fingerprint copy only")
    InspectController._save_fingerprint(vault, "a" * 64)
    screen.path_field.value = str(vault)

    _run(screen._copy_sha())
    assert fake.values == ["a" * 64]
    old_token = screen._clipboard_token

    _run(screen._clear_clipboard_if_current(old_token - 1))
    assert fake.values == ["a" * 64]
    _run(screen._clear_clipboard_if_current(old_token))
    assert fake.values[-1] == ""
    assert shell.status_text.value == "Clipboard cleared"


def test_copy_sha_without_fingerprint_does_not_touch_clipboard(fast_services, tmp_path):
    screen, _page, shell = _make_inspect_screen(fast_services)
    fake = _FakeClipboard()
    screen.clipboard = fake
    vault = tmp_path / "missing.vault"
    vault.write_bytes(b"placeholder")
    screen.path_field.value = str(vault)

    _run(screen._copy_sha())
    assert fake.values == []
    assert shell.status_text.value == "Run Integrity Check first"


def test_selective_extract_copies_only_selected_and_cleans_temps(fast_services, tmp_path, monkeypatch):
    import ui_flet.controllers.inspect_controller as inspect_controller
    from ui_flet.controllers.inspect_controller import InspectController

    temp_root = tmp_path / "temp"
    temp_root.mkdir()
    monkeypatch.setattr(inspect_controller.tempfile, "gettempdir", lambda: str(temp_root))

    one = tmp_path / "one.txt"
    two = tmp_path / "two.txt"
    one.write_bytes(b"one")
    two.write_bytes(b"two")
    vault = _make_vault(fast_services, [one, two], tmp_path / "sel.vault")
    out_dir = tmp_path / "selected"
    out_dir.mkdir()

    InspectController(fast_services)._selective_extract_worker(
        vault,
        "Stage11Pw!",
        None,
        ["one.txt"],
        out_dir,
    )

    assert (out_dir / "one.txt").read_bytes() == b"one"
    assert not (out_dir / "two.txt").exists()
    assert fast_services._active_temp_files == []
    assert not list(temp_root.glob(".rpm_extract_*.zip"))
    assert not list(temp_root.glob(".rpm_extract_dir_*"))


def test_vault_diff_is_header_only_and_reports_added_removed_modified(fast_services, tmp_path, monkeypatch):
    from ui_flet.controllers.inspect_controller import InspectController

    a_dir = tmp_path / "a"
    b_dir = tmp_path / "b"
    a_dir.mkdir()
    b_dir.mkdir()
    same_a = a_dir / "same.txt"
    same_b = b_dir / "same.txt"
    removed = a_dir / "removed.txt"
    added = b_dir / "added.txt"
    mod_a = a_dir / "mod.txt"
    mod_b = b_dir / "mod.txt"
    same_a.write_bytes(b"same")
    same_b.write_bytes(b"same")
    removed.write_bytes(b"removed")
    added.write_bytes(b"added")
    mod_a.write_bytes(b"old")
    mod_b.write_bytes(b"newer")

    vault_a = _make_vault(fast_services, [same_a, removed, mod_a], tmp_path / "a.vault", password="PwA-1")
    vault_b = _make_vault(fast_services, [same_b, added, mod_b], tmp_path / "b.vault", password="PwB-1")

    def fail_decrypt(*_args, **_kwargs):
        raise AssertionError("Vault Diff must not decrypt payload")

    monkeypatch.setattr(fast_services.crypto, "decrypt_file", fail_decrypt)
    InspectController(fast_services)._vault_diff_worker(vault_a, "PwA-1", vault_b, "PwB-1")
    msgs = _drain(fast_services.msg_queue)
    result = [m for m in msgs if m["type"] == "vault_diff_result"][0]

    assert any("added.txt" in item for item in result["added"])
    assert any("removed.txt" in item for item in result["removed"])
    assert any("mod.txt" in item for item in result["modified"])


def test_event_dispatcher_routes_stage11_results():
    from ui_flet.events import EventDispatcher

    calls = []

    class Sink:
        def on_selective_extract_result(self, msg):
            calls.append(("selective", msg))

        def on_vault_diff_result(self, msg):
            calls.append(("diff", msg))

        def on_batch_done(self, text, success=None):
            calls.append(("done", text, success))

    dispatcher = EventDispatcher(Sink())
    dispatcher.dispatch({"type": "selective_extract_result", "count": 1})
    dispatcher.dispatch({"type": "vault_diff_result", "text": "diff"})
    dispatcher.dispatch({"type": "batch_done", "text": "Done", "success": True})
    assert calls == [
        ("selective", {"type": "selective_extract_result", "count": 1}),
        ("diff", {"type": "vault_diff_result", "text": "diff"}),
        ("done", "Done", True),
    ]


def test_shell_success_and_failure_progress_behaviour(fast_services):
    pytest.importorskip("flet")
    from ui_flet.shell import AppShell

    page = _FakePage()
    shell = AppShell(page, fast_services)

    shell.on_batch_done("Batch complete", True)
    token = shell._progress_reset_token
    assert shell.progress_bar.value == 1
    assert shell.progress_pct.value == "100%"

    _run(shell._reset_progress_after_delay(token, delay=0))
    assert shell.progress_bar.value == 0
    assert shell.progress_pct.value == "0%"

    shell.progress_bar.value = 0.5
    shell.progress_pct.value = "50%"
    shell.on_batch_done("Cancelled - 0/1 done", False)
    assert shell.progress_bar.value == 0
    assert shell.progress_pct.value == "0%"


def test_sidebar_privacy_notice_is_removed(fast_services):
    pytest.importorskip("flet")
    from app_config import get_setting
    from ui_flet.shell import AppShell

    page = _FakePage()
    shell = AppShell(page, fast_services)
    assert get_setting("privacy_notice_shown", False) is False
    assert not hasattr(shell, "_build_privacy_notice")


def test_snackbar_helper_avoids_removed_flet_page_apis(fast_services):
    pytest.importorskip("flet")
    from ui_flet.shell import AppShell

    page = _FakePage()
    shell = AppShell(page, fast_services)
    shell.show_snackbar("status", is_error=True)
    assert shell.status_text.value == "status"
    assert page.snack_bar is not None

    root = Path(__file__).resolve().parents[1]
    src = (root / "ui_flet" / "shell.py").read_text(encoding="utf-8")
    assert "show_snack_bar" not in src
    assert "page.open(" not in src
    assert "page.close(" not in src
