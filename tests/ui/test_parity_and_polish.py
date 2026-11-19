"""Stage 11 cross-cutting parity tests for the Flet UI."""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def fast_services(tmp_path, monkeypatch):
    from rpm_encrypter.storage import activity_log
    from rpm_encrypter.storage import config as app_config
    from rpm_encrypter.storage import scanner as vault_scanner
    from rpm_encrypter.storage import versioning

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

    from rpm_encrypter.services.app_services import AppServices

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
    from rpm_encrypter.ui.screens.encrypt_screen import EncryptScreen

    page = _FakePage()
    shell = _FakeShell(page)
    screen = EncryptScreen(page, fast_services, shell)
    screen.build()
    return screen, page, shell


def _make_inspect_screen(fast_services):
    pytest.importorskip("flet")
    from rpm_encrypter.ui.screens.inspect_screen import InspectScreen

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
    from rpm_encrypter.core import generate_recovery_entropy
    from rpm_encrypter.services.controllers.encrypt_controller import EncryptController

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
    from rpm_encrypter.core import generate_recovery_entropy
    from rpm_encrypter.services.controllers.encrypt_controller import EncryptController

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
    root = Path(__file__).resolve().parents[2]
    src = (root / "src" / "rpm_encrypter" / "services" / "controllers" / "encrypt_controller.py").read_text(encoding="utf-8")
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
    from rpm_encrypter.services.controllers.inspect_controller import InspectController

    screen, _page, shell = _make_inspect_screen(fast_services)
    fake = _FakeClipboard()
    screen.clipboard = fake
    vault = tmp_path / "copy.vault"
    vault.write_bytes(b"not a real vault; fingerprint copy only")
    InspectController._save_fingerprint(vault, "a" * 64)
    screen.path_field.value = str(vault)

    _run(screen._copy_sha())
    assert fake.values == ["a" * 64]
    old_token = screen.clipboard_guard.token

    _run(screen.clipboard_guard.clear_if_current(old_token - 1))
    assert fake.values == ["a" * 64]
    _run(screen.clipboard_guard.clear_if_current(old_token))
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
    import rpm_encrypter.services.controllers.inspect_controller as inspect_controller
    from rpm_encrypter.services.controllers.inspect_controller import InspectController

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
    from rpm_encrypter.services.controllers.inspect_controller import InspectController

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
    from rpm_encrypter.services.events import VaultDiffResultEvent

    InspectController(fast_services)._vault_diff_worker(vault_a, "PwA-1", vault_b, "PwB-1")
    msgs = _drain(fast_services.msg_queue)
    result = [m for m in msgs if isinstance(m, VaultDiffResultEvent)][0]

    assert any("added.txt" in item for item in result.added)
    assert any("removed.txt" in item for item in result.removed)
    assert any("mod.txt" in item for item in result.modified)


def test_event_dispatcher_routes_stage11_results():
    from rpm_encrypter.services.events import (
        BatchDoneEvent,
        SelectiveExtractResultEvent,
        VaultDiffResultEvent,
    )
    from rpm_encrypter.ui.events import EventDispatcher

    calls = []

    class Sink:
        def on_selective_extract_result(self, msg):
            calls.append(("selective", msg))

        def on_vault_diff_result(self, msg):
            calls.append(("diff", msg))

        def on_batch_done(self, text, success=None):
            calls.append(("done", text, success))

    dispatcher = EventDispatcher(Sink())
    selective_ev = SelectiveExtractResultEvent(count=1)
    diff_ev = VaultDiffResultEvent(text="diff")
    dispatcher.dispatch(selective_ev)
    dispatcher.dispatch(diff_ev)
    dispatcher.dispatch(BatchDoneEvent(text="Done", success=True))
    assert calls == [
        ("selective", selective_ev),
        ("diff", diff_ev),
        ("done", "Done", True),
    ]


def test_shell_success_and_failure_progress_behaviour(fast_services):
    pytest.importorskip("flet")
    from rpm_encrypter.ui.shell import AppShell

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
    from rpm_encrypter.storage.config import get_setting
    from rpm_encrypter.ui.shell import AppShell

    page = _FakePage()
    shell = AppShell(page, fast_services)
    assert get_setting("privacy_notice_shown", False) is False
    assert not hasattr(shell, "_build_privacy_notice")


def test_snackbar_helper_avoids_removed_flet_page_apis(fast_services):
    pytest.importorskip("flet")
    from rpm_encrypter.ui.shell import AppShell

    page = _FakePage()
    shell = AppShell(page, fast_services)
    shell.show_snackbar("status", is_error=True)
    assert shell.status_text.value == "status"
    assert page.snack_bar is not None

    root = Path(__file__).resolve().parents[2]
    src = (root / "src" / "rpm_encrypter" / "ui" / "shell.py").read_text(encoding="utf-8")
    assert "show_snack_bar" not in src
    assert "page.open(" not in src
    assert "page.close(" not in src


"""Post-Stage-11 UI polish regressions."""
import json
from types import SimpleNamespace

import pytest


@pytest.fixture
def hermetic_cfg(tmp_path, monkeypatch):
    from rpm_encrypter.storage import config as app_config

    cfg = tmp_path / "config.json"
    monkeypatch.setattr(app_config, "CONFIG_FILE", cfg)
    return cfg


class FakePage:
    def __init__(self):
        self.services = []
        self.overlay = []
        self.controls = []
        self.dialogs = []
        self.update_calls = 0
        self.theme = None
        self.theme_mode = None
        self.bgcolor = None
        self.snack_bar = None

    def update(self):
        self.update_calls += 1

    def add(self, control):
        self.controls.append(control)

    def show_dialog(self, dialog):
        self.dialogs.append(dialog)

    def pop_dialog(self):
        if self.dialogs:
            self.dialogs.pop()

    def run_task(self, handler, *args):
        return None


class FakeServices:
    def __init__(self):
        self.shutdown_requested = False
        self.cancel_requested = False
        self.is_processing = False
        self.rebuilds = 0
        self.wiper = SimpleNamespace(passes=1)
        self.activity_logger = SimpleNamespace(enabled=False)
        self.stats = SimpleNamespace(snapshot=lambda: {
            "encrypted": 0,
            "decrypted": 0,
            "rekeyed": 0,
            "uptime": "0s",
        })

    def rebuild_crypto(self):
        self.rebuilds += 1

    def _build_versioner(self):
        return SimpleNamespace(token="rebuilt")


class FakeShell:
    def __init__(self, page):
        self.page = page
        self.status_text = SimpleNamespace(value="Ready")
        self.progress_bar = SimpleNamespace(value=0, color=None)
        self.progress_pct = SimpleNamespace(value="0%")
        self.busy_control = None
        self.theme_calls = []
        self.scale_calls = []

    def safe_update(self):
        self.page.update()
        return True

    def show_snackbar(self, text, is_error=False):
        self.status_text.value = text
        self.safe_update()

    def set_busy(self, control):
        self.busy_control = control
        control.disabled = True

    def apply_theme(self, choice):
        self.theme_calls.append(choice)

    def apply_ui_scale(self, choice):
        self.scale_calls.append(choice)


def test_password_transfer_fills_encrypt_confirmation(hermetic_cfg):
    pytest.importorskip("flet")
    from rpm_encrypter.ui.screens.encrypt_screen import EncryptScreen
    from rpm_encrypter.ui.screens.password_screen import PasswordScreen

    page = FakePage()
    services = FakeServices()

    class Shell(FakeShell):
        def __init__(self, page):
            super().__init__(page)
            self.encrypt_screen = None
            self.active_key = "password"

        def navigate(self, key):
            self.active_key = key
            if key == "encrypt" and self.encrypt_screen is None:
                self.encrypt_screen = EncryptScreen(page, services, self)
                self.encrypt_screen.build()

    shell = Shell(page)
    screen = PasswordScreen(page, services, shell)
    screen.result_field.value = "Generated-Password-123!"

    screen._transfer_to_encrypt()

    assert shell.encrypt_screen.password_field.value == "Generated-Password-123!"
    assert shell.encrypt_screen.confirm_password_field.value == "Generated-Password-123!"


def test_encrypt_and_decrypt_reset_after_success(hermetic_cfg):
    pytest.importorskip("flet")
    from rpm_encrypter.ui.shell import AppShell

    page = FakePage()
    services = FakeServices()
    shell = AppShell(page, services)

    shell._mount_screen("encrypt")
    shell.encrypt_screen.sources = ["C:/tmp/a.txt"]
    shell.encrypt_screen.password_field.value = "pw"
    shell.encrypt_screen.confirm_password_field.value = "pw"
    shell.on_batch_done("Batch complete: 1/1 encrypted", True)
    assert shell.encrypt_screen.sources == []
    assert shell.encrypt_screen.password_field.value == ""
    assert shell.encrypt_screen.confirm_password_field.value == ""

    shell._mount_screen("decrypt")
    shell.decrypt_screen.paths = ["C:/tmp/a.vault"]
    shell.decrypt_screen.password_field.value = "pw"
    shell.decrypt_screen.output_field.value = "C:/tmp"
    shell.on_batch_done("Batch complete: 1/1 decrypted", True)
    assert shell.decrypt_screen.paths == []
    assert shell.decrypt_screen.password_field.value == ""
    assert shell.decrypt_screen.output_field.value == ""

    shell.progress_bar.value = 0.75
    shell.progress_pct.value = "75%"
    shell.on_batch_done("Wrong password or corrupted vault - 4 attempts remaining")
    assert shell.progress_bar.value == 0
    assert shell.progress_pct.value == "0%"


def test_scroll_and_stretch_layout_controls(hermetic_cfg):
    ft = pytest.importorskip("flet")
    from rpm_encrypter.ui.screens.activity_screen import ActivityScreen
    from rpm_encrypter.ui.screens.decrypt_screen import DecryptScreen
    from rpm_encrypter.ui.screens.encrypt_screen import EncryptScreen
    from rpm_encrypter.ui.screens.inspect_screen import InspectScreen
    from rpm_encrypter.ui.screens.library_screen import LibraryScreen
    from rpm_encrypter.ui.screens.notes_screen import NotesScreen
    from rpm_encrypter.ui.screens.rekey_screen import RekeyScreen

    page = FakePage()
    services = FakeServices()
    shell = FakeShell(page)

    encrypt = EncryptScreen(page, services, shell)
    encrypt.build()
    assert encrypt.hidden_source_list.scroll == ft.ScrollMode.AUTO

    decrypt = DecryptScreen(page, services, shell)
    decrypt_root = decrypt.build()
    assert decrypt_root.content.horizontal_alignment == ft.CrossAxisAlignment.STRETCH

    inspect = InspectScreen(page, services, shell)
    inspect.build()
    assert inspect.fingerprint_list.horizontal_alignment == ft.CrossAxisAlignment.STRETCH

    library = LibraryScreen(page, services, shell)
    library_root = library.build()
    vaults_panel = library_root.content.controls[4]
    vaults_container = vaults_panel.content.controls[1]
    assert library_root.content.horizontal_alignment == ft.CrossAxisAlignment.STRETCH
    assert vaults_container.height >= 400

    notes = NotesScreen(page, services, shell)
    notes_root = notes.build()
    assert notes_root.content.horizontal_alignment == ft.CrossAxisAlignment.STRETCH
    assert notes.note_field.min_lines >= 18

    rekey = RekeyScreen(page, services, shell)
    rekey_root = rekey.build()
    history_panel = rekey_root.content.controls[5]
    history_container = history_panel.content.controls[2]
    assert rekey_root.content.horizontal_alignment == ft.CrossAxisAlignment.STRETCH
    assert history_container.height >= 300

    activity = ActivityScreen(page, services, shell)
    activity.build()
    assert activity.table_container.height >= 500
    assert activity.rows_list.horizontal_alignment == ft.CrossAxisAlignment.STRETCH


def test_settings_versioning_dropdown_transient_none_does_not_crash(hermetic_cfg):
    pytest.importorskip("flet")
    from rpm_encrypter.ui.screens.settings_screen import SettingsScreen

    page = FakePage()
    services = FakeServices()
    shell = FakeShell(page)
    screen = SettingsScreen(page, services, shell)
    screen.build()

    screen.version_count_dropdown.value = None
    screen.version_size_dropdown.value = None
    screen._save_versioning()

    assert "Versioning" in shell.status_text.value
    assert services._build_versioner().token == "rebuilt"


def test_classic_theme_and_ui_scale_tokens(hermetic_cfg):
    from rpm_encrypter.services.controllers.settings_controller import THEME_CHOICES
    from rpm_encrypter.ui.tokens import COLORS, TYPE, apply_palette, apply_ui_scale

    assert "Light" not in THEME_CHOICES
    assert "Classic" in THEME_CHOICES
    apply_palette("Classic")
    assert COLORS["bg"] == "#e5e7eb"
    apply_ui_scale("120%")
    assert TYPE["body"]["size"] > 14
    apply_palette("Dark")
    apply_ui_scale("100%")


def test_update_prompt_is_opt_in_and_persists_choice(hermetic_cfg):
    pytest.importorskip("flet")
    from rpm_encrypter.storage.config import get_setting
    from rpm_encrypter.ui.shell import AppShell

    page = FakePage()
    services = FakeServices()
    shell = AppShell(page, services)

    shell.maybe_show_update_prompt()
    assert len(page.dialogs) == 1
    assert get_setting("update_prompt_shown", False) is True

    shell.maybe_show_update_prompt()
    assert len(page.dialogs) == 1

    keep_off = page.dialogs[0].actions[0]
    keep_off.on_click(None)

    assert get_setting("check_updates", False) is False
    assert get_setting("update_prompt_shown", False) is True


def test_update_prompt_enable_does_not_render_sidebar_notice(hermetic_cfg):
    pytest.importorskip("flet")
    from rpm_encrypter.storage.config import get_setting
    from rpm_encrypter.ui.shell import AppShell

    page = FakePage()
    services = FakeServices()
    shell = AppShell(page, services)

    shell.maybe_show_update_prompt()
    enable = page.dialogs[0].actions[1]
    enable.on_click(None)

    assert get_setting("check_updates", False) is True
    assert get_setting("update_prompt_shown", False) is True
    assert not hasattr(shell, "_build_privacy_notice")


def test_encrypt_profile_dropdown_applies_saved_profile(hermetic_cfg):
    pytest.importorskip("flet")
    from rpm_encrypter.storage import config as app_config
    from rpm_encrypter.ui.screens.encrypt_screen import EncryptScreen

    def seed(cfg):
        cfg.setdefault("profiles", {})["Fast"] = {
            "argon2_memory": 16384,
            "argon2_time": 1,
            "argon2_par": 1,
            "wipe_passes": 3,
        }

    app_config._mutate_cfg(seed)

    page = FakePage()
    services = FakeServices()
    shell = FakeShell(page)
    screen = EncryptScreen(page, services, shell)
    screen.build()
    screen.profile_dropdown.value = "Fast"
    screen._apply_profile()

    saved = json.loads(hermetic_cfg.read_text("utf-8"))["settings"]
    assert saved["argon2_memory"] == 16384
    assert saved["wipe_passes"] == 3
    assert services.rebuilds == 1
    assert "Fast" in shell.status_text.value
