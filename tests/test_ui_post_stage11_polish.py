"""Post-Stage-11 UI polish regressions."""
import json
from types import SimpleNamespace

import pytest


@pytest.fixture
def hermetic_cfg(tmp_path, monkeypatch):
    import app_config

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
    from ui_flet.screens.encrypt_screen import EncryptScreen
    from ui_flet.screens.password_screen import PasswordScreen

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
    from ui_flet.shell import AppShell

    page = FakePage()
    services = FakeServices()
    shell = AppShell(page, services)

    shell._placeholder("encrypt")
    shell.encrypt_screen.sources = ["C:/tmp/a.txt"]
    shell.encrypt_screen.password_field.value = "pw"
    shell.encrypt_screen.confirm_password_field.value = "pw"
    shell.on_batch_done("Batch complete: 1/1 encrypted", True)
    assert shell.encrypt_screen.sources == []
    assert shell.encrypt_screen.password_field.value == ""
    assert shell.encrypt_screen.confirm_password_field.value == ""

    shell._placeholder("decrypt")
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
    from ui_flet.screens.activity_screen import ActivityScreen
    from ui_flet.screens.decrypt_screen import DecryptScreen
    from ui_flet.screens.encrypt_screen import EncryptScreen
    from ui_flet.screens.inspect_screen import InspectScreen
    from ui_flet.screens.library_screen import LibraryScreen
    from ui_flet.screens.notes_screen import NotesScreen
    from ui_flet.screens.rekey_screen import RekeyScreen

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
    from ui_flet.screens.settings_screen import SettingsScreen

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
    from ui_flet.controllers.settings_controller import THEME_CHOICES
    from ui_flet.tokens import COLORS, TYPE, apply_palette, apply_ui_scale

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
    from app_config import get_setting
    from ui_flet.shell import AppShell

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
    from app_config import get_setting
    from ui_flet.shell import AppShell

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
    import app_config
    from ui_flet.screens.encrypt_screen import EncryptScreen

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
