import pytest


def test_tokens_palette_matches_brand_identity():
    from rpm_encrypter.ui import tokens
    assert tokens.COLORS["bg"] == "#0d1117"
    assert tokens.COLORS["bg_sidebar"] == "#010409"
    assert tokens.COLORS["accent"] == "#00d4aa"
    assert tokens.COLORS["text_primary"] == "#e6edf3"
    # all 10 brand tokens present
    for key in ("bg", "bg_sidebar", "surface_card", "accent", "accent_hover",
                "text_primary", "text_secondary", "error", "success", "border"):
        assert key in tokens.COLORS


def test_tokens_type_and_spacing_scale():
    from rpm_encrypter.ui import tokens
    assert set(tokens.TYPE) == {"page_title", "section", "body", "caption"}
    assert tokens.SPACING["base"] == 8


def test_nav_model_matches_current_app_screens():
    from rpm_encrypter.ui import tokens
    keys = [k for k, _ in tokens.NAV_ITEMS]
    assert keys == ["encrypt", "decrypt", "inspect", "library", "notes",
                    "rekey", "password", "activity", "settings"]
    assert tokens.BOTTOM_NAV_KEYS == ["settings"]
    assert "settings" not in tokens.TOP_NAV_KEYS
    assert dict(tokens.NAV_ITEMS)["inspect"] == "Vault Info"


def test_theme_builds_a_flet_theme():
    ft = pytest.importorskip("flet")
    from rpm_encrypter.ui.theme import build_theme
    assert isinstance(build_theme(), ft.Theme)


from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def hermetic_home(tmp_path, monkeypatch):
    """Keep AppServices construction off the real home dir."""
    from rpm_encrypter.storage import activity_log, config as app_config, scanner as vault_scanner, versioning
    monkeypatch.setattr(app_config, "CONFIG_FILE", tmp_path / "cfg.json")
    monkeypatch.setattr(activity_log, "DB_PATH", tmp_path / "activity.db")
    monkeypatch.setattr(vault_scanner, "CACHE_FILE", tmp_path / "lib.json")
    monkeypatch.setattr(versioning, "VERSIONS_ROOT_DEFAULT", tmp_path / "versions",
                        raising=False)
    return tmp_path


def test_app_services_builds_all_backend_services(hermetic_home):
    from rpm_encrypter.services.app_services import AppServices
    from rpm_encrypter import core as crypto_core
    from rpm_encrypter.services import state as app_state
    from rpm_encrypter.storage import (
        activity_log,
        inspector,
        packager,
        scanner as vault_scanner,
        versioning,
        wiper,
    )
    s = AppServices()
    assert isinstance(s.crypto, crypto_core.VaultCrypto)
    assert isinstance(s.packager, packager.FolderPackager)
    assert isinstance(s.wiper, wiper.SecureWiper)
    assert isinstance(s.inspector, inspector.VaultInspector)
    assert isinstance(s.limiter, app_state.AttemptLimiter)
    assert isinstance(s.stats, app_state.SessionStats)
    assert isinstance(s.activity_logger, activity_log.ActivityLogger)
    assert isinstance(s.scanner, vault_scanner.VaultScanner)
    assert isinstance(s.versioner, versioning.VaultVersionManager)


def test_msg_queue_is_bounded(hermetic_home):
    from rpm_encrypter.services.app_services import AppServices
    assert AppServices().msg_queue.maxsize == 1000


class _FakeSink:
    def __init__(self):
        self.calls = []
    def on_log(self, text): self.calls.append(("log", text))
    def on_progress_start(self): self.calls.append(("progress_start",))
    def on_progress(self, done, total): self.calls.append(("progress", done, total))
    def on_error(self, text): self.calls.append(("error", text))
    def on_auth_error(self, rem, lock): self.calls.append(("auth_error", rem, lock))
    def on_batch_done(self, text): self.calls.append(("batch_done", text))


def test_event_dispatcher_routes_every_message_type():
    from rpm_encrypter.services.events import (
        AuthErrorEvent,
        BatchDoneEvent,
        ErrorEvent,
        LogEvent,
        ProgressEvent,
        ProgressStartEvent,
    )
    from rpm_encrypter.ui.events import EventDispatcher

    sink = _FakeSink()
    d = EventDispatcher(sink)
    d.dispatch(LogEvent(text="hi"))
    d.dispatch(ProgressStartEvent())
    d.dispatch(ProgressEvent(done=3, total=4))
    d.dispatch(ErrorEvent(text="boom"))
    d.dispatch(AuthErrorEvent(remaining=2, lockout=0))
    d.dispatch(BatchDoneEvent(text="done"))
    assert sink.calls == [
        ("log", "hi"),
        ("progress_start",),
        ("progress", 3, 4),
        ("error", "boom"),
        ("auth_error", 2, 0),
        ("batch_done", "done"),
    ]


def test_event_dispatcher_ignores_unknown_type():
    from rpm_encrypter.ui.events import EventDispatcher
    sink = _FakeSink()
    EventDispatcher(sink).dispatch({"type": "totally_unknown"})
    assert sink.calls == []


def test_cleanup_orphaned_temp_files_targets_rpm_temp_patterns(hermetic_home, tmp_path, monkeypatch):
    import tempfile as _t
    from rpm_encrypter.services.app_services import AppServices
    s = AppServices()
    fake_temp = tmp_path / "t"
    fake_temp.mkdir()
    target = fake_temp / ".rpm_pack_demo.zip"
    target.write_bytes(b"plaintext-ish")
    monkeypatch.setattr(_t, "gettempdir", lambda: str(fake_temp))
    wiped = []
    s.wiper.wipe_file = lambda p: wiped.append(p)
    s.cleanup_orphaned_temp_files()
    assert any(str(target) == str(p) for p in wiped)


def test_stage1_bridge_modules_are_flet_free():
    for rel in (
        "src/rpm_encrypter/services/app_services.py",
        "src/rpm_encrypter/services/events.py",
        "src/rpm_encrypter/ui/events.py",
    ):
        src = (ROOT / rel).read_text(encoding="utf-8")
        assert "import flet" not in src
        assert "from flet" not in src


class _DummyPage:
    def __init__(self):
        self.controls = []
        self.services = []
        self.overlay = []
        self.dialogs = []
        self.snack_bar = None
        self.theme = None
        self.theme_mode = None
        self.bgcolor = None
        self.update_calls = 0

    def update(self):
        self.update_calls += 1

    def run_task(self, *args, **kwargs):
        return None


def _make_shell(hermetic_home):
    from rpm_encrypter.services.app_services import AppServices
    from rpm_encrypter.ui.shell import AppShell

    page = _DummyPage()
    services = AppServices()
    shell = AppShell(page, services)
    page.controls.append(shell.build())
    return shell, services


def test_ctrl_number_keyboard_shortcuts_navigate_tabs(hermetic_home):
    pytest.importorskip("flet")
    from types import SimpleNamespace
    from rpm_encrypter.ui.tokens import NAV_ITEMS

    shell, _ = _make_shell(hermetic_home)

    for idx, (key, _) in enumerate(NAV_ITEMS, 1):
        shell.on_keyboard_event(
            SimpleNamespace(key=str(idx), ctrl=True, alt=False, shift=False, meta=False)
        )
        assert shell.active_key == key

    # Modifiers other than Ctrl alone or non-Ctrl presses must be ignored.
    shell.navigate("encrypt")
    shell.on_keyboard_event(
        SimpleNamespace(key="2", ctrl=False, alt=False, shift=False, meta=False)
    )
    shell.on_keyboard_event(
        SimpleNamespace(key="2", ctrl=True, alt=True, shift=False, meta=False)
    )
    assert shell.active_key == "encrypt"


def test_status_bar_cancel_button_lifecycle(hermetic_home):
    ft = pytest.importorskip("flet")
    from rpm_encrypter.ui.tokens import COLORS

    shell, services = _make_shell(hermetic_home)
    btn = ft.Button("Go")

    assert shell.cancel_btn.visible is False
    shell.set_busy(btn)
    assert btn.disabled is True
    assert shell.cancel_btn.visible is True
    assert shell.cancel_btn.disabled is False

    shell.request_cancel()
    assert services.cancel_requested is True
    assert shell.cancel_btn.disabled is True
    assert shell.status_text.value == "Cancelling..."

    shell.on_batch_done("Cancelled - 0/1 done", False)
    assert btn.disabled is False
    assert shell.cancel_btn.visible is False
    assert shell.progress_bar.color == COLORS["accent"]

    shell.set_busy(btn)
    shell.on_error("Boom")
    assert btn.disabled is False
    assert shell.cancel_btn.visible is False

    shell.set_busy(btn)
    shell.on_auth_error(4, 0)
    assert btn.disabled is False
    assert shell.cancel_btn.visible is False


def test_update_available_event_shows_and_dismisses_banner(hermetic_home):
    pytest.importorskip("flet")
    from rpm_encrypter.services.events import UpdateAvailableEvent
    from rpm_encrypter.ui.events import EventDispatcher

    shell, _ = _make_shell(hermetic_home)
    assert shell._update_banner.visible is False

    EventDispatcher(shell).dispatch(
        UpdateAvailableEvent(
            info={"version": "3.1.0", "url": "https://example.invalid/v3.1.0"},
        )
    )
    assert shell._update_banner.visible is True
    assert "3.1.0" in shell._update_banner_title.value

    # Survives theme/scale rebuilds while not dismissed.
    shell._rebuild_root()
    assert shell._update_banner.visible is True
    assert "3.1.0" in shell._update_banner_title.value

    shell._dismiss_update_banner()
    assert shell._update_banner.visible is False
    assert shell._update_info is None


def test_shell_mount_screen_rejects_unknown_key(hermetic_home):
    pytest.importorskip("flet")
    shell, _ = _make_shell(hermetic_home)
    assert shell._mount_screen("encrypt") is not None
    with pytest.raises(KeyError):
        shell._mount_screen("does_not_exist")
