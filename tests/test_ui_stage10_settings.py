"""Stage 10 (Settings) tests.

The SettingsController is FLET-FREE and exercised directly: it reads the settings
snapshot with safe fallbacks, persists appearance / update / logging toggles via
app_config, saves Argon2id KDF parameters (raising while an operation is in
progress) and rebuilds the crypto engine, saves wipe passes and rebuilds the
wiper, saves vault-versioning settings and rebuilds the versioner, manages Smart
Encryption Profiles (rejecting empty/reserved names), runs the Security Health
Check, and clears local traces WITHOUT touching the Library directories.

Screen behavior (initial render reflecting the snapshot, KDF in-progress guard,
confirmation-gated Clear All Local Traces, shell mounting, source boundaries) is
tested headlessly with fake page/shell/services objects -- no display required.
"""
import json
import queue
from pathlib import Path
from types import SimpleNamespace

import pytest

from ui_flet.controllers.settings_controller import (
    RESERVED_PROFILE_NAMES,
    SettingsController,
    SettingsSnapshot,
    HealthCheckResult,
    ClearTracesResult,
    ensure_modern_settings_defaults,
)


ROOT = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------- fixtures/fakes
@pytest.fixture
def hermetic_cfg(tmp_path, monkeypatch):
    cfg = tmp_path / "config.json"
    import app_config

    monkeypatch.setattr(app_config, "CONFIG_FILE", cfg)
    return cfg


@pytest.fixture
def hermetic_cache(tmp_path, monkeypatch):
    cache = tmp_path / "library_cache.json"
    cache.write_text("{}", encoding="utf-8")
    import vault_scanner

    monkeypatch.setattr(vault_scanner, "CACHE_FILE", cache)
    return cache


class FakeLogger:
    def __init__(self, enabled=False):
        self.enabled = enabled
        self.clear_count = 0

    def clear_logs(self):
        self.clear_count += 1


class FakeScanner:
    def __init__(self):
        self.cache = {"stale": 1}


class FakeServices:
    def __init__(self, is_processing=False):
        self.is_processing = is_processing
        self.shutdown_requested = False
        self.cancel_requested = False
        self.activity_logger = FakeLogger()
        self.scanner = FakeScanner()
        self.wiper = SimpleNamespace(passes=1)
        self.versioner = SimpleNamespace(token="orig")
        self.crypto_rebuilds = 0
        self.versioner_builds = 0

    def rebuild_crypto(self):
        self.crypto_rebuilds += 1

    def _build_versioner(self):
        self.versioner_builds += 1
        return SimpleNamespace(token="rebuilt")


class FakePage:
    def __init__(self):
        self.services = []
        self.overlay = []
        self.dialogs = []
        self.update_calls = 0
        self.theme_mode = None

    def update(self):
        self.update_calls += 1

    def show_dialog(self, dialog):
        self.dialogs.append(dialog)

    def pop_dialog(self):
        if self.dialogs:
            self.dialogs.pop()


class FakeShell:
    def __init__(self, page):
        self.page = page
        self.status_text = SimpleNamespace(value="Ready")

    def safe_update(self):
        self.page.update()
        return True


def _shell_services(logger=None):
    return SimpleNamespace(
        activity_logger=logger or FakeLogger(),
        scanner=FakeScanner(),
        wiper=SimpleNamespace(passes=1),
        versioner=SimpleNamespace(token="orig"),
        shutdown_requested=False,
        cancel_requested=False,
        is_processing=False,
        msg_queue=queue.Queue(),
        rebuild_crypto=lambda: None,
        _build_versioner=lambda: SimpleNamespace(token="rebuilt"),
        stats=SimpleNamespace(snapshot=lambda: {
            "encrypted": 0, "decrypted": 0, "rekeyed": 0, "uptime": "0s"
        }),
    )


def _make_screen(services=None, page=None):
    from ui_flet.screens.settings_screen import SettingsScreen

    page = page or FakePage()
    services = services or FakeServices()
    shell = FakeShell(page)
    return SettingsScreen(page, services, shell), page, shell


def _collect_texts(control):
    out = []
    value = getattr(control, "value", None)
    if isinstance(value, str):
        out.append(value)
    content = getattr(control, "content", None)
    if content is not None:
        out.extend(_collect_texts(content))
    for attr in ("controls", "actions"):
        children = getattr(control, attr, None)
        if children:
            for child in children:
                out.extend(_collect_texts(child))
    title = getattr(control, "title", None)
    if title is not None:
        out.extend(_collect_texts(title))
    return out


# ===================================================== 1. controller boundary
def test_controller_source_boundary():
    src = (ROOT / "ui_flet" / "controllers" / "settings_controller.py").read_text(encoding="utf-8")
    assert "import flet" not in src and "from flet" not in src
    assert "tkinter" not in src
    assert "customtkinter" not in src
    assert "import gui_app" not in src and "from gui_app" not in src
    assert "views.settings_view" not in src


# ===================================================== 2. snapshot
def test_controller_snapshot_defaults(hermetic_cfg):
    snap = SettingsController(FakeServices()).get_snapshot()
    assert isinstance(snap, SettingsSnapshot)
    assert snap.theme == "Dark"
    assert snap.ui_scale == "100%"
    assert snap.check_updates is False
    assert snap.argon2_memory == 65536
    assert snap.argon2_time == 3
    assert snap.argon2_par == 4
    assert snap.wipe_passes == 1
    assert snap.versioning_enabled is False
    assert snap.versioning_max_per_vault == 5
    assert snap.versioning_max_total_mb == 2048
    assert snap.versioning_dir == ""
    assert snap.logging_enabled is False


def test_controller_snapshot_coerces_bad_numbers(hermetic_cfg):
    import app_config
    app_config.save_setting("argon2_memory", "not-a-number")
    app_config.save_setting("argon2_time", 999)
    app_config.save_setting("argon2_par", 0)
    app_config.save_setting("wipe_passes", None)
    app_config.save_setting("versioning_max_per_vault", 999)
    app_config.save_setting("versioning_max_total_mb", "bad")
    app_config.save_setting("theme", "Light")
    app_config.save_setting("check_updates", "False")
    snap = SettingsController(FakeServices()).get_snapshot()
    assert snap.argon2_memory == 65536
    assert snap.argon2_time == 3
    assert snap.argon2_par == 4
    assert snap.wipe_passes == 1
    assert snap.versioning_max_per_vault == 5
    assert snap.versioning_max_total_mb == 2048
    assert snap.theme == "Dark"
    assert snap.check_updates is False


def test_controller_ensure_defaults_persists_modern_ssd_settings(hermetic_cfg):
    import app_config

    def seed(cfg):
        cfg["settings"] = {
            "theme": "Light",
            "ui_scale": "",
            "argon2_memory": 1,
            "argon2_time": 0,
            "argon2_par": 999,
            "wipe_passes": 0,
            "versioning_enabled": "False",
            "versioning_max_per_vault": 999,
            "versioning_max_total_mb": "bad",
        }

    app_config._mutate_cfg(seed)
    ensure_modern_settings_defaults()
    saved = json.loads(hermetic_cfg.read_text("utf-8"))["settings"]

    assert saved["theme"] == "Dark"
    assert saved["ui_scale"] == "100%"
    assert saved["check_updates"] is False
    assert saved["argon2_memory"] == 65536
    assert saved["argon2_time"] == 3
    assert saved["argon2_par"] == 4
    assert saved["wipe_passes"] == 1
    assert saved["versioning_enabled"] is False
    assert saved["versioning_max_per_vault"] == 5
    assert saved["versioning_max_total_mb"] == 2048
    assert saved["logging_enabled"] is False


# ===================================================== 3. simple toggles
def test_controller_set_theme_persists_and_clamps(hermetic_cfg):
    ctrl = SettingsController(FakeServices())
    assert ctrl.set_theme("Classic") == "Classic"
    assert json.loads(hermetic_cfg.read_text("utf-8"))["settings"]["theme"] == "Classic"
    assert ctrl.set_theme("Neon") == "Dark"  # invalid clamps to Dark


def test_controller_set_ui_scale_and_updates_persist(hermetic_cfg):
    ctrl = SettingsController(FakeServices())
    assert ctrl.set_ui_scale("999%") == "100%"  # invalid clamps to 100%
    assert ctrl.set_ui_scale("120%") == "120%"
    assert ctrl.set_check_updates(True) is True
    saved = json.loads(hermetic_cfg.read_text("utf-8"))["settings"]
    assert saved["ui_scale"] == "120%"
    assert saved["check_updates"] is True


def test_controller_set_logging_persists_and_updates_logger(hermetic_cfg):
    services = FakeServices()
    ctrl = SettingsController(services)
    assert ctrl.set_logging_enabled(True) is True
    assert services.activity_logger.enabled is True
    assert json.loads(hermetic_cfg.read_text("utf-8"))["settings"]["logging_enabled"] is True


# ===================================================== 4. KDF
def test_controller_save_kdf_persists_and_rebuilds(hermetic_cfg):
    services = FakeServices()
    ctrl = SettingsController(services)
    ctrl.save_kdf_settings(131072, 4, 2)
    saved = json.loads(hermetic_cfg.read_text("utf-8"))["settings"]
    assert saved["argon2_memory"] == 131072
    assert saved["argon2_time"] == 4
    assert saved["argon2_par"] == 2
    assert services.crypto_rebuilds == 1


def test_controller_save_kdf_raises_while_processing(hermetic_cfg):
    services = FakeServices(is_processing=True)
    ctrl = SettingsController(services)
    with pytest.raises(RuntimeError, match="while an operation is in progress"):
        ctrl.save_kdf_settings(65536, 3, 4)
    # Nothing persisted, no rebuild.
    assert services.crypto_rebuilds == 0
    assert not hermetic_cfg.exists() or "argon2_memory" not in json.loads(
        hermetic_cfg.read_text("utf-8")).get("settings", {})


# ===================================================== 5. wipe
def test_controller_save_wipe_passes_rebuilds_wiper(hermetic_cfg):
    services = FakeServices()
    ctrl = SettingsController(services)
    assert ctrl.save_wipe_passes(3) == 3
    assert json.loads(hermetic_cfg.read_text("utf-8"))["settings"]["wipe_passes"] == 3
    assert getattr(services.wiper, "passes", None) == 3


# ===================================================== 6. versioning
def test_controller_save_versioning_persists_and_rebuilds(hermetic_cfg):
    services = FakeServices()
    ctrl = SettingsController(services)
    ctrl.save_versioning_settings(True, 10, 4096, "  /tmp/versions  ")
    saved = json.loads(hermetic_cfg.read_text("utf-8"))["settings"]
    assert saved["versioning_enabled"] is True
    assert saved["versioning_max_per_vault"] == 10
    assert saved["versioning_max_total_mb"] == 4096
    assert saved["versioning_dir"] == "/tmp/versions"  # trimmed
    assert services.versioner_builds == 1
    assert services.versioner.token == "rebuilt"


def test_controller_disabling_versioning_sanitizes_invalid_limits(hermetic_cfg):
    services = FakeServices()
    ctrl = SettingsController(services)
    ctrl.save_versioning_settings(False, 999, "bad", "")
    saved = json.loads(hermetic_cfg.read_text("utf-8"))["settings"]
    assert saved["versioning_enabled"] is False
    assert saved["versioning_max_per_vault"] == 5
    assert saved["versioning_max_total_mb"] == 2048
    assert services.versioner_builds == 1


# =============================================== 6b. security-value validation
def test_controller_save_kdf_rejects_invalid_values_without_side_effects(hermetic_cfg):
    services = FakeServices()
    ctrl = SettingsController(services)
    bad_cases = [
        (1, 3, 4),
        (65536, 0, 4),
        (65536, 3, 999),
        ("bad", 3, 4),
    ]
    for args in bad_cases:
        with pytest.raises(ValueError):
            ctrl.save_kdf_settings(*args)
    assert services.crypto_rebuilds == 0
    if hermetic_cfg.exists():
        settings = json.loads(hermetic_cfg.read_text("utf-8")).get("settings", {})
        assert "argon2_memory" not in settings
        assert "argon2_time" not in settings
        assert "argon2_par" not in settings


def test_controller_save_kdf_processing_guard_runs_before_validation(hermetic_cfg):
    services = FakeServices(is_processing=True)
    ctrl = SettingsController(services)
    with pytest.raises(RuntimeError, match="while an operation is in progress"):
        ctrl.save_kdf_settings(1, 0, 999)
    assert services.crypto_rebuilds == 0


def test_controller_save_wipe_passes_rejects_invalid_values_without_side_effects(hermetic_cfg):
    services = FakeServices()
    original_wiper = services.wiper
    ctrl = SettingsController(services)
    for value in (0, 2, 99, "bad"):
        with pytest.raises(ValueError):
            ctrl.save_wipe_passes(value)
    assert services.wiper is original_wiper
    if hermetic_cfg.exists():
        settings = json.loads(hermetic_cfg.read_text("utf-8")).get("settings", {})
        assert "wipe_passes" not in settings


def test_controller_save_versioning_rejects_invalid_values_without_side_effects(hermetic_cfg):
    services = FakeServices()
    original_versioner = services.versioner
    ctrl = SettingsController(services)
    bad_cases = [
        (True, 999, 2048, "/tmp/v"),
        (True, 5, 1, "/tmp/v"),
        (True, "bad", 2048, "/tmp/v"),
        (True, 5, "bad", "/tmp/v"),
    ]
    for args in bad_cases:
        with pytest.raises(ValueError):
            ctrl.save_versioning_settings(*args)
    assert services.versioner is original_versioner
    assert services.versioner_builds == 0
    if hermetic_cfg.exists():
        settings = json.loads(hermetic_cfg.read_text("utf-8")).get("settings", {})
        assert "versioning_enabled" not in settings
        assert "versioning_max_per_vault" not in settings
        assert "versioning_max_total_mb" not in settings
        assert "versioning_dir" not in settings


# ===================================================== 7. profiles
def test_controller_profiles_save_list_delete(hermetic_cfg):
    import app_config
    app_config.save_setting("argon2_memory", 262144)
    app_config.save_setting("argon2_time", 5)
    app_config.save_setting("argon2_par", 8)
    app_config.save_setting("wipe_passes", 7)

    ctrl = SettingsController(FakeServices())
    assert ctrl.save_profile("  Paranoid  ") == "Paranoid"
    assert ctrl.list_profiles() == ["Paranoid"]
    stored = json.loads(hermetic_cfg.read_text("utf-8"))["profiles"]["Paranoid"]
    assert stored == {
        "argon2_memory": 262144, "argon2_time": 5, "argon2_par": 8, "wipe_passes": 7,
    }
    assert ctrl.delete_profile("Paranoid") is True
    assert ctrl.list_profiles() == []
    assert ctrl.delete_profile("ghost") is False


def test_controller_save_profile_rejects_empty_and_reserved(hermetic_cfg):
    ctrl = SettingsController(FakeServices())
    with pytest.raises(ValueError):
        ctrl.save_profile("   ")
    for reserved in RESERVED_PROFILE_NAMES:
        with pytest.raises(ValueError):
            ctrl.save_profile(reserved)
        with pytest.raises(ValueError):
            ctrl.save_profile(reserved.upper())


def test_controller_save_profile_rejects_invalid_current_settings_without_side_effects(hermetic_cfg):
    import app_config
    app_config.save_setting("argon2_memory", 1)
    app_config.save_setting("argon2_time", 0)
    app_config.save_setting("argon2_par", 999)
    app_config.save_setting("wipe_passes", 0)

    ctrl = SettingsController(FakeServices())
    with pytest.raises(ValueError):
        ctrl.save_profile("Broken")

    saved = json.loads(hermetic_cfg.read_text("utf-8"))
    assert "profiles" not in saved


def test_controller_apply_profile_sets_settings_and_rebuilds(hermetic_cfg):
    import app_config

    def _seed(cfg):
        cfg.setdefault("profiles", {})["Fast"] = {
            "argon2_memory": 16384, "argon2_time": 1, "argon2_par": 1, "wipe_passes": 1,
        }
    app_config._mutate_cfg(_seed)

    services = FakeServices()
    ctrl = SettingsController(services)
    assert ctrl.apply_profile("Fast") is True
    saved = json.loads(hermetic_cfg.read_text("utf-8"))["settings"]
    assert saved["argon2_memory"] == 16384
    assert saved["argon2_time"] == 1
    assert saved["wipe_passes"] == 1
    assert services.crypto_rebuilds == 1
    assert getattr(services.wiper, "passes", None) == 1


def test_controller_apply_profile_rejects_invalid_profile_without_side_effects(hermetic_cfg):
    import app_config

    def _seed(cfg):
        cfg.setdefault("profiles", {})["Broken"] = {
            "argon2_memory": 1, "argon2_time": 0, "argon2_par": 999, "wipe_passes": 0,
        }
    app_config._mutate_cfg(_seed)

    services = FakeServices()
    original_wiper = services.wiper
    ctrl = SettingsController(services)

    with pytest.raises(ValueError):
        ctrl.apply_profile("Broken")

    settings = json.loads(hermetic_cfg.read_text("utf-8")).get("settings", {})
    assert "argon2_memory" not in settings
    assert "argon2_time" not in settings
    assert "argon2_par" not in settings
    assert "wipe_passes" not in settings
    assert services.crypto_rebuilds == 0
    assert services.wiper is original_wiper


def test_controller_apply_profile_skips_sentinels_and_missing(hermetic_cfg):
    ctrl = SettingsController(FakeServices())
    assert ctrl.apply_profile("Custom") is False
    assert ctrl.apply_profile("No Profiles Saved") is False
    assert ctrl.apply_profile("does-not-exist") is False


# ===================================================== 8. health check
def test_controller_health_check_passes_with_strong_settings(hermetic_cfg, monkeypatch):
    import app_config
    app_config.save_setting("argon2_memory", 131072)
    app_config.save_setting("argon2_time", 4)
    app_config.save_setting("wipe_passes", 3)
    monkeypatch.setattr(SettingsController, "_detect_ssd", lambda self: True)

    res = SettingsController(FakeServices()).run_health_check()
    assert isinstance(res, HealthCheckResult)
    assert res.issues == []
    assert any("OWASP" in p for p in res.passes)
    assert "SECURITY HEALTH CHECK RESULTS" in res.text
    assert "Needs Attention" not in res.text


def test_controller_health_check_flags_weak_settings(hermetic_cfg, monkeypatch):
    import app_config
    app_config.save_setting("argon2_memory", 16384)
    app_config.save_setting("argon2_time", 1)
    app_config.save_setting("wipe_passes", 1)
    monkeypatch.setattr(SettingsController, "_detect_ssd", lambda self: False)

    res = SettingsController(FakeServices()).run_health_check()
    assert any("below OWASP" in i for i in res.issues)
    assert "Needs Attention" in res.text


# ===================================================== 9. clear local traces
def test_controller_clear_local_traces_preserves_library_dirs(hermetic_cfg, hermetic_cache):
    import app_config

    def _seed(cfg):
        cfg["fingerprints"] = {"a": 1}
        cfg["enc_sources"] = ["x"]
        cfg["dec_sources"] = ["y"]
        cfg["rekey_vaults"] = ["z"]
        cfg["library_dirs"] = ["/keep/me"]
    app_config._mutate_cfg(_seed)

    services = FakeServices()
    res = SettingsController(services).clear_local_traces()

    assert isinstance(res, ClearTracesResult)
    assert res.errors == []
    assert services.activity_logger.clear_count == 1
    assert services.scanner.cache == {}
    assert not hermetic_cache.exists()  # cache file unlinked

    cfg = json.loads(hermetic_cfg.read_text("utf-8"))
    assert cfg["fingerprints"] == {}
    assert cfg["enc_sources"] == []
    assert cfg["dec_sources"] == []
    assert cfg["rekey_vaults"] == []
    assert cfg["library_dirs"] == ["/keep/me"]  # MUST be preserved


# ===================================================== 10. screen render
def test_screen_initial_render_reflects_snapshot(hermetic_cfg):
    pytest.importorskip("flet")
    import app_config
    app_config.save_setting("theme", "Classic")
    app_config.save_setting("logging_enabled", True)

    screen, _page, _shell = _make_screen()
    root = screen.build()
    texts = _collect_texts(root)

    assert "Settings" in texts
    assert screen.theme_dropdown.value == "Classic"
    assert screen.logging_checkbox.value is True


def test_screen_initial_render_repairs_invalid_dropdown_settings(hermetic_cfg):
    pytest.importorskip("flet")
    import app_config

    def seed(cfg):
        cfg["settings"] = {
            "argon2_memory": 1,
            "argon2_time": 0,
            "argon2_par": 999,
            "wipe_passes": 0,
            "versioning_enabled": False,
            "versioning_max_per_vault": 999,
            "versioning_max_total_mb": "bad",
        }

    app_config._mutate_cfg(seed)
    screen, _page, _shell = _make_screen()
    screen.build()

    assert screen.kdf_memory_dropdown.value == "65536"
    assert screen.kdf_time_dropdown.value == "3"
    assert screen.kdf_par_dropdown.value == "4"
    assert screen.wipe_dropdown.value == "1"
    assert screen.version_count_dropdown.value == "5"
    assert screen.version_size_dropdown.value == "2048"


def test_screen_disabling_versioning_with_stale_invalid_values_does_not_crash(hermetic_cfg):
    pytest.importorskip("flet")
    services = FakeServices()
    screen, _page, shell = _make_screen(services=services)
    screen.build()

    screen.versioning_checkbox.value = False
    screen.version_count_dropdown.value = "999"
    screen.version_size_dropdown.value = None
    screen._save_versioning()

    assert shell.status_text.value == "Versioning disabled"
    assert screen.version_count_dropdown.value == "5"
    assert screen.version_size_dropdown.value == "2048"
    assert services.versioner_builds == 1


def test_screen_versioning_save_button_persists_path_and_choices(hermetic_cfg):
    pytest.importorskip("flet")
    services = FakeServices()
    screen, _page, shell = _make_screen(services=services)
    screen.build()

    screen.versioning_checkbox.value = True
    screen.version_count_dropdown.value = "10"
    screen.version_size_dropdown.value = "4096"
    screen.version_dir_field.value = "  C:/VaultVersions  "
    screen.save_versioning_button.on_click(None)

    saved = json.loads(hermetic_cfg.read_text("utf-8"))["settings"]
    assert saved["versioning_enabled"] is True
    assert saved["versioning_max_per_vault"] == 10
    assert saved["versioning_max_total_mb"] == 4096
    assert saved["versioning_dir"] == "C:/VaultVersions"
    assert shell.status_text.value == "Versioning enabled"


# ===================================================== 11. screen KDF guard
def test_screen_kdf_in_progress_sets_status(hermetic_cfg):
    pytest.importorskip("flet")
    services = FakeServices(is_processing=True)
    screen, _page, shell = _make_screen(services=services)
    screen.build()

    screen.kdf_memory_dropdown.value = "131072"
    screen.kdf_time_dropdown.value = "4"
    screen.kdf_par_dropdown.value = "2"
    screen._save_kdf()

    assert "in progress" in shell.status_text.value
    assert services.crypto_rebuilds == 0


def test_screen_kdf_save_succeeds_when_idle(hermetic_cfg):
    pytest.importorskip("flet")
    services = FakeServices()
    screen, _page, shell = _make_screen(services=services)
    screen.build()

    screen.kdf_memory_dropdown.value = "262144"
    screen.kdf_time_dropdown.value = "5"
    screen.kdf_par_dropdown.value = "4"
    screen._save_kdf()

    assert services.crypto_rebuilds == 1
    assert shell.status_text.value == "Crypto engine reloaded with new KDF parameters"


# ===================================================== 12. clear confirmation
def test_screen_clear_traces_requires_confirmation(hermetic_cfg, hermetic_cache):
    pytest.importorskip("flet")
    services = FakeServices()
    screen, page, shell = _make_screen(services=services)
    screen.build()

    # Opening the dialog must NOT clear anything.
    screen._confirm_clear_traces()
    assert len(page.dialogs) == 1
    assert services.activity_logger.clear_count == 0

    # Confirming clears + closes the dialog + sets status.
    screen._clear_traces_confirmed()
    assert services.activity_logger.clear_count == 1
    assert page.dialogs == []
    assert shell.status_text.value == "All local traces cleared"


# ===================================================== 13. health dialog
def test_screen_health_check_shows_dialog(hermetic_cfg, monkeypatch):
    pytest.importorskip("flet")
    monkeypatch.setattr(SettingsController, "_detect_ssd", lambda self: True)
    screen, page, _shell = _make_screen()
    screen.build()

    screen._run_health_check()
    assert len(page.dialogs) == 1
    texts = _collect_texts(page.dialogs[0])
    assert any("SECURITY HEALTH CHECK RESULTS" in t for t in texts)

    screen._close_dialog()
    assert page.dialogs == []


# ===================================================== 14. shell mounting
def test_shell_mounts_settings_and_reuses_instance():
    pytest.importorskip("flet")
    from ui_flet.shell import AppShell

    page = FakePage()
    shell = AppShell(page, _shell_services())
    assert shell.settings_screen is None

    control = shell._placeholder("settings")
    assert control is not None
    first = shell.settings_screen
    assert first is not None

    shell._placeholder("settings")
    assert shell.settings_screen is first  # reused


# ===================================================== 15. source boundaries
def test_screen_source_avoids_old_ui_and_overlay():
    src = (ROOT / "ui_flet" / "screens" / "settings_screen.py").read_text(encoding="utf-8")
    assert "messagebox" not in src
    assert "tkinter" not in src
    assert "customtkinter" not in src
    assert "views.settings_view" not in src
    assert "page.overlay" not in src
    assert ".overlay" not in src
