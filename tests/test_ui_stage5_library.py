"""Stage 5 (Vault Library) tests.

The LibraryController is FLET-FREE and the Library is non-sensitive (no password,
no decrypt, no inspect). Controller scans are exercised with a fake scanner and
with the real VaultScanner (proving it reports only the on-disk .vault name and
locked placeholders, never unlocked metadata). Screen/dispatcher behavior is
tested with fake services, no display required.
"""
import json
import queue
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def fast_services(tmp_path, monkeypatch):
    import app_config, activity_log, vault_scanner, versioning

    cfg = tmp_path / "cfg.json"
    cfg.write_text(json.dumps({"settings": {
        "argon2_memory": 8192,
        "argon2_time": 1,
        "argon2_par": 1,
        "wipe_passes": 1,
    }}), encoding="utf-8")
    monkeypatch.setattr(app_config, "CONFIG_FILE", cfg)
    monkeypatch.setattr(activity_log, "DB_PATH", tmp_path / "activity.db")
    monkeypatch.setattr(vault_scanner, "CACHE_FILE", tmp_path / "lib.json")
    monkeypatch.setattr(versioning, "VERSIONS_ROOT_DEFAULT", tmp_path / "versions", raising=False)
    from ui_flet.services import AppServices

    return AppServices()


@pytest.fixture
def hermetic_cfg(tmp_path, monkeypatch):
    import app_config

    cfg = tmp_path / "cfg.json"
    cfg.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(app_config, "CONFIG_FILE", cfg)
    return cfg


def _drain(q):
    out = []
    while not q.empty():
        out.append(q.get_nowait())
    return out


def _make_vault(services, tmp_path, password="PwStage5!", name="secret.txt"):
    src = tmp_path / name
    src.write_bytes(b"stage 5 library payload " * 200)
    manifest = services.packager.get_manifest(src)
    temp_zip = services.packager.package_files([src], compress=True)
    vault_dir = tmp_path / "vaults"
    vault_dir.mkdir(exist_ok=True)
    vault = vault_dir / f"{name}.vault"
    try:
        services.crypto.encrypt_file(
            temp_zip,
            vault,
            password,
            original_filename=src.name,
            metadata=manifest,
            recovery_key=None,
            target_container_mb=0,
        )
    finally:
        try:
            if temp_zip.exists():
                services.wiper.wipe_file(temp_zip)
        except Exception:
            pass
    return vault, src.name


class _FakeScanner:
    def __init__(self, results, exc=None):
        self.results = results
        self.exc = exc
        self.received = None

    def scan_directories(self, dirs):
        self.received = list(dirs)
        if self.exc:
            raise self.exc
        return self.results


def _fake_services():
    return SimpleNamespace(
        is_processing=False,
        cancel_requested=False,
        scanner=_FakeScanner([]),
        msg_queue=queue.Queue(),
        activity_logger=None,
    )


# --------------------------------------------------------------- controller
def test_library_controller_adds_and_removes_dirs_via_config(hermetic_cfg, tmp_path):
    from ui_flet.controllers.library_controller import LibraryController

    assert LibraryController.add_dir(tmp_path) is True
    assert LibraryController.add_dir(tmp_path) is False  # duplicate
    assert str(tmp_path.resolve()) in LibraryController.load_dirs()

    assert LibraryController.remove_dir(tmp_path) is True
    assert str(tmp_path.resolve()) not in LibraryController.load_dirs()
    assert tmp_path.exists()  # config-only removal never deletes the directory


def test_library_controller_removes_legacy_slash_paths(hermetic_cfg, tmp_path):
    from ui_flet.controllers.library_controller import LibraryController

    watched = tmp_path / "watched"
    watched.mkdir()
    legacy_value = str(watched.resolve()).replace("\\", "/")
    hermetic_cfg.write_text(json.dumps({"library_dirs": [legacy_value]}), encoding="utf-8")

    assert LibraryController.remove_dir(watched) is True
    assert LibraryController.load_dirs() == []
    assert watched.exists()


def test_library_controller_add_dedupes_legacy_slash_paths(hermetic_cfg, tmp_path):
    from ui_flet.controllers.library_controller import LibraryController

    watched = tmp_path / "watched"
    watched.mkdir()
    legacy_value = str(watched.resolve()).replace("\\", "/")
    hermetic_cfg.write_text(json.dumps({"library_dirs": [legacy_value]}), encoding="utf-8")

    assert LibraryController.add_dir(watched) is False
    assert LibraryController.load_dirs() == [legacy_value]


def test_library_controller_scan_posts_results_with_fake_scanner(tmp_path):
    from ui_flet.controllers.library_controller import LibraryController

    scanner = _FakeScanner([{"path": "x", "filename": "x.vault"}])
    services = SimpleNamespace(scanner=scanner, msg_queue=queue.Queue(), activity_logger=None)

    LibraryController(services)._scan_worker([str(tmp_path)])

    msgs = _drain(services.msg_queue)
    results = [m for m in msgs if m["type"] == "library_results"]
    assert results and results[0]["error"] == "" and results[0]["data"]
    assert scanner.received == [str(Path(tmp_path).resolve())]


def test_library_controller_scan_error_posts_library_results_error(tmp_path):
    from ui_flet.controllers.library_controller import LibraryController

    scanner = _FakeScanner([], exc=RuntimeError("boom"))
    services = SimpleNamespace(scanner=scanner, msg_queue=queue.Queue(), activity_logger=None)

    LibraryController(services)._scan_worker([str(tmp_path)])

    msgs = _drain(services.msg_queue)
    results = [m for m in msgs if m["type"] == "library_results"]
    assert results and results[0]["data"] == []
    assert "Scan failed" in results[0]["error"]


def test_real_scanner_finds_vault_without_sensitive_metadata(fast_services, tmp_path):
    from ui_flet.controllers.library_controller import LibraryController

    vault, original_name = _make_vault(fast_services, tmp_path, name="secret.txt")
    # Rename to an opaque on-disk name so the scan can't possibly echo the
    # plaintext filename unless it (wrongly) unlocked the sealed metadata.
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    opaque = scan_dir / "opaque_box.vault"
    vault.rename(opaque)

    LibraryController(fast_services)._scan_worker([str(scan_dir)])

    msgs = _drain(fast_services.msg_queue)
    results = [m for m in msgs if m["type"] == "library_results"]
    assert results and results[0]["error"] == ""
    data = results[0]["data"]
    assert len(data) == 1
    entry = data[0]
    assert entry["path"] == str(opaque.resolve())
    assert entry["filename"] == opaque.name
    assert entry["source_type"] == "Encrypted Metadata"
    assert entry["created_at"] == "Requires Password"
    assert entry["encrypted_size"] == opaque.stat().st_size
    assert "container_size" in entry
    # The scanner must NOT unlock the true plaintext filename.
    assert original_name not in entry["filename"]
    assert entry["filename"] != original_name


def test_library_controller_is_flet_free_and_scan_only():
    root = Path(__file__).resolve().parents[1]
    src = (root / "ui_flet" / "controllers" / "library_controller.py").read_text(encoding="utf-8")
    assert "import flet" not in src and "from flet" not in src
    assert "decrypt_file(" not in src
    assert "verify_password_and_get_header" not in src
    assert ".inspector.inspect(" not in src and "VaultInspector" not in src
    assert ".scanner.scan_directories(" in src


def test_event_dispatcher_routes_library_results():
    from ui_flet.events import EventDispatcher

    calls = []

    class FakeSink:
        def on_library_results(self, msg):
            calls.append(msg)

    EventDispatcher(FakeSink()).dispatch({"type": "library_results", "data": []})
    assert calls and calls[0]["data"] == []


# ------------------------------------------------------------------- screen
class _FakePage:
    def __init__(self):
        self.services = []
        self.overlay = []
        self.update_calls = 0
        self.web = False

    def update(self):
        self.update_calls += 1

    def run_task(self, *args, **kwargs):
        return None


class _FakeShell:
    def __init__(self, page):
        self.page = page
        self.status_text = SimpleNamespace(value="")
        self.progress_bar = SimpleNamespace(value=0)
        self.progress_pct = SimpleNamespace(value="0%")
        self.busy_control = None

    def set_busy(self, control):
        self.busy_control = control
        control.disabled = True

    def safe_update(self):
        self.page.update()
        return True


def _rendered_dir_values(screen):
    values = []
    for row in screen.dir_list.controls:
        content = getattr(row, "content", None)
        controls = getattr(content, "controls", [])
        if controls and hasattr(controls[0], "value"):
            values.append(controls[0].value)
    return values


def _shell_services():
    return SimpleNamespace(
        shutdown_requested=False,
        cancel_requested=False,
        is_processing=False,
        msg_queue=queue.Queue(),
        scanner=_FakeScanner([]),
        activity_logger=None,
        stats=SimpleNamespace(snapshot=lambda: {
            "encrypted": 0, "decrypted": 0, "rekeyed": 0, "uptime": "0s"
        }),
    )


def test_library_file_picker_is_registered_as_service_not_visual_control(hermetic_cfg):
    ft = pytest.importorskip("flet")
    from ui_flet.screens.library_screen import LibraryScreen

    page = _FakePage()
    screen = LibraryScreen(page, _fake_services(), _FakeShell(page))
    screen.build()
    screen.build()

    assert page.overlay == []
    assert page.services == [screen.directory_picker]
    assert all(isinstance(item, ft.FilePicker) for item in page.services)


def test_library_directory_list_is_scrollable(hermetic_cfg):
    ft = pytest.importorskip("flet")
    from ui_flet.screens.library_screen import LibraryScreen

    page = _FakePage()
    screen = LibraryScreen(page, _fake_services(), _FakeShell(page))
    screen.build()

    assert screen.dir_list.scroll == ft.ScrollMode.AUTO


def test_library_screen_source_does_not_use_overlay():
    root = Path(__file__).resolve().parents[1]
    src = (root / "ui_flet" / "screens" / "library_screen.py").read_text(encoding="utf-8")
    assert "page.overlay" not in src
    assert ".overlay" not in src


def test_shell_mounts_library_screen_on_navigate(hermetic_cfg):
    pytest.importorskip("flet")
    from ui_flet.shell import AppShell

    page = _FakePage()
    shell = AppShell(page, _shell_services())
    assert shell.library_screen is None

    shell.navigate("library")

    assert shell.library_screen is not None
    assert page.overlay == []
    assert any(item is shell.library_screen.directory_picker for item in page.services)


def test_library_screen_filters_results(hermetic_cfg, tmp_path):
    pytest.importorskip("flet")
    from ui_flet.screens.library_screen import LibraryScreen
    from ui_flet.controllers.library_controller import LibraryController

    page = _FakePage()
    screen = LibraryScreen(page, _fake_services(), _FakeShell(page))
    screen.build()
    LibraryController.add_dir(tmp_path)  # so the library_dirs render gate passes

    screen.last_results = [
        {"filename": "alpha.vault", "path": str(tmp_path / "alpha.vault"),
         "source_type": "Encrypted Metadata", "container_size": 1048576,
         "encrypted_size": 1100000, "created_at": "Requires Password"},
        {"filename": "beta.vault", "path": str(tmp_path / "beta.vault"),
         "source_type": "Encrypted Metadata", "container_size": 2097152,
         "encrypted_size": 2200000, "created_at": "Requires Password"},
    ]
    screen.search_field.value = "alpha"

    assert [r["filename"] for r in screen._filtered_results()] == ["alpha.vault"]
    screen._render_results()
    assert len(screen.results_list.controls) == 1


def test_library_remove_dir_does_not_delete_directory(hermetic_cfg, tmp_path):
    from ui_flet.controllers.library_controller import LibraryController

    watched = tmp_path / "watched"
    watched.mkdir()
    marker = watched / "marker.txt"
    marker.write_text("keep me", encoding="utf-8")

    assert LibraryController.add_dir(watched) is True
    assert LibraryController.remove_dir(watched) is True

    assert LibraryController.load_dirs() == []
    assert watched.exists()
    assert marker.exists()


def test_library_remove_dir_updates_screen_while_scan_is_busy(hermetic_cfg, tmp_path):
    pytest.importorskip("flet")
    from ui_flet.screens.library_screen import LibraryScreen
    from ui_flet.controllers.library_controller import LibraryController

    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    assert LibraryController.add_dir(first) is True
    assert LibraryController.add_dir(second) is True

    page = _FakePage()
    services = _fake_services()
    services.is_processing = True
    shell = _FakeShell(page)
    screen = LibraryScreen(page, services, shell)
    screen.build()
    update_calls_before = page.update_calls
    busy_before = shell.busy_control

    screen._remove_dir(str(first))

    dirs = LibraryController.load_dirs()
    assert str(first.resolve()) not in dirs
    assert str(second.resolve()) in dirs
    assert first.exists()
    assert second.exists()
    assert page.update_calls > update_calls_before
    assert _rendered_dir_values(screen) == [str(second.resolve())]
    assert services.is_processing is True
    assert shell.busy_control is busy_before
    assert shell.status_text.value == "Directory removed"
    assert shell.status_text.value != "Scanning directories..."


def test_library_remove_dir_does_not_start_scan_when_idle(hermetic_cfg, tmp_path):
    pytest.importorskip("flet")
    from ui_flet.screens.library_screen import LibraryScreen
    from ui_flet.controllers.library_controller import LibraryController

    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    assert LibraryController.add_dir(first) is True
    assert LibraryController.add_dir(second) is True

    page = _FakePage()
    services = _fake_services()
    shell = _FakeShell(page)
    screen = LibraryScreen(page, services, shell)
    screen._auto_scan_started = True
    screen.build()
    update_calls_before = page.update_calls

    screen._remove_dir(str(first))

    dirs = LibraryController.load_dirs()
    assert str(first.resolve()) not in dirs
    assert str(second.resolve()) in dirs
    assert _rendered_dir_values(screen) == [str(second.resolve())]
    assert page.update_calls > update_calls_before
    assert services.is_processing is False
    assert services.scanner.received is None
    assert shell.busy_control is None
    assert shell.status_text.value == "Directory removed"


def test_library_stale_scan_results_ignore_removed_directory(hermetic_cfg, tmp_path):
    pytest.importorskip("flet")
    from ui_flet.screens.library_screen import LibraryScreen
    from ui_flet.controllers.library_controller import LibraryController

    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    assert LibraryController.add_dir(first) is True
    assert LibraryController.add_dir(second) is True

    page = _FakePage()
    services = _fake_services()
    services.is_processing = True
    screen = LibraryScreen(page, services, _FakeShell(page))
    screen.build()

    removed_vault = first / "removed.vault"
    kept_vault = second / "kept.vault"
    screen._remove_dir(str(first))
    screen.on_library_results({"data": [
        {"filename": "removed.vault", "path": str(removed_vault),
         "source_type": "Encrypted Metadata", "container_size": 1,
         "encrypted_size": 1, "created_at": "Requires Password"},
        {"filename": "kept.vault", "path": str(kept_vault),
         "source_type": "Encrypted Metadata", "container_size": 1,
         "encrypted_size": 1, "created_at": "Requires Password"},
    ], "error": ""})

    assert [r["filename"] for r in screen.last_results] == ["kept.vault"]
    assert len(screen.results_list.controls) == 1
    assert "Found 1 vaults" in screen.shell.status_text.value


def test_library_remove_last_dir_clears_results_and_updates(hermetic_cfg, tmp_path):
    pytest.importorskip("flet")
    from ui_flet.screens.library_screen import LibraryScreen
    from ui_flet.controllers.library_controller import LibraryController

    watched = tmp_path / "watched"
    watched.mkdir()
    assert LibraryController.add_dir(watched) is True

    page = _FakePage()
    services = _fake_services()
    services.is_processing = True
    screen = LibraryScreen(page, services, _FakeShell(page))
    screen.build()
    screen.last_results = [
        {"filename": "old.vault", "path": str(watched / "old.vault")}
    ]
    update_calls_before = page.update_calls

    screen._remove_dir(str(watched))

    assert LibraryController.load_dirs() == []
    assert screen.last_results == []
    assert page.update_calls > update_calls_before
    assert len(screen.results_list.controls) == 1
    assert screen.results_list.controls[0].value == (
        "No directories monitored. Add a directory to start."
    )
    assert screen.shell.status_text.value == "No directories monitored"
    assert watched.exists()


def test_library_screen_on_results_renders_rows(hermetic_cfg, tmp_path):
    pytest.importorskip("flet")
    from ui_flet.screens.library_screen import LibraryScreen
    from ui_flet.controllers.library_controller import LibraryController

    page = _FakePage()
    services = _fake_services()
    screen = LibraryScreen(page, services, _FakeShell(page))
    screen.build()
    LibraryController.add_dir(tmp_path)

    screen.on_library_results({"data": [
        {"filename": "one.vault", "path": str(tmp_path / "one.vault"),
         "source_type": "Encrypted Metadata", "container_size": 1048576,
         "encrypted_size": 1100000, "created_at": "Requires Password"},
    ], "error": ""})

    assert len(screen.results_list.controls) == 1
    assert services.is_processing is False
    assert "Found 1 vaults" in screen.shell.status_text.value
