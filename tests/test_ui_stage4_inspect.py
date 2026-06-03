"""Stage 4 (Vault Info / Inspect core) tests.

The InspectController is FLET-FREE, so it is exercised headlessly with real
vaults using a fast (hermetic) KDF config, mirroring the Stage 3 style. Behavioral
intent: inspect metadata by password and by recovery phrase (header-only, never a
payload decrypt), wrong-password auth_error with the limiter, integrity SHA-256 +
fingerprint save, verify-vs-saved unchanged/mismatch, structure rejection of
non-vault files, the controller stays Flet-free and never decrypts payload, the
dispatcher routes the new result types, and the screen keeps FilePicker on
page.services.
"""
import hashlib
import json
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


def _drain(q):
    out = []
    while not q.empty():
        out.append(q.get_nowait())
    return out


def _make_vault(services, tmp_path, password="PwStage4!", name="secret.txt", recovery_key=None):
    src = tmp_path / name
    src.write_bytes(b"stage 4 inspect payload " * 200)
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
            recovery_key=recovery_key,
            target_container_mb=0,
        )
    finally:
        try:
            if temp_zip.exists():
                services.wiper.wipe_file(temp_zip)
        except Exception:
            pass
    return vault, src.name


def test_inspect_controller_reads_metadata_by_password(fast_services, tmp_path):
    from ui_flet.controllers.inspect_controller import InspectController

    vault, filename = _make_vault(fast_services, tmp_path)
    InspectController(fast_services)._inspect_worker(vault, "PwStage4!", None)

    msgs = _drain(fast_services.msg_queue)
    results = [m for m in msgs if m["type"] == "inspect_result"]
    assert results and results[0]["error"] == ""
    md = results[0]["metadata"]
    assert md["filename"] == filename
    assert md["original_size"] > 0
    assert md.get("kdf_algorithm") and md.get("encryption")
    # Successful inspect resets the limiter to full attempts.
    from app_state import MAX_ATTEMPTS
    assert fast_services.limiter.attempts_remaining() == MAX_ATTEMPTS


def test_inspect_controller_reads_metadata_by_recovery_phrase(fast_services, tmp_path):
    from crypto_core import generate_recovery_entropy, entropy_to_mnemonic, mnemonic_to_entropy
    from ui_flet.controllers.inspect_controller import InspectController

    recovery_entropy = generate_recovery_entropy()
    phrase = entropy_to_mnemonic(recovery_entropy)
    recovery_key = mnemonic_to_entropy(phrase)
    vault, filename = _make_vault(
        fast_services, tmp_path, password="MainPassword1!", recovery_key=recovery_key
    )

    InspectController(fast_services)._inspect_worker(vault, None, recovery_key)

    msgs = _drain(fast_services.msg_queue)
    results = [m for m in msgs if m["type"] == "inspect_result"]
    assert results and results[0]["error"] == ""
    assert results[0]["metadata"]["filename"] == filename


def test_inspect_wrong_password_posts_auth_error(fast_services, tmp_path):
    from app_state import MAX_ATTEMPTS
    from ui_flet.controllers.inspect_controller import InspectController

    vault, _filename = _make_vault(fast_services, tmp_path, password="RightPw1!")
    InspectController(fast_services)._inspect_worker(vault, "WrongPw1!", None)

    expected_remaining = MAX_ATTEMPTS - 1
    msgs = _drain(fast_services.msg_queue)
    assert any(
        m["type"] == "auth_error" and m["remaining"] == expected_remaining for m in msgs
    )
    results = [m for m in msgs if m["type"] == "inspect_result"]
    assert results and results[0]["error"]
    assert fast_services.limiter.attempts_remaining() == expected_remaining


def test_integrity_check_hashes_and_saves_fingerprint(fast_services, tmp_path):
    from ui_flet.controllers.inspect_controller import InspectController

    vault, _filename = _make_vault(fast_services, tmp_path)
    expected = hashlib.sha256(vault.read_bytes()).hexdigest()

    InspectController(fast_services)._integrity_worker(vault)

    msgs = _drain(fast_services.msg_queue)
    results = [m for m in msgs if m["type"] == "integrity_result"]
    assert results and results[0]["ok"] is True
    assert results[0]["sha"] == expected

    fps = InspectController.load_fingerprints()
    assert fps[str(vault.resolve())]["sha256"] == expected


def test_verify_saved_reports_unchanged_then_mismatch(fast_services, tmp_path):
    from ui_flet.controllers.inspect_controller import InspectController

    vault, _filename = _make_vault(fast_services, tmp_path)
    ctrl = InspectController(fast_services)

    ctrl._integrity_worker(vault)
    _drain(fast_services.msg_queue)

    ctrl._verify_worker(vault)
    msgs = _drain(fast_services.msg_queue)
    verify = [m for m in msgs if m["type"] == "verify_result"]
    assert verify and verify[0]["status"] == "unchanged"

    with open(vault, "ab") as f:
        f.write(b"\x00")

    ctrl._verify_worker(vault)
    msgs = _drain(fast_services.msg_queue)
    verify = [m for m in msgs if m["type"] == "verify_result"]
    assert verify and verify[0]["status"] == "mismatch"
    assert verify[0]["current_sha"] != verify[0]["saved_sha"]


def test_integrity_rejects_non_vault_magic(tmp_path):
    from ui_flet.controllers.inspect_controller import InspectController

    fake = tmp_path / "fake.bin"
    fake.write_bytes(b"NOTRPMV_" + b"0" * 60)

    ok, msg, sha = InspectController._check_vault_integrity(fake)
    assert ok is False
    assert sha == ""
    assert msg


def test_inspect_controller_is_flet_free_and_keeps_inspect_header_only():
    root = Path(__file__).resolve().parents[1]
    src = (root / "ui_flet" / "controllers" / "inspect_controller.py").read_text(encoding="utf-8")
    assert "import flet" not in src and "from flet" not in src
    assert "services.inspector.inspect" in src or ".inspector.inspect(" in src
    inspect_body = src.split("def _inspect_worker", 1)[1].split("def _integrity_worker", 1)[0]
    assert "decrypt_file(" not in inspect_body


def test_event_dispatcher_routes_stage4_results():
    from ui_flet.events import EventDispatcher

    calls = []

    class FakeSink:
        def on_inspect_result(self, msg):
            calls.append(("inspect", msg))

        def on_integrity_result(self, msg):
            calls.append(("integrity", msg))

        def on_verify_result(self, msg):
            calls.append(("verify", msg))

    dispatcher = EventDispatcher(FakeSink())
    dispatcher.dispatch({"type": "inspect_result", "path": "a"})
    dispatcher.dispatch({"type": "integrity_result", "path": "b"})
    dispatcher.dispatch({"type": "verify_result", "path": "c"})

    assert [c[0] for c in calls] == ["inspect", "integrity", "verify"]
    assert calls[0][1]["path"] == "a"


# --- screen runtime guards (mirror the Stage-2/3 FilePicker-as-service rule) ---
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

    def set_busy(self, control):
        control.disabled = True

    def safe_update(self):
        self.page.update()
        return True


def _shell_services():
    return SimpleNamespace(
        shutdown_requested=False,
        cancel_requested=False,
        is_processing=False,
        msg_queue=SimpleNamespace(get_nowait=lambda: None),
        stats=SimpleNamespace(snapshot=lambda: {
            "encrypted": 0, "decrypted": 0, "rekeyed": 0, "uptime": "0s"
        }),
    )


def test_inspect_file_picker_is_registered_as_service_not_visual_control():
    ft = pytest.importorskip("flet")
    from ui_flet.screens.inspect_screen import InspectScreen

    page = _FakePage()
    services = SimpleNamespace(is_processing=False, cancel_requested=False)
    screen = InspectScreen(page, services, _FakeShell(page))
    screen.build()
    screen.build()

    assert page.overlay == []
    assert page.services[:4] == [
        screen.vault_picker,
        screen.selective_output_picker,
        screen.diff_vault_a_picker,
        screen.diff_vault_b_picker,
    ]
    assert all(isinstance(item, ft.FilePicker) for item in page.services[:4])
    assert isinstance(page.services[4], ft.Clipboard)


def test_inspect_screen_source_does_not_use_overlay():
    root = Path(__file__).resolve().parents[1]
    src = (root / "ui_flet" / "screens" / "inspect_screen.py").read_text(encoding="utf-8")
    assert "page.overlay" not in src
    assert ".overlay" not in src


def test_shell_mounts_inspect_screen_on_navigate():
    pytest.importorskip("flet")
    from ui_flet.shell import AppShell

    page = _FakePage()
    shell = AppShell(page, _shell_services())
    assert shell.inspect_screen is None

    shell.navigate("inspect")

    assert shell.inspect_screen is not None
    assert page.overlay == []
    assert any(item is shell.inspect_screen.vault_picker for item in page.services)
    assert any(item is shell.inspect_screen.clipboard for item in page.services)


def test_inspect_screen_recovery_toggle_swaps_fields():
    pytest.importorskip("flet")
    from ui_flet.screens.inspect_screen import InspectScreen

    page = _FakePage()
    services = SimpleNamespace(is_processing=False, cancel_requested=False)
    screen = InspectScreen(page, services, _FakeShell(page))
    screen.build()

    assert screen.password_field.visible is True
    assert screen.recovery_field.visible is False

    screen.use_recovery_checkbox.value = True
    screen._toggle_recovery()
    assert screen.password_field.visible is False
    assert screen.recovery_field.visible is True
