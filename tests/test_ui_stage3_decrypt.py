"""Stage 3 (Decrypt screen) controller tests.

The DecryptController is FLET-FREE, so it is exercised headlessly with real
crypto round-trips using a fast (hermetic) KDF config, mirroring the Stage 2
test style. Behavioral intent: a real vault decrypts by password, a real vault
decrypts by recovery phrase, auth_error is posted on wrong password, the extract
directory collision is numbered, partial plaintext is wiped on failure, the
controller stays Flet-free, and no pre-verify KDF path is introduced.
"""
import json
from pathlib import Path

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


def _make_vault(services, tmp_path, password="PwStage3!", name="secret.txt", recovery_key=None):
    src = tmp_path / name
    src.write_bytes(b"stage 3 decrypt payload " * 200)
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
    return vault, src.read_bytes(), src.name


def test_decrypt_controller_round_trips_by_password(fast_services, tmp_path):
    from ui_flet.controllers.decrypt_controller import DecryptController

    vault, payload, filename = _make_vault(fast_services, tmp_path)
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    DecryptController(fast_services)._worker([str(vault)], "PwStage3!", out_dir, None)

    msgs = _drain(fast_services.msg_queue)
    assert any(m["type"] == "batch_done" and "1/1" in m.get("text", "") for m in msgs)
    restored = out_dir / Path(filename).stem / filename
    assert restored.read_bytes() == payload


def test_decrypt_controller_round_trips_by_recovery_phrase(fast_services, tmp_path):
    from crypto_core import generate_recovery_entropy, entropy_to_mnemonic, mnemonic_to_entropy
    from ui_flet.controllers.decrypt_controller import DecryptController

    recovery_entropy = generate_recovery_entropy()
    phrase = entropy_to_mnemonic(recovery_entropy)
    recovery_key = mnemonic_to_entropy(phrase)
    vault, payload, filename = _make_vault(
        fast_services, tmp_path, password="MainPassword1!", recovery_key=recovery_key
    )
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    DecryptController(fast_services)._worker([str(vault)], None, out_dir, recovery_key)

    restored = out_dir / Path(filename).stem / filename
    assert restored.read_bytes() == payload


def test_decrypt_wrong_password_posts_auth_error(fast_services, tmp_path):
    from app_state import MAX_ATTEMPTS
    from ui_flet.controllers.decrypt_controller import DecryptController

    vault, _payload, _filename = _make_vault(fast_services, tmp_path, password="RightPw1!")
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    DecryptController(fast_services)._worker([str(vault)], "WrongPw1!", out_dir, None)

    # The local backend uses MAX_ATTEMPTS=5, so one failure leaves MAX_ATTEMPTS-1
    # remaining (the spec example assumed 3). Derive it so the assertion tracks
    # the real constant rather than a hard-coded value.
    expected_remaining = MAX_ATTEMPTS - 1
    msgs = _drain(fast_services.msg_queue)
    assert any(
        m["type"] == "auth_error" and m["remaining"] == expected_remaining for m in msgs
    )
    assert any(m["type"] == "batch_done" and "Wrong password" in m.get("text", "") for m in msgs)
    assert fast_services.limiter.attempts_remaining() == expected_remaining


def test_decrypt_output_collision_creates_numbered_extract_dir(fast_services, tmp_path):
    from ui_flet.controllers.decrypt_controller import DecryptController

    vault, payload, filename = _make_vault(fast_services, tmp_path, name="dup.txt")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    existing = out_dir / "dup"
    existing.mkdir()
    (existing / "marker.txt").write_text("existing", encoding="utf-8")

    DecryptController(fast_services)._worker([str(vault)], "PwStage3!", out_dir, None)

    restored = out_dir / "dup_1" / filename
    assert restored.read_bytes() == payload


def test_decrypt_generic_failure_wipes_partial_extract_dir(fast_services, tmp_path, monkeypatch):
    from ui_flet.controllers.decrypt_controller import DecryptController

    vault, _payload, _filename = _make_vault(fast_services, tmp_path, name="partial.txt")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    wiped = []

    def fake_extract(_archive, extract_dir, **_kwargs):
        extract_dir.mkdir(parents=True, exist_ok=True)
        (extract_dir / "partial.txt").write_bytes(b"partial plaintext")
        raise RuntimeError("forced extract failure")

    monkeypatch.setattr(fast_services.packager, "extract_archive", fake_extract)
    monkeypatch.setattr(fast_services.wiper, "wipe_folder", lambda p: wiped.append(Path(p)))

    DecryptController(fast_services)._worker([str(vault)], "PwStage3!", out_dir, None)

    assert wiped
    assert wiped[0].name == "partial"


def test_decrypt_controller_is_flet_free_and_single_kdf_path():
    root = Path(__file__).resolve().parents[1]
    src = (root / "ui_flet" / "controllers" / "decrypt_controller.py").read_text(encoding="utf-8")
    assert "import flet" not in src and "from flet" not in src
    assert "verify_password_and_get_header" not in src
    assert ".decrypt_file(" in src


def test_decrypt_controller_keeps_collision_loop_and_partial_wipe():
    root = Path(__file__).resolve().parents[1]
    src = (root / "ui_flet" / "controllers" / "decrypt_controller.py").read_text(encoding="utf-8")
    assert "while extract_dir.exists()" in src
    assert "wipe_folder(extract_dir)" in src or "_wipe_extract_dir(extract_dir)" in src


# --- Screen runtime guards: the Stage-2 "Unknown control: FilePicker" bug was
# caused by registering pickers on page.overlay. Mirror the Stage-2 runtime-fix
# tests so the Decrypt screen keeps FilePicker on page.services. ---
from types import SimpleNamespace


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


def _stats_snapshot():
    return {"encrypted": 0, "decrypted": 0, "rekeyed": 0, "uptime": "0s"}


def _shell_services():
    return SimpleNamespace(
        shutdown_requested=False,
        cancel_requested=False,
        is_processing=False,
        msg_queue=SimpleNamespace(get_nowait=lambda: None),
        stats=SimpleNamespace(snapshot=_stats_snapshot),
    )


def test_decrypt_file_pickers_are_registered_as_services_not_overlay():
    ft = pytest.importorskip("flet")
    from ui_flet.screens.decrypt_screen import DecryptScreen

    page = _FakePage()
    services = SimpleNamespace(is_processing=False, cancel_requested=False)
    shell = _FakeShell(page)

    screen = DecryptScreen(page, services, shell)
    screen.build()
    screen.build()  # idempotent across re-builds (navigation revisits)

    assert page.overlay == []
    assert len(page.services) == 2
    assert all(isinstance(item, ft.FilePicker) for item in page.services)
    assert page.services == [screen.vault_picker, screen.output_picker]


def test_decrypt_screen_no_longer_uses_page_overlay_for_file_picker():
    root = Path(__file__).resolve().parents[1]
    src = (root / "ui_flet" / "screens" / "decrypt_screen.py").read_text(encoding="utf-8")
    assert "page.overlay" not in src
    assert ".overlay" not in src
    assert "page.services" in src or ".services" in src


def test_decrypt_screen_recovery_toggle_swaps_password_and_phrase_fields():
    pytest.importorskip("flet")
    from ui_flet.screens.decrypt_screen import DecryptScreen

    page = _FakePage()
    services = SimpleNamespace(is_processing=False, cancel_requested=False)
    screen = DecryptScreen(page, services, _FakeShell(page))
    screen.build()

    # Default: password visible, phrase hidden.
    assert screen.password_field.visible is True
    assert screen.recovery_field.visible is False

    screen.use_recovery_checkbox.value = True
    screen._toggle_recovery()
    assert screen.password_field.visible is False
    assert screen.recovery_field.visible is True


def test_decrypt_screen_only_accepts_vault_paths():
    pytest.importorskip("flet")
    from ui_flet.screens.decrypt_screen import DecryptScreen

    page = _FakePage()
    services = SimpleNamespace(is_processing=False, cancel_requested=False)
    screen = DecryptScreen(page, services, _FakeShell(page))

    assert screen._append_source("C:/data/notes.txt") == "invalid"
    assert screen._append_source("C:/data/secret.txt.vault") == "added"
    assert screen._append_source("C:/data/secret.txt.vault") == "dup"
    assert screen.paths == [str(Path("C:/data/secret.txt.vault"))]


def test_shell_mounts_decrypt_screen_on_navigate():
    pytest.importorskip("flet")
    from ui_flet.shell import AppShell

    page = _FakePage()
    shell = AppShell(page, _shell_services())
    assert shell.decrypt_screen is None

    shell.navigate("decrypt")

    assert shell.decrypt_screen is not None
    assert page.overlay == []
    assert any(item is shell.decrypt_screen.vault_picker for item in page.services)
