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


def test_encrypt_controller_round_trips(fast_services, tmp_path):
    from ui_flet.controllers.encrypt_controller import EncryptController

    src = tmp_path / "secret.txt"
    src.write_bytes(b"stage 2 payload " * 200)
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    EncryptController(fast_services)._worker(
        [str(src)], "PwStage2!", None, True, False, str(out_dir)
    )
    msgs = _drain(fast_services.msg_queue)
    assert any(m["type"] == "batch_done" and "1/1" in m.get("text", "") for m in msgs)
    vaults = list(out_dir.glob("*.vault"))
    assert len(vaults) == 1

    restored = tmp_path / "restored.bin"
    header = fast_services.crypto.decrypt_file(vaults[0], restored, "PwStage2!")
    assert header.payload.filename == "secret.txt"


def test_encrypt_wrong_password_rejected(fast_services, tmp_path):
    from ui_flet.controllers.encrypt_controller import EncryptController
    from crypto_core import AuthenticationError

    src = tmp_path / "a.txt"
    src.write_bytes(b"x" * 500)
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    EncryptController(fast_services)._worker(
        [str(src)], "RightPw1!", None, True, False, str(out_dir)
    )
    vault = next(iter(out_dir.glob("*.vault")))
    with pytest.raises(AuthenticationError):
        fast_services.crypto.decrypt_file(vault, tmp_path / "o.bin", "WrongPw9!")


def test_encrypt_output_collision_creates_distinct_vaults(fast_services, tmp_path):
    from ui_flet.controllers.encrypt_controller import EncryptController

    src = tmp_path / "dup.txt"
    src.write_bytes(b"y" * 300)
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    ctrl = EncryptController(fast_services)
    ctrl._worker([str(src)], "PwStage2!", None, True, False, str(out_dir))
    ctrl._worker([str(src)], "PwStage2!", None, True, False, str(out_dir))
    names = sorted(p.name for p in out_dir.glob("*.vault"))
    assert names == ["dup.txt.vault", "dup.txt_1.vault"]


def test_encrypt_secure_wipe_removes_original(fast_services, tmp_path):
    from ui_flet.controllers.encrypt_controller import EncryptController

    src = tmp_path / "wipeme.txt"
    src.write_bytes(b"z" * 400)
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    EncryptController(fast_services)._worker(
        [str(src)], "PwStage2!", None, True, True, str(out_dir)
    )
    assert not src.exists()
    assert len(list(out_dir.glob("*.vault"))) == 1


def test_encrypt_controller_is_flet_free():
    root = Path(__file__).resolve().parents[1]
    src = (root / "ui_flet" / "controllers" / "encrypt_controller.py").read_text(
        encoding="utf-8"
    )
    assert "import flet" not in src
    assert "from flet" not in src
