import io
import tempfile
import zipfile
from pathlib import Path

import pytest

import crypto_core
from crypto_core import (
    AuthenticationError,
    CHUNK_SIZE,
    OperationCancelledError,
    VaultCrypto,
)
from file_handler import FolderPackager, atomic_output


ROOT = Path(__file__).resolve().parents[1]
PASSWORD = "CorrectHorseBatteryStaple!123"
DECOY_PASSWORD = "DecoyPassword123!"
HIDDEN_PASSWORD = "HiddenPassword456!"


def _cancel_on_call(n: int):
    state = {"calls": 0}

    def check() -> bool:
        state["calls"] += 1
        return state["calls"] >= n

    return check


def _normal_vault_bytes(crypto: VaultCrypto, plaintext: bytes, *, cancel_check=None) -> bytes:
    out = io.BytesIO()
    crypto.encrypt_stream(
        input_stream=io.BytesIO(plaintext),
        output_stream=out,
        password=PASSWORD,
        original_filename="normal.bin",
        original_size=len(plaintext),
        metadata={"source_type": "file"},
        cancel_check=cancel_check,
    )
    return out.getvalue()


def _decrypt_bytes(
    crypto: VaultCrypto,
    vault_bytes: bytes,
    password: str = PASSWORD,
    *,
    cancel_check=None,
) -> bytes:
    out = io.BytesIO()
    crypto.decrypt_stream(
        input_stream=io.BytesIO(vault_bytes),
        output_stream=out,
        password=password,
        cancel_check=cancel_check,
    )
    return out.getvalue()


def _hidden_vault_bytes(crypto: VaultCrypto, decoy_plaintext: bytes, hidden_plaintext: bytes) -> bytes:
    out = io.BytesIO()
    crypto.encrypt_hidden_vault(
        decoy_input_stream=io.BytesIO(decoy_plaintext),
        hidden_input_stream=io.BytesIO(hidden_plaintext),
        output_stream=out,
        password_a=DECOY_PASSWORD,
        password_b=HIDDEN_PASSWORD,
        target_total_size=0,
        decoy_filename="decoy.bin",
        hidden_filename="hidden.bin",
        decoy_metadata={"source_type": "file", "role": "decoy"},
        hidden_metadata={"source_type": "file", "role": "hidden"},
        target_container_mb=0,
    )
    return out.getvalue()


def _method_slice(source: str, method_name: str) -> str:
    marker = f"    def {method_name}"
    start = source.index(marker)
    next_def = source.find("\n    def ", start + len(marker))
    if next_def == -1:
        return source[start:]
    return source[start:next_def]


def _install_argon2_counter(monkeypatch):
    original = crypto_core.argon2.low_level.hash_secret_raw
    counter = {"count": 0}

    def counting_hash_secret_raw(*args, **kwargs):
        counter["count"] += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(
        crypto_core.argon2.low_level,
        "hash_secret_raw",
        counting_hash_secret_raw,
    )
    return counter


def test_encrypt_cancel_cleans_atomic_output_temp(tmp_path, fast_crypto):
    src = tmp_path / "large.bin"
    final = tmp_path / "large.vault"
    src.write_bytes(b"A" * (CHUNK_SIZE * 2 + 17))

    with pytest.raises(OperationCancelledError):
        atomic_output(
            final,
            lambda p: fast_crypto.encrypt_file(
                src,
                p,
                PASSWORD,
                cancel_check=_cancel_on_call(1),
            ),
        )

    assert not final.exists()
    assert not list(tmp_path.glob(".rpm_vaulttmp_*.part"))


def test_decrypt_cancel_raises_and_leaves_removable_partial_output(tmp_path, fast_crypto):
    plaintext = b"B" * (CHUNK_SIZE * 2 + 31)
    vault_path = tmp_path / "payload.vault"
    restored = tmp_path / "restored.bin"
    vault_path.write_bytes(_normal_vault_bytes(fast_crypto, plaintext))

    with pytest.raises(OperationCancelledError):
        fast_crypto.decrypt_file(
            vault_path,
            restored,
            PASSWORD,
            cancel_check=_cancel_on_call(2),
        )

    assert restored.exists()
    assert 0 < restored.stat().st_size < len(plaintext)
    restored.unlink()
    assert not restored.exists()


def test_no_cancel_round_trips_still_work_for_normal_and_hidden(fast_crypto):
    normal_plaintext = b"normal no cancel" * 100
    normal_vault = _normal_vault_bytes(
        fast_crypto,
        normal_plaintext,
        cancel_check=lambda: False,
    )
    assert _decrypt_bytes(fast_crypto, normal_vault, cancel_check=lambda: False) == normal_plaintext

    decoy_plaintext = b"decoy no cancel" * 100
    hidden_plaintext = b"hidden no cancel" * 100
    hidden_vault = _hidden_vault_bytes(fast_crypto, decoy_plaintext, hidden_plaintext)
    assert _decrypt_bytes(fast_crypto, hidden_vault, DECOY_PASSWORD) == decoy_plaintext
    assert _decrypt_bytes(fast_crypto, hidden_vault, HIDDEN_PASSWORD) == hidden_plaintext


def test_packaging_and_extraction_cancel(tmp_path):
    folder = tmp_path / "folder"
    folder.mkdir()
    (folder / "a.txt").write_text("A")
    (folder / "b.txt").write_text("B")
    packager = FolderPackager()
    temp_root = Path(tempfile.gettempdir())
    before = set(temp_root.glob(".rpm_pack_*.zip"))

    with pytest.raises(OperationCancelledError):
        packager.package_folder(folder, cancel_check=lambda: True)

    after = set(temp_root.glob(".rpm_pack_*.zip"))
    assert after <= before

    zip_path = packager.package_folder(folder)
    out = tmp_path / "out"
    try:
        with pytest.raises(OperationCancelledError):
            packager.extract_archive(zip_path, out, cancel_check=lambda: True)
        assert not any(out.rglob("*"))
    finally:
        zip_path.unlink(missing_ok=True)


def test_m2_argon2_count_unchanged_by_cancellation_plumbing(monkeypatch, fast_crypto):
    normal_vault = _normal_vault_bytes(fast_crypto, b"normal m2" * 100)
    hidden_vault = _hidden_vault_bytes(fast_crypto, b"decoy m2" * 100, b"hidden m2" * 100)
    counter = _install_argon2_counter(monkeypatch)

    counter["count"] = 0
    _decrypt_bytes(fast_crypto, normal_vault, PASSWORD)
    normal_count = counter["count"]

    counter["count"] = 0
    _decrypt_bytes(fast_crypto, hidden_vault, HIDDEN_PASSWORD)
    hidden_count = counter["count"]

    counter["count"] = 0
    with pytest.raises(AuthenticationError):
        _decrypt_bytes(fast_crypto, normal_vault, "WrongPassword789!")
    wrong_count = counter["count"]

    assert normal_count == hidden_count == wrong_count == 2


def test_gui_workers_pass_cancel_check_and_handle_operation_cancelled():
    gui_src = (ROOT / "gui_app.py").read_text(encoding="utf-8")
    rekey_src = (ROOT / "views" / "rekey_view.py").read_text(encoding="utf-8")
    decrypt_src = (ROOT / "views" / "decrypt_view.py").read_text(encoding="utf-8")
    encrypt_src = (ROOT / "views" / "encrypt_view.py").read_text(encoding="utf-8")
    inspect_src = (ROOT / "views" / "inspect_view.py").read_text(encoding="utf-8")
    workers = {
        "_batch_encrypt_worker": (encrypt_src, 5),
        "_batch_decrypt_worker": (decrypt_src, 2),
        "_selective_extract_worker": (inspect_src, 2),
        "_rekey_worker": (rekey_src, 1),
    }

    for name, (source, min_cancel_uses) in workers.items():
        body = _method_slice(source, name)
        assert body.count("cancel_check=") >= min_cancel_uses
        assert "except OperationCancelledError:" in body
        assert "Cancelling and cleaning up" in body
