import io
from pathlib import Path

import pytest

import crypto_core
from crypto_core import (
    AuthenticationError,
    VaultCrypto,
    generate_recovery_entropy,
)


ROOT = Path(__file__).resolve().parents[1]
PASSWORD = "CorrectHorseBatteryStaple!123"
WRONG_PASSWORD = "WrongHorseBatteryStaple!123"
DECOY_PASSWORD = "DecoyPassword123!"
HIDDEN_PASSWORD = "HiddenPassword456!"


def _normal_vault_bytes(
    crypto: VaultCrypto,
    plaintext: bytes = b"normal payload",
    *,
    password: str = PASSWORD,
    recovery_key: bytes | None = None,
) -> bytes:
    out = io.BytesIO()
    crypto.encrypt_stream(
        input_stream=io.BytesIO(plaintext),
        output_stream=out,
        password=password,
        original_filename="normal.txt",
        original_size=len(plaintext),
        metadata={"source_type": "file", "role": "normal"},
        recovery_key=recovery_key,
    )
    return out.getvalue()


def _hidden_vault_bytes(
    crypto: VaultCrypto,
    decoy_plaintext: bytes = b"decoy payload",
    hidden_plaintext: bytes = b"hidden payload",
) -> bytes:
    out = io.BytesIO()
    crypto.encrypt_hidden_vault(
        decoy_input_stream=io.BytesIO(decoy_plaintext),
        hidden_input_stream=io.BytesIO(hidden_plaintext),
        output_stream=out,
        password_a=DECOY_PASSWORD,
        password_b=HIDDEN_PASSWORD,
        target_total_size=0,
        decoy_filename="decoy.txt",
        hidden_filename="hidden.txt",
        decoy_metadata={"source_type": "file", "role": "decoy"},
        hidden_metadata={"source_type": "file", "role": "hidden"},
        target_container_mb=0,
    )
    return out.getvalue()


def _decrypt_bytes(
    crypto: VaultCrypto,
    vault_bytes: bytes,
    *,
    password: str | None = PASSWORD,
    recovery_key: bytes | None = None,
) -> bytes:
    restored = io.BytesIO()
    crypto.decrypt_stream(
        input_stream=io.BytesIO(vault_bytes),
        output_stream=restored,
        password=password,
        recovery_key=recovery_key,
    )
    return restored.getvalue()


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


def _method_slice(source: str, method_name: str) -> str:
    marker = f"    def {method_name}"
    start = source.index(marker)
    next_def = source.find("\n    def ", start + len(marker))
    if next_def == -1:
        return source[start:]
    return source[start:next_def]


def test_password_decrypt_keeps_m2_constant_work_at_two_argon2_calls(monkeypatch, fast_crypto):
    normal_plaintext = b"normal secret" * 32
    decoy_plaintext = b"decoy secret" * 32
    hidden_plaintext = b"hidden secret" * 32
    normal_vault = _normal_vault_bytes(fast_crypto, normal_plaintext)
    hidden_vault = _hidden_vault_bytes(fast_crypto, decoy_plaintext, hidden_plaintext)
    counter = _install_argon2_counter(monkeypatch)

    counter["count"] = 0
    assert _decrypt_bytes(fast_crypto, normal_vault, password=PASSWORD) == normal_plaintext
    normal_correct_count = counter["count"]

    counter["count"] = 0
    assert _decrypt_bytes(fast_crypto, hidden_vault, password=DECOY_PASSWORD) == decoy_plaintext
    hidden_decoy_count = counter["count"]

    counter["count"] = 0
    assert _decrypt_bytes(fast_crypto, hidden_vault, password=HIDDEN_PASSWORD) == hidden_plaintext
    hidden_hidden_count = counter["count"]

    counter["count"] = 0
    with pytest.raises(AuthenticationError):
        _decrypt_bytes(fast_crypto, normal_vault, password=WRONG_PASSWORD)
    normal_wrong_count = counter["count"]

    assert normal_correct_count == hidden_decoy_count == hidden_hidden_count == normal_wrong_count == 2


def test_recovery_decrypt_path_still_uses_one_argon2_call(monkeypatch, fast_crypto):
    recovery_key = generate_recovery_entropy()
    plaintext = b"recovery secret" * 32
    vault = _normal_vault_bytes(fast_crypto, plaintext, recovery_key=recovery_key)
    counter = _install_argon2_counter(monkeypatch)

    restored = _decrypt_bytes(
        fast_crypto,
        vault,
        password=None,
        recovery_key=recovery_key,
    )

    assert restored == plaintext
    assert counter["count"] == 1


def test_batch_decrypt_worker_uses_decrypt_return_header_without_redundant_verify():
    source = (ROOT / "views" / "decrypt_view.py").read_text(encoding="utf-8")
    body = _method_slice(source, "_batch_decrypt_worker")

    # Before Phase 12: verify pass (2 Argon2) + decrypt pass (2 Argon2) = 4/file.
    # After Phase 12: decrypt pass only = 2/file, while M2 still makes that pass
    # exactly two derivations: main first, hidden second, unconditionally.
    assert "verify_password_and_get_header(" not in body
    assert "Verifying" not in body
    assert "header = self.crypto.decrypt_file(" in body


def test_normal_decrypt_file_round_trip_still_returns_header(tmp_path, fast_crypto):
    plaintext = b"normal file decrypt" * 32
    src = tmp_path / "payload.zip"
    vault = tmp_path / "payload.vault"
    restored = tmp_path / "restored.zip"
    src.write_bytes(plaintext)

    fast_crypto.encrypt_file(
        input_path=src,
        output_path=vault,
        password=PASSWORD,
        original_filename="payload.zip",
        metadata={"source_type": "file"},
    )

    header = fast_crypto.decrypt_file(vault, restored, PASSWORD)

    assert restored.read_bytes() == plaintext
    assert header.payload.filename == "payload.zip"
    assert header.payload.original_size == len(plaintext)


def test_hidden_decoy_and_hidden_round_trips_still_work(fast_crypto):
    decoy_plaintext = b"decoy roundtrip" * 32
    hidden_plaintext = b"hidden roundtrip" * 32
    vault = _hidden_vault_bytes(fast_crypto, decoy_plaintext, hidden_plaintext)

    assert _decrypt_bytes(fast_crypto, vault, password=DECOY_PASSWORD) == decoy_plaintext
    assert _decrypt_bytes(fast_crypto, vault, password=HIDDEN_PASSWORD) == hidden_plaintext
