import io
import os

import pytest

import crypto_core
from crypto_core import PayloadTooLargeError, VaultCrypto


PASSWORD = "CorrectHorseBatteryStaple!123"
DECOY_PASSWORD = "DecoyPassword123!"
HIDDEN_PASSWORD = "HiddenPassword456!"


class FakeLargeStream:
    def __init__(self, size: int):
        self._size = size
        self._pos = 0

    def seek(self, off: int, whence: int = 0) -> int:
        if whence == os.SEEK_END:
            self._pos = self._size + off
        elif whence == os.SEEK_CUR:
            self._pos += off
        else:
            self._pos = off
        return self._pos

    def tell(self) -> int:
        return self._pos

    def read(self, n: int = -1) -> bytes:
        return b""


def _encrypt_to_memory(crypto: VaultCrypto, plaintext: bytes, password: str = PASSWORD) -> io.BytesIO:
    vault = io.BytesIO()
    crypto.encrypt_stream(
        input_stream=io.BytesIO(plaintext),
        output_stream=vault,
        password=password,
        original_filename="payload.bin",
        original_size=len(plaintext),
        metadata={"source_type": "file"},
    )
    vault.seek(0)
    return vault


def _decrypt_from_memory(crypto: VaultCrypto, vault: io.BytesIO, password: str) -> bytes:
    vault.seek(0)
    restored = io.BytesIO()
    crypto.decrypt_stream(vault, restored, password)
    return restored.getvalue()


def test_max_payload_size_constant_is_32_gib():
    assert crypto_core.MAX_PAYLOAD_SIZE == 32 * 1024 * 1024 * 1024


def test_encrypt_stream_rejects_oversize_before_kdf(monkeypatch, fast_crypto):
    def fail_if_called(*args, **kwargs):
        raise AssertionError("Argon2 must not run after an oversized payload is rejected")

    monkeypatch.setattr(crypto_core.argon2.low_level, "hash_secret_raw", fail_if_called)
    out = io.BytesIO()

    with pytest.raises(PayloadTooLargeError):
        fast_crypto.encrypt_stream(
            input_stream=io.BytesIO(b"tiny"),
            output_stream=out,
            password=PASSWORD,
            original_filename="too-large.bin",
            original_size=crypto_core.MAX_PAYLOAD_SIZE + 1,
            metadata={"source_type": "file"},
        )

    assert out.getvalue() == b""


def test_exact_payload_limit_does_not_trigger_size_guard(monkeypatch, fast_crypto):
    class PostGuardReached(Exception):
        pass

    def raise_after_guard(size: int) -> bytes:
        raise PostGuardReached

    monkeypatch.setattr(VaultCrypto, "_secure_random", staticmethod(raise_after_guard))

    with pytest.raises(PostGuardReached):
        fast_crypto.encrypt_stream(
            input_stream=io.BytesIO(b""),
            output_stream=io.BytesIO(),
            password=PASSWORD,
            original_filename="boundary.bin",
            original_size=crypto_core.MAX_PAYLOAD_SIZE,
            metadata={"source_type": "file"},
        )


def test_small_encrypt_stream_round_trip_still_works(fast_crypto):
    plaintext = b"phase 8 normal payload" * 128
    vault = _encrypt_to_memory(fast_crypto, plaintext)

    assert _decrypt_from_memory(fast_crypto, vault, PASSWORD) == plaintext


def test_encrypt_hidden_vault_rejects_oversize_decoy_or_hidden(fast_crypto):
    with pytest.raises(PayloadTooLargeError):
        fast_crypto.encrypt_hidden_vault(
            decoy_input_stream=FakeLargeStream(crypto_core.MAX_PAYLOAD_SIZE + 1),
            hidden_input_stream=io.BytesIO(b"hidden"),
            output_stream=io.BytesIO(),
            password_a=DECOY_PASSWORD,
            password_b=HIDDEN_PASSWORD,
            target_total_size=0,
            decoy_filename="decoy.bin",
            hidden_filename="hidden.bin",
        )

    with pytest.raises(PayloadTooLargeError):
        fast_crypto.encrypt_hidden_vault(
            decoy_input_stream=io.BytesIO(b"decoy"),
            hidden_input_stream=FakeLargeStream(crypto_core.MAX_PAYLOAD_SIZE + 1),
            output_stream=io.BytesIO(),
            password_a=DECOY_PASSWORD,
            password_b=HIDDEN_PASSWORD,
            target_total_size=0,
            decoy_filename="decoy.bin",
            hidden_filename="hidden.bin",
        )


def test_small_hidden_vault_decoy_and_hidden_round_trip_still_work(fast_crypto):
    decoy_plaintext = b"decoy payload" * 100
    hidden_plaintext = b"hidden payload" * 100
    vault = io.BytesIO()

    fast_crypto.encrypt_hidden_vault(
        decoy_input_stream=io.BytesIO(decoy_plaintext),
        hidden_input_stream=io.BytesIO(hidden_plaintext),
        output_stream=vault,
        password_a=DECOY_PASSWORD,
        password_b=HIDDEN_PASSWORD,
        target_total_size=0,
        decoy_filename="decoy.txt",
        hidden_filename="hidden.txt",
        decoy_metadata={"source_type": "file", "role": "decoy"},
        hidden_metadata={"source_type": "file", "role": "hidden"},
        target_container_mb=0,
    )

    assert _decrypt_from_memory(fast_crypto, vault, DECOY_PASSWORD) == decoy_plaintext
    assert _decrypt_from_memory(fast_crypto, vault, HIDDEN_PASSWORD) == hidden_plaintext
