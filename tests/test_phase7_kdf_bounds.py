import io
import json
import struct

import argon2.low_level
import pytest

from crypto_core import (
    AES_KEY_SIZE,
    KDFParams,
    MAX_ARGON2_MEMORY,
    MAX_ARGON2_PARALLELISM,
    MAX_ARGON2_TIME,
    MIN_ARGON2_MEMORY,
    MIN_ARGON2_PARALLELISM,
    MIN_ARGON2_TIME,
    VAULT_MAGIC,
    VaultCrypto,
    VaultFormatError,
    _validate_kdf_params,
)


PASSWORD = "KdfBoundsPassword123!"


def make_vault_bytes(crypto: VaultCrypto, plaintext: bytes = b"kdf bounds payload") -> bytes:
    out = io.BytesIO()
    crypto.encrypt_stream(
        input_stream=io.BytesIO(plaintext),
        output_stream=out,
        password=PASSWORD,
        original_filename="kdf.txt",
        original_size=len(plaintext),
        metadata={"source_type": "file"},
    )
    return out.getvalue()


def rewrite_kdf(vault_bytes: bytes, **kdf_updates) -> bytes:
    stream = io.BytesIO(vault_bytes)
    magic = stream.read(len(VAULT_MAGIC))
    assert magic == VAULT_MAGIC
    version = stream.read(1)
    (old_header_len,) = struct.unpack("!I", stream.read(4))
    header = json.loads(stream.read(old_header_len).decode("utf-8"))
    rest = stream.read()

    header["kdf"].update(kdf_updates)
    new_header = json.dumps(header, separators=(",", ":")).encode("utf-8")
    return b"".join([
        magic,
        version,
        struct.pack("!I", len(new_header)),
        new_header,
        rest,
    ])


def assert_rejects_before_argon(monkeypatch, crypto: VaultCrypto, vault_bytes: bytes) -> None:
    def fail_if_called(*args, **kwargs):
        raise AssertionError("Argon2 must not be called for rejected KDF header values")

    monkeypatch.setattr(argon2.low_level, "hash_secret_raw", fail_if_called)

    with pytest.raises(VaultFormatError):
        crypto.decrypt_stream(io.BytesIO(vault_bytes), io.BytesIO(), PASSWORD)

    with pytest.raises(VaultFormatError):
        crypto.verify_password_and_get_header(io.BytesIO(vault_bytes), PASSWORD)


def test_valid_vault_still_opens_and_policy_accepts_fast_default_and_ui_extremes(fast_crypto):
    vault = make_vault_bytes(fast_crypto, b"valid vault still opens")
    restored = io.BytesIO()
    header = fast_crypto.decrypt_stream(io.BytesIO(vault), restored, PASSWORD)

    assert restored.getvalue() == b"valid vault still opens"
    assert header.payload.filename == "kdf.txt"

    valid_cases = [
        KDFParams(memory=8192, iterations=1, parallelism=1, length=AES_KEY_SIZE),
        KDFParams(memory=65536, iterations=3, parallelism=4, length=AES_KEY_SIZE),
        KDFParams(memory=16384, iterations=1, parallelism=1, length=AES_KEY_SIZE),
        KDFParams(memory=524288, iterations=10, parallelism=16, length=AES_KEY_SIZE),
        KDFParams(
            memory=MAX_ARGON2_MEMORY,
            iterations=MAX_ARGON2_TIME,
            parallelism=MAX_ARGON2_PARALLELISM,
            length=AES_KEY_SIZE,
        ),
    ]
    for kdf in valid_cases:
        _validate_kdf_params(kdf)


def test_huge_memory_rejected_fast_before_argon(monkeypatch, fast_crypto):
    vault = rewrite_kdf(make_vault_bytes(fast_crypto), memory=68719476736)

    assert_rejects_before_argon(monkeypatch, fast_crypto, vault)


@pytest.mark.parametrize(
    "updates",
    [
        {"memory": 0},
        {"memory": -1},
        {"memory": 1024},
        {"iterations": 0},
        {"iterations": -1},
        {"parallelism": 0},
        {"parallelism": -1},
    ],
)
def test_zero_negative_and_tiny_kdf_values_rejected(updates):
    kdf = KDFParams(
        memory=8192,
        iterations=1,
        parallelism=1,
        length=AES_KEY_SIZE,
    )
    for key, value in updates.items():
        setattr(kdf, key, value)

    with pytest.raises(VaultFormatError):
        _validate_kdf_params(kdf)


@pytest.mark.parametrize(
    "updates",
    [
        {"memory": "65536"},
        {"memory": True},
        {"iterations": "3"},
        {"iterations": False},
        {"parallelism": "4"},
        {"parallelism": True},
    ],
)
def test_non_integer_and_bool_kdf_values_rejected(updates):
    kdf = KDFParams(
        memory=8192,
        iterations=1,
        parallelism=1,
        length=AES_KEY_SIZE,
    )
    for key, value in updates.items():
        setattr(kdf, key, value)

    with pytest.raises(VaultFormatError):
        _validate_kdf_params(kdf)


@pytest.mark.parametrize(
    "updates",
    [
        {"iterations": 10**9},
        {"parallelism": 10**6},
    ],
)
def test_huge_iterations_and_parallelism_rejected(updates):
    kdf = KDFParams(
        memory=8192,
        iterations=1,
        parallelism=1,
        length=AES_KEY_SIZE,
    )
    for key, value in updates.items():
        setattr(kdf, key, value)

    with pytest.raises(VaultFormatError):
        _validate_kdf_params(kdf)


@pytest.mark.parametrize("length", [0, 16, 64, "32", True])
def test_invalid_kdf_length_rejected(length):
    kdf = KDFParams(
        memory=8192,
        iterations=1,
        parallelism=1,
        length=length,
    )

    with pytest.raises(VaultFormatError):
        _validate_kdf_params(kdf)


def test_rekey_vault_rejects_out_of_policy_header_before_derivation(monkeypatch, fast_crypto, tmp_path):
    bad_vault = tmp_path / "bad.vault"
    out_vault = tmp_path / "out.vault"
    bad_vault.write_bytes(rewrite_kdf(make_vault_bytes(fast_crypto), memory=68719476736))

    def fail_if_called(*args, **kwargs):
        raise AssertionError("Argon2 must not be called before KDF header rejection")

    monkeypatch.setattr(argon2.low_level, "hash_secret_raw", fail_if_called)

    with pytest.raises(VaultFormatError):
        fast_crypto.rekey_vault(bad_vault, out_vault, PASSWORD, "NewPassword123!")


def test_engine_constructor_clamps_out_of_policy_values_to_maxima():
    crypto = VaultCrypto(
        argon_memory=10**12,
        argon_iterations=10**9,
        argon_parallelism=10**6,
    )

    assert crypto.argon_memory == MAX_ARGON2_MEMORY
    assert crypto.argon_iterations == MAX_ARGON2_TIME
    assert crypto.argon_parallelism == MAX_ARGON2_PARALLELISM


def test_engine_constructor_leaves_fast_fixture_values_unchanged():
    crypto = VaultCrypto(argon_memory=8192, argon_iterations=1, argon_parallelism=1)

    assert crypto.argon_memory == MIN_ARGON2_MEMORY
    assert crypto.argon_iterations == MIN_ARGON2_TIME
    assert crypto.argon_parallelism == MIN_ARGON2_PARALLELISM


def test_engine_constructor_replaces_non_integer_values_with_defaults():
    crypto = VaultCrypto(argon_memory="65536", argon_iterations=True, argon_parallelism=None)

    assert crypto.argon_memory == 65536
    assert crypto.argon_iterations == 3
    assert crypto.argon_parallelism == 4
