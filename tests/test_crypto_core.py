import io

import pytest

from crypto_core import (
    AuthenticationError,
    VaultCrypto,
    entropy_to_mnemonic,
    generate_recovery_entropy,
    mnemonic_to_entropy,
)


PASSWORD = "CorrectHorseBatteryStaple!123"
WRONG_PASSWORD = "WrongHorseBatteryStaple!123"


def encrypt_to_memory(
    crypto: VaultCrypto,
    plaintext: bytes,
    password: str = PASSWORD,
    *,
    filename: str = "secret.txt",
    metadata: dict | None = None,
    recovery_key: bytes | None = None,
) -> io.BytesIO:
    vault = io.BytesIO()
    crypto.encrypt_stream(
        input_stream=io.BytesIO(plaintext),
        output_stream=vault,
        password=password,
        original_filename=filename,
        original_size=len(plaintext),
        metadata=metadata,
        recovery_key=recovery_key,
    )
    vault.seek(0)
    return vault


def decrypt_from_memory(
    crypto: VaultCrypto,
    vault: io.BytesIO,
    password: str | None = PASSWORD,
    *,
    recovery_key: bytes | None = None,
) -> tuple[bytes, object]:
    vault.seek(0)
    restored = io.BytesIO()
    header = crypto.decrypt_stream(
        input_stream=vault,
        output_stream=restored,
        password=password,
        recovery_key=recovery_key,
    )
    return restored.getvalue(), header


def test_encrypt_decrypt_stream_round_trip_preserves_payload_filename_and_metadata(fast_crypto):
    plaintext = b"This is a secret message. " * 1000
    metadata = {
        "file_count": 1,
        "created_at": "2024-01-01T00:00:00",
        "source_type": "file",
    }

    vault = encrypt_to_memory(
        fast_crypto,
        plaintext,
        filename="secret.txt",
        metadata=metadata,
    )
    restored, header = decrypt_from_memory(fast_crypto, vault)

    assert restored == plaintext
    assert header.payload.filename == "secret.txt"
    assert header.payload.original_size == len(plaintext)
    assert header.payload.metadata == metadata


def test_wrong_password_rejected(fast_crypto):
    vault = encrypt_to_memory(fast_crypto, b"wrong password test")

    with pytest.raises(AuthenticationError):
        decrypt_from_memory(fast_crypto, vault, WRONG_PASSWORD)


def test_verify_password_and_get_header_accepts_valid_password_and_rejects_wrong_password(fast_crypto):
    metadata = {"file_count": 1, "created_at": "2024-01-01T00:00:00"}
    vault = encrypt_to_memory(
        fast_crypto,
        b"metadata verification test",
        filename="verified.txt",
        metadata=metadata,
    )

    vault.seek(0)
    header = fast_crypto.verify_password_and_get_header(vault, PASSWORD)
    assert header.payload.filename == "verified.txt"
    assert header.payload.original_size == len(b"metadata verification test")
    assert header.payload.metadata == metadata

    vault.seek(0)
    with pytest.raises(AuthenticationError):
        fast_crypto.verify_password_and_get_header(vault, WRONG_PASSWORD)


def test_recovery_phrase_round_trip_and_recovery_decrypt_path(fast_crypto):
    plaintext = b"recovery protected plaintext" * 50
    recovery_key = generate_recovery_entropy()
    mnemonic = entropy_to_mnemonic(recovery_key)

    assert mnemonic_to_entropy(mnemonic) == recovery_key

    vault = encrypt_to_memory(
        fast_crypto,
        plaintext,
        password=PASSWORD,
        filename="recovery.bin",
        metadata={"source_type": "file"},
        recovery_key=recovery_key,
    )

    restored, header = decrypt_from_memory(
        fast_crypto,
        vault,
        password=None,
        recovery_key=recovery_key,
    )
    assert restored == plaintext
    assert header.payload.filename == "recovery.bin"
    assert header.payload.original_size == len(plaintext)


def test_rekey_rejects_old_password_and_accepts_new_password(fast_crypto, tmp_path):
    plaintext = b"rekey me safely" * 100
    old_vault = tmp_path / "old.vault"
    new_vault = tmp_path / "new.vault"
    new_password = "NewPassword456!@#"

    with old_vault.open("wb") as f:
        fast_crypto.encrypt_stream(
            io.BytesIO(plaintext),
            f,
            PASSWORD,
            original_filename="rekey.txt",
            original_size=len(plaintext),
            metadata={"file_count": 1},
        )

    fast_crypto.rekey_vault(old_vault, new_vault, PASSWORD, new_password)

    with new_vault.open("rb") as f:
        with pytest.raises(AuthenticationError):
            fast_crypto.decrypt_stream(f, io.BytesIO(), PASSWORD)

    restored = io.BytesIO()
    with new_vault.open("rb") as f:
        header = fast_crypto.decrypt_stream(f, restored, new_password)

    assert restored.getvalue() == plaintext
    assert header.payload.filename == "rekey.txt"
    assert header.payload.original_size == len(plaintext)


def test_hidden_vault_decoy_hidden_and_unknown_password_paths(fast_crypto):
    decoy_plaintext = b"decoy payload" * 200
    hidden_plaintext = b"hidden payload" * 200
    vault = io.BytesIO()

    fast_crypto.encrypt_hidden_vault(
        decoy_input_stream=io.BytesIO(decoy_plaintext),
        hidden_input_stream=io.BytesIO(hidden_plaintext),
        output_stream=vault,
        password_a="DecoyPassword123!",
        password_b="HiddenPassword456!",
        target_total_size=0,
        decoy_filename="decoy.txt",
        hidden_filename="hidden.txt",
        decoy_metadata={"source_type": "file", "role": "decoy"},
        hidden_metadata={"source_type": "file", "role": "hidden"},
        target_container_mb=0,
    )

    vault.seek(0)
    decoy_out = io.BytesIO()
    decoy_header = fast_crypto.decrypt_stream(vault, decoy_out, "DecoyPassword123!")
    assert decoy_out.getvalue() == decoy_plaintext
    assert decoy_header.payload.filename == "decoy.txt"
    assert decoy_header.payload.metadata["role"] == "decoy"

    vault.seek(0)
    hidden_out = io.BytesIO()
    hidden_header = fast_crypto.decrypt_stream(vault, hidden_out, "HiddenPassword456!")
    assert hidden_out.getvalue() == hidden_plaintext
    assert hidden_header.payload.filename == "hidden.txt"
    assert hidden_header.payload.metadata["role"] == "hidden"

    vault.seek(0)
    with pytest.raises(AuthenticationError):
        fast_crypto.decrypt_stream(vault, io.BytesIO(), "UnknownPassword789!")


def test_moderate_streaming_round_trip_from_inline_self_test(fast_crypto):
    plaintext = b"X" * (2 * 1024 * 1024)
    vault = encrypt_to_memory(
        fast_crypto,
        plaintext,
        filename="moderate.bin",
    )

    restored, header = decrypt_from_memory(fast_crypto, vault)

    assert restored == plaintext
    assert header.payload.filename == "moderate.bin"
    assert header.payload.original_size == len(plaintext)
