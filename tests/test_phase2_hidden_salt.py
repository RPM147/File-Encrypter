import base64
import io
import json
import struct

import pytest

from crypto_core import (
    AES_TAG_SIZE,
    AuthenticationError,
    MIN_SALT_SIZE,
    VAULT_MAGIC,
    VaultCrypto,
)


PASSWORD = "VisiblePassword123!"
HIDDEN_PASSWORD = "HiddenPassword456!"
WRONG_PASSWORD = "WrongPassword789!"
GENERIC_AUTH_ERROR = "Vault access denied: Invalid password or corrupted vault envelope."


def read_cleartext_header(vault_bytes: bytes) -> dict:
    stream = io.BytesIO(vault_bytes)
    magic = stream.read(len(VAULT_MAGIC))
    assert magic == VAULT_MAGIC
    version_data = stream.read(1)
    assert len(version_data) == 1
    (version,) = struct.unpack("!B", version_data)
    (header_len,) = struct.unpack("!I", stream.read(4))
    header_bytes = stream.read(header_len)
    header = json.loads(header_bytes.decode("utf-8"))
    header["_test_version"] = version
    header["_test_header_len"] = header_len
    header["_test_payload_offset"] = stream.tell()
    return header


def rewrite_cleartext_header(vault_bytes: bytes, mutate_header) -> bytes:
    stream = io.BytesIO(vault_bytes)
    magic = stream.read(len(VAULT_MAGIC))
    version = stream.read(1)
    (old_header_len,) = struct.unpack("!I", stream.read(4))
    old_header = json.loads(stream.read(old_header_len).decode("utf-8"))
    rest = stream.read()

    mutate_header(old_header)
    new_header = json.dumps(old_header, separators=(",", ":")).encode("utf-8")
    return b"".join([
        magic,
        version,
        struct.pack("!I", len(new_header)),
        new_header,
        rest,
    ])


def hidden_salt_bytes(header: dict) -> bytes:
    value = header["kdf"]["hidden_salt"]
    assert value
    return base64.b64decode(value)


def assert_no_clear_hidden_flag(header: dict) -> None:
    forbidden_keys = {
        "has_hidden",
        "hidden_exists",
        "is_hidden",
        "hidden",
        "hasHidden",
        "hiddenExists",
        "isHidden",
    }
    assert forbidden_keys.isdisjoint(header.keys())
    assert forbidden_keys.isdisjoint(header["kdf"].keys())
    assert forbidden_keys.isdisjoint(header["payload"].keys())


def encrypt_normal_vault(crypto: VaultCrypto, plaintext: bytes = b"normal payload") -> bytes:
    out = io.BytesIO()
    crypto.encrypt_stream(
        input_stream=io.BytesIO(plaintext),
        output_stream=out,
        password=PASSWORD,
        original_filename="normal.txt",
        original_size=len(plaintext),
        metadata={"source_type": "file", "role": "normal"},
    )
    return out.getvalue()


def encrypt_hidden_vault(
    crypto: VaultCrypto,
    decoy_plaintext: bytes = b"decoy payload",
    hidden_plaintext: bytes = b"hidden payload",
) -> bytes:
    out = io.BytesIO()
    crypto.encrypt_hidden_vault(
        decoy_input_stream=io.BytesIO(decoy_plaintext),
        hidden_input_stream=io.BytesIO(hidden_plaintext),
        output_stream=out,
        password_a=PASSWORD,
        password_b=HIDDEN_PASSWORD,
        target_total_size=0,
        decoy_filename="decoy.txt",
        hidden_filename="hidden.txt",
        decoy_metadata={"source_type": "file", "role": "decoy"},
        hidden_metadata={"source_type": "file", "role": "hidden"},
        target_container_mb=0,
    )
    return out.getvalue()


def decrypt_bytes(crypto: VaultCrypto, vault_bytes: bytes, password: str) -> tuple[bytes, object]:
    out = io.BytesIO()
    header = crypto.decrypt_stream(io.BytesIO(vault_bytes), out, password)
    return out.getvalue(), header


def test_new_normal_vault_has_non_empty_random_hidden_trial_salt(fast_crypto):
    vault_a = encrypt_normal_vault(fast_crypto, b"normal A")
    vault_b = encrypt_normal_vault(fast_crypto, b"normal B")

    header_a = read_cleartext_header(vault_a)
    header_b = read_cleartext_header(vault_b)
    salt_a = hidden_salt_bytes(header_a)
    salt_b = hidden_salt_bytes(header_b)

    assert len(salt_a) >= MIN_SALT_SIZE
    assert len(salt_b) >= MIN_SALT_SIZE
    assert header_a["kdf"]["hidden_salt"] != header_b["kdf"]["hidden_salt"]
    assert_no_clear_hidden_flag(header_a)

    restored, header = decrypt_bytes(fast_crypto, vault_a, PASSWORD)
    assert restored == b"normal A"
    assert header.payload.filename == "normal.txt"


def test_hidden_and_normal_headers_do_not_expose_empty_vs_nonempty_hidden_flag(fast_crypto):
    normal_vault = encrypt_normal_vault(fast_crypto, b"normal data")
    hidden_vault = encrypt_hidden_vault(
        fast_crypto,
        decoy_plaintext=b"decoy data",
        hidden_plaintext=b"hidden data",
    )

    normal_header = read_cleartext_header(normal_vault)
    hidden_header = read_cleartext_header(hidden_vault)

    assert len(hidden_salt_bytes(normal_header)) >= MIN_SALT_SIZE
    assert len(hidden_salt_bytes(hidden_header)) >= MIN_SALT_SIZE
    assert set(normal_header["kdf"].keys()) == set(hidden_header["kdf"].keys())
    assert normal_header["kdf"]["hidden_salt"] != ""
    assert hidden_header["kdf"]["hidden_salt"] != ""
    assert_no_clear_hidden_flag(normal_header)
    assert_no_clear_hidden_flag(hidden_header)


def test_normal_wrong_password_and_hidden_unknown_password_fail_generically(fast_crypto):
    normal_vault = encrypt_normal_vault(fast_crypto, b"normal secret")
    hidden_vault = encrypt_hidden_vault(fast_crypto)

    with pytest.raises(AuthenticationError) as normal_exc:
        decrypt_bytes(fast_crypto, normal_vault, WRONG_PASSWORD)
    assert str(normal_exc.value) == GENERIC_AUTH_ERROR

    with pytest.raises(AuthenticationError) as hidden_exc:
        decrypt_bytes(fast_crypto, hidden_vault, WRONG_PASSWORD)
    assert str(hidden_exc.value) == GENERIC_AUTH_ERROR


def test_hidden_decoy_and_hidden_passwords_still_decrypt_correct_payloads(fast_crypto):
    decoy_plaintext = b"decoy payload" * 100
    hidden_plaintext = b"hidden payload" * 100
    hidden_vault = encrypt_hidden_vault(
        fast_crypto,
        decoy_plaintext=decoy_plaintext,
        hidden_plaintext=hidden_plaintext,
    )

    decoy_out, decoy_header = decrypt_bytes(fast_crypto, hidden_vault, PASSWORD)
    assert decoy_out == decoy_plaintext
    assert decoy_header.payload.filename == "decoy.txt"
    assert decoy_header.payload.metadata["role"] == "decoy"

    hidden_out, hidden_header = decrypt_bytes(fast_crypto, hidden_vault, HIDDEN_PASSWORD)
    assert hidden_out == hidden_plaintext
    assert hidden_header.payload.filename == "hidden.txt"
    assert hidden_header.payload.metadata["role"] == "hidden"


def test_rekey_preserves_hidden_salt_byte_for_byte(fast_crypto, tmp_path):
    old_vault = tmp_path / "old.vault"
    new_vault = tmp_path / "new.vault"
    old_vault.write_bytes(encrypt_normal_vault(fast_crypto, b"rekey probe salt"))

    old_hidden_salt = read_cleartext_header(old_vault.read_bytes())["kdf"]["hidden_salt"]
    fast_crypto.rekey_vault(old_vault, new_vault, PASSWORD, "NewPassword123!")
    new_hidden_salt = read_cleartext_header(new_vault.read_bytes())["kdf"]["hidden_salt"]

    assert old_hidden_salt == new_hidden_salt
    restored, _ = decrypt_bytes(fast_crypto, new_vault.read_bytes(), "NewPassword123!")
    assert restored == b"rekey probe salt"


def test_hidden_trial_salt_is_long_enough_for_wrong_password_hidden_probe(fast_crypto):
    vault = encrypt_normal_vault(fast_crypto, b"x" * (AES_TAG_SIZE + 1))
    header = read_cleartext_header(vault)

    decoded = base64.b64decode(header["kdf"]["hidden_salt"])
    assert len(decoded) >= MIN_SALT_SIZE
