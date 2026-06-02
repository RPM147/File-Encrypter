import io
import json
import struct
from pathlib import Path

import pytest

from crypto_core import (
    AES_TAG_SIZE,
    AuthenticationError,
    VAULT_MAGIC,
    VaultCrypto,
)


DECOY_PASSWORD = "DecoyPassword123!"
HIDDEN_PASSWORD = "HiddenPassword456!"
GENERIC_AUTH_ERROR = "Vault access denied: Invalid password or corrupted vault envelope."


def _read_cleartext_header_bytes(vault_bytes: bytes) -> bytes:
    stream = io.BytesIO(vault_bytes)
    assert stream.read(len(VAULT_MAGIC)) == VAULT_MAGIC
    assert len(stream.read(1)) == 1
    (header_len,) = struct.unpack("!I", stream.read(4))
    return stream.read(header_len)


def _read_cleartext_header(vault_bytes: bytes) -> dict:
    return json.loads(_read_cleartext_header_bytes(vault_bytes).decode("utf-8"))


def _encrypt_hidden(
    crypto: VaultCrypto,
    hidden_metadata: dict,
    decoy_plaintext: bytes = b"decoy folder placeholder",
    hidden_plaintext: bytes = b"hidden folder archive",
) -> bytes:
    out = io.BytesIO()
    crypto.encrypt_hidden_vault(
        decoy_input_stream=io.BytesIO(decoy_plaintext),
        hidden_input_stream=io.BytesIO(hidden_plaintext),
        output_stream=out,
        password_a=DECOY_PASSWORD,
        password_b=HIDDEN_PASSWORD,
        target_total_size=0,
        decoy_filename="decoy.zip",
        hidden_filename="hidden-folder.zip",
        decoy_metadata={"source_type": "folder", "manifest": [{"name": "cover.txt"}]},
        hidden_metadata=hidden_metadata,
        target_container_mb=0,
    )
    return out.getvalue()


def _decrypt(crypto: VaultCrypto, vault_bytes: bytes, password: str) -> tuple[bytes, object]:
    out = io.BytesIO()
    header = crypto.decrypt_stream(io.BytesIO(vault_bytes), out, password=password)
    return out.getvalue(), header


def _walk_keys(value):
    if isinstance(value, dict):
        for key, nested in value.items():
            yield key
            yield from _walk_keys(nested)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_keys(item)


def test_hidden_vault_accepts_large_folder_metadata_block(fast_crypto):
    hidden_plaintext = b"hidden data" * 128
    large_files = [
        {
            "path": f"folder/subfolder/file_{index:03d}.txt",
            "size": index * 17 + 3,
            "mtime": f"2026-06-01T12:{index % 60:02d}:00Z",
            "sha256": f"{index:064x}"[-64:],
        }
        for index in range(80)
    ]
    hidden_metadata = {
        "source_type": "folder",
        "root": "private-folder",
        "files": large_files,
    }

    assert len(json.dumps(hidden_metadata).encode("utf-8")) > 512 - 32 - 12

    vault = _encrypt_hidden(fast_crypto, hidden_metadata, hidden_plaintext=hidden_plaintext)

    decoy_out, decoy_header = _decrypt(fast_crypto, vault, DECOY_PASSWORD)
    assert decoy_out == b"decoy folder placeholder"
    assert decoy_header.payload.filename == "decoy.zip"

    hidden_out, hidden_header = _decrypt(fast_crypto, vault, HIDDEN_PASSWORD)
    assert hidden_out == hidden_plaintext
    assert hidden_header.payload.filename == "hidden-folder.zip"
    assert hidden_header.payload.metadata == hidden_metadata


def test_cleartext_headers_do_not_expose_hidden_layout_keys(fast_crypto):
    forbidden_keys = {
        "has_hidden",
        "hidden_metadata",
        "hidden_meta",
        "hidden_offset",
        "hidden_payload_offset",
        "hidden_metadata_len",
        "hidden_meta_len",
    }

    normal_out = io.BytesIO()
    fast_crypto.encrypt_stream(
        input_stream=io.BytesIO(b"normal"),
        output_stream=normal_out,
        password=DECOY_PASSWORD,
        original_filename="normal.txt",
        original_size=len(b"normal"),
        metadata={"source_type": "file"},
    )
    hidden_vault = _encrypt_hidden(
        fast_crypto,
        {"source_type": "folder", "files": [{"path": "secret.txt", "size": 9, "mtime": "2026-06-01T12:00:00Z"}]},
    )

    for vault_bytes in (normal_out.getvalue(), hidden_vault):
        header = _read_cleartext_header(vault_bytes)
        assert header["kdf"]["hidden_salt"]
        assert forbidden_keys.isdisjoint(set(_walk_keys(header)))


def test_old_hidden_metadata_mini_header_capacity_check_is_gone():
    source = (Path(__file__).resolve().parents[1] / "crypto_core.py").read_text(encoding="utf-8")
    assert "Hidden metadata too large for mini-header" not in source
    assert "512 - 32 - 12" not in source


def test_tampered_hidden_metadata_block_rejects_hidden_password(fast_crypto):
    hidden_metadata = {
        "source_type": "folder",
        "files": [
            {"path": f"secret_{index}.bin", "size": index, "mtime": "2026-06-01T12:00:00Z"}
            for index in range(20)
        ],
    }
    vault = bytearray(_encrypt_hidden(fast_crypto, hidden_metadata))
    hidden_offset = fast_crypto._derive_hidden_offset(HIDDEN_PASSWORD, len(vault))
    hidden_meta_offset = hidden_offset + fast_crypto.HIDDEN_TOTAL_HEADER_BYTES
    assert hidden_meta_offset + AES_TAG_SIZE < len(vault)
    vault[hidden_meta_offset] ^= 0x01

    decoy_out, _ = _decrypt(fast_crypto, bytes(vault), DECOY_PASSWORD)
    assert decoy_out == b"decoy folder placeholder"

    with pytest.raises(AuthenticationError) as exc:
        _decrypt(fast_crypto, bytes(vault), HIDDEN_PASSWORD)
    assert str(exc.value) == GENERIC_AUTH_ERROR
