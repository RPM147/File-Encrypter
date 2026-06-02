import io

import pytest

from crypto_core import (
    HeaderMixin,
    VaultCrypto,
    VaultFormatError,
)

PASSWORD = "HeaderUnitPassword123!"


def _make_vault(crypto, plaintext: bytes = b"header unit payload") -> bytes:
    out = io.BytesIO()
    crypto.encrypt_stream(
        input_stream=io.BytesIO(plaintext),
        output_stream=out,
        password=PASSWORD,
        original_filename="hdr.txt",
        original_size=len(plaintext),
        metadata={"source_type": "file"},
    )
    return out.getvalue()


def test_header_methods_live_on_headermixin_not_vaultcrypto():
    # VaultCrypto now COMPOSES the header unit via inheritance...
    assert issubclass(VaultCrypto, HeaderMixin)
    # ...the two methods are DEFINED on the mixin...
    assert "_read_header" in HeaderMixin.__dict__
    assert "_read_encrypted_metadata" in HeaderMixin.__dict__
    # ...and are NO longer defined directly on VaultCrypto (now inherited via MRO).
    assert "_read_header" not in VaultCrypto.__dict__
    assert "_read_encrypted_metadata" not in VaultCrypto.__dict__
    # Back-compat: existing `VaultCrypto._read_header(...)` callers still work.
    assert callable(VaultCrypto._read_header)
    assert callable(VaultCrypto._read_encrypted_metadata)


def test_read_header_parses_identically_via_class_and_mixin(fast_crypto):
    vault = _make_vault(fast_crypto)
    header_via_class, offset_via_class = VaultCrypto._read_header(io.BytesIO(vault))
    header_via_mixin, offset_via_mixin = HeaderMixin._read_header(io.BytesIO(vault))

    assert offset_via_class == offset_via_mixin
    assert header_via_class == header_via_mixin
    assert header_via_class.payload.container_size > 0
    # Current vault format keeps filenames inside encrypted metadata, not the clear header.
    assert not hasattr(header_via_class.payload, "filename")


def test_read_header_still_rejects_non_vault_bytes():
    with pytest.raises(VaultFormatError):
        VaultCrypto._read_header(io.BytesIO(b"this is not an RPM vault"))
