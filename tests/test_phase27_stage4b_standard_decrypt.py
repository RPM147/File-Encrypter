import io

import pytest

from crypto_core import AuthenticationError, StandardVaultMixin, VaultCrypto


def test_both_stream_methods_now_live_on_standardvaultmixin():
    assert issubclass(VaultCrypto, StandardVaultMixin)
    # Both standard-vault stream methods now live on the mixin...
    assert "encrypt_stream" in StandardVaultMixin.__dict__
    assert "decrypt_stream" in StandardVaultMixin.__dict__
    # ...and neither is defined directly on VaultCrypto anymore (inherited via MRO).
    assert "encrypt_stream" not in VaultCrypto.__dict__
    assert "decrypt_stream" not in VaultCrypto.__dict__
    assert callable(VaultCrypto.decrypt_stream)


def test_standard_round_trip_via_inherited_paths(fast_crypto):
    plaintext = b"standard vault stage 4b payload"
    out = io.BytesIO()
    fast_crypto.encrypt_stream(
        input_stream=io.BytesIO(plaintext),
        output_stream=out,
        password="pw-4b",
        original_filename="d.txt",
        original_size=len(plaintext),
        metadata={"source_type": "file"},
    )

    restored = io.BytesIO()
    header = fast_crypto.decrypt_stream(io.BytesIO(out.getvalue()), restored, "pw-4b")

    assert restored.getvalue() == plaintext
    assert header.payload.filename == "d.txt"


def test_decrypt_stream_wrong_password_raises(fast_crypto):
    plaintext = b"secret"
    out = io.BytesIO()
    fast_crypto.encrypt_stream(
        input_stream=io.BytesIO(plaintext),
        output_stream=out,
        password="right-pw",
        original_filename="d.txt",
        original_size=len(plaintext),
        metadata={"source_type": "file"},
    )

    with pytest.raises(AuthenticationError):
        fast_crypto.decrypt_stream(io.BytesIO(out.getvalue()), io.BytesIO(), "wrong-pw")
