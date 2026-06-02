import io

from crypto_core import StandardVaultMixin, VaultCrypto


def test_encrypt_stream_lives_on_standardvaultmixin_not_vaultcrypto():
    # VaultCrypto now COMPOSES the standard-vault encrypt path via inheritance...
    assert issubclass(VaultCrypto, StandardVaultMixin)
    assert "encrypt_stream" in StandardVaultMixin.__dict__
    # ...and it is NO longer defined directly on VaultCrypto (now inherited via MRO).
    assert "encrypt_stream" not in VaultCrypto.__dict__
    assert callable(VaultCrypto.encrypt_stream)
    # decrypt_stream moved to StandardVaultMixin in Stage 4b (now inherited, not on VaultCrypto).
    assert "decrypt_stream" not in VaultCrypto.__dict__


def test_encrypt_stream_round_trips_via_inherited_path(fast_crypto):
    plaintext = b"standard vault stage 4a payload"
    out = io.BytesIO()
    fast_crypto.encrypt_stream(
        input_stream=io.BytesIO(plaintext),
        output_stream=out,
        password="pw-4a",
        original_filename="s.txt",
        original_size=len(plaintext),
        metadata={"source_type": "file"},
    )

    restored = io.BytesIO()
    header = fast_crypto.decrypt_stream(io.BytesIO(out.getvalue()), restored, "pw-4a")

    assert restored.getvalue() == plaintext
    assert header.payload.filename == "s.txt"   # decrypt re-attaches the filename from encrypted metadata
