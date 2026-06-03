import io

import pytest

import crypto_core
from crypto_core import AuthenticationError, VaultCrypto, VerifyMixin

PW = "VerifyUnitPassword123!"
DECOY_PW = "DecoyPassword123!"
HIDDEN_PW = "HiddenPassword456!"


def _normal_vault(crypto, plaintext=b"verify unit payload"):
    out = io.BytesIO()
    crypto.encrypt_stream(
        input_stream=io.BytesIO(plaintext),
        output_stream=out,
        password=PW,
        original_filename="v.txt",
        original_size=len(plaintext),
        metadata={"source_type": "file"},
    )
    return out.getvalue()


def _hidden_vault(crypto, decoy=b"decoy v", hidden=b"hidden v"):
    out = io.BytesIO()
    crypto.encrypt_hidden_vault(
        decoy_input_stream=io.BytesIO(decoy),
        hidden_input_stream=io.BytesIO(hidden),
        output_stream=out,
        password_a=DECOY_PW,
        password_b=HIDDEN_PW,
        target_total_size=0,
        decoy_filename="d.bin",
        hidden_filename="h.bin",
        decoy_metadata={"source_type": "file"},
        hidden_metadata={"source_type": "file"},
        target_container_mb=0,
    )
    return out.getvalue()


def test_verify_lives_on_verifymixin_not_vaultcrypto():
    assert issubclass(VaultCrypto, VerifyMixin)
    assert "verify_password_and_get_header" in VerifyMixin.__dict__
    assert "verify_password_and_get_header" not in VaultCrypto.__dict__
    assert callable(VaultCrypto.verify_password_and_get_header)


def test_verify_returns_metadata_without_full_decrypt(fast_crypto):
    vault = _normal_vault(fast_crypto)
    header = fast_crypto.verify_password_and_get_header(io.BytesIO(vault), PW)
    assert header.payload.filename == "v.txt"
    with pytest.raises(AuthenticationError):
        fast_crypto.verify_password_and_get_header(io.BytesIO(vault), "WrongPassword!")


def test_verify_reads_hidden_metadata_via_inherited_path(fast_crypto):
    vault = _hidden_vault(fast_crypto)
    decoy_header = fast_crypto.verify_password_and_get_header(io.BytesIO(vault), DECOY_PW)
    assert decoy_header.payload.filename == "d.bin"
    hidden_header = fast_crypto.verify_password_and_get_header(io.BytesIO(vault), HIDDEN_PW)
    assert hidden_header.payload.filename == "h.bin"


def test_verify_performs_exactly_two_argon2_derivations(monkeypatch, fast_crypto):
    # M2: verify must do exactly two derivations on the password path -- the same
    # for a normal vault, a hidden vault, and a wrong password -- so it is
    # timing-indistinguishable (this mirrors the decrypt_stream M2 count guard,
    # which verify previously lacked).
    normal = _normal_vault(fast_crypto)
    hidden = _hidden_vault(fast_crypto)

    counter = {"n": 0}
    original = crypto_core.argon2.low_level.hash_secret_raw

    def counting(*args, **kwargs):
        counter["n"] += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(crypto_core.argon2.low_level, "hash_secret_raw", counting)

    counter["n"] = 0
    fast_crypto.verify_password_and_get_header(io.BytesIO(normal), PW)
    normal_count = counter["n"]

    counter["n"] = 0
    fast_crypto.verify_password_and_get_header(io.BytesIO(hidden), HIDDEN_PW)
    hidden_count = counter["n"]

    counter["n"] = 0
    with pytest.raises(AuthenticationError):
        fast_crypto.verify_password_and_get_header(io.BytesIO(normal), "WrongPassword!")
    wrong_count = counter["n"]

    assert normal_count == hidden_count == wrong_count == 2
