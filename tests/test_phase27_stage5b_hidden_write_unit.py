import io

import pytest

from crypto_core import HiddenVaultMixin, VaultCrypto

DECOY_PW = "DecoyPassword123!"
HIDDEN_PW = "HiddenPassword456!"


def _make_hidden(crypto, decoy=b"decoy payload 5b", hidden=b"hidden payload 5b"):
    out = io.BytesIO()
    crypto.encrypt_hidden_vault(
        decoy_input_stream=io.BytesIO(decoy),
        hidden_input_stream=io.BytesIO(hidden),
        output_stream=out,
        password_a=DECOY_PW,
        password_b=HIDDEN_PW,
        target_total_size=0,
        decoy_filename="decoy.bin",
        hidden_filename="hidden.bin",
        decoy_metadata={"source_type": "file"},
        hidden_metadata={"source_type": "file"},
        target_container_mb=0,
    )
    return out.getvalue()


def _decrypt(crypto, vault, password):
    out = io.BytesIO()
    header = crypto.decrypt_stream(io.BytesIO(vault), out, password=password)
    return out.getvalue(), header


def test_whole_hidden_vault_unit_now_lives_on_hiddenvaultmixin():
    assert issubclass(VaultCrypto, HiddenVaultMixin)
    for name in ("_derive_hidden_offset", "_open_hidden_vault", "_try_hidden_vault", "encrypt_hidden_vault"):
        assert name in HiddenVaultMixin.__dict__
        assert name not in VaultCrypto.__dict__
    assert callable(VaultCrypto.encrypt_hidden_vault)


def test_hidden_vault_create_and_open_via_inherited_path(fast_crypto):
    decoy, hidden = b"decoy payload 5b", b"hidden payload 5b"
    vault = _make_hidden(fast_crypto, decoy, hidden)

    decoy_out, decoy_header = _decrypt(fast_crypto, vault, DECOY_PW)
    assert decoy_out == decoy
    assert decoy_header.payload.filename == "decoy.bin"

    hidden_out, hidden_header = _decrypt(fast_crypto, vault, HIDDEN_PW)
    assert hidden_out == hidden
    assert hidden_header.payload.filename == "hidden.bin"


def test_encrypt_hidden_vault_rejects_equal_passwords(fast_crypto):
    out = io.BytesIO()
    with pytest.raises(ValueError):
        fast_crypto.encrypt_hidden_vault(
            decoy_input_stream=io.BytesIO(b"a"),
            hidden_input_stream=io.BytesIO(b"b"),
            output_stream=out,
            password_a="SamePassword123!",
            password_b="SamePassword123!",
            target_total_size=0,
            decoy_filename="d.bin",
            hidden_filename="h.bin",
            target_container_mb=0,
        )
