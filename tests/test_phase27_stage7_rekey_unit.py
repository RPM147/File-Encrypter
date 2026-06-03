import io

import pytest

from crypto_core import AuthenticationError, RekeyMixin, VaultCrypto

PW = "RekeyOldPassword123!"
NEW_PW = "RekeyNewPassword456!"


def _write_vault(crypto, path, plaintext=b"rekey unit payload abc"):
    out = io.BytesIO()
    crypto.encrypt_stream(
        input_stream=io.BytesIO(plaintext),
        output_stream=out,
        password=PW,
        original_filename="r.txt",
        original_size=len(plaintext),
        metadata={"source_type": "file"},
    )
    path.write_bytes(out.getvalue())
    return plaintext


def test_rekey_lives_on_rekeymixin_not_vaultcrypto():
    assert issubclass(VaultCrypto, RekeyMixin)
    assert "rekey_vault" in RekeyMixin.__dict__
    assert "rekey_vault" not in VaultCrypto.__dict__
    assert callable(VaultCrypto.rekey_vault)


def test_rekey_changes_password_and_preserves_payload(tmp_path, fast_crypto):
    old_vault = tmp_path / "old.vault"
    new_vault = tmp_path / "new.vault"
    plaintext = _write_vault(fast_crypto, old_vault)

    fast_crypto.rekey_vault(old_vault, new_vault, PW, NEW_PW)

    # The new password decrypts the re-keyed vault to the identical payload.
    restored = io.BytesIO()
    header = fast_crypto.decrypt_stream(io.BytesIO(new_vault.read_bytes()), restored, NEW_PW)
    assert restored.getvalue() == plaintext
    assert header.payload.filename == "r.txt"

    # The old password no longer opens the re-keyed vault.
    with pytest.raises(AuthenticationError):
        fast_crypto.decrypt_stream(io.BytesIO(new_vault.read_bytes()), io.BytesIO(), PW)


def test_arch02_end_state_vaultcrypto_is_a_thin_shell_plus_facade():
    # End state of Phase 27 (ARCH-02): every heavy operation now lives on a mixin;
    # VaultCrypto keeps only the constructor, the shared utilities, the HIDDEN_*
    # constants, and the thin high-level wrappers (the public facade).
    own = set(VaultCrypto.__dict__)
    assert {
        "__init__",
        "_secure_random",
        "_calculate_container_size",
        "encrypt_file",
        "decrypt_file",
        "encrypt_note",
        "decrypt_note",
    } <= own
    for moved in (
        "_read_header",
        "_encrypt_dek",
        "_decrypt_dek",
        "_derive_kek",
        "_derive_hidden_kek",
        "encrypt_stream",
        "decrypt_stream",
        "_open_hidden_vault",
        "encrypt_hidden_vault",
        "verify_password_and_get_header",
        "rekey_vault",
    ):
        assert moved not in own
