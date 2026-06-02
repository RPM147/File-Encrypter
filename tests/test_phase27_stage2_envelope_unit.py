import os

import pytest

from crypto_core import (
    AES_KEY_SIZE,
    AuthenticationError,
    EnvelopeMixin,
    VaultCrypto,
)


def test_envelope_methods_live_on_envelopemixin_not_vaultcrypto():
    # VaultCrypto now COMPOSES the DEK-envelope unit via inheritance...
    assert issubclass(VaultCrypto, EnvelopeMixin)
    # ...the two methods are DEFINED on the mixin...
    assert "_encrypt_dek" in EnvelopeMixin.__dict__
    assert "_decrypt_dek" in EnvelopeMixin.__dict__
    # ...and are NO longer defined directly on VaultCrypto (now inherited via MRO).
    assert "_encrypt_dek" not in VaultCrypto.__dict__
    assert "_decrypt_dek" not in VaultCrypto.__dict__
    # Back-compat: existing `self._encrypt_dek(...)` / `VaultCrypto._encrypt_dek(...)` callers still work.
    assert callable(VaultCrypto._encrypt_dek)
    assert callable(VaultCrypto._decrypt_dek)


def test_dek_envelope_round_trips_via_class_and_mixin():
    kek = os.urandom(AES_KEY_SIZE)
    dek = os.urandom(AES_KEY_SIZE)

    # Encrypt via the class (inherited), decrypt via the mixin (origin): identical behavior.
    nonce, ciphertext = VaultCrypto._encrypt_dek(dek, kek)
    assert EnvelopeMixin._decrypt_dek(ciphertext, nonce, kek) == dek

    # And the reverse pairing.
    nonce2, ciphertext2 = EnvelopeMixin._encrypt_dek(dek, kek)
    assert VaultCrypto._decrypt_dek(ciphertext2, nonce2, kek) == dek


def test_decrypt_dek_rejects_wrong_kek():
    kek = os.urandom(AES_KEY_SIZE)
    wrong_kek = os.urandom(AES_KEY_SIZE)
    dek = os.urandom(AES_KEY_SIZE)

    nonce, ciphertext = VaultCrypto._encrypt_dek(dek, kek)
    with pytest.raises(AuthenticationError):
        VaultCrypto._decrypt_dek(ciphertext, nonce, wrong_kek)
