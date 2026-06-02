import base64
import os

from crypto_core import (
    AES_KEY_SIZE,
    DerivationMixin,
    KDFParams,
    VaultCrypto,
)


def _fast_kdf(hidden_salt: str) -> KDFParams:
    # Fast Argon2 params so the test is quick; _derive_hidden_kek reads cost from
    # the KDFParams it is given (not from self), so this controls its speed.
    return KDFParams(
        salt=base64.b64encode(os.urandom(32)).decode(),
        memory=8192,
        iterations=1,
        parallelism=1,
        length=AES_KEY_SIZE,
        hidden_salt=hidden_salt,
    )


def test_derivation_methods_live_on_derivationmixin_not_vaultcrypto():
    # VaultCrypto now COMPOSES the derivation unit via inheritance...
    assert issubclass(VaultCrypto, DerivationMixin)
    # ...the two methods are DEFINED on the mixin...
    assert "_derive_kek" in DerivationMixin.__dict__
    assert "_derive_hidden_kek" in DerivationMixin.__dict__
    # ...and are NO longer defined directly on VaultCrypto (now inherited via MRO).
    assert "_derive_kek" not in VaultCrypto.__dict__
    assert "_derive_hidden_kek" not in VaultCrypto.__dict__
    assert callable(VaultCrypto._derive_kek)
    assert callable(VaultCrypto._derive_hidden_kek)


def test_derive_kek_is_deterministic_via_inherited_path(fast_crypto):
    salt = os.urandom(32)
    kek = fast_crypto._derive_kek("correct horse battery", salt)
    assert isinstance(kek, bytes) and len(kek) == AES_KEY_SIZE
    assert fast_crypto._derive_kek("correct horse battery", salt) == kek   # deterministic
    assert fast_crypto._derive_kek("wrong horse battery", salt) != kek     # password-sensitive


def test_derive_hidden_kek_both_branches_via_inherited_path(fast_crypto):
    real_kdf = _fast_kdf(hidden_salt=base64.b64encode(os.urandom(32)).decode())
    hk_real = fast_crypto._derive_hidden_kek("pw", real_kdf)
    assert isinstance(hk_real, bytes) and len(hk_real) == AES_KEY_SIZE

    # M2 constant-work branch: an EMPTY hidden_salt still yields a 32-byte KEK,
    # derived over a deterministic dummy salt, so the work is identical to the
    # real hidden case (this is what makes normal vs hidden timing-indistinguishable).
    dummy_kdf = KDFParams(
        salt=real_kdf.salt,
        memory=8192,
        iterations=1,
        parallelism=1,
        length=AES_KEY_SIZE,
        hidden_salt="",
    )
    hk_dummy = fast_crypto._derive_hidden_kek("pw", dummy_kdf)
    assert isinstance(hk_dummy, bytes) and len(hk_dummy) == AES_KEY_SIZE
    assert hk_real != hk_dummy
