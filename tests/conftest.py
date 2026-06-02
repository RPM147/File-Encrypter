import pytest

from crypto_core import VaultCrypto


@pytest.fixture
def fast_crypto() -> VaultCrypto:
    return VaultCrypto(
        argon_memory=8192,
        argon_iterations=1,
        argon_parallelism=1,
    )
