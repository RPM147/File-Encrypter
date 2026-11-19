"""DEK envelope encryption/decryption helpers."""

from typing import Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .constants import AES_KEY_SIZE, AES_NONCE_SIZE
from .exceptions import AuthenticationError


class EnvelopeMixin:
    """Stateless AES-256-GCM wrap/unwrap of the DEK under a derived KEK."""

    @staticmethod
    def _encrypt_dek(dek: bytes, kek: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt the DEK using AES-256-GCM with the KEK.

        Args:
            dek: 32-byte Data Encryption Key.
            kek: 32-byte Key Encryption Key.

        Returns:
            Tuple of (nonce, ciphertext_with_tag).
        """
        from .vault import VaultCrypto

        nonce = VaultCrypto._secure_random(AES_NONCE_SIZE)
        aesgcm = AESGCM(kek)
        ciphertext = aesgcm.encrypt(nonce, dek, None)
        return nonce, ciphertext

    @staticmethod
    def _decrypt_dek(encrypted_dek: bytes, nonce: bytes, kek: bytes) -> bytes:
        """Decrypt the DEK. Raises AuthenticationError on any integrity failure."""
        aesgcm = AESGCM(kek)
        try:
            dek = aesgcm.decrypt(nonce, encrypted_dek, None)
        except InvalidTag:
            raise AuthenticationError(
                "DEK decryption failed: invalid password or corrupted vault envelope."
            ) from None
        if len(dek) != AES_KEY_SIZE:
            raise AuthenticationError(
                f"DEK has unexpected length {len(dek)} (expected {AES_KEY_SIZE}). "
                f"Vault envelope is corrupted."
            )
        return dek
