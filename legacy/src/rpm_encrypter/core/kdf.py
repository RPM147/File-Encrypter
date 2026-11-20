"""Argon2id key derivation mixin preserving the M2 constant-work invariant."""

import base64
import hashlib
from typing import Optional

import argon2

from .constants import ARGON2_HASH_LENGTH
from .exceptions import AuthenticationError
from .models import KDFParams


class DerivationMixin:
    """Argon2id key-derivation methods for main and hidden KEKs."""

    def _derive_kek(
        self,
        password: str,
        salt: bytes,
        memory_cost: Optional[int] = None,
        time_cost: Optional[int] = None,
        parallelism: Optional[int] = None,
        hash_len: Optional[int] = None,
    ) -> bytes:
        """
        Derive the Key Encryption Key (KEK) from a user password and salt.

        Uses `hash_secret_raw` to obtain raw bytes suitable for AES-256.
        """
        kek = argon2.low_level.hash_secret_raw(
            secret=password.encode('utf-8'),
            salt=salt,
            memory_cost=memory_cost if memory_cost is not None else self.argon_memory,
            time_cost=time_cost if time_cost is not None else self.argon_iterations,
            parallelism=parallelism if parallelism is not None else self.argon_parallelism,
            hash_len=hash_len if hash_len is not None else ARGON2_HASH_LENGTH,
            type=argon2.Type.ID,
        )
        return kek

    def _derive_hidden_kek(self, password: str, main_header_kdf: KDFParams) -> bytes:
        """
        Derive the hidden-vault KEK exactly once using the visible header's KDF
        parameters.

        M2 FIX: every password unlock path must perform two Argon2 derivations.
        Normal vaults carry a random probe hidden_salt too, so a non-empty
        value is not proof of hidden data. If a malformed current-format header
        leaves it empty, derive over a deterministic dummy salt so the M2
        constant-work invariant is still preserved.
        """
        try:
            if main_header_kdf.hidden_salt:
                hidden_salt_bytes = base64.b64decode(main_header_kdf.hidden_salt)
            else:
                main_salt = base64.b64decode(main_header_kdf.salt)
                hidden_salt_bytes = hashlib.sha256(
                    main_salt + b"RPM_DUMMY_HIDDEN_SALT"
                ).digest()

            return argon2.low_level.hash_secret_raw(
                secret=password.encode('utf-8'),
                salt=hidden_salt_bytes,
                time_cost=main_header_kdf.iterations,
                memory_cost=main_header_kdf.memory,
                parallelism=main_header_kdf.parallelism,
                hash_len=main_header_kdf.length,
                type=argon2.Type.ID,
            )
        except Exception as exc:
            raise AuthenticationError("Failed to derive hidden KEK") from exc
