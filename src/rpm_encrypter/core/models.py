"""Dataclass models describing the RPM Vault v4 header."""

from dataclasses import dataclass
from typing import Optional

from .constants import (
    ARGON2_HASH_LENGTH,
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    ARGON2_TIME_COST,
    CHUNK_SIZE,
)


@dataclass
class KDFParams:
    """
    Argon2id parameters stored in the vault header.

    Storing these alongside the salt ensures that future versions of the
    application can always reconstruct the KEK with the exact same parameters
    that were used during vault creation.

    Phase 2 deniability note: ``hidden_salt`` is always populated. For
    hidden-bearing vaults it is the real hidden KEK salt; for normal vaults it
    is a random probe salt so the cleartext header shape does not reveal
    hidden-vault existence.
    """
    algorithm: str = "Argon2id"
    salt: str = ""           # base64-encoded random salt (minimum 256 bits)
    memory: int = ARGON2_MEMORY_COST
    iterations: int = ARGON2_TIME_COST
    parallelism: int = ARGON2_PARALLELISM
    length: int = ARGON2_HASH_LENGTH
    hidden_salt: str = ""    # base64 hidden-trial salt; real for hidden vaults, random probe for normal vaults


@dataclass
class EnvelopeParams:
    """
    Envelope encryption metadata for the Data Encryption Key (DEK).

    The DEK is encrypted with AES-256-GCM using the KEK. A unique nonce is
    generated for this operation and never reused across vaults.
    """
    algorithm: str = "AES-256-GCM"
    dek_nonce: str = ""      # base64-encoded 12-byte nonce
    encrypted_dek: str = ""  # base64-encoded ciphertext + 16-byte auth tag
    recovery_salt: str = ""  # base64-encoded independent salt for the recovery KEK


@dataclass
class PayloadParams:
    """
    Payload stream encryption metadata.

    The actual file/folder archive is encrypted with AES-256-GCM using the DEK.
    A separate nonce is used for the payload to ensure cryptographic isolation
    between the envelope and the payload.

    F1 FIX: ``filename`` and ``metadata`` are NO LONGER stored here. They live
    in a separate AES-256-GCM block encrypted with the DEK (see
    ``VaultHeader.encrypted_meta_nonce``), so the cleartext header leaks neither
    the original name nor the file manifest.

    C2 FIX (format v4): ``original_size`` is ALSO removed from the cleartext
    header -- the true payload size is a deniability/size-leak vector, so it now
    lives ONLY inside the encrypted metadata block. The cleartext header instead
    carries ``container_size``: the bucketed, padded on-disk file size (a value
    on the 1.25x size ladder). Every vault is padded with random bytes up to its
    ``container_size`` so the file length carries no signal about the real
    payload size.

    After a successful decrypt, ``filename``, ``metadata`` and ``original_size``
    are re-attached to this object as plain instance attributes for the UI;
    because they are not declared fields, ``asdict`` never serialises them back
    into the cleartext header.
    """
    algorithm: str = "AES-256-GCM"
    nonce: str = ""          # base64-encoded 12-byte nonce for payload stream
    chunk_size: int = CHUNK_SIZE
    container_size: int = 0  # C2 FIX: bucketed/padded on-disk size in bytes (cleartext, display-only)


@dataclass
class VaultHeader:
    """Complete vault header container."""
    kdf: KDFParams
    envelope: EnvelopeParams
    payload: PayloadParams
    recovery_envelope: Optional[EnvelopeParams] = None
    encrypted_meta_nonce: str = ""  # F1 FIX: base64-encoded 12-byte nonce for the encrypted metadata block
