"""Public exports for the RPM Encrypter cryptographic core."""

from .constants import (
    AES_KEY_SIZE,
    AES_NONCE_SIZE,
    AES_TAG_SIZE,
    ARGON2_HASH_LENGTH,
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    ARGON2_TIME_COST,
    CHUNK_SIZE,
    MAX_ARGON2_MEMORY,
    MAX_ARGON2_PARALLELISM,
    MAX_ARGON2_TIME,
    MAX_FIELD_VALUE_LEN,
    MAX_FILENAME_LEN,
    MAX_HEADER_SIZE,
    MAX_METADATA_FIELDS,
    MAX_PAYLOAD_SIZE,
    MIN_ARGON2_MEMORY,
    MIN_ARGON2_PARALLELISM,
    MIN_ARGON2_TIME,
    MIN_SALT_SIZE,
    SUPPORTED_VAULT_VERSIONS,
    VAULT_MAGIC,
    VAULT_VERSION,
    is_supported_vault_version,
)
from .envelope import EnvelopeMixin
from .exceptions import (
    AuthenticationError,
    CryptoError,
    OperationCancelledError,
    PayloadTooLargeError,
    VaultFormatError,
    _raise_if_cancelled,
)
from .header import (
    HeaderMixin,
    _validate_kdf_params,
    sanitize_filename,
    sanitize_metadata,
    serialize_aad,
)
from .hidden import HiddenVaultMixin
from .kdf import DerivationMixin
from .models import EnvelopeParams, KDFParams, PayloadParams, VaultHeader
from .recovery import entropy_to_mnemonic, generate_recovery_entropy, mnemonic_to_entropy
from .rekey import RekeyMixin
from .standard import StandardVaultMixin
from .vault import VaultCrypto
from .verify import VerifyMixin
from .wordlist import WORDLIST

__all__ = [
    "AES_KEY_SIZE",
    "AES_NONCE_SIZE",
    "AES_TAG_SIZE",
    "ARGON2_HASH_LENGTH",
    "ARGON2_MEMORY_COST",
    "ARGON2_PARALLELISM",
    "ARGON2_TIME_COST",
    "CHUNK_SIZE",
    "MAX_ARGON2_MEMORY",
    "MAX_ARGON2_PARALLELISM",
    "MAX_ARGON2_TIME",
    "MAX_FIELD_VALUE_LEN",
    "MAX_FILENAME_LEN",
    "MAX_HEADER_SIZE",
    "MAX_METADATA_FIELDS",
    "MAX_PAYLOAD_SIZE",
    "MIN_ARGON2_MEMORY",
    "MIN_ARGON2_PARALLELISM",
    "MIN_ARGON2_TIME",
    "MIN_SALT_SIZE",
    "SUPPORTED_VAULT_VERSIONS",
    "VAULT_MAGIC",
    "VAULT_VERSION",
    "is_supported_vault_version",
    "AuthenticationError",
    "CryptoError",
    "OperationCancelledError",
    "PayloadTooLargeError",
    "VaultFormatError",
    "_raise_if_cancelled",
    "EnvelopeParams",
    "KDFParams",
    "PayloadParams",
    "VaultHeader",
    "HeaderMixin",
    "EnvelopeMixin",
    "DerivationMixin",
    "StandardVaultMixin",
    "HiddenVaultMixin",
    "VerifyMixin",
    "RekeyMixin",
    "VaultCrypto",
    "_validate_kdf_params",
    "sanitize_filename",
    "sanitize_metadata",
    "serialize_aad",
    "entropy_to_mnemonic",
    "generate_recovery_entropy",
    "mnemonic_to_entropy",
    "WORDLIST",
]
