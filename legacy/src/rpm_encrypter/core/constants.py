"""Cryptographic and vault format constants for RPM Encrypter."""

# Vault file format identifiers
VAULT_MAGIC = b"RPMV"       # 4-byte magic for file type identification
VAULT_VERSION = 4           # On-disk vault format version this app writes.

# Vault compatibility policy (COMPAT-01): this application reads and writes
# ONLY format v4. Earlier development formats (v1/v2/v3) were never released and
# are NOT supported; any other version byte is rejected cleanly as unsupported.
# This frozenset + helper are the SINGLE SOURCE OF TRUTH for version support;
# every reader gates on is_supported_vault_version().
SUPPORTED_VAULT_VERSIONS = frozenset({VAULT_VERSION})


def is_supported_vault_version(version: int) -> bool:
    """Single source of truth for vault-version support (policy: v4 only)."""
    return version in SUPPORTED_VAULT_VERSIONS


# AES-256-GCM constants
AES_KEY_SIZE = 32           # 256 bits (32 bytes)
AES_NONCE_SIZE = 12         # 96 bits recommended for GCM (maximizes safe payload length)
AES_TAG_SIZE = 16           # 128-bit authentication tag (standard for GCM)

# Argon2id parameters (OWASP recommended baseline for high-security applications)
ARGON2_MEMORY_COST = 65536  # 64 MiB
ARGON2_TIME_COST = 3        # 3 iterations
ARGON2_PARALLELISM = 4      # 4 parallel lanes
ARGON2_HASH_LENGTH = 32     # 256-bit KEK output

# ------------------------------------------------------------------------------
# KDF PARAMETER BOUNDS (Phase 7 / SEC-05)
# ------------------------------------------------------------------------------
# Attacker-controlled Argon2 parameters from a vault header are validated against
# this policy BEFORE any derivation, to prevent a denial-of-service (e.g. a vault
# demanding tens of GiB of memory). The range is deliberately WIDER than the
# Settings UI offers (16 MiB-512 MiB / 1-10 / 1-16) and also accepts the fast test
# fixture (8 MiB / 1 / 1), so the app can always open any vault it could create.
MIN_ARGON2_MEMORY = 8192             # 8 MiB  (KiB) - fast_crypto floor; rejects tiny/0/neg
MAX_ARGON2_MEMORY = 4 * 1024 * 1024  # 4 GiB  (KiB) - well above the 512 MiB UI max; rejects OOM/DoS
MIN_ARGON2_TIME = 1                  # Argon2 floor; UI + fast fixture min
MAX_ARGON2_TIME = 64                 # generous over the UI max of 10
MIN_ARGON2_PARALLELISM = 1           # Argon2 floor; UI + fast fixture min
MAX_ARGON2_PARALLELISM = 64          # generous over the UI max of 16
# Hash length is pinned to exactly AES_KEY_SIZE (32) in _validate_kdf_params.

# Streaming chunk size: 1 MiB is optimal for modern SSD/NVMe
CHUNK_SIZE = 1 * 1024 * 1024  # 1048576 bytes

# Security constraints
MIN_SALT_SIZE = 32          # 256 bits (upgraded from 16)
MAX_HEADER_SIZE = 1048576   # 1 MiB sanity limit
MAX_FILENAME_LEN = 255
MAX_METADATA_FIELDS = 100
MAX_FIELD_VALUE_LEN = 10000

# ------------------------------------------------------------------------------
# MAX PAYLOAD SIZE (Phase 8 / SEC-06)
# ------------------------------------------------------------------------------
# A single AES-256-GCM stream (96-bit nonce -> 32-bit counter) can safely cover at
# most 2^36 bytes = 64 GiB of plaintext before the counter wraps and keystream is
# reused. The v4 format encrypts each payload as ONE GCM stream, so we cap the
# plaintext payload at 32 GiB -- exactly half the structural ceiling (2x margin).
# This bounds the PLAINTEXT (original_size); trailing random padding up to
# container_size is NOT part of the GCM stream and is unaffected.
MAX_PAYLOAD_SIZE = 32 * 1024 * 1024 * 1024  # 32 GiB
