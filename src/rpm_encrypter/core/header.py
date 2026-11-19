"""Vault header parsing, sanitization, AAD serialization, and KDF bounds policy."""

import base64
import json
import logging
import struct
from typing import Any, BinaryIO, Dict, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .constants import (
    AES_KEY_SIZE,
    AES_NONCE_SIZE,
    AES_TAG_SIZE,
    MAX_FIELD_VALUE_LEN,
    MAX_FILENAME_LEN,
    MAX_HEADER_SIZE,
    MAX_METADATA_FIELDS,
    MAX_ARGON2_MEMORY,
    MAX_ARGON2_PARALLELISM,
    MAX_ARGON2_TIME,
    MIN_ARGON2_MEMORY,
    MIN_ARGON2_PARALLELISM,
    MIN_ARGON2_TIME,
    MIN_SALT_SIZE,
    SUPPORTED_VAULT_VERSIONS,
    VAULT_MAGIC,
    is_supported_vault_version,
)
from .exceptions import AuthenticationError, VaultFormatError
from .models import EnvelopeParams, KDFParams, PayloadParams, VaultHeader

logger = logging.getLogger(__name__)


def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent injection attacks."""
    if len(filename) > MAX_FILENAME_LEN:
        filename = filename[:MAX_FILENAME_LEN]
    dangerous_chars = ['<', '>', ':', '"', '/', '\\', '|', '?', '*', '\x00']
    for char in dangerous_chars:
        filename = filename.replace(char, '_')
    return filename


def sanitize_metadata(data: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Sanitize metadata to prevent JSON injection and oversized headers."""
    if data is None:
        return None

    if not isinstance(data, dict):
        logger.warning("Metadata is not a dict, converting to empty dict")
        return {}

    if len(data) > MAX_METADATA_FIELDS:
        logger.warning(
            "Metadata has too many fields (%d), truncating to %d",
            len(data),
            MAX_METADATA_FIELDS,
        )
        data = dict(list(data.items())[:MAX_METADATA_FIELDS])

    sanitized = {}
    for k, v in data.items():
        if not isinstance(k, str) or len(k) > 100:
            continue

        if isinstance(v, str):
            if len(v) > MAX_FIELD_VALUE_LEN:
                v = v[:MAX_FIELD_VALUE_LEN] + "...[truncated]"
        elif isinstance(v, (list, dict)):
            v = _sanitize_nested(v)

        sanitized[k] = v

    return sanitized


def _sanitize_nested(obj, depth=0, max_depth=5):
    """Recursively sanitize nested dict/list structures."""
    if depth > max_depth:
        return "[max depth exceeded]"

    if isinstance(obj, dict):
        return {
            k: _sanitize_nested(v, depth + 1, max_depth)
            for k, v in list(obj.items())[:MAX_METADATA_FIELDS]
            if isinstance(k, str)
        }
    if isinstance(obj, list):
        return [
            _sanitize_nested(item, depth + 1, max_depth)
            for item in obj[:MAX_METADATA_FIELDS]
        ]
    if isinstance(obj, str):
        return obj[:MAX_FIELD_VALUE_LEN]
    return obj


def serialize_aad(data: dict) -> bytes:
    """
    Deterministic JSON serialization for AAD.

    Ensures bit-identical output across encrypt/decrypt operations by:
    - Sorting all keys recursively
    - Using consistent separators
    - Enforcing ASCII encoding
    """
    return json.dumps(
        data,
        separators=(',', ':'),
        sort_keys=True,
        ensure_ascii=True,
    ).encode('utf-8')


def _validate_kdf_params(kdf: KDFParams) -> None:
    """
    Phase 7 (SEC-05): reject attacker-controlled Argon2 parameters that are
    non-integer, out of policy, or absurd, BEFORE any derivation. Raises
    VaultFormatError (a safe, already-UI-surfaced error). Does not leak
    secrets: these values are cleartext header fields.
    """
    def _check_int(name: str, value, lo: int, hi: int) -> None:
        # bool is a subclass of int -- reject it explicitly (a JSON `true`
        # would otherwise sneak through as 1).
        if isinstance(value, bool) or not isinstance(value, int):
            raise VaultFormatError(
                f"Vault rejected: Argon2 {name} is not an integer "
                f"({value!r}). The file is malformed or tampered."
            )
        if value < lo or value > hi:
            raise VaultFormatError(
                f"Vault rejected: Argon2 {name} ({value}) is outside the "
                f"allowed range [{lo}, {hi}]. Refusing to derive keys to "
                f"avoid resource exhaustion."
            )

    _check_int("memory", kdf.memory, MIN_ARGON2_MEMORY, MAX_ARGON2_MEMORY)
    _check_int("iterations", kdf.iterations, MIN_ARGON2_TIME, MAX_ARGON2_TIME)
    _check_int(
        "parallelism",
        kdf.parallelism,
        MIN_ARGON2_PARALLELISM,
        MAX_ARGON2_PARALLELISM,
    )
    if kdf.length != AES_KEY_SIZE:
        raise VaultFormatError(
            f"Vault rejected: KDF hash length is {kdf.length} bytes "
            f"(expected exactly {AES_KEY_SIZE})."
        )


class HeaderMixin:
    """Stateless vault-header parsing and encrypted metadata-block decoding."""

    @staticmethod
    def _read_header(input_stream: BinaryIO) -> Tuple[VaultHeader, int]:
        """
        Parse and validate the vault file header.

        Returns:
            Tuple of (VaultHeader, payload_start_offset).

        Raises:
            VaultFormatError: If magic, version, or structure is invalid.
        """
        magic = input_stream.read(len(VAULT_MAGIC))
        if magic != VAULT_MAGIC:
            raise VaultFormatError(
                f"Invalid vault magic. Expected {VAULT_MAGIC!r}, got {magic!r}. "
                f"File is not an RPM Vault or is severely corrupted."
            )

        version_data = input_stream.read(1)
        if len(version_data) != 1:
            raise VaultFormatError("Vault file truncated: missing version byte.")
        (version,) = struct.unpack('!B', version_data)
        if not is_supported_vault_version(version):
            raise VaultFormatError(
                f"Unsupported vault version {version}. This application supports "
                f"vault format version(s): {sorted(SUPPORTED_VAULT_VERSIONS)}."
            )

        header_len_data = input_stream.read(4)
        if len(header_len_data) != 4:
            raise VaultFormatError("Vault file truncated: missing header length.")
        (header_len,) = struct.unpack('!I', header_len_data)

        if header_len > MAX_HEADER_SIZE:
            raise VaultFormatError(
                f"Vault header length field ({header_len:,} bytes) exceeds the "
                f"{MAX_HEADER_SIZE:,} byte sanity limit. File is malformed or malicious."
            )

        header_json = input_stream.read(header_len)
        if len(header_json) != header_len:
            raise VaultFormatError(
                f"Vault file truncated: expected {header_len} header bytes, "
                f"got {len(header_json)}."
            )

        try:
            header_dict = json.loads(header_json.decode('utf-8'))
            header = VaultHeader(
                kdf=KDFParams(**header_dict['kdf']),
                envelope=EnvelopeParams(**header_dict['envelope']),
                payload=PayloadParams(**header_dict['payload']),
                encrypted_meta_nonce=header_dict.get('encrypted_meta_nonce', ''),
            )
            if 'recovery_envelope' in header_dict and header_dict['recovery_envelope']:
                header.recovery_envelope = EnvelopeParams(**header_dict['recovery_envelope'])
        except (json.JSONDecodeError, UnicodeDecodeError, KeyError, TypeError) as exc:
            raise VaultFormatError(f"Invalid vault header: {exc}") from exc

        try:
            salt_bytes = base64.b64decode(header.kdf.salt)
            dek_nonce_bytes = base64.b64decode(header.envelope.dek_nonce)
            enc_dek_bytes = base64.b64decode(header.envelope.encrypted_dek)
            payload_nonce_bytes = base64.b64decode(header.payload.nonce)
        except Exception as exc:
            raise VaultFormatError(f"Vault header contains invalid base64 data: {exc}") from exc

        if len(salt_bytes) < MIN_SALT_SIZE:
            raise VaultFormatError(
                f"KDF salt too short: {len(salt_bytes)} bytes (minimum {MIN_SALT_SIZE})."
            )
        if len(dek_nonce_bytes) != AES_NONCE_SIZE:
            raise VaultFormatError(
                f"DEK nonce has wrong size: {len(dek_nonce_bytes)} "
                f"(expected {AES_NONCE_SIZE})."
            )
        expected_dek_enc = AES_KEY_SIZE + AES_TAG_SIZE
        if len(enc_dek_bytes) != expected_dek_enc:
            raise VaultFormatError(
                f"Encrypted DEK has wrong size: {len(enc_dek_bytes)} "
                f"(expected {expected_dek_enc})."
            )
        if len(payload_nonce_bytes) != AES_NONCE_SIZE:
            raise VaultFormatError(
                f"Payload nonce has wrong size: {len(payload_nonce_bytes)} "
                f"(expected {AES_NONCE_SIZE})."
            )

        _validate_kdf_params(header.kdf)

        payload_offset = input_stream.tell()
        return header, payload_offset

    @staticmethod
    def _read_encrypted_metadata(
        input_stream: BinaryIO,
        offset: int,
        dek: bytes,
        encrypted_meta_nonce_b64: str,
    ) -> Tuple[dict, int]:
        """
        Read and decrypt the F1 metadata block that sits between the cleartext
        header and the payload (standard, non-hidden vaults).
        """
        input_stream.seek(offset)
        meta_len_data = input_stream.read(4)
        if len(meta_len_data) != 4:
            raise VaultFormatError("Vault file truncated: missing encrypted metadata length.")
        (meta_len,) = struct.unpack("!I", meta_len_data)
        if meta_len > MAX_HEADER_SIZE:
            raise VaultFormatError(
                f"Encrypted metadata length ({meta_len:,} bytes) exceeds the "
                f"{MAX_HEADER_SIZE:,} byte sanity limit."
            )
        encrypted_meta = input_stream.read(meta_len)
        if len(encrypted_meta) != meta_len:
            raise VaultFormatError("Vault file truncated: encrypted metadata block incomplete.")
        try:
            meta_aesgcm = AESGCM(dek)
            meta_bytes = meta_aesgcm.decrypt(
                base64.b64decode(encrypted_meta_nonce_b64), encrypted_meta, None
            )
            meta_dict = json.loads(meta_bytes.decode('utf-8'))
        except InvalidTag:
            raise AuthenticationError(
                "Encrypted metadata integrity check failed. The vault has been "
                "corrupted or tampered with."
            )
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise VaultFormatError(f"Invalid encrypted metadata block: {exc}") from exc
        return meta_dict, offset + 4 + meta_len
