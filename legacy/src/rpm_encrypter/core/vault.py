"""VaultCrypto facade composing all cryptographic mixins."""

import io
import logging
import math
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from .constants import (
    AES_KEY_SIZE,
    AES_NONCE_SIZE,
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    ARGON2_TIME_COST,
    MAX_ARGON2_MEMORY,
    MAX_ARGON2_PARALLELISM,
    MAX_ARGON2_TIME,
    MIN_ARGON2_MEMORY,
    MIN_ARGON2_PARALLELISM,
    MIN_ARGON2_TIME,
)
from .envelope import EnvelopeMixin
from .header import HeaderMixin
from .hidden import HiddenVaultMixin
from .kdf import DerivationMixin
from .models import VaultHeader
from .rekey import RekeyMixin
from .standard import StandardVaultMixin
from .verify import VerifyMixin

logger = logging.getLogger(__name__)


class VaultCrypto(
    HeaderMixin,
    EnvelopeMixin,
    DerivationMixin,
    StandardVaultMixin,
    HiddenVaultMixin,
    VerifyMixin,
    RekeyMixin,
):
    """High-level, thread-safe cryptographic engine for RPM Vault operations."""

    # --- Hidden Vault Constants ---
    HIDDEN_SALT_SUFFIX = b"RPM_HIDDEN_SALT"
    HIDDEN_OFFSET_MSG = b"RPM_OFFSET"
    HIDDEN_MINI_HEADER_SIZE = 512
    HIDDEN_MINI_HEADER_CIPHERTEXT_SIZE = 512 + 16
    HIDDEN_MINI_HEADER_NONCE_SIZE = 12
    HIDDEN_TOTAL_HEADER_BYTES = 12 + 512 + 16
    HIDDEN_INTERNAL_MAGIC = b"RPMH"
    HIDDEN_INTERNAL_VERSION = 1
    HIDDEN_MINI_FIXED_HEADER_SIZE = 4 + 1 + 3 + 4 + AES_KEY_SIZE + AES_NONCE_SIZE + AES_NONCE_SIZE
    HIDDEN_METADATA_AAD = b"RPM_ENCRYPTER_HIDDEN_METADATA_V1"

    def __init__(
        self,
        argon_memory: int = ARGON2_MEMORY_COST,
        argon_iterations: int = ARGON2_TIME_COST,
        argon_parallelism: int = ARGON2_PARALLELISM,
    ):
        def _clamp(name, value, lo, hi, default):
            if isinstance(value, bool) or not isinstance(value, int):
                logger.warning("Argon2 %s is not an int (%r); using default %d", name, value, default)
                return default
            if value < lo:
                logger.warning("Argon2 %s %d below policy min %d; clamping", name, value, lo)
                return lo
            if value > hi:
                logger.warning("Argon2 %s %d above policy max %d; clamping", name, value, hi)
                return hi
            return value

        self.argon_memory = _clamp(
            "memory", argon_memory, MIN_ARGON2_MEMORY, MAX_ARGON2_MEMORY, ARGON2_MEMORY_COST
        )
        self.argon_iterations = _clamp(
            "iterations", argon_iterations, MIN_ARGON2_TIME, MAX_ARGON2_TIME, ARGON2_TIME_COST
        )
        self.argon_parallelism = _clamp(
            "parallelism",
            argon_parallelism,
            MIN_ARGON2_PARALLELISM,
            MAX_ARGON2_PARALLELISM,
            ARGON2_PARALLELISM,
        )

    @staticmethod
    def _secure_random(size: int) -> bytes:
        """Generate cryptographically secure random bytes using the OS CSPRNG."""
        return os.urandom(size)

    @staticmethod
    def _calculate_container_size(total_size: int, min_container_mb: int = 0) -> int:
        """Snap a vault's on-disk size to a shared 1.25x ladder bucket."""
        min_bytes = min_container_mb * 1024 * 1024
        target = max(total_size, min_bytes)

        if target > 10 * 1024 * 1024 * 1024:
            gb = 1024 * 1024 * 1024
            return ((target + gb - 1) // gb) * gb

        bucket = 1 * 1024 * 1024
        while bucket < target:
            bucket = int(math.ceil(bucket * 1.25))
        return bucket

    def encrypt_file(
        self,
        input_path: Path,
        output_path: Path,
        password: str,
        original_filename: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        recovery_key: Optional[bytes] = None,
        target_container_mb: int = 0,
        cancel_check: Optional[Callable[[], bool]] = None,
    ) -> None:
        """Convenience wrapper to encrypt a file on disk into a .vault file."""
        src_path = Path(input_path)
        dst_path = Path(output_path)
        size = src_path.stat().st_size
        name = original_filename or src_path.name

        with open(src_path, 'rb') as f_in, open(dst_path, 'wb') as f_out:
            self.encrypt_stream(
                f_in,
                f_out,
                password,
                name,
                size,
                metadata,
                progress_callback,
                recovery_key,
                target_container_mb=target_container_mb,
                cancel_check=cancel_check,
            )

    def decrypt_file(
        self,
        input_path: Path,
        output_path: Path,
        password: Optional[str] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        recovery_key: Optional[bytes] = None,
        cancel_check: Optional[Callable[[], bool]] = None,
    ) -> VaultHeader:
        """Convenience wrapper to decrypt a .vault file back to its original form."""
        with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            return self.decrypt_stream(
                f_in,
                f_out,
                password,
                progress_callback,
                recovery_key,
                cancel_check=cancel_check,
            )

    def encrypt_note(
        self,
        note_text: str,
        output_path: Path,
        password: str,
        note_title: str = "Encrypted Note",
        recovery_key: Optional[bytes] = None,
    ) -> None:
        """Convenience wrapper to encrypt raw text directly into a .vault file."""
        raw_bytes = note_text.encode('utf-8')
        src_stream = io.BytesIO(raw_bytes)
        dst_path = Path(output_path)

        metadata = {
            "source_type": "note",
            "file_count": 1,
            "created_at": datetime.now().isoformat(),
        }

        with open(dst_path, 'wb') as f_out:
            self.encrypt_stream(
                input_stream=src_stream,
                output_stream=f_out,
                password=password,
                original_filename=note_title,
                original_size=len(raw_bytes),
                metadata=metadata,
                recovery_key=recovery_key,
            )

    def decrypt_note(
        self,
        input_path: Path,
        password: Optional[str] = None,
        recovery_key: Optional[bytes] = None,
    ) -> str:
        """Convenience wrapper to decrypt a .vault file directly to a string in memory."""
        dst_stream = io.BytesIO()
        with open(input_path, 'rb') as f_in:
            self.decrypt_stream(f_in, dst_stream, password, recovery_key=recovery_key)

        return dst_stream.getvalue().decode('utf-8')
