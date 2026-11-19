"""Hidden-vault (plausible deniability) compartment read/write mixin."""

import base64
import hashlib
import hmac
import json
import os
import struct
from typing import Any, BinaryIO, Callable, Dict, Optional, Tuple

import argon2
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .constants import (
    AES_KEY_SIZE,
    AES_NONCE_SIZE,
    AES_TAG_SIZE,
    CHUNK_SIZE,
    MAX_HEADER_SIZE,
    MAX_PAYLOAD_SIZE,
    MIN_SALT_SIZE,
)
from .exceptions import (
    AuthenticationError,
    CryptoError,
    PayloadTooLargeError,
    VaultFormatError,
    _raise_if_cancelled,
)
from .header import serialize_aad
from .models import KDFParams, VaultHeader


class HiddenVaultMixin:
    """Hidden-compartment read and write operations."""

    def _derive_hidden_offset(self, password: str, total_file_size: int) -> int:
        offset_seed = hmac.new(
            password.encode('utf-8'), self.HIDDEN_OFFSET_MSG, hashlib.sha256
        ).digest()
        offset_int = int.from_bytes(offset_seed, byteorder='big')
        if total_file_size <= self.HIDDEN_TOTAL_HEADER_BYTES:
            return 0
        return offset_int % (total_file_size - self.HIDDEN_TOTAL_HEADER_BYTES)

    def _open_hidden_vault(
        self,
        input_stream: BinaryIO,
        password: str,
        total_file_size: int,
        hidden_kek: bytes,
    ) -> Tuple[bytes, bytes, int, dict]:
        """Open a hidden compartment and return its DEK, nonce, payload offset, and metadata."""
        hidden_offset = self._derive_hidden_offset(password, total_file_size)

        input_stream.seek(hidden_offset)
        header_bytes = input_stream.read(self.HIDDEN_TOTAL_HEADER_BYTES)
        if len(header_bytes) < self.HIDDEN_TOTAL_HEADER_BYTES:
            raise AuthenticationError("Invalid hidden offset (EOF)")

        nonce = header_bytes[:self.HIDDEN_MINI_HEADER_NONCE_SIZE]
        ciphertext = header_bytes[self.HIDDEN_MINI_HEADER_NONCE_SIZE:-AES_TAG_SIZE]
        tag = header_bytes[-AES_TAG_SIZE:]

        cipher = Cipher(algorithms.AES(hidden_kek), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        try:
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        except InvalidTag:
            raise AuthenticationError("Hidden mini-header tag invalid") from None

        if len(plaintext) != self.HIDDEN_MINI_HEADER_SIZE:
            raise AuthenticationError("Invalid hidden mini-header length")

        fixed_len = self.HIDDEN_MINI_FIXED_HEADER_SIZE
        fixed = plaintext[:fixed_len]
        hidden_magic = fixed[:4]
        hidden_version = fixed[4]
        reserved = fixed[5:8]
        encrypted_meta_len = struct.unpack("!I", fixed[8:12])[0]
        hidden_dek = fixed[12:12 + AES_KEY_SIZE]
        nonce_start = 12 + AES_KEY_SIZE
        hidden_payload_nonce = fixed[nonce_start:nonce_start + AES_NONCE_SIZE]
        meta_nonce_start = nonce_start + AES_NONCE_SIZE
        hidden_meta_nonce = fixed[meta_nonce_start:meta_nonce_start + AES_NONCE_SIZE]

        if (
            hidden_magic != self.HIDDEN_INTERNAL_MAGIC
            or hidden_version != self.HIDDEN_INTERNAL_VERSION
            or reserved != b"\x00\x00\x00"
        ):
            raise AuthenticationError("Invalid hidden mini-header layout")
        if encrypted_meta_len <= AES_TAG_SIZE or encrypted_meta_len > MAX_HEADER_SIZE:
            raise AuthenticationError("Invalid hidden metadata length")

        hidden_meta_offset = hidden_offset + self.HIDDEN_TOTAL_HEADER_BYTES
        hidden_payload_offset = hidden_meta_offset + encrypted_meta_len
        if hidden_payload_offset + AES_TAG_SIZE > total_file_size:
            raise AuthenticationError("Invalid hidden metadata extent")

        input_stream.seek(hidden_meta_offset)
        encrypted_meta = input_stream.read(encrypted_meta_len)
        if len(encrypted_meta) != encrypted_meta_len:
            raise AuthenticationError("Truncated hidden metadata block")

        try:
            meta_bytes = AESGCM(hidden_dek).decrypt(
                hidden_meta_nonce,
                encrypted_meta,
                self.HIDDEN_METADATA_AAD,
            )
            metadata = json.loads(meta_bytes.decode('utf-8'))
            if not isinstance(metadata, dict):
                raise ValueError("hidden metadata must be a JSON object")
        except Exception:
            raise AuthenticationError("Invalid hidden metadata JSON") from None

        return hidden_dek, hidden_payload_nonce, hidden_payload_offset, metadata

    def _try_hidden_vault(
        self,
        input_stream: BinaryIO,
        password: str,
        total_file_size: int,
        main_header_kdf: KDFParams,
    ) -> Tuple[bytes, bytes, int, dict]:
        """Derive the hidden KEK once and open the hidden compartment."""
        hidden_kek = self._derive_hidden_kek(password, main_header_kdf)
        return self._open_hidden_vault(input_stream, password, total_file_size, hidden_kek)

    def encrypt_hidden_vault(
        self,
        decoy_input_stream: BinaryIO,
        hidden_input_stream: BinaryIO,
        output_stream: BinaryIO,
        password_a: str,
        password_b: str,
        target_total_size: int,
        decoy_filename: str,
        hidden_filename: str,
        decoy_metadata: Optional[Dict[str, Any]] = None,
        hidden_metadata: Optional[Dict[str, Any]] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        recovery_key: Optional[bytes] = None,
        target_container_mb: int = 0,
        cancel_check: Optional[Callable[[], bool]] = None,
    ) -> VaultHeader:
        """
        Create a plausible deniability vault containing both Decoy and Hidden data.

        C2 FIX (format v4): the final on-disk size is snapped to a 1.25x ladder
        bucket (>= the user's explicit ``target_container_mb`` floor), so a hidden
        vault is size-indistinguishable from a normal padded vault.
        """
        if hmac.compare_digest(password_a.encode('utf-8'), password_b.encode('utf-8')):
            raise ValueError("Decoy and Hidden passwords must be different.")

        decoy_input_stream.seek(0, os.SEEK_END)
        decoy_size = decoy_input_stream.tell()
        hidden_input_stream.seek(0, os.SEEK_END)
        hidden_size = hidden_input_stream.tell()
        decoy_input_stream.seek(0)
        hidden_input_stream.seek(0)

        if decoy_size > MAX_PAYLOAD_SIZE or hidden_size > MAX_PAYLOAD_SIZE:
            raise PayloadTooLargeError(
                f"Hidden-vault compartment too large: decoy={decoy_size:,} bytes, "
                f"hidden={hidden_size:,} bytes; each must be <= {MAX_PAYLOAD_SIZE:,} "
                f"bytes (32 GiB)."
            )

        hidden_salt_bytes = self._secure_random(MIN_SALT_SIZE)
        b64_hidden_salt = base64.b64encode(hidden_salt_bytes).decode('ascii')

        h_meta = {
            "original_size": hidden_size,
            "filename": hidden_filename,
            "metadata": hidden_metadata,
        }
        h_meta_json = json.dumps(h_meta, separators=(',', ':')).encode('utf-8')
        hidden_meta_ciphertext_len = len(h_meta_json) + AES_TAG_SIZE
        if hidden_meta_ciphertext_len > MAX_HEADER_SIZE:
            raise VaultFormatError(
                f"Hidden metadata block ({hidden_meta_ciphertext_len:,} bytes) exceeds "
                f"the {MAX_HEADER_SIZE:,} byte sanity limit."
            )

        hidden_section_total = (
            self.HIDDEN_TOTAL_HEADER_BYTES
            + hidden_meta_ciphertext_len
            + hidden_size
            + AES_TAG_SIZE
        )
        min_slack = 1024
        offset_int = int.from_bytes(
            hmac.new(password_b.encode('utf-8'), self.HIDDEN_OFFSET_MSG, hashlib.sha256).digest(),
            byteorder='big',
        )

        decoy_start = output_stream.tell()
        floor_bytes = max(int(target_total_size), target_container_mb * 1024 * 1024)
        final_container = self._calculate_container_size(
            max(floor_bytes, 1), min_container_mb=target_container_mb
        )
        decoy_header = None
        decoy_end = 0
        valid_offset = -1
        max_attempts = 10000
        for _ in range(max_attempts):
            output_stream.seek(decoy_start)
            decoy_input_stream.seek(0)
            decoy_header = self.encrypt_stream(
                input_stream=decoy_input_stream,
                output_stream=output_stream,
                password=password_a,
                original_filename=decoy_filename,
                original_size=decoy_size,
                metadata=decoy_metadata,
                progress_callback=progress_callback,
                recovery_key=recovery_key,
                hidden_salt=b64_hidden_salt,
                apply_padding=False,
                forced_container_size=final_container,
                cancel_check=cancel_check,
            )
            decoy_end = output_stream.tell()

            required_total = decoy_end + hidden_section_total + min_slack
            needed = self._calculate_container_size(
                max(required_total, floor_bytes), min_container_mb=target_container_mb
            )
            if needed > final_container:
                final_container = needed
                continue

            offset = offset_int % (final_container - self.HIDDEN_TOTAL_HEADER_BYTES)
            if offset >= decoy_end and offset + hidden_section_total <= final_container:
                valid_offset = offset
                break

            final_container = self._calculate_container_size(
                final_container + 1, min_container_mb=target_container_mb
            )

        if valid_offset < 0:
            raise CryptoError("Unable to place hidden compartment within a padded container.")

        padding_size = valid_offset - decoy_end
        if padding_size > 0:
            written = 0
            while written < padding_size:
                _raise_if_cancelled(cancel_check)
                chunk = min(CHUNK_SIZE, padding_size - written)
                output_stream.write(os.urandom(chunk))
                written += chunk

        hidden_kek = argon2.low_level.hash_secret_raw(
            secret=password_b.encode('utf-8'),
            salt=hidden_salt_bytes,
            time_cost=decoy_header.kdf.iterations,
            memory_cost=decoy_header.kdf.memory,
            parallelism=decoy_header.kdf.parallelism,
            hash_len=decoy_header.kdf.length,
            type=argon2.Type.ID,
        )

        hidden_dek = os.urandom(AES_KEY_SIZE)
        hidden_mini_nonce = os.urandom(self.HIDDEN_MINI_HEADER_NONCE_SIZE)
        hidden_payload_nonce = os.urandom(AES_NONCE_SIZE)
        hidden_meta_nonce = os.urandom(AES_NONCE_SIZE)
        hidden_meta_ciphertext = AESGCM(hidden_dek).encrypt(
            hidden_meta_nonce,
            h_meta_json,
            self.HIDDEN_METADATA_AAD,
        )

        mini_header_fixed = b"".join([
            self.HIDDEN_INTERNAL_MAGIC,
            struct.pack("!B", self.HIDDEN_INTERNAL_VERSION),
            b"\x00\x00\x00",
            struct.pack("!I", len(hidden_meta_ciphertext)),
            hidden_dek,
            hidden_payload_nonce,
            hidden_meta_nonce,
        ])
        if len(mini_header_fixed) != self.HIDDEN_MINI_FIXED_HEADER_SIZE:
            raise CryptoError("Internal hidden mini-header layout mismatch.")
        mini_header_plaintext = mini_header_fixed.ljust(self.HIDDEN_MINI_HEADER_SIZE, b'\x00')

        cipher_mini = Cipher(
            algorithms.AES(hidden_kek),
            modes.GCM(hidden_mini_nonce),
            backend=default_backend(),
        )
        encryptor_mini = cipher_mini.encryptor()
        mini_ciphertext = encryptor_mini.update(mini_header_plaintext) + encryptor_mini.finalize()
        mini_tag = encryptor_mini.tag

        output_stream.write(hidden_mini_nonce + mini_ciphertext + mini_tag)
        output_stream.write(hidden_meta_ciphertext)

        cipher_payload = Cipher(
            algorithms.AES(hidden_dek),
            modes.GCM(hidden_payload_nonce),
            backend=default_backend(),
        )
        encryptor_payload = cipher_payload.encryptor()

        payload_aad_dict = {
            "nonce": base64.b64encode(hidden_payload_nonce).decode('utf-8'),
            "chunk_size": CHUNK_SIZE,
            "original_size": hidden_size,
            "filename": hidden_filename,
            "metadata": hidden_metadata,
        }
        payload_aad = serialize_aad(payload_aad_dict)
        encryptor_payload.authenticate_additional_data(payload_aad)

        while True:
            _raise_if_cancelled(cancel_check)
            chunk = hidden_input_stream.read(CHUNK_SIZE)
            if not chunk:
                break
            output_stream.write(encryptor_payload.update(chunk))

        output_stream.write(encryptor_payload.finalize() + encryptor_payload.tag)

        final_padding_size = final_container - output_stream.tell()
        if final_padding_size > 0:
            written = 0
            while written < final_padding_size:
                _raise_if_cancelled(cancel_check)
                chunk = min(CHUNK_SIZE, final_padding_size - written)
                output_stream.write(os.urandom(chunk))
                written += chunk

        return decoy_header
