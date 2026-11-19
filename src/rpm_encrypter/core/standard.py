"""Standard (non-hidden) vault stream encryption and decryption."""

import base64
import json
import logging
import os
import struct
from dataclasses import asdict
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
    VAULT_MAGIC,
    VAULT_VERSION,
)
from .exceptions import (
    AuthenticationError,
    PayloadTooLargeError,
    VaultFormatError,
    _raise_if_cancelled,
)
from .header import sanitize_filename, sanitize_metadata, serialize_aad
from .models import EnvelopeParams, KDFParams, PayloadParams, VaultHeader

logger = logging.getLogger(__name__)


class StandardVaultMixin:
    """Standard (non-hidden) vault stream encryption and decryption."""

    def _build_recovery_envelope(
        self,
        dek: bytes,
        recovery_key: Optional[bytes],
    ) -> Optional[EnvelopeParams]:
        if recovery_key is None:
            return None
        # C1 FIX: Use a cryptographically independent random salt for the
        # recovery KEK instead of deriving it from the main salt, so re-keying
        # does not break recovery.
        recovery_salt_bytes = self._secure_random(MIN_SALT_SIZE)
        b64_recovery_salt = base64.b64encode(recovery_salt_bytes).decode('ascii')
        recovery_kek = argon2.low_level.hash_secret_raw(
            secret=recovery_key,
            salt=recovery_salt_bytes,
            time_cost=self.argon_iterations,
            memory_cost=self.argon_memory,
            parallelism=self.argon_parallelism,
            hash_len=AES_KEY_SIZE,
            type=argon2.Type.ID,
        )
        r_dek_nonce, r_encrypted_dek = self._encrypt_dek(dek, recovery_kek)
        return EnvelopeParams(
            dek_nonce=base64.b64encode(r_dek_nonce).decode('ascii'),
            encrypted_dek=base64.b64encode(r_encrypted_dek).decode('ascii'),
            recovery_salt=b64_recovery_salt,
        )

    def _encrypt_metadata_block(
        self,
        dek: bytes,
        original_filename: str,
        original_size: int,
        metadata: Optional[Dict[str, Any]],
    ) -> Tuple[bytes, bytes]:
        # F1/C2 FIX: Encrypt filename, manifest, and original_size under DEK
        # so the cleartext header leaks none of them.
        meta_dict = {
            "filename": original_filename,
            "metadata": metadata,
            "original_size": original_size,
        }
        meta_bytes = json.dumps(meta_dict, separators=(',', ':')).encode('utf-8')
        meta_nonce = self._secure_random(AES_NONCE_SIZE)
        encrypted_meta = AESGCM(dek).encrypt(meta_nonce, meta_bytes, None)
        return meta_nonce, encrypted_meta

    def _resolve_container_size(
        self,
        build_header_fn: Callable[[int], Tuple[VaultHeader, bytes]],
        encrypted_meta_len: int,
        original_size: int,
        target_container_mb: int,
        forced_container_size: Optional[int],
    ) -> int:
        if forced_container_size is not None:
            return forced_container_size
        container_size = 0
        for _ in range(8):  # converges in 1-2 rounds (ladder gaps >> digit growth)
            _, probe_json = build_header_fn(container_size)
            pre_pad_size = (
                4 + 1 + 4 + len(probe_json)
                + 4 + encrypted_meta_len
                + original_size + AES_TAG_SIZE
            )
            new_container_size = self._calculate_container_size(
                pre_pad_size, min_container_mb=target_container_mb
            )
            if new_container_size == container_size:
                break
            container_size = new_container_size
        return container_size

    def _write_random_padding(
        self,
        output_stream: BinaryIO,
        container_size: int,
        progress_callback: Optional[Callable[[int, int], None]],
        cancel_check: Optional[Callable[[], bool]],
    ) -> None:
        current_pos = output_stream.tell()
        padding_needed = container_size - current_pos
        if padding_needed <= 0:
            return
        written = 0
        while written < padding_needed:
            _raise_if_cancelled(cancel_check)
            chunk = min(CHUNK_SIZE, padding_needed - written)
            output_stream.write(os.urandom(chunk))
            written += chunk
            if progress_callback:
                try:
                    progress_callback(current_pos + written, container_size)
                except Exception:
                    pass

    def encrypt_stream(
        self,
        input_stream: BinaryIO,
        output_stream: BinaryIO,
        password: str,
        original_filename: str,
        original_size: int,
        metadata: Optional[Dict[str, Any]] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        recovery_key: Optional[bytes] = None,
        hidden_salt: Optional[str] = None,
        target_container_mb: int = 0,
        apply_padding: bool = True,
        forced_container_size: Optional[int] = None,
        cancel_check: Optional[Callable[[], bool]] = None,
    ) -> VaultHeader:
        """
        Encrypt a binary stream into the RPM Vault format (v4).

        Operational Flow:
            1. Generate a unique random DEK (256 bits) and payload nonce (96 bits).
            2. Generate a unique random salt and derive the KEK from the password
               using Argon2id.
            3. Encrypt the DEK with the KEK (AES-256-GCM) -> envelope.
            4. Encrypt the metadata block (filename + manifest + original_size,
               sealed under the DEK) so its length is known (F1/C2).
            5. Determine the bucketed ``container_size`` from the FULL pre-padding
               on-disk size and write the cleartext header (C2).
            6. Write the encrypted metadata block directly after the header.
            7. Stream-encrypt the payload in chunks using AES-256-GCM and append
               the 16-byte GCM authentication tag.
            8. Pad with random bytes (1 MiB chunks) up to ``container_size``.
        """
        original_filename = sanitize_filename(original_filename)
        metadata = sanitize_metadata(metadata)

        if original_size > MAX_PAYLOAD_SIZE:
            raise PayloadTooLargeError(
                f"Payload is {original_size:,} bytes, which exceeds the "
                f"{MAX_PAYLOAD_SIZE:,} byte (32 GiB) limit of the single-stream "
                f"AES-GCM vault format. Encrypt a smaller selection or split the data."
            )

        salt = self._secure_random(MIN_SALT_SIZE)
        dek = self._secure_random(AES_KEY_SIZE)
        payload_nonce = self._secure_random(AES_NONCE_SIZE)
        if hidden_salt:
            b64_hidden_salt = hidden_salt
        else:
            b64_hidden_salt = base64.b64encode(
                self._secure_random(MIN_SALT_SIZE)
            ).decode('ascii')

        kek = self._derive_kek(password, salt)
        dek_nonce, encrypted_dek = self._encrypt_dek(dek, kek)
        recovery_env = self._build_recovery_envelope(dek, recovery_key)
        meta_nonce, encrypted_meta = self._encrypt_metadata_block(
            dek, original_filename, original_size, metadata
        )

        def _build_header(container_size: int) -> Tuple[VaultHeader, bytes]:
            hdr = VaultHeader(
                kdf=KDFParams(
                    salt=base64.b64encode(salt).decode('ascii'),
                    memory=self.argon_memory,
                    iterations=self.argon_iterations,
                    parallelism=self.argon_parallelism,
                    hidden_salt=b64_hidden_salt,
                ),
                envelope=EnvelopeParams(
                    dek_nonce=base64.b64encode(dek_nonce).decode('ascii'),
                    encrypted_dek=base64.b64encode(encrypted_dek).decode('ascii'),
                ),
                payload=PayloadParams(
                    nonce=base64.b64encode(payload_nonce).decode('ascii'),
                    chunk_size=CHUNK_SIZE,
                    container_size=container_size,
                ),
                recovery_envelope=recovery_env,
                encrypted_meta_nonce=base64.b64encode(meta_nonce).decode('ascii'),
            )
            try:
                hdr_json = json.dumps(asdict(hdr), separators=(',', ':')).encode('utf-8')
            except (TypeError, ValueError) as exc:
                raise VaultFormatError(
                    f"Vault header could not be serialised to JSON. "
                    f"Ensure all metadata values are JSON-compatible types: {exc}"
                ) from exc
            return hdr, hdr_json

        container_size = self._resolve_container_size(
            _build_header,
            len(encrypted_meta),
            original_size,
            target_container_mb,
            forced_container_size,
        )

        header, header_json = _build_header(container_size)
        header_len = len(header_json)

        if header_len > MAX_HEADER_SIZE:
            raise VaultFormatError(
                f"Vault header JSON ({header_len:,} bytes) exceeds the {MAX_HEADER_SIZE:,} byte limit. "
                f"Reduce the metadata payload."
            )

        output_stream.write(VAULT_MAGIC)
        output_stream.write(struct.pack('!B', VAULT_VERSION))
        output_stream.write(struct.pack('!I', header_len))
        output_stream.write(header_json)

        output_stream.write(struct.pack('!I', len(encrypted_meta)))
        output_stream.write(encrypted_meta)

        cipher = Cipher(
            algorithms.AES(dek),
            modes.GCM(payload_nonce),
            backend=default_backend(),
        )
        encryptor = cipher.encryptor()

        payload_aad_dict = {
            "nonce": base64.b64encode(payload_nonce).decode('ascii'),
            "chunk_size": CHUNK_SIZE,
            "original_size": original_size,
            "filename": original_filename,
            "metadata": metadata,
        }
        payload_aad = serialize_aad(payload_aad_dict)
        encryptor.authenticate_additional_data(payload_aad)

        bytes_processed = 0
        while True:
            _raise_if_cancelled(cancel_check)
            chunk = input_stream.read(CHUNK_SIZE)
            if not chunk:
                break
            encrypted_chunk = encryptor.update(chunk)
            output_stream.write(encrypted_chunk)
            bytes_processed += len(chunk)

            if progress_callback:
                try:
                    progress_callback(bytes_processed, original_size)
                except Exception as exc:
                    logger.warning("Progress callback failed: %s", exc)

        encryptor.finalize()
        auth_tag = encryptor.tag
        output_stream.write(auth_tag)

        if apply_padding:
            self._write_random_padding(
                output_stream, container_size, progress_callback, cancel_check
            )

        logger.info(
            "Encryption complete: %d bytes, filename='%s', container_size=%d, vault_offset=%d",
            bytes_processed,
            original_filename,
            container_size,
            output_stream.tell(),
        )
        return header

    def decrypt_stream(
        self,
        input_stream: BinaryIO,
        output_stream: BinaryIO,
        password: Optional[str] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        recovery_key: Optional[bytes] = None,
        cancel_check: Optional[Callable[[], bool]] = None,
    ) -> VaultHeader:
        """
        Decrypt an RPM Vault stream back to its original plaintext.
        """
        header, payload_offset = self._read_header(input_stream)
        salt = base64.b64decode(header.kdf.salt)

        payload_nonce = None

        if recovery_key is not None:
            try:
                if not header.recovery_envelope:
                    raise AuthenticationError("No recovery phrase exists for this vault.")
                if header.recovery_envelope.recovery_salt:
                    recovery_salt = base64.b64decode(header.recovery_envelope.recovery_salt)
                else:
                    recovery_salt = salt + b"RECOVERY"
                recovery_kek = argon2.low_level.hash_secret_raw(
                    secret=recovery_key,
                    salt=recovery_salt,
                    time_cost=header.kdf.iterations,
                    memory_cost=header.kdf.memory,
                    parallelism=header.kdf.parallelism,
                    hash_len=header.kdf.length,
                    type=argon2.Type.ID,
                )
                encrypted_dek = base64.b64decode(header.recovery_envelope.encrypted_dek)
                dek_nonce = base64.b64decode(header.recovery_envelope.dek_nonce)
                dek = self._decrypt_dek(encrypted_dek, dek_nonce, recovery_kek)
            except AuthenticationError as exc:
                raise AuthenticationError("Vault access denied: Invalid password or corrupted vault envelope.") from exc
        else:
            try:
                if password is None:
                    raise AuthenticationError("Must provide either a password or a recovery key.")

                # M2 FIX: Always perform the same two Argon2 derivations in the
                # same order on the password path: main KEK first, hidden KEK second.
                kek = self._derive_kek(
                    password,
                    salt,
                    memory_cost=header.kdf.memory,
                    time_cost=header.kdf.iterations,
                    parallelism=header.kdf.parallelism,
                    hash_len=header.kdf.length,
                )
                hidden_kek = self._derive_hidden_kek(password, header.kdf)

                encrypted_dek = base64.b64decode(header.envelope.encrypted_dek)
                dek_nonce = base64.b64decode(header.envelope.dek_nonce)

                try:
                    dek = self._decrypt_dek(encrypted_dek, dek_nonce, kek)
                    main_ok = True
                except AuthenticationError:
                    main_ok = False

                if not main_ok:
                    input_stream.seek(0, os.SEEK_END)
                    total_size = input_stream.tell()
                    if total_size >= payload_offset + self.HIDDEN_TOTAL_HEADER_BYTES + AES_TAG_SIZE:
                        dek, payload_nonce, hidden_payload_offset, metadata = self._open_hidden_vault(
                            input_stream, password, total_size, hidden_kek
                        )
                        header.payload.nonce = base64.b64encode(payload_nonce).decode('utf-8')
                        header.payload.original_size = metadata.get('original_size', 0)
                        header.payload.filename = metadata.get('filename', '')
                        header.payload.metadata = metadata.get('metadata', None)
                        payload_offset = hidden_payload_offset
                    else:
                        raise AuthenticationError("Vault access denied: Invalid password or corrupted vault envelope.")
            except AuthenticationError as exc:
                raise AuthenticationError("Vault access denied: Invalid password or corrupted vault envelope.") from exc

        if payload_nonce is None:
            meta_dict, payload_offset = self._read_encrypted_metadata(
                input_stream, payload_offset, dek, header.encrypted_meta_nonce
            )
            header.payload.filename = meta_dict.get('filename', '')
            header.payload.metadata = meta_dict.get('metadata', None)
            header.payload.original_size = meta_dict.get('original_size', 0)
            payload_nonce = base64.b64decode(header.payload.nonce)

        cipher = Cipher(
            algorithms.AES(dek),
            modes.GCM(payload_nonce),
            backend=default_backend(),
        )
        decryptor = cipher.decryptor()

        payload_aad_dict = {
            "nonce": header.payload.nonce,
            "chunk_size": header.payload.chunk_size,
            "original_size": header.payload.original_size,
            "filename": header.payload.filename,
            "metadata": header.payload.metadata,
        }
        payload_aad = serialize_aad(payload_aad_dict)
        decryptor.authenticate_additional_data(payload_aad)

        tag_offset = payload_offset + header.payload.original_size

        input_stream.seek(0, os.SEEK_END)
        total_size = input_stream.tell()

        if tag_offset > total_size - AES_TAG_SIZE:
            raise VaultFormatError(
                "Vault file is too short to contain the required payload and auth tag."
            )

        payload_size = header.payload.original_size
        input_stream.seek(payload_offset)

        bytes_processed = 0
        while input_stream.tell() < tag_offset:
            _raise_if_cancelled(cancel_check)
            remaining = tag_offset - input_stream.tell()
            read_size = min(CHUNK_SIZE, remaining)
            chunk = input_stream.read(read_size)
            if not chunk:
                break

            decrypted_chunk = decryptor.update(chunk)
            output_stream.write(decrypted_chunk)
            bytes_processed += len(chunk)

            if progress_callback:
                try:
                    progress_callback(bytes_processed, payload_size)
                except Exception as exc:
                    logger.warning("Progress callback failed: %s", exc)

        input_stream.seek(tag_offset)
        auth_tag = input_stream.read(AES_TAG_SIZE)

        try:
            decryptor.finalize_with_tag(auth_tag)
        except InvalidTag:
            raise AuthenticationError(
                "Payload integrity check failed. The vault file has been corrupted, "
                "truncated, or tampered with. Do not trust the decrypted data."
            )

        logger.info(
            "Decryption complete: %d bytes restored, filename='%s'",
            bytes_processed,
            header.payload.filename,
        )
        return header
