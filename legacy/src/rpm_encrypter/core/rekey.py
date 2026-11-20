"""Password rotation (re-keying) via DEK envelope re-encryption."""

import base64
import json
import logging
import os
import struct
from dataclasses import asdict
from pathlib import Path
from typing import Callable, Optional

import argon2

from .constants import CHUNK_SIZE, MIN_SALT_SIZE, VAULT_MAGIC, VAULT_VERSION
from .exceptions import CryptoError, VaultFormatError, _raise_if_cancelled
from .models import EnvelopeParams, KDFParams, PayloadParams, VaultHeader

logger = logging.getLogger(__name__)


class RekeyMixin:
    """Password change via envelope re-encryption without decrypting payload."""

    def rekey_vault(
        self,
        input_path: Path,
        output_path: Path,
        old_password: str,
        new_password: str,
        cancel_check: Optional[Callable[[], bool]] = None,
    ) -> None:
        """
        Change the password of a vault by re-encrypting only the DEK envelope.
        """
        input_path = Path(input_path).resolve()
        output_path = Path(output_path).resolve()

        if input_path == output_path:
            raise VaultFormatError(
                "input_path and output_path must be different files. "
                "Use a temporary path and rename atomically after success."
            )

        with open(input_path, 'rb') as f_in:
            header, payload_offset = self._read_header(f_in)

            old_salt = base64.b64decode(header.kdf.salt)
            old_kek = self._derive_kek(
                old_password,
                old_salt,
                memory_cost=header.kdf.memory,
                time_cost=header.kdf.iterations,
                parallelism=header.kdf.parallelism,
                hash_len=header.kdf.length,
            )

            encrypted_dek = base64.b64decode(header.envelope.encrypted_dek)
            dek_nonce = base64.b64decode(header.envelope.dek_nonce)
            dek = self._decrypt_dek(encrypted_dek, dek_nonce, old_kek)

            new_salt = self._secure_random(MIN_SALT_SIZE)
            new_kek = argon2.low_level.hash_secret_raw(
                secret=new_password.encode('utf-8'),
                salt=new_salt,
                memory_cost=header.kdf.memory,
                time_cost=header.kdf.iterations,
                parallelism=header.kdf.parallelism,
                hash_len=header.kdf.length,
                type=argon2.Type.ID,
            )
            new_dek_nonce, new_encrypted_dek = self._encrypt_dek(dek, new_kek)

            new_header = VaultHeader(
                kdf=KDFParams(
                    salt=base64.b64encode(new_salt).decode('ascii'),
                    memory=header.kdf.memory,
                    iterations=header.kdf.iterations,
                    parallelism=header.kdf.parallelism,
                    length=header.kdf.length,
                    hidden_salt=header.kdf.hidden_salt,
                ),
                envelope=EnvelopeParams(
                    dek_nonce=base64.b64encode(new_dek_nonce).decode('ascii'),
                    encrypted_dek=base64.b64encode(new_encrypted_dek).decode('ascii'),
                ),
                payload=PayloadParams(
                    algorithm=header.payload.algorithm,
                    nonce=header.payload.nonce,
                    chunk_size=header.payload.chunk_size,
                    container_size=header.payload.container_size,
                ),
                recovery_envelope=header.recovery_envelope,
                encrypted_meta_nonce=header.encrypted_meta_nonce,
            )

            new_header_json = json.dumps(asdict(new_header), separators=(',', ':')).encode('utf-8')

            old_header_len = payload_offset - 9
            if len(new_header_json) > old_header_len:
                raise CryptoError(
                    "New header is larger than old header; cannot safely re-key "
                    "without risking Plausible Deniability."
                )
            new_header_json = new_header_json.ljust(old_header_len, b' ')
            new_header_len = len(new_header_json)

            f_in.seek(0, os.SEEK_END)
            total_size = f_in.tell()
            payload_size = total_size - payload_offset

            with open(output_path, 'wb') as f_out:
                f_out.write(VAULT_MAGIC)
                f_out.write(struct.pack('!B', VAULT_VERSION))
                f_out.write(struct.pack('!I', new_header_len))
                f_out.write(new_header_json)

                f_in.seek(payload_offset)
                remaining = payload_size
                while remaining > 0:
                    _raise_if_cancelled(cancel_check)
                    read_size = min(CHUNK_SIZE, remaining)
                    chunk = f_in.read(read_size)
                    if not chunk:
                        break
                    f_out.write(chunk)
                    remaining -= len(chunk)

        logger.info(
            "Re-keying complete: %s -> %s (payload_size=%d bytes untouched)",
            Path(input_path).name,
            Path(output_path).name,
            payload_size,
        )
