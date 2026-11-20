"""Password verification and header/metadata inspection without payload decryption."""

import base64
import os
from typing import BinaryIO, Optional

import argon2

from .constants import AES_TAG_SIZE
from .exceptions import AuthenticationError
from .models import EnvelopeParams, VaultHeader


class VerifyMixin:
    """Verify password or recovery phrase and return metadata without touching payload."""

    def verify_password_and_get_header(
        self,
        input_stream: BinaryIO,
        password: Optional[str] = None,
        recovery_key: Optional[bytes] = None,
    ) -> VaultHeader:
        """
        Verify a password and return the vault header WITHOUT decrypting the payload.
        """
        header, payload_offset = self._read_header(input_stream)
        salt = base64.b64decode(header.kdf.salt)

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

                # M2 FIX: mirror decrypt_stream. Always derive main KEK then hidden KEK.
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
                        _, payload_nonce, _, metadata = self._open_hidden_vault(
                            input_stream, password, total_size, hidden_kek
                        )
                        header.payload.nonce = base64.b64encode(payload_nonce).decode('utf-8')
                        header.payload.original_size = metadata.get('original_size', 0)
                        header.payload.filename = metadata.get('filename', '')
                        header.payload.metadata = metadata.get('metadata', None)
                        header.envelope = EnvelopeParams(encrypted_dek="", dek_nonce="")
                        header.recovery_envelope = None
                        return header
                    raise AuthenticationError("Vault access denied: Invalid password or corrupted vault envelope.")
            except AuthenticationError as exc:
                raise AuthenticationError("Vault access denied: Invalid password or corrupted vault envelope.") from exc

        meta_dict, _ = self._read_encrypted_metadata(
            input_stream, payload_offset, dek, header.encrypted_meta_nonce
        )
        header.payload.filename = meta_dict.get('filename', '')
        header.payload.metadata = meta_dict.get('metadata', None)
        header.payload.original_size = meta_dict.get('original_size', 0)

        return header
