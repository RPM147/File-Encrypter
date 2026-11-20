"""Authenticated vault metadata inspector (header + encrypted metadata block only)."""

from pathlib import Path
from typing import Any, Dict, Optional

from rpm_encrypter.core import AuthenticationError, VaultCrypto, VaultFormatError


class VaultInspector:
    """Provides authenticated metadata extraction without decrypting the payload stream."""

    def __init__(self, crypto: VaultCrypto):
        self.crypto = crypto

    def inspect(
        self,
        vault_path: Path,
        password: Optional[str] = None,
        recovery_key: Optional[bytes] = None,
    ) -> Dict[str, Any]:
        """Verify password or recovery key and return vault metadata."""
        vault_path = Path(vault_path)
        if not vault_path.exists():
            raise VaultFormatError(f"Vault file not found: {vault_path}")

        try:
            with open(vault_path, "rb") as f:
                header = self.crypto.verify_password_and_get_header(
                    f, password=password, recovery_key=recovery_key
                )
        except AuthenticationError:
            raise
        except Exception as exc:
            raise VaultFormatError(f"Failed to read vault header: {exc}") from exc

        metadata = {
            "filename": header.payload.filename,
            "original_size": header.payload.original_size,
            "kdf_algorithm": header.kdf.algorithm,
            "encryption": header.envelope.algorithm,
            "payload_encryption": header.payload.algorithm,
            "argon_memory": header.kdf.memory,
            "argon_iterations": header.kdf.iterations,
            "argon_parallelism": header.kdf.parallelism,
        }

        if header.payload.metadata:
            metadata.update(header.payload.metadata)

        return metadata
