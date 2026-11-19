"""Custom exception hierarchy and cancellation helper for cryptographic operations."""


class CryptoError(Exception):
    """Base exception for all cryptographic failures."""


class AuthenticationError(CryptoError):
    """
    Raised when integrity verification fails.

    Causes:
        - Incorrect password (KEK derivation fails to decrypt DEK).
        - Corrupted or tampered vault (GCM authentication tag mismatch).
    """


class PayloadTooLargeError(CryptoError):
    """Raised when a payload exceeds the single-stream AES-GCM size policy."""


class OperationCancelledError(CryptoError):
    """Raised when a long operation is cancelled mid-stream by the user."""


class VaultFormatError(CryptoError):
    """Raised when the vault file structure is invalid or unsupported."""


def _raise_if_cancelled(cancel_check) -> None:
    if cancel_check is not None and cancel_check():
        raise OperationCancelledError("Operation cancelled by user.")
