"""BIP-39 style 24-word recovery phrase generation and conversion."""

import hashlib
import os

from .wordlist import WORDLIST


def generate_recovery_entropy() -> bytes:
    """Generate 32 bytes (256 bits) of secure random entropy for BIP-39."""
    return os.urandom(32)


def entropy_to_mnemonic(entropy: bytes) -> str:
    """Convert 32 bytes of entropy to a 24-word BIP-39 mnemonic phrase."""
    if len(entropy) != 32:
        raise ValueError("Entropy must be 32 bytes.")

    hash_bytes = hashlib.sha256(entropy).digest()
    checksum = bin(hash_bytes[0])[2:].zfill(8)

    entropy_bin = "".join(bin(b)[2:].zfill(8) for b in entropy)
    full_bin = entropy_bin + checksum

    words = []
    for i in range(24):
        chunk = full_bin[i * 11 : (i + 1) * 11]
        idx = int(chunk, 2)
        words.append(WORDLIST[idx])

    return " ".join(words)


def mnemonic_to_entropy(mnemonic: str) -> bytes:
    """Convert a 24-word BIP-39 mnemonic phrase back to 32 bytes of entropy."""
    words = mnemonic.strip().lower().split()
    if len(words) != 24:
        raise ValueError("Mnemonic must be exactly 24 words.")

    full_bin = ""
    for w in words:
        if w not in WORDLIST:
            raise ValueError(f"Invalid word in mnemonic: '{w}'")
        idx = WORDLIST.index(w)
        full_bin += bin(idx)[2:].zfill(11)

    entropy_bin = full_bin[:256]
    checksum_bin = full_bin[256:]

    entropy_bytes = bytearray()
    for i in range(32):
        chunk = entropy_bin[i * 8 : (i + 1) * 8]
        entropy_bytes.append(int(chunk, 2))

    entropy = bytes(entropy_bytes)

    hash_bytes = hashlib.sha256(entropy).digest()
    expected_checksum = bin(hash_bytes[0])[2:].zfill(8)

    if checksum_bin != expected_checksum:
        raise ValueError("Mnemonic checksum failed. The phrase is incorrect.")

    return entropy
