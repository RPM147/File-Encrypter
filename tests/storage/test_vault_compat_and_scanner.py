import io
import struct
from pathlib import Path

import pytest

from rpm_encrypter.core import (
    SUPPORTED_VAULT_VERSIONS,
    VAULT_MAGIC,
    VAULT_VERSION,
    VaultCrypto,
    VaultFormatError,
    is_supported_vault_version,
)
from rpm_encrypter.storage import scanner as scanner_mod
from rpm_encrypter.storage.scanner import VaultScanner

ROOT = Path(__file__).resolve().parents[2]


def test_supported_versions_policy_is_v4_only():
    assert SUPPORTED_VAULT_VERSIONS == frozenset({4})
    assert VAULT_VERSION == 4
    assert is_supported_vault_version(4) is True
    for bad in (0, 1, 2, 3, 255):
        assert is_supported_vault_version(bad) is False


def test_read_header_rejects_non_v4_with_vaultformaterror():
    stream = io.BytesIO(VAULT_MAGIC + struct.pack("!B", 3) + struct.pack("!I", 0))
    with pytest.raises(VaultFormatError):
        VaultCrypto._read_header(stream)


def _write(tmp_path, data: bytes) -> Path:
    p = tmp_path / "x.vault"
    p.write_bytes(data)
    return p


def test_scanner_rejects_non_v4_cleanly(tmp_path):
    p = _write(tmp_path, VAULT_MAGIC + struct.pack("!B", 3) + struct.pack("!I", 0))
    with pytest.raises(VaultFormatError):
        VaultScanner()._extract_metadata(p)


def test_scanner_truncated_missing_version_is_vaultformaterror_not_structerror(tmp_path):
    p = _write(tmp_path, VAULT_MAGIC)
    with pytest.raises(VaultFormatError):
        VaultScanner()._extract_metadata(p)


def test_scanner_truncated_header_body_is_vaultformaterror(tmp_path):
    p = _write(tmp_path, VAULT_MAGIC + struct.pack("!B", 4) + struct.pack("!I", 100) + b"{}")
    with pytest.raises(VaultFormatError):
        VaultScanner()._extract_metadata(p)


def test_scanner_sources_aligned_on_single_version_policy():
    scanner_src = (ROOT / "src" / "rpm_encrypter" / "storage" / "scanner.py").read_text(encoding="utf-8")
    assert "if version == 3:" not in scanner_src
    assert "if version == 4:" not in scanner_src
    assert "is_supported_vault_version" in scanner_src
    const_src = (ROOT / "src" / "rpm_encrypter" / "core" / "constants.py").read_text(encoding="utf-8")
    assert "SUPPORTED_VAULT_VERSIONS = frozenset({VAULT_VERSION})" in const_src
    assert "def is_supported_vault_version" in const_src
    inspect_ctrl_src = (
        ROOT / "src" / "rpm_encrypter" / "services" / "controllers" / "inspect_controller.py"
    ).read_text(encoding="utf-8")
    assert "is_supported_vault_version" in inspect_ctrl_src


def test_scanner_does_not_evict_sibling_prefix_directories(tmp_path, monkeypatch, fast_crypto):
    cache_file = tmp_path / "lib_cache.json"
    monkeypatch.setattr(scanner_mod, "CACHE_FILE", cache_file)

    vault_dir = tmp_path / "vault"
    sibling_dir = tmp_path / "vault-backup"
    vault_dir.mkdir()
    sibling_dir.mkdir()

    plain = tmp_path / "plain.txt"
    plain.write_bytes(b"scanner sibling prefix test")
    v1 = vault_dir / "one.vault"
    v2 = sibling_dir / "two.vault"
    fast_crypto.encrypt_file(plain, v1, "Password123!", original_filename="one.txt")
    fast_crypto.encrypt_file(plain, v2, "Password123!", original_filename="two.txt")

    scanner = VaultScanner()
    scanner.scan_directories([str(vault_dir), str(sibling_dir)])
    sibling_key = str(v2.resolve())
    assert sibling_key in scanner.cache

    # Scanning only `vault` must NOT evict cached entries from sibling `vault-backup`.
    scanner.scan_directories([str(vault_dir)])
    assert sibling_key in scanner.cache
