import io
import struct
from pathlib import Path

import pytest

from crypto_core import (
    VAULT_MAGIC, VAULT_VERSION, VaultFormatError,
    SUPPORTED_VAULT_VERSIONS, is_supported_vault_version, VaultCrypto,
)
from vault_scanner import VaultScanner

ROOT = Path(__file__).resolve().parents[1]


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


def test_scanner_landmine_removed_and_sources_aligned():
    scanner_src = (ROOT / "vault_scanner.py").read_text(encoding="utf-8")
    assert "if version == 3:" not in scanner_src
    assert "if version == 4:" not in scanner_src
    assert "is_supported_vault_version" in scanner_src
    core_src = (ROOT / "crypto_core.py").read_text(encoding="utf-8")
    assert "SUPPORTED_VAULT_VERSIONS = frozenset({VAULT_VERSION})" in core_src
    assert "def is_supported_vault_version" in core_src
    gui_src = (ROOT / "gui_app.py").read_text(encoding="utf-8")
    assert "is_supported_vault_version" in gui_src
