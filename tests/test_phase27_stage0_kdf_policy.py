from pathlib import Path

import pytest

import crypto_core
from crypto_core import KDFParams, VaultFormatError, _validate_kdf_params

ROOT = Path(__file__).resolve().parents[1]


def test_validate_kdf_params_is_now_a_module_level_function():
    # Importable as a standalone unit, and no longer a method in the class body.
    assert callable(_validate_kdf_params)
    src = (ROOT / "crypto_core.py").read_text(encoding="utf-8")
    assert "\ndef _validate_kdf_params(" in src          # module-level def (column 0)
    assert "    def _validate_kdf_params(" not in src     # not a class method anymore


def test_validate_kdf_params_accepts_in_policy_and_rejects_bad():
    _validate_kdf_params(KDFParams())                      # defaults are in policy -> no raise
    with pytest.raises(VaultFormatError):
        _validate_kdf_params(KDFParams(length=16))         # wrong hash length -> reject
    with pytest.raises(VaultFormatError):
        _validate_kdf_params(KDFParams(iterations=True))   # bool is not an int -> reject
