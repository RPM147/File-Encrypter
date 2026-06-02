"""
Phase 6 (SEC-04) regression tests: atomic vault output.

The encrypt paths must write to a same-directory temp and ``os.replace`` it onto
the final ``.vault`` only after the whole write succeeds, so the final name is
never left as a partial stump. A failed write must leave NOTHING under the final
name and no ``.rpm_vaulttmp_*`` leftover.

These tests are GUI-free (they import only ``file_handler`` + ``crypto_core``).
The ``fast_crypto`` fixture (small/fast Argon2 params) comes from tests/conftest.py.
"""

from pathlib import Path

import pytest

from file_handler import atomic_output


PASSWORD = "AtomicOutputTest123!"


def _temps_left(directory: Path):
    """Recognizable Phase 6 ciphertext temps remaining in ``directory``."""
    return list(Path(directory).glob(".rpm_vaulttmp_*"))


def test_atomic_output_success_writes_final_and_leaves_no_temp(tmp_path):
    """1. On success the final file holds exactly the written bytes and no temp remains."""
    final = tmp_path / "out.vault"
    payload = b"complete-and-valid-contents"

    atomic_output(final, lambda p: Path(p).write_bytes(payload))

    assert final.exists()
    assert final.read_bytes() == payload
    assert _temps_left(tmp_path) == []          # temp was renamed away, none left


def test_atomic_output_failure_leaves_nothing_under_final_name(tmp_path):
    """2. If write_fn raises after writing some bytes, the exception propagates, the
    final name does NOT exist, and the partial temp is cleaned up."""
    final = tmp_path / "out.vault"

    def write_then_fail(p):
        Path(p).write_bytes(b"partial-bytes-should-be-discarded")
        raise RuntimeError("simulated mid-write failure")

    with pytest.raises(RuntimeError, match="simulated mid-write failure"):
        atomic_output(final, write_then_fail)

    assert not final.exists()                    # nothing under the real .vault name
    assert _temps_left(tmp_path) == []           # partial temp cleaned up


def test_atomic_output_temp_has_recognizable_prefix_in_final_dir(tmp_path):
    """3. The temp handed to write_fn is named .rpm_vaulttmp_*.part and lives in the
    SAME directory as the final path (required for an atomic os.replace)."""
    final = tmp_path / "sub" / "out.vault"
    final.parent.mkdir()
    captured = {}

    def wf(p):
        captured["p"] = Path(p)
        Path(p).write_bytes(b"x")

    atomic_output(final, wf)

    tmp_seen = captured["p"]
    assert tmp_seen.name.startswith(".rpm_vaulttmp_")
    assert tmp_seen.name.endswith(".part")
    assert tmp_seen.parent == final.parent        # same dir → replace is atomic
    assert final.exists()
    assert _temps_left(final.parent) == []


def test_atomic_output_real_crypto_round_trip(tmp_path, fast_crypto):
    """4. Real VaultCrypto: encrypt a source into a final .vault THROUGH the helper,
    then decrypt and confirm the payload + filename round-trip."""
    src = tmp_path / "plain.bin"
    payload = b"the quick brown fox " * 100
    src.write_bytes(payload)

    final = tmp_path / "data.bin.vault"
    atomic_output(final, lambda p: fast_crypto.encrypt_file(
        src, p, PASSWORD,
        original_filename="data.bin",
        metadata={"source_type": "file"},
    ))

    assert final.exists()
    assert _temps_left(tmp_path) == []

    restored = tmp_path / "restored.bin"
    header = fast_crypto.decrypt_file(final, restored, PASSWORD)
    assert restored.read_bytes() == payload
    assert header.payload.filename == "data.bin"


def test_atomic_output_real_crypto_failure_no_leftover(tmp_path, fast_crypto):
    """5. Real VaultCrypto failure (encrypt_file against a non-existent source) must
    propagate, leave no final .vault, and leave no temp behind."""
    missing_src = tmp_path / "does_not_exist.bin"   # intentionally never created
    final = tmp_path / "data.bin.vault"

    with pytest.raises(Exception):
        atomic_output(final, lambda p: fast_crypto.encrypt_file(
            missing_src, p, PASSWORD, original_filename="data.bin"))

    assert not final.exists()
    assert _temps_left(tmp_path) == []
