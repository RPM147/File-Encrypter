import hashlib
import logging
import threading
from pathlib import Path

from rpm_encrypter.services.controllers.inspect_controller import InspectController
from rpm_encrypter.services.recovery_copy import (
    DECRYPT_RECOVERY_LABEL,
    INSPECT_RECOVERY_LABEL,
    get_recovery_dialog_copy,
)
from rpm_encrypter.services.state import assert_main_thread

ROOT = Path(__file__).resolve().parents[2]
PASSWORD = "CorrectHorseBatteryStaple!123"


def _worker_call(fn):
    results = []
    errors = []

    def run():
        try:
            results.append(fn())
        except Exception as exc:
            errors.append(exc)

    thread = threading.Thread(target=run, name="state-test-worker")
    thread.start()
    thread.join()
    return results, errors


def _method_slice(source: str, method_name: str) -> str:
    marker = f"    def {method_name}"
    start = source.index(marker)
    next_def = source.find("\n    def ", start + len(marker))
    return source[start:] if next_def == -1 else source[start:next_def]


def test_assert_main_thread_returns_true_and_logs_nothing_on_main_thread(caplog):
    caplog.set_level(logging.WARNING, logger="RPM_GUI")

    assert assert_main_thread("main-thread-test") is True
    assert not [
        record
        for record in caplog.records
        if record.name == "RPM_GUI" and record.levelno >= logging.WARNING
    ]


def test_assert_main_thread_warns_and_returns_false_off_thread(caplog):
    caplog.set_level(logging.WARNING, logger="RPM_GUI")
    results, errors = _worker_call(lambda: assert_main_thread("worker-thread-test"))

    assert errors == []
    assert results == [False]
    assert any(
        record.name == "RPM_GUI"
        and record.levelno == logging.WARNING
        and "worker-thread-test" in record.getMessage()
        and "Off-main-thread UI mutation" in record.getMessage()
        for record in caplog.records
    )


def test_assert_main_thread_can_raise_in_strict_dev_mode(monkeypatch):
    monkeypatch.setenv("RPM_STRICT_UI_THREAD", "1")
    results, errors = _worker_call(lambda: assert_main_thread("strict-worker-test"))

    assert results == []
    assert len(errors) == 1
    assert isinstance(errors[0], RuntimeError)
    assert "strict-worker-test" in str(errors[0])


def test_normal_recovery_dialog_copy_is_standard_vault_only():
    copy = get_recovery_dialog_copy(hidden_mode=False)
    combined = " ".join([copy.title, copy.heading, copy.description, copy.checkbox_text]).lower()

    assert copy.title == "Recovery Phrase"
    assert "recover" in combined
    assert "vault" in combined
    assert "hidden" not in combined
    assert "decoy" not in combined


def test_hidden_recovery_dialog_copy_is_explicitly_decoy_only_and_unrecoverable():
    copy = get_recovery_dialog_copy(hidden_mode=True)
    combined = " ".join([copy.title, copy.heading, copy.description, copy.checkbox_text]).lower()

    assert "decoy" in combined
    assert "recovers only" in combined or "only the decoy" in combined
    assert "cannot recover hidden" in combined
    assert "hidden password" in combined
    assert "permanently unrecoverable" in combined
    assert "unrecoverable without the hidden password" in combined


def test_recovery_labels_clarify_standard_or_decoy_only_scope():
    assert DECRYPT_RECOVERY_LABEL == "Use Recovery Phrase (standard/decoy only)"
    assert INSPECT_RECOVERY_LABEL == "Use Recovery Phrase (standard/decoy only)"


def test_encrypt_screen_warns_hidden_has_no_recovery_and_shows_single_dialog():
    src = (ROOT / "src" / "rpm_encrypter" / "ui" / "screens" / "encrypt_screen.py").read_text(
        encoding="utf-8"
    )
    assert '"type": "recovery_phrase"' not in src
    assert "Hidden data has no recovery phrase" in src
    assert "requires the hidden password" in src


def test_decrypt_and_rekey_controllers_hardening():
    ctrl_dir = ROOT / "src" / "rpm_encrypter" / "services" / "controllers"
    dec_src = (ctrl_dir / "decrypt_controller.py").read_text(encoding="utf-8")
    assert dec_src.count("self._wipe_temp_dir(extract_dir)") >= 2
    assert "while extract_dir.exists()" in dec_src

    rk_src = (ctrl_dir / "rekey_controller.py").read_text(encoding="utf-8")
    core_hidden_src = (ROOT / "src" / "rpm_encrypter" / "core" / "hidden.py").read_text(
        encoding="utf-8"
    )
    assert "Re-Key is not supported for vaults containing a hidden compartment" not in rk_src
    assert "Re-Key is not supported" not in core_hidden_src


def test_check_vault_integrity_accepts_real_vault_and_returns_sha(tmp_path, fast_crypto):
    plaintext = tmp_path / "plain.txt"
    vault = tmp_path / "plain.vault"
    plaintext.write_bytes(b"integrity payload" * 32)

    fast_crypto.encrypt_file(
        input_path=plaintext,
        output_path=vault,
        password=PASSWORD,
        original_filename=plaintext.name,
        metadata={"source_type": "file"},
    )

    ok, msg, sha = InspectController._check_vault_integrity(vault)
    assert ok is True
    assert "valid" in msg.lower()
    assert sha == hashlib.sha256(vault.read_bytes()).hexdigest()


def test_check_vault_integrity_rejects_bad_magic_and_too_short_file(tmp_path):
    bad_magic = tmp_path / "bad.vault"
    bad_magic.write_bytes(b"NOPE" + b"\x04" + b"\x00\x00\x00\x01" + b"{}" + b"0" * 32)
    ok, msg, sha = InspectController._check_vault_integrity(bad_magic)
    assert ok is False
    assert "magic" in msg.lower()
    assert sha == ""

    too_short = tmp_path / "short.vault"
    too_short.write_bytes(b"RPMV")
    ok, msg, sha = InspectController._check_vault_integrity(too_short)
    assert ok is False
    assert "too small" in msg.lower()
    assert sha == ""


def test_ssd_detection_uses_powershell_with_safe_fallback_and_linux_path():
    src = (
        ROOT / "src" / "rpm_encrypter" / "services" / "controllers" / "settings_controller.py"
    ).read_text(encoding="utf-8")
    assert "wmic" not in src
    body = _method_slice(src, "_detect_ssd")
    assert "Get-PhysicalDisk" in body
    assert "powershell" in body
    assert "/sys/block" in body
    assert "rotational" in body
    assert "timeout=" in body
    assert "return False" in body
