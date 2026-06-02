import hashlib
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
PASSWORD = "CorrectHorseBatteryStaple!123"

try:
    from gui_app import RPMEncrypterApp
except Exception as exc:  # pragma: no cover - depends on local GUI availability
    RPMEncrypterApp = None
    GUI_IMPORT_ERROR = exc
else:
    GUI_IMPORT_ERROR = None


def _require_gui_app():
    if GUI_IMPORT_ERROR is not None:
        pytest.skip(f"gui_app import unavailable: {GUI_IMPORT_ERROR}")


def _method_slice(source: str, method_name: str) -> str:
    marker = f"    def {method_name}"
    start = source.index(marker)
    next_def = source.find("\n    def ", start + len(marker))
    if next_def == -1:
        return source[start:]
    return source[start:next_def]


def test_check_vault_integrity_accepts_real_vault_and_returns_manual_sha(tmp_path, fast_crypto):
    _require_gui_app()

    plaintext = tmp_path / "plain.txt"
    vault = tmp_path / "plain.vault"
    plaintext.write_bytes(b"phase 10 integrity payload" * 32)

    fast_crypto.encrypt_file(
        input_path=plaintext,
        output_path=vault,
        password=PASSWORD,
        original_filename=plaintext.name,
        metadata={"source_type": "file"},
    )

    ok, msg, sha = RPMEncrypterApp._check_vault_integrity(vault)

    assert ok is True
    assert "OK" in msg or "valid" in msg.lower()
    assert sha == hashlib.sha256(vault.read_bytes()).hexdigest()


def test_check_vault_integrity_rejects_bad_magic_and_too_short_file(tmp_path):
    _require_gui_app()

    bad_magic = tmp_path / "bad.vault"
    bad_magic.write_bytes(b"NOPE" + b"\x03" + b"\x00\x00\x00\x01" + b"{}" + b"0" * 32)
    ok, msg, sha = RPMEncrypterApp._check_vault_integrity(bad_magic)
    assert ok is False
    assert "magic" in msg.lower()
    assert sha == ""

    too_short = tmp_path / "short.vault"
    too_short.write_bytes(b"RPMV")
    ok, msg, sha = RPMEncrypterApp._check_vault_integrity(too_short)
    assert ok is False
    assert "too small" in msg.lower()
    assert sha == ""


def test_integrity_and_verify_buttons_are_stored_for_disable_helper():
    source = (ROOT / "views" / "inspect_view.py").read_text(encoding="utf-8")
    inspect_body = _method_slice(source, "_create_inspect_frame")
    helper_body = _method_slice(source, "_set_inspect_hash_buttons")

    assert "self.integrity_btn = ctk.CTkButton" in inspect_body
    assert "self.integrity_btn.pack(" in inspect_body
    assert "self.verify_btn = ctk.CTkButton" in inspect_body
    assert "self.verify_btn.pack(" in inspect_body
    assert 'for attr in ("integrity_btn", "verify_btn")' in helper_body
    assert "getattr(self, attr, None)" in helper_body
    assert "btn.configure(state=state)" in helper_body


def test_integrity_check_hashes_in_background_and_posts_result():
    source = (ROOT / "views" / "inspect_view.py").read_text(encoding="utf-8")
    body = _method_slice(source, "_do_integrity_check")

    assert "_set_inspect_hash_buttons(False)" in body
    assert "Verifying integrity (hashing file)" in body
    assert "threading.Thread(target=worker, daemon=True).start()" in body
    assert '"type": "integrity_result"' in body
    assert "self._check_vault_integrity(path)" in body


def test_verify_against_saved_hashes_in_background_and_posts_result():
    source = (ROOT / "views" / "inspect_view.py").read_text(encoding="utf-8")
    body = _method_slice(source, "_verify_against_saved")

    assert "_set_inspect_hash_buttons(False)" in body
    assert "threading.Thread(target=worker, daemon=True).start()" in body
    assert '"type": "verify_result"' in body
    assert "self._check_vault_integrity(path)" in body
    assert "messagebox.showwarning(\"No Record\"" in body


def test_handle_message_processes_hash_results_and_reenables_buttons():
    source = (ROOT / "gui_app.py").read_text(encoding="utf-8")
    body = _method_slice(source, "_handle_message")

    assert 'elif mtype == "integrity_result":' in body
    assert 'elif mtype == "verify_result":' in body
    assert body.count("_set_inspect_hash_buttons(True)") >= 2
    assert "self._save_fingerprint(path, sha)" in body
    assert "self._refresh_fingerprint_panel()" in body
    assert "messagebox.showinfo(\"Match" in body
    assert "messagebox.showerror(\"Mismatch" in body
