import logging
import os
import re
from pathlib import Path

from rpm_encrypter.storage import log_hygiene
from rpm_encrypter.storage.wiper import SecureWiper
from rpm_encrypter.storage.log_hygiene import redact_path

ROOT = Path(__file__).resolve().parents[2]


def test_redact_path_reduces_to_basename():
    assert redact_path(r"C:\Users\me\Documents\secret.txt") == "secret.txt"
    assert redact_path("/home/me/private/report.pdf") == "report.pdf"
    assert redact_path("already_basename.bin") == "already_basename.bin"
    out = redact_path(str(Path("parentdir") / "child" / "leaf.txt"))
    assert out == "leaf.txt"
    assert os.sep not in out
    assert isinstance(redact_path(None), str)


def test_redact_path_is_cross_platform():
    assert redact_path(r"C:\Users\me\Documents\secret.txt") == "secret.txt"
    assert redact_path("/home/me/private/report.pdf") == "report.pdf"
    assert redact_path("C:/Users/me\\mixed/leaf.bin") == "leaf.bin"
    assert redact_path("plain.txt") == "plain.txt"
    out = redact_path(r"D:\a\b\c.dat")
    assert "\\" not in out and "/" not in out
    assert isinstance(redact_path(None), str)


def test_wiper_logging_keeps_basename_not_parent_dir(tmp_path, caplog):
    wiper = SecureWiper(passes=1)
    secret_dir = tmp_path / "TOPSECRET_UNIQUE_DIR"
    secret_dir.mkdir()
    ghost = secret_dir / "ghostfile.bin"
    with caplog.at_level(logging.WARNING):
        wiper.wipe_file(ghost)
    text = caplog.text
    assert "ghostfile.bin" in text
    assert "TOPSECRET_UNIQUE_DIR" not in text
    assert str(secret_dir) not in text


_SECRET = r"(password|passphrase|mnemonic|recovery_phrase|plaintext)"
_SECRET_INTERP = re.compile(
    r"(\{[^}]*" + _SECRET + r"|%[(]?\s*" + _SECRET
    + r"|\.format\([^)]*" + _SECRET + r"|,\s*\w*" + _SECRET + r"\w*\s*[,)])",
    re.IGNORECASE,
)


_STATUS_CALLS = ("logger.", "_set_status(", "set_screen_status(")


def test_no_secret_value_interpolated_into_logs_or_status():
    pkg_root = Path(log_hygiene.__file__).resolve().parents[1]
    offenders = []
    for py in sorted(pkg_root.rglob("*.py")):
        for i, line in enumerate(py.read_text(encoding="utf-8").splitlines(), 1):
            if any(call in line for call in _STATUS_CALLS) and _SECRET_INTERP.search(line):
                offenders.append(f"{py.relative_to(ROOT)}:{i}: {line.strip()}")
    assert not offenders, "Secret value interpolated into a log/status call:\n" + "\n".join(offenders)
