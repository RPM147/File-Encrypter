import logging
import os
import re
from pathlib import Path

import log_hygiene
from log_hygiene import redact_path


def test_redact_path_reduces_to_basename():
    assert redact_path(r"C:\Users\me\Documents\secret.txt") == "secret.txt"
    assert redact_path("/home/me/private/report.pdf") == "report.pdf"
    assert redact_path("already_basename.bin") == "already_basename.bin"
    out = redact_path(str(Path("parentdir") / "child" / "leaf.txt"))
    assert out == "leaf.txt"
    assert os.sep not in out
    assert isinstance(redact_path(None), str)


def test_file_handler_logging_keeps_basename_not_parent_dir(tmp_path, caplog):
    import file_handler
    wiper = file_handler.SecureWiper(passes=1)
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


def test_no_secret_value_interpolated_into_logs_or_status():
    root = Path(log_hygiene.__file__).resolve().parent
    targets = list(root.glob("*.py")) + list((root / "views").glob("*.py"))
    offenders = []
    for py in targets:
        if py.name.startswith("test_"):
            continue
        for i, line in enumerate(py.read_text(encoding="utf-8").splitlines(), 1):
            if ("logger." in line or "_set_status(" in line) and _SECRET_INTERP.search(line):
                offenders.append(f"{py.name}:{i}: {line.strip()}")
    assert not offenders, "Secret value interpolated into a log/status call:\n" + "\n".join(offenders)
