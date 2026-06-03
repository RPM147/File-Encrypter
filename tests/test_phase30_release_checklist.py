import re
from pathlib import Path

import app_config

ROOT = Path(app_config.__file__).resolve().parent
CHECKLIST = ROOT / "RELEASE_CHECKLIST.md"


def test_release_checklist_exists_and_is_nontrivial():
    assert CHECKLIST.is_file(), "RELEASE_CHECKLIST.md is missing at the repo root"
    text = CHECKLIST.read_text(encoding="utf-8")
    assert len(text) > 800
    # It is a checklist: it has check items.
    assert "- [ ]" in text


def test_release_checklist_covers_all_mandated_topics():
    text = CHECKLIST.read_text(encoding="utf-8").lower()
    required = [
        "clean install",
        "launch",
        "encrypt",
        "decrypt",
        "hidden vault",
        "recovery phrase",
        "re-key",
        "update",
        "trace",
        "uninstall",
    ]
    missing = [kw for kw in required if kw not in text]
    assert not missing, f"RELEASE_CHECKLIST.md is missing mandated topics: {missing}"
