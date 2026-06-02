from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _method_slice(source: str, method_name: str) -> str:
    marker = f"    def {method_name}"
    start = source.index(marker)
    next_def = source.find("\n    def ", start + len(marker))
    return source[start:] if next_def == -1 else source[start:next_def]


def test_psutil_is_gone_from_source_and_requirements():
    src = (ROOT / "gui_app.py").read_text(encoding="utf-8")
    assert "import psutil" not in src
    assert "psutil" not in src
    reqs = (ROOT / "requirements.txt").read_text(encoding="utf-8")
    assert "psutil" not in reqs


def test_health_check_keeps_platform_import():
    # The sibling import must survive: _run_health_check uses platform.system().
    body = _method_slice((ROOT / "views" / "settings_view.py").read_text(encoding="utf-8"), "_run_health_check")
    assert "import platform" in body
    assert "platform.system()" in body


def test_requirements_still_lists_the_real_deps():
    reqs = (ROOT / "requirements.txt").read_text(encoding="utf-8")
    for pkg in ("customtkinter", "argon2-cffi", "cryptography", "tkinterdnd2", "zxcvbn"):
        assert pkg in reqs
