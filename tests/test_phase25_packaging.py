from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

RUNTIME_PKGS = ["customtkinter", "argon2-cffi", "cryptography", "tkinterdnd2", "zxcvbn"]


def test_pyproject_exists_with_project_metadata():
    pp = ROOT / "pyproject.toml"
    assert pp.exists()
    text = pp.read_text(encoding="utf-8")
    assert "[project]" in text
    assert 'name = "rpm-encrypter"' in text
    assert "version" in text
    for pkg in RUNTIME_PKGS:
        assert pkg in text


def test_requirements_lock_is_fully_pinned_with_closure():
    lock = ROOT / "requirements.lock"
    assert lock.exists()
    lines = [ln.strip() for ln in lock.read_text(encoding="utf-8").splitlines()
             if ln.strip() and not ln.strip().startswith("#")]
    assert lines, "lock must not be empty"
    for ln in lines:
        assert "==" in ln, f"not an exact pin: {ln}"
        assert ">=" not in ln and "<" not in ln, f"loose constraint in lock: {ln}"
    joined = "\n".join(lines)
    for pkg in RUNTIME_PKGS:
        assert pkg in joined
    for dep in ("argon2-cffi-bindings", "cffi", "pycparser", "darkdetect", "packaging"):
        assert dep in joined


def test_spec_collects_tkinterdnd2_native_data_and_icon():
    spec = (ROOT / "RPM Encrypter.spec").read_text(encoding="utf-8")
    assert "collect_all('tkinterdnd2')" in spec or 'collect_all("tkinterdnd2")' in spec
    assert "icon.ico" in spec


def test_build_script_uses_clean_venv_lock_and_spec():
    bp = ROOT / "build.ps1"
    assert bp.exists()
    text = bp.read_text(encoding="utf-8")
    assert "venv" in text
    assert "requirements.lock" in text
    assert "RPM Encrypter.spec" in text
