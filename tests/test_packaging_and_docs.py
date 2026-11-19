"""Packaging, layout, privacy defaults, and documentation tests."""

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _pyproject_text() -> str:
    return (ROOT / "pyproject.toml").read_text(encoding="utf-8")


def _pyproject_data() -> dict:
    return tomllib.loads(_pyproject_text())


def test_update_and_logging_default_to_off_everywhere():
    pkg_dir = ROOT / "src" / "rpm_encrypter"
    for py in sorted(pkg_dir.rglob("*.py")):
        src = py.read_text(encoding="utf-8")
        assert 'get_setting("check_updates", True)' not in src, py.name
        assert 'get_setting("logging_enabled", True)' not in src, py.name

    app_services_src = (pkg_dir / "services" / "app_services.py").read_text(encoding="utf-8")
    assert 'get_setting("check_updates", False)' in app_services_src
    assert 'get_setting("logging_enabled", False)' in app_services_src

    settings_screen_src = (pkg_dir / "ui" / "screens" / "settings_screen.py").read_text(
        encoding="utf-8"
    )
    assert "file's NAME" in settings_screen_src or "filename" in settings_screen_src.lower()
    assert "off by default" in settings_screen_src.lower()


def test_no_legacy_or_unused_dependencies_in_src_or_manifests():
    forbidden_pkgs = ("customtkinter", "tkinterdnd2", "psutil")
    reqs = (ROOT / "requirements.txt").read_text(encoding="utf-8").lower()
    pp = _pyproject_text().lower()
    for pkg in forbidden_pkgs:
        assert pkg not in reqs
        assert pkg not in pp

    data = _pyproject_data()
    assert "legacy" not in data["project"].get("optional-dependencies", {})

    for pkg in ("flet==0.85.2", "argon2-cffi", "cryptography", "zxcvbn"):
        assert pkg in reqs

    src_dir = ROOT / "src"
    for py in sorted(src_dir.rglob("*.py")):
        txt = py.read_text(encoding="utf-8")
        for bad in ("import customtkinter", "import tkinterdnd2", "import psutil", "import gui_app", "from views"):
            assert bad not in txt, f"{bad} found in {py.relative_to(ROOT)}"


def test_pyproject_flet_and_pytest_configuration():
    data = _pyproject_data()
    assert data["tool"]["flet"]["product"] == "RPM Encrypter"
    assert data["tool"]["flet"]["app"]["path"] == "src"
    assert data["tool"]["flet"]["app"]["module"] == "main"
    assert data["tool"]["pytest"]["ini_options"]["pythonpath"] == ["src"]
    assert "flet==0.85.2" in _pyproject_text()


def test_entry_assets_launcher_and_build_script():
    assert (ROOT / "src" / "main.py").is_file()
    assert (ROOT / "src" / "assets" / "icon.png").is_file()
    assert (ROOT / "launcher" / "icon.ico").is_file()
    assert (ROOT / "launcher" / "launcher.c").is_file()

    rc_text = (ROOT / "launcher" / "launcher.rc").read_text(encoding="utf-8")
    assert 'launcher\\\\icon.ico' in rc_text

    build_text = (ROOT / "build.ps1").read_text(encoding="utf-8")
    assert "flet build windows" in build_text
    assert '/Fo`"launcher\\launcher.obj`"' in build_text
    assert "-Legacy" not in build_text
    assert "RPM Encrypter.spec" not in build_text
    assert "PyInstaller" not in build_text


def test_security_md_exists_and_covers_all_limitation_areas():
    sec = ROOT / "SECURITY.md"
    assert sec.exists()
    text = sec.read_text(encoding="utf-8").lower()
    assert "threat model" in text
    assert "wear-leveling" in text or "wear leveling" in text
    assert "deniability" in text
    assert "swap" in text and "ram" in text
    assert "lockout" in text and "offline" in text
    assert "future v4 chunked-aead" not in text


def test_readme_drops_marketing_and_legacy_references():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    low = readme.lower()
    assert "military-grade" not in low
    assert "irrecoverably" not in low
    assert "argon2" in low
    assert "SECURITY.md" in readme
    assert "RPM Encrypter.spec" not in readme
    assert "gui_app.py" not in readme
    assert "future v4 chunked-aead" not in low


def test_release_checklist_exists_and_covers_all_mandated_topics():
    checklist = ROOT / "RELEASE_CHECKLIST.md"
    assert checklist.is_file()
    text = checklist.read_text(encoding="utf-8")
    assert len(text) > 800
    assert "- [ ]" in text

    low = text.lower()
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
    missing = [kw for kw in required if kw not in low]
    assert not missing, f"RELEASE_CHECKLIST.md is missing mandated topics: {missing}"
    assert "gui_app.py" not in text
    assert "RPM Encrypter.spec" not in text


def test_architecture_md_documents_clean_slate_policy():
    arch = ROOT / "ARCHITECTURE.md"
    assert arch.is_file()
    low = arch.read_text(encoding="utf-8").lower()
    assert "no backward compatibility" in low
    assert "shim" in low
    assert "vault format v4" in low
    assert "ARCHITECTURE.md" in (ROOT / "README.md").read_text(encoding="utf-8")


def test_ci_workflow_runs_lint_and_tests():
    ci = ROOT / ".github" / "workflows" / "ci.yml"
    assert ci.is_file()
    text = ci.read_text(encoding="utf-8")
    assert "ruff check src tests" in text
    assert "python -m pytest" in text
    assert "VAULT_VERSION == 4" in text


def test_storage_split_has_no_legacy_file_handler_shim():
    storage = ROOT / "src" / "rpm_encrypter" / "storage"
    assert not (storage / "file_handler.py").exists()
    for module in ("atomic.py", "wiper.py", "packager.py", "inspector.py"):
        assert (storage / module).is_file(), module
    for py in sorted((ROOT / "src").rglob("*.py")):
        assert "file_handler" not in py.read_text(encoding="utf-8"), py.relative_to(ROOT)


def test_repo_hygiene_gitattributes_python_floor_and_ruff_b():
    assert (ROOT / ".gitattributes").is_file()
    data = _pyproject_data()
    assert data["project"]["requires-python"] == ">=3.11"
    lint_select = data["tool"]["ruff"]["lint"]["select"]
    assert "B" in lint_select
