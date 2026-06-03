"""Stage 12 packaging cutover.

The PRIMARY artifact is now the Flet (Flutter) desktop app built with
`flet build windows`; the legacy CustomTkinter PyInstaller build is kept as a
fallback (its wiring is covered by test_phase25_packaging.py). These tests pin
the new Flet build configuration so it cannot silently regress.
"""
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _pyproject_text() -> str:
    return (ROOT / "pyproject.toml").read_text(encoding="utf-8")


def _pyproject_data() -> dict:
    return tomllib.loads(_pyproject_text())


def test_pyproject_has_flet_build_section_and_entry_module():
    data = _pyproject_data()
    assert "flet" in data["tool"], "[tool.flet] section is required by `flet build`"
    # Entry module flet build will run -> app_flet.py -> ui_flet.app.run().
    assert data["tool"]["flet"]["app"]["module"] == "app_flet"
    assert data["tool"]["flet"]["product"] == "RPM Encrypter"


def test_flet_is_pinned_for_api_stability_everywhere():
    # The UI targets the 0.85.2 API; a loose floor could pull a breaking 1.x.
    assert "flet==0.85.2" in _pyproject_text()
    assert "flet==0.85.2" in (ROOT / "requirements.txt").read_text(encoding="utf-8")


def test_flet_build_does_not_bundle_legacy_ctk_gui_deps():
    """customtkinter/tkinterdnd2 belong to the legacy fallback only. They must NOT
    sit in [project.dependencies] -- that list is exactly what `flet build`
    bundles -- but they must remain declared for the fallback build."""
    data = _pyproject_data()
    runtime = " ".join(data["project"]["dependencies"])
    assert "flet" in runtime
    assert "customtkinter" not in runtime
    assert "tkinterdnd2" not in runtime

    legacy = " ".join(data["project"]["optional-dependencies"]["legacy"])
    assert "customtkinter" in legacy
    assert "tkinterdnd2" in legacy


def test_build_script_exposes_both_flet_and_legacy_paths():
    text = (ROOT / "build.ps1").read_text(encoding="utf-8")
    assert "flet build windows" in text          # primary path
    assert "-Legacy" in text                       # fallback switch
    assert "RPM Encrypter.spec" in text            # fallback still buildable
