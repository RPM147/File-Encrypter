from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_security_md_exists_and_covers_all_limitation_areas():
    sec = ROOT / "SECURITY.md"
    assert sec.exists(), "SECURITY.md must be created in Phase 24"
    text = sec.read_text(encoding="utf-8").lower()
    # The four required limitation areas + the local threat model.
    assert "threat model" in text
    assert "wear-leveling" in text or "wear leveling" in text
    assert "deniability" in text
    assert "swap" in text and "ram" in text
    assert "lockout" in text and "offline" in text


def test_readme_drops_marketing_and_overclaims():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    low = readme.lower()
    assert "military-grade" not in low
    assert "irrecoverably" not in low
    assert "argon2" in low


def test_readme_build_uses_committed_spec_and_links_security():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "RPM Encrypter.spec" in readme
    assert "SECURITY.md" in readme
