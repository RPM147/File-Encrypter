from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _label_line(source: str, text: str) -> str:
    needle = f'text="{text}"'
    for line in source.splitlines():
        if needle in line and "CTkLabel" in line:
            return line
    return ""


def test_three_page_titles_are_22_bold():
    gui_src = (ROOT / "gui_app.py").read_text(encoding="utf-8")
    inspect_src = (ROOT / "views" / "inspect_view.py").read_text(encoding="utf-8")
    activity_src = (ROOT / "views" / "activity_view.py").read_text(encoding="utf-8")
    password_src = (ROOT / "views" / "password_view.py").read_text(encoding="utf-8")
    sources = {
        "Vault Information": inspect_src,
        "Password Generator": password_src,
        "Activity Feed & Statistics": activity_src,
    }
    for title, src in sources.items():
        line = _label_line(src, title)
        assert line, f"label not found: {title}"
        assert "size=22" in line and 'weight="bold"' in line, f"{title} not 22 bold: {line}"


def test_confirm_labels_are_14_normal():
    src = (ROOT / "views" / "encrypt_view.py").read_text(encoding="utf-8")
    for label in ("Confirm Password", "Confirm Hidden Password"):
        line = _label_line(src, label)
        assert line, f"label not found: {label}"
        assert "size=14" in line, f"{label} not size 14: {line}"
        assert 'weight="bold"' not in line, f"{label} still bold: {line}"


def test_other_page_titles_remain_22_bold():
    # Regression: the already-compliant titles are untouched (some now live in view modules).
    gui_src = (ROOT / "gui_app.py").read_text(encoding="utf-8")
    encrypt_src = (ROOT / "views" / "encrypt_view.py").read_text(encoding="utf-8")
    notes_src = (ROOT / "views" / "notes_view.py").read_text(encoding="utf-8")
    library_src = (ROOT / "views" / "library_view.py").read_text(encoding="utf-8")
    rekey_src = (ROOT / "views" / "rekey_view.py").read_text(encoding="utf-8")
    decrypt_src = (ROOT / "views" / "decrypt_view.py").read_text(encoding="utf-8")
    settings_src = (ROOT / "views" / "settings_view.py").read_text(encoding="utf-8")
    sources = {
        "Encrypt Folders & Files": encrypt_src,
        "Decrypt Vault": decrypt_src,
        "Re-Key Vault": rekey_src,
        "Vault Library": library_src,
        "Encrypted Notes": notes_src,
        "Settings": settings_src,
    }
    for title, src in sources.items():
        line = _label_line(src, title)
        assert line, f"label not found: {title}"
        assert "size=22" in line and 'weight="bold"' in line, f"{title} regressed: {line}"
