from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_redact_path_is_cross_platform():
    from log_hygiene import redact_path
    # Windows-style path reduces to basename on ANY OS now:
    assert redact_path(r"C:\Users\me\Documents\secret.txt") == "secret.txt"
    # POSIX-style path too:
    assert redact_path("/home/me/private/report.pdf") == "report.pdf"
    # mixed separators:
    assert redact_path("C:/Users/me\\mixed/leaf.bin") == "leaf.bin"
    # bare name unchanged:
    assert redact_path("plain.txt") == "plain.txt"
    # never leaks a separator, never raises:
    out = redact_path(r"D:\a\b\c.dat")
    assert "\\" not in out and "/" not in out
    assert isinstance(redact_path(None), str)


def test_decrypt_wipes_partial_plaintext_on_generic_failure():
    src = (ROOT / "views" / "decrypt_view.py").read_text(encoding="utf-8")
    # extract_dir is now wiped in BOTH the cancel branch AND the generic failure
    # branch (previously only on cancel):
    assert src.count("wipe_folder(extract_dir)") >= 2


def test_decrypt_extract_dir_collision_uses_a_loop():
    src = (ROOT / "views" / "decrypt_view.py").read_text(encoding="utf-8")
    assert "while extract_dir.exists()" in src


def test_rekey_view_dead_hidden_guard_removed():
    rk = (ROOT / "views" / "rekey_view.py").read_text(encoding="utf-8")
    cc = (ROOT / "crypto_core.py").read_text(encoding="utf-8")
    # The guard string is gone from the view, and crypto_core never raises it:
    assert "Re-Key is not supported for vaults containing a hidden compartment" not in rk
    assert "Re-Key is not supported" not in cc
