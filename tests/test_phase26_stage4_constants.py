from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_app_constants_defines_shared_values():
    import app_constants
    assert app_constants.DEFAULT_PW_LEN == 24
    assert isinstance(app_constants.STRENGTH_COLORS, dict)
    assert 0 in app_constants.STRENGTH_COLORS and 4 in app_constants.STRENGTH_COLORS
    assert hasattr(app_constants, "ZXCVBN_AVAILABLE")
    assert hasattr(app_constants, "zxcvbn")  # name always defined (None if package missing)


def test_gui_app_reexports_the_constants():
    import gui_app
    for name in ("DEFAULT_PW_LEN", "STRENGTH_COLORS", "ZXCVBN_AVAILABLE", "zxcvbn"):
        assert hasattr(gui_app, name), name
    assert gui_app.DEFAULT_PW_LEN == 24


def test_constant_defs_moved_out_of_gui_app():
    src = (ROOT / "gui_app.py").read_text(encoding="utf-8")
    # The definitions moved; gui_app now re-imports them.
    assert "STRENGTH_COLORS = {" not in src
    assert "from zxcvbn import zxcvbn" not in src
    assert "from app_constants import" in src
