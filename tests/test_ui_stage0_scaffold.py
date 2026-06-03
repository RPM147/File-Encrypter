import pytest


def test_tokens_palette_matches_brand_identity():
    from ui_flet import tokens
    assert tokens.COLORS["bg"] == "#0d1117"
    assert tokens.COLORS["bg_sidebar"] == "#010409"
    assert tokens.COLORS["accent"] == "#00d4aa"
    assert tokens.COLORS["text_primary"] == "#e6edf3"
    # all 10 brand tokens present
    for key in ("bg", "bg_sidebar", "surface_card", "accent", "accent_hover",
                "text_primary", "text_secondary", "error", "success", "border"):
        assert key in tokens.COLORS


def test_tokens_type_and_spacing_scale():
    from ui_flet import tokens
    assert set(tokens.TYPE) == {"page_title", "section", "body", "caption"}
    assert tokens.SPACING["base"] == 8


def test_nav_model_matches_current_app_screens():
    from ui_flet import tokens
    keys = [k for k, _ in tokens.NAV_ITEMS]
    assert keys == ["encrypt", "decrypt", "inspect", "library", "notes",
                    "rekey", "password", "activity", "settings"]
    assert tokens.BOTTOM_NAV_KEYS == ["settings"]
    assert "settings" not in tokens.TOP_NAV_KEYS
    assert dict(tokens.NAV_ITEMS)["inspect"] == "Vault Info"


def test_theme_builds_a_flet_theme():
    ft = pytest.importorskip("flet")
    from ui_flet.theme import build_theme
    assert isinstance(build_theme(), ft.Theme)
