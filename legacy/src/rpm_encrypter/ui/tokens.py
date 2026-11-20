"""Design tokens and navigation model.

The Flet screens keep references to these dictionaries, so runtime theme and
scale changes mutate them in place instead of replacing the objects.
"""

DARK_COLORS = {
    "bg": "#0d1117",
    "bg_sidebar": "#010409",
    "surface_card": "#161b22",
    "accent": "#00d4aa",
    "accent_hover": "#00ffcc",
    "text_primary": "#e6edf3",
    "text_secondary": "#7d8590",
    "error": "#f85149",
    "success": "#3fb950",
    "border": "#30363d",
}

CLASSIC_COLORS = {
    "bg": "#e5e7eb",
    "bg_sidebar": "#d1d5db",
    "surface_card": "#f9fafb",
    "accent": "#60a5fa",
    "accent_hover": "#93c5fd",
    "text_primary": "#111827",
    "text_secondary": "#4b5563",
    "error": "#dc2626",
    "success": "#16a34a",
    "border": "#cbd5e1",
}

COLORS = dict(DARK_COLORS)

BASE_TYPE = {
    "page_title": {"size": 26, "weight": "w700"},
    "section": {"size": 17, "weight": "w600"},
    "body": {"size": 14, "weight": "w400"},
    "caption": {"size": 12, "weight": "w400"},
}

TYPE = {key: dict(value) for key, value in BASE_TYPE.items()}

BASE_SPACING = {"base": 8, "card_pad": 18, "radius": 12}
SPACING = dict(BASE_SPACING)


def apply_palette(choice: str) -> str:
    """Mutate COLORS to the selected app palette and return the normalized name."""
    normalized = choice if choice in ("Dark", "Classic") else "Dark"
    COLORS.clear()
    COLORS.update(CLASSIC_COLORS if normalized == "Classic" else DARK_COLORS)
    return normalized


def apply_ui_scale(choice: str) -> str:
    """Mutate TYPE/SPACING to the selected scale and return the normalized name."""
    normalized = choice if choice in ("80%", "90%", "100%", "110%", "120%") else "100%"
    factor = int(normalized.rstrip("%")) / 100
    for key, base in BASE_TYPE.items():
        TYPE[key]["size"] = max(8, round(base["size"] * factor))
        TYPE[key]["weight"] = base["weight"]
    for key, base in BASE_SPACING.items():
        SPACING[key] = max(4, round(base * factor))
    return normalized


NAV_ITEMS = [
    ("encrypt", "Encrypt"),
    ("decrypt", "Decrypt"),
    ("inspect", "Vault Info"),
    ("library", "Library"),
    ("notes", "Notes"),
    ("rekey", "Re-Key"),
    ("password", "Password Gen"),
    ("activity", "Activity"),
    ("settings", "Settings"),
]
TOP_NAV_KEYS = [key for key, _ in NAV_ITEMS if key != "settings"]
BOTTOM_NAV_KEYS = ["settings"]
