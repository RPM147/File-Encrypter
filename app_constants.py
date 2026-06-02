"""Shared, view-relevant constants for RPM Encrypter: default password length,
password-strength colors, and the optional zxcvbn strength estimator.

Phase 26 (ARCH-01) Stage 4: extracted from gui_app.py so the view mixins (and the
shell) can import these without importing gui_app (which would be a circular
import). gui_app re-imports them, so existing call sites and tests are unaffected.
"""

DEFAULT_PW_LEN = 24

STRENGTH_COLORS = {
    0: ("#ff4444", "Very Weak"),
    1: ("#ff8844", "Weak"),
    2: ("#ffaa44", "Fair"),
    3: ("#44aa44", "Strong"),
    4: ("#008800", "Very Strong"),
}

try:
    from zxcvbn import zxcvbn
    ZXCVBN_AVAILABLE = True
except ImportError:
    ZXCVBN_AVAILABLE = False
    zxcvbn = None   # keep the name defined so importers never hit ImportError


APP_NAME = "RPM Encrypter"
APP_VERSION = "3.0.0"

# C2: "Container Size" selector options and label -> MiB mapping. "Auto" (0) lets
# crypto_core pick the smallest 1.25x ladder bucket; an explicit choice sets a floor.
CONTAINER_SIZE_CHOICES = ["Auto", "100 MB", "500 MB", "1 GB", "2 GB", "5 GB", "10 GB"]


def container_label_to_mb(label: str) -> int:
    """Map a Container Size label (e.g. '1 GB', '100 MB', 'Auto') to MiB (Auto -> 0)."""
    if not label or label.strip().lower() == "auto":
        return 0
    parts = label.split()
    try:
        num = int(parts[0])
    except (ValueError, IndexError):
        return 0
    unit = parts[1].upper() if len(parts) > 1 else "MB"
    return num * 1024 if unit == "GB" else num
