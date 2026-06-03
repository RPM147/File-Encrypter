"""Password generation + strength estimation for the Flet UI (Stage 8).

FLET-FREE so it is unit-testable without a display. Mirrors the old
views/password_view.py rules: length 8..64 (default DEFAULT_PW_LEN), the same
symbol set and ambiguous-character set, at least one character from every enabled
class, and strength text via the shared app_constants / optional zxcvbn.

Generation uses the secrets module only (secrets.choice + a
secrets.SystemRandom().shuffle) -- never random/uuid/time/hashlib. Nothing here
is logged or persisted; the generated password is returned to the caller only.
"""
import secrets
import string
from dataclasses import dataclass

from app_constants import (
    DEFAULT_PW_LEN,
    STRENGTH_COLORS,
    ZXCVBN_AVAILABLE,
    zxcvbn,
)

MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 64
SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?"
AMBIGUOUS = "0O1lI|`"


@dataclass(frozen=True)
class StrengthResult:
    text: str
    color: str | None = None
    score: int | None = None


class PasswordController:
    """Generates passwords and calculates strength text.
    FLET-FREE -> unit-testable without a display."""

    def generate_password(
        self,
        *,
        length: int,
        use_upper: bool,
        use_lower: bool,
        use_digits: bool,
        use_symbols: bool,
        exclude_ambiguous: bool,
    ) -> str:
        length = int(length)
        if length < MIN_PASSWORD_LENGTH or length > MAX_PASSWORD_LENGTH:
            raise ValueError("Length must be between 8 and 64")

        pools = []
        if use_upper:
            pools.append(string.ascii_uppercase)
        if use_lower:
            pools.append(string.ascii_lowercase)
        if use_digits:
            pools.append(string.digits)
        if use_symbols:
            pools.append(SYMBOLS)

        if exclude_ambiguous:
            pools = ["".join(c for c in pool if c not in AMBIGUOUS) for pool in pools]

        pools = [pool for pool in pools if pool]
        if not pools:
            raise ValueError("Select at least one character type")

        chars = "".join(pools)
        # One guaranteed character from each enabled (post-filter) class, then
        # fill the remainder from the combined pool. length >= 8 and at most 4
        # classes, so the per-class requirement always fits.
        required = [secrets.choice(pool) for pool in pools]
        remainder = [secrets.choice(chars) for _ in range(max(0, length - len(required)))]
        password_list = required + remainder
        secrets.SystemRandom().shuffle(password_list)
        return "".join(password_list)

    def strength(self, password: str) -> StrengthResult:
        password = password or ""
        if not password:
            return StrengthResult("Strength: -", None, None)

        if ZXCVBN_AVAILABLE and zxcvbn is not None:
            result = zxcvbn(password)
            score = int(result.get("score", 0))
            color, label = STRENGTH_COLORS.get(score, STRENGTH_COLORS[0])
            crack = result.get("crack_times_display", {}).get(
                "offline_slow_hashing_1e4_per_second", "unknown"
            )
            return StrengthResult(
                f"Strength: {label}  -  Est. crack time: {crack}",
                color,
                score,
            )

        return StrengthResult(
            f"Length: {len(password)} chars  (install zxcvbn for strength analysis)",
            None,
            None,
        )
