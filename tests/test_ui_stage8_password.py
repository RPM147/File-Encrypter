"""Stage 8 (Password Generator) tests.

The PasswordController is FLET-FREE and exercised directly: generation uses only
the secrets module, honours the 8..64 length range and the per-class
requirements, filters ambiguous characters, and produces strength text from the
shared app_constants / optional zxcvbn. Screen behavior (service registration,
generation flow, clipboard copy + token-based auto-clear, transfer-to-Encrypt,
shell mounting) is tested headlessly with fake page/shell objects -- no display
and no real 30-second sleep.
"""
import asyncio
import queue
import string
from pathlib import Path
from types import SimpleNamespace

import pytest

from app_constants import DEFAULT_PW_LEN, STRENGTH_COLORS
from ui_flet.controllers.password_controller import (
    AMBIGUOUS,
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    SYMBOLS,
    PasswordController,
    StrengthResult,
)


def _run(coro):
    return asyncio.run(coro)


# ============================================================ controller (flet-free)
def test_controller_generates_correct_length_and_all_classes():
    pw = PasswordController().generate_password(
        length=24,
        use_upper=True,
        use_lower=True,
        use_digits=True,
        use_symbols=True,
        exclude_ambiguous=False,
    )
    assert len(pw) == 24
    assert any(c in string.ascii_uppercase for c in pw)
    assert any(c in string.ascii_lowercase for c in pw)
    assert any(c in string.digits for c in pw)
    assert any(c in SYMBOLS for c in pw)
    allowed = set(string.ascii_uppercase + string.ascii_lowercase + string.digits + SYMBOLS)
    assert all(c in allowed for c in pw)


def test_controller_excludes_ambiguous_characters():
    ctrl = PasswordController()
    for _ in range(200):
        pw = ctrl.generate_password(
            length=32,
            use_upper=True,
            use_lower=True,
            use_digits=True,
            use_symbols=True,
            exclude_ambiguous=True,
        )
        assert not any(c in AMBIGUOUS for c in pw)
        # Spelled out explicitly to match the prompt's banned set.
        for bad in "0O1lI|`":
            assert bad not in pw


def test_controller_only_digits_and_all_disabled():
    ctrl = PasswordController()
    pw = ctrl.generate_password(
        length=16,
        use_upper=False,
        use_lower=False,
        use_digits=True,
        use_symbols=False,
        exclude_ambiguous=False,
    )
    assert pw and all(c in string.digits for c in pw)

    with pytest.raises(ValueError, match="Select at least one character type"):
        ctrl.generate_password(
            length=16,
            use_upper=False,
            use_lower=False,
            use_digits=False,
            use_symbols=False,
            exclude_ambiguous=False,
        )


def test_controller_length_validation():
    ctrl = PasswordController()
    kwargs = dict(use_upper=True, use_lower=True, use_digits=True, use_symbols=True, exclude_ambiguous=False)
    with pytest.raises(ValueError, match="between 8 and 64"):
        ctrl.generate_password(length=7, **kwargs)
    with pytest.raises(ValueError, match="between 8 and 64"):
        ctrl.generate_password(length=65, **kwargs)

    assert MIN_PASSWORD_LENGTH == 8 and MAX_PASSWORD_LENGTH == 64
    pw = ctrl.generate_password(length=DEFAULT_PW_LEN, **kwargs)
    assert len(pw) == DEFAULT_PW_LEN


def test_controller_source_uses_secrets_only_and_no_persistence():
    root = Path(__file__).resolve().parents[1]
    src = (root / "ui_flet" / "controllers" / "password_controller.py").read_text(encoding="utf-8")
    assert "import flet" not in src and "from flet" not in src
    assert "secrets.choice" in src
    assert "secrets.SystemRandom" in src
    assert "import random" not in src
    # Nothing here may persist a generated password.
    for forbidden in ("push_recent", "log_event", "_save_cfg", "_mutate_cfg", "activity_logger", "open("):
        assert forbidden not in src


def test_controller_strength_text_fallback_and_zxcvbn(monkeypatch):
    import ui_flet.controllers.password_controller as pc

    # Fallback (no zxcvbn): text mentions Length and carries no color/score.
    monkeypatch.setattr(pc, "ZXCVBN_AVAILABLE", False)
    res = pc.PasswordController().strength("abcDEF123!@#")
    assert isinstance(res, StrengthResult)
    assert "Length:" in res.text
    assert res.color is None and res.score is None

    # zxcvbn path: label/color come from STRENGTH_COLORS, crack time is shown.
    monkeypatch.setattr(pc, "ZXCVBN_AVAILABLE", True)
    monkeypatch.setattr(
        pc,
        "zxcvbn",
        lambda password: {
            "score": 3,
            "crack_times_display": {"offline_slow_hashing_1e4_per_second": "centuries"},
        },
    )
    res = pc.PasswordController().strength("whatever")
    color, label = STRENGTH_COLORS[3]
    assert res.color == color
    assert res.score == 3
    assert label in res.text
    assert "centuries" in res.text

    # Empty input is a neutral placeholder.
    assert pc.PasswordController().strength("").text == "Strength: -"


# ====================================================================== screen
class _FakePage:
    def __init__(self):
        self.services = []
        self.overlay = []
        self.update_calls = 0
        self.web = False
        self.tasks = []

    def update(self):
        self.update_calls += 1

    def run_task(self, handler, *args):
        # Store, never execute -> the 30s clear timer never fires in tests.
        self.tasks.append((handler, args))
        return None


class _FakeShell:
    def __init__(self, page, services):
        self.page = page
        self.services = services
        self.status_text = SimpleNamespace(value="Ready")
        self.encrypt_screen = None
        self.active_key = "password"

    def safe_update(self):
        self.page.update()
        return True

    def navigate(self, key):
        self.active_key = key
        if key == "encrypt" and self.encrypt_screen is None:
            from ui_flet.screens.encrypt_screen import EncryptScreen

            self.encrypt_screen = EncryptScreen(self.page, self.services, self)
            self.encrypt_screen.build()


class _FakeClipboard:
    def __init__(self):
        self.values = []
        self.fail_next = False

    async def set(self, value):
        if self.fail_next:
            self.fail_next = False
            raise RuntimeError("simulated clipboard failure")
        self.values.append(value)


def _screen_services():
    return SimpleNamespace(is_processing=False, cancel_requested=False, shutdown_requested=False)


def _shell_services():
    return SimpleNamespace(
        shutdown_requested=False,
        cancel_requested=False,
        is_processing=False,
        msg_queue=queue.Queue(),
        stats=SimpleNamespace(snapshot=lambda: {
            "encrypted": 0, "decrypted": 0, "rekeyed": 0, "uptime": "0s"
        }),
    )


def _make_screen(page=None):
    from ui_flet.screens.password_screen import PasswordScreen

    page = page or _FakePage()
    services = _screen_services()
    shell = _FakeShell(page, services)
    return PasswordScreen(page, services, shell), page, shell


def test_password_screen_registers_one_clipboard_service_not_overlay():
    ft = pytest.importorskip("flet")
    screen, page, _shell = _make_screen()

    screen.build()
    screen.build()

    assert page.overlay == []
    clipboards = [s for s in page.services if isinstance(s, ft.Clipboard)]
    assert len(clipboards) == 1
    assert page.services == [screen.clipboard]


def test_password_screen_source_does_not_use_overlay():
    root = Path(__file__).resolve().parents[1]
    src = (root / "ui_flet" / "screens" / "password_screen.py").read_text(encoding="utf-8")
    assert "page.overlay" not in src
    assert ".overlay" not in src


def test_password_screen_generation_flow_fills_result_and_strength():
    pytest.importorskip("flet")
    screen, _page, _shell = _make_screen()
    screen.build()

    screen._generate_password()

    assert screen.result_field.value
    assert len(screen.result_field.value) == int(screen.length_slider.value)
    assert screen.strength_text.value != "Strength: -"


def test_password_screen_copy_and_token_based_autoclear():
    pytest.importorskip("flet")
    screen, page, _shell = _make_screen()

    fake = _FakeClipboard()
    screen.clipboard = fake
    screen._ensure_services()
    assert any(s is fake for s in page.services)

    # Copy #1.
    screen.result_field.value = "first"
    _run(screen._copy_password())
    assert fake.values[-1] == "first"
    token_a = screen._clipboard_token

    # Copy #2 (newer) replaces the clipboard and advances the token.
    screen.result_field.value = "second"
    _run(screen._copy_password())
    assert fake.values[-1] == "second"
    assert screen._clipboard_token != token_a

    # A stale timer (token A) must NOT clear the newer password.
    before = list(fake.values)
    _run(screen._clear_clipboard_if_current(token_a))
    assert fake.values == before

    # The current timer clears the clipboard with "".
    _run(screen._clear_clipboard_if_current(screen._clipboard_token))
    assert fake.values[-1] == ""


def test_password_screen_failed_copy_does_not_invalidate_existing_clear_timer():
    pytest.importorskip("flet")
    screen, page, shell = _make_screen()

    fake = _FakeClipboard()
    screen.clipboard = fake
    screen._ensure_services()

    screen.result_field.value = "first"
    _run(screen._copy_password())
    token_a = screen._clipboard_token
    assert fake.values == ["first"]

    fake.fail_next = True
    screen.result_field.value = "second"
    _run(screen._copy_password())

    assert screen._clipboard_token == token_a
    assert fake.values == ["first"]
    assert shell.status_text.value == "Clipboard failed: simulated clipboard failure"

    _run(screen._clear_clipboard_if_current(token_a))
    assert fake.values[-1] == ""


def test_password_screen_empty_copy_and_transfer_validation():
    pytest.importorskip("flet")
    screen, _page, shell = _make_screen()
    screen.result_field.value = ""

    _run(screen._copy_password())
    assert shell.status_text.value == "Generate a password first"

    shell.status_text.value = "Ready"
    screen._transfer_to_encrypt()
    assert shell.status_text.value == "Generate a password first"


def test_password_screen_transfer_to_encrypt_fills_encrypt_password():
    pytest.importorskip("flet")
    from ui_flet.shell import AppShell

    page = _FakePage()
    shell = AppShell(page, _shell_services())
    # Mount the Password screen through the real shell so transfer uses the
    # real navigate() + real EncryptScreen.
    shell._placeholder("password")
    screen = shell.password_screen
    assert screen is not None

    generated = "Tr0ub4dour-&3-Example!Pw"
    screen.result_field.value = generated

    screen._transfer_to_encrypt()

    assert shell.active_key == "encrypt"
    assert shell.encrypt_screen is not None
    assert shell.encrypt_screen.password_field.value == generated
    assert shell.encrypt_screen.strength_text.value != "Strength: -"
    assert hasattr(shell.encrypt_screen, "confirm_password_field")
    assert shell.encrypt_screen.confirm_password_field.value == generated


def test_shell_mounts_password_screen_without_duplicate_clipboard():
    ft = pytest.importorskip("flet")
    from ui_flet.shell import AppShell

    page = _FakePage()
    shell = AppShell(page, _shell_services())
    assert shell.password_screen is None

    control = shell._placeholder("password")
    assert control is not None
    assert shell.password_screen is not None

    # Repeated mounting must not register a second clipboard service.
    shell._placeholder("password")
    clipboards = [s for s in page.services if isinstance(s, ft.Clipboard)]
    assert len(clipboards) == 1
    assert page.overlay == []


def test_password_screen_uses_clipboard_service_not_page_level_method():
    root = Path(__file__).resolve().parents[1]
    src = (root / "ui_flet" / "screens" / "password_screen.py").read_text(encoding="utf-8")
    assert "ft.Clipboard" in src
    assert ".set(" in src
    # The installed Flet has no page-level clipboard setter; build the forbidden
    # name by concatenation so the literal never appears in this test either.
    forbidden = "set_" + "clipboard"
    assert forbidden not in src
