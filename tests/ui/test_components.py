"""Unit tests for the shared Flet UI components."""

import asyncio
from types import SimpleNamespace

import pytest

ft = pytest.importorskip("flet")

from rpm_encrypter.ui.components import (  # noqa: E402
    AutoClearClipboard,
    card_panel,
    empty_text,
    finish_screen_operation,
    hint_text,
    register_page_services,
    set_screen_status,
    show_confirm_dialog,
    source_row,
)


def _run(coro):
    return asyncio.run(coro)


class _FakePage:
    def __init__(self):
        self.services = []
        self.dialogs = []
        self.popped = 0
        self.tasks = []
        self.updates = 0

    def show_dialog(self, dialog):
        self.dialogs.append(dialog)

    def pop_dialog(self):
        self.popped += 1

    def run_task(self, fn, *args):
        self.tasks.append((fn, args))

    def update(self):
        self.updates += 1


class _FakeShell:
    def __init__(self, page, *, snackbar=True):
        self.page = page
        self.status_text = SimpleNamespace(value="Ready")
        self.progress_bar = SimpleNamespace(value=0.7)
        self.progress_pct = SimpleNamespace(value="70%")
        self.busy_control = None
        self.snacks = []
        self.updates = 0
        if snackbar:
            self.show_snackbar = self._show_snackbar

    def _show_snackbar(self, text, is_error=False):
        self.snacks.append((text, is_error))
        self.status_text.value = text

    def safe_update(self):
        self.updates += 1
        return True


class _FakeClipboard:
    def __init__(self, fail=False):
        self.values = []
        self.fail = fail

    async def set(self, value):
        if self.fail:
            raise RuntimeError("clipboard down")
        self.values.append(value)


# --- layout primitives ---------------------------------------------------

def test_card_panel_title_controls_and_stretch():
    body = ft.Text("body")
    panel = card_panel("Title", [body])
    col = panel.content
    assert isinstance(panel, ft.Container)
    assert col.controls[0].value == "Title"
    assert col.controls[1] is body
    assert col.horizontal_alignment == ft.CrossAxisAlignment.STRETCH

    loose = card_panel("Loose", [], stretch=False)
    assert loose.content.horizontal_alignment != ft.CrossAxisAlignment.STRETCH
    assert len(loose.content.controls) == 1


def test_empty_and_hint_text():
    assert empty_text("nothing").value == "nothing"
    assert hint_text("hint").value == "hint"


def test_source_row_with_and_without_subtitle():
    removed = []
    row = source_row("file.vault", lambda _e: removed.append("x"), subtitle="C:/dir")
    controls = row.content.controls
    assert [c.value for c in controls[:2]] == ["file.vault", "C:/dir"]
    button = controls[-1]
    assert isinstance(button, ft.Button)
    button.on_click(None)
    assert removed == ["x"]

    plain = source_row("dir", lambda _e: None, remove_label="Drop")
    assert len(plain.content.controls) == 2
    assert plain.content.controls[-1].content == "Drop"


def test_register_page_services_is_identity_idempotent():
    page = _FakePage()
    a, b = ft.FilePicker(), ft.FilePicker()
    register_page_services(page, a, b)
    register_page_services(page, a, b, a)
    assert len(page.services) == 2
    assert page.services[0] is a and page.services[1] is b


# --- status helpers -------------------------------------------------------

def test_set_screen_status_normal_error_and_fallback():
    page = _FakePage()
    shell = _FakeShell(page)
    set_screen_status(shell, "ok")
    assert shell.status_text.value == "ok"
    assert shell.snacks == []

    set_screen_status(shell, "bad", is_error=True)
    assert shell.snacks == [("bad", True)]

    set_screen_status(shell, "toast", snackbar=True)
    assert shell.snacks[-1] == ("toast", False)

    bare = _FakeShell(page, snackbar=False)
    set_screen_status(bare, "bad", is_error=True)
    assert bare.status_text.value == "bad"
    assert bare.updates == 1


def test_finish_screen_operation_resets_busy_state():
    page = _FakePage()
    shell = _FakeShell(page)
    button = SimpleNamespace(disabled=True)
    shell.busy_control = button
    services = SimpleNamespace(is_processing=True)

    finish_screen_operation(services, shell, "Done")

    assert services.is_processing is False
    assert shell.status_text.value == "Done"
    assert shell.progress_bar.value == 0
    assert shell.progress_pct.value == "0%"
    assert button.disabled is False
    assert shell.busy_control is None

    cleared = []
    shell.clear_busy = lambda: cleared.append(True)
    finish_screen_operation(services, shell, "Again")
    assert cleared == [True]


# --- dialogs --------------------------------------------------------------

def test_show_confirm_dialog_confirm_and_cancel_paths():
    page = _FakePage()
    shell = _FakeShell(page)
    confirmed = []
    dialog = show_confirm_dialog(
        page, shell, title="Delete?", body="Sure?", action_label="Delete",
        on_confirm=lambda: confirmed.append(True),
    )
    assert page.dialogs == [dialog]
    assert dialog.modal is True
    cancel_btn, action_btn = dialog.actions
    assert action_btn.content == "Delete"

    action_btn.on_click(None)
    assert confirmed == [True]
    assert page.popped == 1

    cancel_btn.on_click(None)
    assert page.popped == 2

    custom_cancel = []
    dialog2 = show_confirm_dialog(
        page, shell, title="t", body="b", action_label="Go",
        on_confirm=lambda: None, on_cancel=lambda: custom_cancel.append(True),
        pop_on_confirm=False,
    )
    dialog2.actions[0].on_click(None)
    dialog2.actions[1].on_click(None)
    assert custom_cancel == [True]
    assert page.popped == 2


# --- clipboard ------------------------------------------------------------

def test_auto_clear_clipboard_copy_and_token_guarded_clear():
    page = _FakePage()
    shell = _FakeShell(page)
    services = SimpleNamespace(shutdown_requested=False)
    holder = SimpleNamespace(clip=_FakeClipboard())
    guard = AutoClearClipboard(page, shell, services, lambda: holder.clip, clear_seconds=0)

    assert _run(guard.copy("one", copied_status="copied")) is True
    assert holder.clip.values == ["one"]
    assert shell.status_text.value == "copied"
    assert page.tasks[-1] == (guard.clear_after_delay, (guard.token,))
    stale = guard.token

    # Getter honours a swapped clipboard instance.
    holder.clip = _FakeClipboard()
    _run(guard.copy("two"))
    assert holder.clip.values == ["two"]

    _run(guard.clear_if_current(stale))
    assert holder.clip.values == ["two"]

    _run(guard.clear_after_delay(guard.token))
    assert holder.clip.values == ["two", ""]
    assert shell.status_text.value == "Clipboard cleared"


def test_auto_clear_clipboard_error_and_shutdown_paths():
    page = _FakePage()
    shell = _FakeShell(page)
    services = SimpleNamespace(shutdown_requested=False)
    clip = _FakeClipboard(fail=True)
    guard = AutoClearClipboard(page, shell, services, clip)

    errors = []
    assert _run(guard.copy("x", on_error=errors.append)) is False
    assert guard.token == 0
    assert len(errors) == 1 and "clipboard down" in str(errors[0])
    assert page.tasks == []

    ok = _FakeClipboard()
    guard = AutoClearClipboard(page, shell, services, ok)
    _run(guard.copy("secret"))
    services.shutdown_requested = True
    _run(guard.clear_if_current(guard.token))
    assert ok.values == ["secret"]
