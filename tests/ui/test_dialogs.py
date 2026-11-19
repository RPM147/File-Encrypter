"""Unit tests for Phase 3 extracted dialogs, HiddenVaultPanel, and Inspect formatters."""

import shutil
from types import SimpleNamespace

import pytest

ft = pytest.importorskip("flet")

from rpm_encrypter.services.controllers.inspect_controller import InspectController  # noqa: E402
from rpm_encrypter.ui.components import HIDDEN_RECOVERY_WARNING, HiddenVaultPanel  # noqa: E402
from rpm_encrypter.ui.dialogs import (  # noqa: E402
    show_recovery_dialog,
    show_selective_extract_dialog,
    show_vault_diff_dialog,
)
from rpm_encrypter.ui.screens.inspect_formatters import (  # noqa: E402
    build_fingerprint_rows,
    format_vault_metadata,
)


class _FakePage:
    def __init__(self, *, allow_dialogs=True):
        self.dialogs = []
        self.popped = 0
        self.tasks = []
        self.updates = 0
        if allow_dialogs:
            self.show_dialog = self._show_dialog
            self.pop_dialog = self._pop_dialog

    def _show_dialog(self, dialog):
        self.dialogs.append(dialog)

    def _pop_dialog(self):
        self.popped += 1

    def run_task(self, fn, *args):
        self.tasks.append((fn, args))

    def update(self):
        self.updates += 1


class _FakeShell:
    def __init__(self, page):
        self.page = page
        self.status_text = SimpleNamespace(value="Ready")
        self.snacks = []
        self.busy_controls = []
        self.updates = 0

    def show_snackbar(self, text, is_error=False):
        self.snacks.append((text, is_error))
        self.status_text.value = text

    def set_busy(self, control):
        self.busy_controls.append(control)

    def safe_update(self):
        self.updates += 1
        return True


def _services():
    return SimpleNamespace(is_processing=False, cancel_requested=False)


# --- recovery dialog ------------------------------------------------------

def test_show_recovery_dialog_normal_hidden_confirm_cancel_and_unavailable():
    page = _FakePage()
    shell = _FakeShell(page)
    confirmed, cancelled = [], []

    dialog = show_recovery_dialog(
        page,
        shell,
        phrase="word " * 24,
        hidden_mode=False,
        on_confirm=lambda: confirmed.append(True),
        on_cancel=lambda: cancelled.append(True),
    )
    assert page.dialogs == [dialog]
    cancel_btn, continue_btn = dialog.actions

    # Continue requires checkbox confirmation first.
    continue_btn.on_click(None)
    assert confirmed == []
    assert "Confirm" in shell.status_text.value

    checkbox = dialog.content.content.controls[-1]
    checkbox.value = True
    continue_btn.on_click(None)
    assert confirmed == [True]
    assert page.popped == 1

    cancel_btn.on_click(None)
    assert cancelled == [True]
    assert page.popped == 2

    hidden_dlg = show_recovery_dialog(
        page, shell, phrase="word " * 24, hidden_mode=True,
        on_confirm=lambda: None, on_cancel=lambda: None,
    )
    assert "decoy" in hidden_dlg.content.content.controls[0].value.lower()

    no_dlg_page = _FakePage(allow_dialogs=False)
    no_dlg_shell = _FakeShell(no_dlg_page)
    unavail = []
    res = show_recovery_dialog(
        no_dlg_page, no_dlg_shell, phrase="w", hidden_mode=False,
        on_confirm=lambda: None, on_cancel=lambda: None,
        on_unavailable=lambda: unavail.append(True),
    )
    assert res is None
    assert unavail == [True]
    assert no_dlg_shell.status_text.value == "Recovery dialog unavailable"


# --- selective extract dialog ---------------------------------------------

def test_show_selective_extract_dialog_validation_and_launch(tmp_path, monkeypatch):
    page = _FakePage()
    shell = _FakeShell(page)
    services = _services()
    busy = ft.Button("Selective Extract")

    assert show_selective_extract_dialog(
        page, shell, services, metadata={"files": []}, vault_path=tmp_path / "v.vault",
        password="pw", recovery_key=None, output_picker=ft.FilePicker(), busy_control=busy,
    ) is None
    assert "No files available" in shell.status_text.value

    launched = []
    monkeypatch.setattr(
        InspectController,
        "start_selective_extract",
        lambda _self, *args: launched.append(args),
    )

    meta = {"files": [{"path": "docs/a.txt", "size": 128}], "original_size": 128}
    dlg = show_selective_extract_dialog(
        page, shell, services, metadata=meta, vault_path=tmp_path / "v.vault",
        password="pw", recovery_key=None, output_picker=ft.FilePicker(), busy_control=busy,
    )
    assert dlg is not None
    col = dlg.content.content
    checks = col.controls[1].content.controls
    out_field = col.controls[2].controls[0]
    cancel_btn, extract_btn = dlg.actions

    # Validation: nothing checked.
    extract_btn.on_click(None)
    assert "Select at least one file" in shell.status_text.value

    # Validation: missing/invalid output dir.
    checks[0].value = True
    out_field.value = str(tmp_path / "missing_dir")
    extract_btn.on_click(None)
    assert "valid output directory" in shell.status_text.value

    # Validation: low temp / output free space.
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    out_field.value = str(out_dir)
    monkeypatch.setattr(shutil, "disk_usage", lambda _p: SimpleNamespace(free=10))
    extract_btn.on_click(None)
    assert "free space" in shell.status_text.value

    # Happy path launches controller.
    monkeypatch.setattr(shutil, "disk_usage", lambda _p: SimpleNamespace(free=10_000_000))
    extract_btn.on_click(None)
    assert page.popped == 1
    assert services.is_processing is True
    assert shell.busy_controls == [busy]
    assert launched == [(tmp_path / "v.vault", "pw", None, ["docs/a.txt"], out_dir)]

    cancel_btn.on_click(None)
    assert page.popped == 2


# --- vault diff dialog ----------------------------------------------------

def test_show_vault_diff_dialog_validation_and_launch(tmp_path, monkeypatch):
    page = _FakePage()
    shell = _FakeShell(page)
    services = _services()
    busy = ft.Button("Vault Diff")
    launched = []
    monkeypatch.setattr(
        InspectController,
        "start_vault_diff",
        lambda _self, *args: launched.append(args),
    )

    dlg = show_vault_diff_dialog(
        page, shell, services, picker_a=ft.FilePicker(), picker_b=ft.FilePicker(), busy_control=busy,
    )
    assert dlg is not None
    rows = dlg.content.content.controls
    path_a_field = rows[0].controls[0]
    pw_a_field = rows[1]
    path_b_field = rows[2].controls[0]
    pw_b_field = rows[3]
    cancel_btn, compare_btn = dlg.actions

    compare_btn.on_click(None)
    assert "Vault paths and passwords are required" in shell.status_text.value

    va, vb = tmp_path / "a.vault", tmp_path / "b.vault"
    va.write_bytes(b"a")
    vb.write_bytes(b"b")
    path_a_field.value = str(va)
    path_b_field.value = str(vb)
    pw_a_field.value = "pw-a"
    pw_b_field.value = "pw-b"

    compare_btn.on_click(None)
    assert page.popped == 1
    assert services.is_processing is True
    assert shell.busy_controls == [busy]
    assert launched == [(va, "pw-a", vb, "pw-b")]

    cancel_btn.on_click(None)
    assert page.popped == 2


# --- HiddenVaultPanel -----------------------------------------------------

def test_hidden_vault_panel_sources_toggle_and_validation(tmp_path):
    page = _FakePage()
    shell = _FakeShell(page)
    hp = HiddenVaultPanel(page, shell)
    hp.build_controls()
    assert "Hidden data has no recovery phrase" in HIDDEN_RECOVERY_WARNING
    assert hp.validate("decoy") == (
        {
            "hidden_mode": False,
            "hidden_password": None,
            "hidden_size_label": "100 MB",
            "hidden_sources": [],
        },
        "",
    )

    hp.toggle.value = True
    hp.toggle_visibility()
    assert hp.panel.visible is True

    _, err = hp.validate("decoy")
    assert err == "Enter a hidden password"

    hp.password_field.value = "hid1"
    hp.confirm_password_field.value = "hid2"
    assert hp.validate("decoy") == (None, "Hidden passwords do not match")

    hp.password_field.value = "same"
    hp.confirm_password_field.value = "same"
    assert hp.validate("same") == (None, "Decoy and hidden passwords must be different")

    hp.password_field.value = "hidden-pw"
    hp.confirm_password_field.value = "hidden-pw"
    assert hp.validate("decoy") == (None, "Add at least one hidden source")

    secret = tmp_path / "secret.txt"
    secret.write_bytes(b"x")
    hp.append_source(f'"{secret}"')
    hp.append_source(str(secret))  # deduplicated
    assert hp.sources == [str(secret)]

    hp.size_dropdown.value = "INVALID"
    assert hp.validate("decoy") == (None, "Select an explicit hidden container size")

    hp.size_dropdown.value = "10 MB"
    args, err = hp.validate("decoy")
    assert err == ""
    assert args == {
        "hidden_mode": True,
        "hidden_password": "hidden-pw",
        "hidden_size_label": "10 MB",
        "hidden_sources": [str(secret)],
    }

    hp.remove_source(str(secret))
    assert hp.sources == []
    hp.append_source(str(secret))
    hp.reset()
    assert hp.sources == []
    assert hp.toggle.value is False
    assert hp.panel.visible is False


# --- inspect formatters ---------------------------------------------------

def test_inspect_formatters_metadata_and_fingerprints():
    files = [{"path": f"file_{i}.txt", "size": i} for i in range(105)]
    rendered = format_vault_metadata(
        {
            "filename": "archive.vault",
            "original_size": 1024,
            "file_count": 105,
            "created_at": "2026-01-01",
            "source_type": "folder",
            "kdf_algorithm": "Argon2id",
            "encryption": "AES-256-GCM",
            "payload_encryption": "AES-256-GCM",
            "argon_memory": 65536,
            "argon_iterations": 3,
            "argon_parallelism": 4,
            "files": files,
        }
    )
    assert "archive.vault" in rendered
    assert "Argon2id" in rendered
    assert "... and 5 more files" in rendered

    empty_rows = build_fingerprint_rows({})
    assert len(empty_rows) == 1
    assert empty_rows[0].value == "No fingerprints saved yet."

    rows = build_fingerprint_rows(
        {
            "C:/a.vault": {"filename": "a.vault", "size": 2 * 1024 * 1024, "sha256": "a" * 64, "recorded": "2026-01-01"},
            "C:/b.vault": {"filename": "b.vault", "size": 4 * 1024 * 1024, "sha256": "b" * 64, "recorded": "2026-02-01"},
        }
    )
    assert len(rows) == 2
    assert "b.vault" in rows[0].content.controls[0].value
    assert "a.vault" in rows[1].content.controls[0].value
