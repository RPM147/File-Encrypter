from pathlib import Path

from recovery_dialog_copy import (
    DECRYPT_RECOVERY_LABEL,
    INSPECT_RECOVERY_LABEL,
    get_recovery_dialog_copy,
)


ROOT = Path(__file__).resolve().parents[1]


def test_normal_recovery_dialog_copy_is_standard_vault_only():
    copy = get_recovery_dialog_copy(hidden_mode=False)
    combined = " ".join([copy.title, copy.heading, copy.description, copy.checkbox_text]).lower()

    assert copy.title == "Recovery Phrase"
    assert "recover" in combined
    assert "vault" in combined
    assert "hidden" not in combined
    assert "decoy" not in combined


def test_hidden_recovery_dialog_copy_is_explicitly_decoy_only_and_unrecoverable():
    copy = get_recovery_dialog_copy(hidden_mode=True)
    combined = " ".join([copy.title, copy.heading, copy.description, copy.checkbox_text]).lower()

    assert "decoy" in combined
    assert "recovers only" in combined or "only the decoy" in combined
    assert "cannot recover hidden" in combined
    assert "hidden password" in combined
    assert "permanently unrecoverable" in combined
    assert "unrecoverable without the hidden password" in combined


def test_recovery_labels_clarify_standard_or_decoy_only_scope():
    assert DECRYPT_RECOVERY_LABEL == "Use Recovery Phrase (standard/decoy only)"
    assert INSPECT_RECOVERY_LABEL == "Use Recovery Phrase (standard/decoy only)"


def test_hidden_worker_does_not_queue_a_second_recovery_phrase_dialog():
    source = (ROOT / "views" / "encrypt_view.py").read_text(encoding="utf-8")

    assert '"type": "recovery_phrase"' not in source
    assert "msg_queue.put({\"type\": \"recovery_phrase\"" not in source


def test_hidden_panel_contains_unrecoverable_warning_text():
    source = (ROOT / "views" / "encrypt_view.py").read_text(encoding="utf-8")

    assert "Hidden data has no recovery phrase" in source
    assert "requires the hidden password" in source
