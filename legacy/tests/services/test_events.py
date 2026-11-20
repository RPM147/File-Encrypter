"""Unit tests for typed AppEvent dataclasses and EventDispatcher routing."""

from dataclasses import FrozenInstanceError

import pytest

from rpm_encrypter.services import AppEvent
from rpm_encrypter.services.events import (
    AuthErrorEvent,
    BatchDoneEvent,
    ErrorEvent,
    InspectResultEvent,
    IntegrityResultEvent,
    LibraryResultsEvent,
    LogEvent,
    NoteDecryptedEvent,
    ProgressEvent,
    ProgressStartEvent,
    RekeyPasswordStrengthEvent,
    RekeyVersionActionEvent,
    RekeyVersionsEvent,
    SelectiveExtractResultEvent,
    UpdateAvailableEvent,
    VaultDiffResultEvent,
    VerifyResultEvent,
)
from rpm_encrypter.ui.events import EventDispatcher


class _RecordingSink:
    def __init__(self):
        self.calls = []

    def on_log(self, text):
        self.calls.append(("on_log", text))

    def on_progress_start(self):
        self.calls.append(("on_progress_start",))

    def on_progress(self, done, total):
        self.calls.append(("on_progress", done, total))

    def on_error(self, text):
        self.calls.append(("on_error", text))

    def on_auth_error(self, rem, lock):
        self.calls.append(("on_auth_error", rem, lock))

    def on_inspect_result(self, event):
        self.calls.append(("on_inspect_result", event))

    def on_integrity_result(self, event):
        self.calls.append(("on_integrity_result", event))

    def on_verify_result(self, event):
        self.calls.append(("on_verify_result", event))

    def on_selective_extract_result(self, event):
        self.calls.append(("on_selective_extract_result", event))

    def on_vault_diff_result(self, event):
        self.calls.append(("on_vault_diff_result", event))

    def on_library_results(self, event):
        self.calls.append(("on_library_results", event))

    def on_note_decrypted(self, text):
        self.calls.append(("on_note_decrypted", text))

    def on_rekey_versions(self, event):
        self.calls.append(("on_rekey_versions", event))

    def on_rekey_password_strength(self, event):
        self.calls.append(("on_rekey_password_strength", event))

    def on_rekey_version_action(self, event):
        self.calls.append(("on_rekey_version_action", event))

    def on_update_available(self, info):
        self.calls.append(("on_update_available", info))

    def on_batch_done(self, *args):
        self.calls.append(("on_batch_done", *args))


_ALL_EVENTS = [
    LogEvent(text="msg"),
    ProgressStartEvent(),
    ProgressEvent(done=5, total=10),
    ErrorEvent(text="err"),
    AuthErrorEvent(remaining=3, lockout=0),
    InspectResultEvent(path="a.vault"),
    IntegrityResultEvent(path="a.vault", ok=True, msg="ok", sha="abc"),
    VerifyResultEvent(path="a.vault", status="unchanged"),
    SelectiveExtractResultEvent(path="a.vault", count=2),
    VaultDiffResultEvent(path_a="a.vault", path_b="b.vault", text="diff"),
    LibraryResultsEvent(data=[{"path": "a.vault"}]),
    NoteDecryptedEvent(text="secret"),
    RekeyVersionsEvent(vault="a.vault"),
    RekeyPasswordStrengthEvent(score=4, crack_time="centuries"),
    RekeyVersionActionEvent(text="restored", refresh=True),
    UpdateAvailableEvent(info={"version": "3.2.0"}),
    BatchDoneEvent(text="all good", success=True),
]


def test_all_events_inherit_app_event_and_are_frozen():
    assert len(_ALL_EVENTS) == 17
    for ev in _ALL_EVENTS:
        assert isinstance(ev, AppEvent)
    with pytest.raises(FrozenInstanceError):
        _ALL_EVENTS[0].text = "mutated"


def test_event_defaults_are_isolated_per_instance():
    e1 = InspectResultEvent()
    e2 = InspectResultEvent()
    assert e1.metadata == {}
    e1.metadata["k"] = 1
    assert e2.metadata == {}


def test_event_dispatcher_routes_all_17_event_types_and_ignores_unknown():
    sink = _RecordingSink()
    dispatcher = EventDispatcher(sink)
    for ev in _ALL_EVENTS:
        dispatcher.dispatch(ev)
    dispatcher.dispatch(BatchDoneEvent(text="simple"))
    dispatcher.dispatch(object())
    dispatcher.dispatch({"type": "legacy_dict_ignored"})

    assert sink.calls == [
        ("on_log", "msg"),
        ("on_progress_start",),
        ("on_progress", 5, 10),
        ("on_error", "err"),
        ("on_auth_error", 3, 0),
        ("on_inspect_result", _ALL_EVENTS[5]),
        ("on_integrity_result", _ALL_EVENTS[6]),
        ("on_verify_result", _ALL_EVENTS[7]),
        ("on_selective_extract_result", _ALL_EVENTS[8]),
        ("on_vault_diff_result", _ALL_EVENTS[9]),
        ("on_library_results", _ALL_EVENTS[10]),
        ("on_note_decrypted", "secret"),
        ("on_rekey_versions", _ALL_EVENTS[12]),
        ("on_rekey_password_strength", _ALL_EVENTS[13]),
        ("on_rekey_version_action", _ALL_EVENTS[14]),
        ("on_update_available", {"version": "3.2.0"}),
        ("on_batch_done", "all good", True),
        ("on_batch_done", "simple"),
    ]
