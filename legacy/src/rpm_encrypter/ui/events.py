"""Queue-message dispatcher for the Flet UI bridge.

No Flet imports: tests pass a fake sink, while AppShell implements the same
duck-typed sink methods at runtime.
"""

from rpm_encrypter.services.events import (
    AppEvent,
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


class EventDispatcher:
    """Maps a typed AppEvent from msg_queue to UI-sink calls. No flet import -> testable."""

    def __init__(self, sink):
        self.sink = sink

    def dispatch(self, event: AppEvent) -> None:
        match event:
            case LogEvent(text=text):
                self.sink.on_log(text)
            case ProgressStartEvent():
                self.sink.on_progress_start()
            case ProgressEvent(done=done, total=total):
                self.sink.on_progress(done, total)
            case ErrorEvent(text=text):
                self.sink.on_error(text)
            case AuthErrorEvent(remaining=rem, lockout=lock):
                self.sink.on_auth_error(rem, lock)
            case InspectResultEvent():
                self.sink.on_inspect_result(event)
            case IntegrityResultEvent():
                self.sink.on_integrity_result(event)
            case VerifyResultEvent():
                self.sink.on_verify_result(event)
            case SelectiveExtractResultEvent():
                self.sink.on_selective_extract_result(event)
            case VaultDiffResultEvent():
                self.sink.on_vault_diff_result(event)
            case LibraryResultsEvent():
                self.sink.on_library_results(event)
            case NoteDecryptedEvent(text=text):
                self.sink.on_note_decrypted(text)
            case RekeyVersionsEvent():
                self.sink.on_rekey_versions(event)
            case RekeyPasswordStrengthEvent():
                self.sink.on_rekey_password_strength(event)
            case RekeyVersionActionEvent():
                self.sink.on_rekey_version_action(event)
            case UpdateAvailableEvent(info=info):
                self.sink.on_update_available(info)
            case BatchDoneEvent(text=text, success=success):
                if success is not None:
                    self.sink.on_batch_done(text, success)
                else:
                    self.sink.on_batch_done(text)
            case _:
                pass
