"""Encrypted Notes controller for the Flet UI.

This module intentionally imports no Flet symbols. It drives the backend note
wrappers (crypto.encrypt_note / crypto.decrypt_note) on worker threads and reports
results through the Stage-1 message queue protocol, so it is unit-testable with
real crypto round-trips in a headless environment.

Notes are password-only `.vault` files that bypass the ZIP archive layer. Saving
is atomic (file_handler.atomic_output, Phase-6 SEC-04) so a failure never leaves a
partial under the final `.vault` name. A wrong note password is reported via a
plain batch_done status (NOT auth_error) -- the old Notes UI deliberately does not
route note failures through the AttemptLimiter.
"""
import logging
import queue
import threading
from pathlib import Path

from crypto_core import AuthenticationError
from file_handler import atomic_output
from log_hygiene import redact_path

logger = logging.getLogger("RPM_GUI")


class NotesController:
    """Drives encrypted note save/load operations.
    FLET-FREE -> unit-testable with real crypto round-trips."""

    def __init__(self, services):
        self.services = services

    def start_encrypt(self, text, path, password):
        threading.Thread(
            target=self._encrypt_worker,
            args=(str(text), Path(path), password),
            daemon=True,
        ).start()

    def start_decrypt(self, path, password):
        threading.Thread(
            target=self._decrypt_worker,
            args=(Path(path), password),
            daemon=True,
        ).start()

    def _put(self, msg, timeout=0.1):
        try:
            self.services.msg_queue.put(msg, timeout=timeout)
        except queue.Full:
            pass

    def _log_activity(self, action, target, result, details=""):
        logger_obj = getattr(self.services, "activity_logger", None)
        if logger_obj:
            logger_obj.log_event(action, target, result, details)

    def _encrypt_worker(self, text, path, password):
        path = Path(path)
        try:
            # Phase-6 SEC-04: a note is a `.vault` too -> write atomically so a
            # failure never leaves a partial under the final name. The title is
            # taken from the FINAL path; the bytes are written into the temp.
            atomic_output(
                path,
                lambda p: self.services.crypto.encrypt_note(
                    text,
                    p,
                    password,
                    note_title=path.name,
                ),
            )
            self._log_activity("Note Encrypt", path.name, "Success")
            self._put({"type": "batch_done", "text": f"Note saved to {path.name}"}, timeout=1.0)
        except Exception as exc:
            logger.exception("Note encryption failed for %s", redact_path(path))
            self._log_activity("Note Encrypt", path.name, "Failed", str(exc))
            self._put({"type": "batch_done", "text": f"Note save failed: {exc}"}, timeout=1.0)

    def _decrypt_worker(self, path, password):
        path = Path(path)
        try:
            text = self.services.crypto.decrypt_note(path, password)
            self._log_activity("Note Decrypt", path.name, "Success")
            self._put({"type": "note_decrypted", "text": text}, timeout=1.0)
            self._put({"type": "batch_done", "text": f"Note loaded: {path.name}"}, timeout=1.0)
        except AuthenticationError:
            # Notes deliberately do NOT use the AttemptLimiter (no auth_error).
            self._log_activity("Note Decrypt", path.name, "Failed", "Auth Error")
            self._put({"type": "batch_done", "text": "Note load failed: Wrong Password"}, timeout=1.0)
        except Exception as exc:
            logger.exception("Note decryption failed for %s", redact_path(path))
            self._log_activity("Note Decrypt", path.name, "Failed", str(exc))
            self._put({"type": "batch_done", "text": f"Note load failed: {exc}"}, timeout=1.0)
