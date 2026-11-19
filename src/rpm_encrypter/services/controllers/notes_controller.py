"""Encrypted Notes controller for the Flet UI (Flet-free)."""

import logging
from pathlib import Path

from rpm_encrypter.core import AuthenticationError
from rpm_encrypter.storage.atomic import atomic_output
from rpm_encrypter.storage.log_hygiene import redact_path
from .base import BaseController

logger = logging.getLogger("RPM_GUI")


class NotesController(BaseController):
    """Drives encrypted note save/load operations."""

    def start_encrypt(self, text, path, password):
        self._spawn(self._encrypt_worker, str(text), Path(path), password)

    def start_decrypt(self, path, password):
        self._spawn(self._decrypt_worker, Path(path), password)

    def _encrypt_worker(self, text, path, password):
        path = Path(path)
        try:
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
            self._log_activity("Note Decrypt", path.name, "Failed", "Auth Error")
            self._put({"type": "batch_done", "text": "Note load failed: Wrong Password"}, timeout=1.0)
        except Exception as exc:
            logger.exception("Note decryption failed for %s", redact_path(path))
            self._log_activity("Note Decrypt", path.name, "Failed", str(exc))
            self._put({"type": "batch_done", "text": f"Note load failed: {exc}"}, timeout=1.0)
