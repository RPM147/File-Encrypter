"""Re-Key + version-history controller for the Flet UI.

This module intentionally imports no Flet symbols. It mirrors the legacy
views/rekey_view.py worker on background threads and reports results through the
Stage-1 message queue protocol, so it is unit-testable with real crypto round-
trips in a headless environment.

Re-Key re-encrypts ONLY the small DEK envelope via crypto.rekey_vault (the
backend is the single authority for old-password auth) and copies the payload /
hidden compartment byte-for-byte; the plaintext is never decrypted. Version
history is managed entirely through VaultVersionManager.
"""
import logging
import queue
import threading
from datetime import datetime
from pathlib import Path

import versioning
from app_config import push_recent
from app_constants import ZXCVBN_AVAILABLE, zxcvbn
from crypto_core import OperationCancelledError, AuthenticationError, CryptoError
from log_hygiene import redact_path

logger = logging.getLogger("RPM_GUI")


class RekeyController:
    """Drives Re-Key and version-history operations.
    FLET-FREE -> unit-testable without a display."""

    def __init__(self, services):
        self.services = services

    def _put(self, msg, timeout=0.1):
        try:
            self.services.msg_queue.put(msg, timeout=timeout)
        except queue.Full:
            pass

    def _log(self, text):
        self._put({"type": "log", "text": text})

    def _log_activity(self, action, target, result, details=""):
        logger_obj = getattr(self.services, "activity_logger", None)
        if logger_obj:
            logger_obj.log_event(action, target, result, details)

    # ------------------------------------------------------------------- re-key
    def start_rekey(self, vault, old_password, new_password):
        threading.Thread(
            target=self._rekey_worker,
            args=(Path(vault), old_password, new_password),
            daemon=True,
        ).start()

    def _rekey_worker(self, vault, old_password, new_password):
        vault = Path(vault)
        tmp = vault.with_suffix(".rekey.tmp")
        cancel_check = lambda: bool(getattr(self.services, "cancel_requested", False))
        try:
            self._log(f"Re-keying -> {vault.name}")

            # Versioning: save a copy BEFORE any modification. Non-fatal.
            if self.services.versioner.enabled:
                self._log("Saving version before re-key...")
                saved = self.services.versioner.save_version(vault)
                if saved:
                    self._log(f"Version saved: {saved.name}")
                    self._post_versions(vault)
                else:
                    self._log("Versioning skipped (disk full or disabled)")

            # The backend re-key API is the single authority for old-password
            # authentication. Write to a temp sibling, then atomically replace.
            self.services.crypto.rekey_vault(
                vault, tmp, old_password, new_password, cancel_check=cancel_check
            )
            tmp.replace(vault)

            stats = getattr(self.services, "stats", None)
            if stats is not None:
                stats.add_rekeyed()
            self._log(f"Re-key complete -> {vault.name}")
            self._log_activity("Re-Key", vault.name, "Success")
            push_recent("rekey_vaults", str(vault))
            self._post_versions(vault)
            self._put({"type": "batch_done", "text": f"Re-key complete: {vault.name}"}, timeout=1.0)

        except OperationCancelledError:
            self._log("Cancelling and cleaning up...")
            self._put({"type": "batch_done", "text": "Cancelled - 0/1 done"}, timeout=1.0)
        except AuthenticationError:
            # AuthenticationError subclasses CryptoError -> must be caught FIRST.
            self._log("Wrong current password")
            self._log_activity("Re-Key", vault.name, "Failed", "Wrong current password")
            self._put({"type": "batch_done", "text": "Re-key failed: wrong current password"}, timeout=1.0)
        except CryptoError as exc:
            logger.exception("Re-key failed for %s", redact_path(vault))
            self._log(f"FAILED: {exc}")
            self._log_activity("Re-Key", vault.name, "Failed", str(exc))
            self._put({"type": "batch_done", "text": f"Re-key failed: {exc}"}, timeout=1.0)
        except Exception as exc:
            logger.exception("Re-key failed for %s", redact_path(vault))
            self._log(f"FAILED: {exc}")
            self._log_activity("Re-Key", vault.name, "Failed", str(exc))
            self._put({"type": "batch_done", "text": f"Re-key failed: {exc}"}, timeout=1.0)
        finally:
            try:
                if tmp.exists():
                    tmp.unlink()
            except Exception:
                pass

    # --------------------------------------------------------- password strength
    def start_strength_check(self, password):
        threading.Thread(
            target=self._strength_worker, args=(str(password),), daemon=True
        ).start()

    def _strength_worker(self, password):
        if not password:
            self._put({"type": "rekey_password_strength", "score": 0, "crack_time": ""})
            return
        if ZXCVBN_AVAILABLE:
            try:
                res = zxcvbn(password)
                self._put({
                    "type": "rekey_password_strength",
                    "score": res["score"],
                    "crack_time": res["crack_times_display"]["offline_slow_hashing_1e4_per_second"],
                })
                return
            except Exception:
                pass
        self._put({"type": "rekey_password_strength", "score": 0, "crack_time": ""})

    # -------------------------------------------------------- version history
    @staticmethod
    def serialize_entry(entry: versioning.VersionEntry) -> dict:
        return {
            "path": str(entry.path),
            "name": entry.path.name,
            "display_timestamp": entry.display_timestamp,
            "display_size": entry.display_size,
            "size_bytes": entry.size_bytes,
        }

    def _post_versions(self, vault):
        vault = Path(vault)
        try:
            # list_versions is oldest-first; reverse so newest is shown first.
            entries = list(reversed(self.services.versioner.list_versions(vault)))
            self._put({
                "type": "rekey_versions",
                "vault": str(vault),
                "entries": [self.serialize_entry(e) for e in entries],
                "error": "",
            }, timeout=1.0)
        except Exception as exc:
            logger.exception("Version refresh failed for %s", redact_path(vault))
            self._put({
                "type": "rekey_versions",
                "vault": str(vault),
                "entries": [],
                "error": f"Version refresh failed: {exc}",
            }, timeout=1.0)

    def start_refresh_versions(self, vault):
        threading.Thread(
            target=self._post_versions, args=(Path(vault),), daemon=True
        ).start()

    def _entry_from_payload(self, payload: dict) -> versioning.VersionEntry:
        path = Path(str(payload.get("path", "")))
        if not path.is_file():
            raise OSError("Selected version does not exist")
        size = path.stat().st_size
        # The timestamp is display-only and not used by the version operations
        # (they act on entry.path); mtime is an acceptable reconstruction.
        return versioning.VersionEntry(
            path=path,
            timestamp=datetime.fromtimestamp(path.stat().st_mtime),
            size_bytes=size,
        )

    def start_restore_copy(self, entry_payload, vault):
        threading.Thread(
            target=self._restore_copy_worker,
            args=(entry_payload, Path(vault)),
            daemon=True,
        ).start()

    def _restore_copy_worker(self, entry_payload, vault):
        vault = Path(vault)
        try:
            entry = self._entry_from_payload(entry_payload)
            copy_path = self.services.versioner.restore_as_copy(entry, vault)
            self._log_activity("Version Restore", vault.name, "Success", f"Copy: {copy_path.name}")
            text = f"Restored copy: {copy_path.name}"
            self._put({"type": "rekey_version_action", "text": text, "error": "", "refresh": False}, timeout=1.0)
            self._put({"type": "batch_done", "text": text}, timeout=1.0)
        except Exception as exc:
            logger.exception("Version restore failed for %s", redact_path(vault))
            self._log_activity("Version Restore", vault.name, "Failed", str(exc))
            self._put({"type": "rekey_version_action", "text": "Restore failed", "error": str(exc), "refresh": False}, timeout=1.0)
            self._put({"type": "batch_done", "text": f"Restore failed: {exc}"}, timeout=1.0)

    def start_replace_current(self, entry_payload, vault):
        threading.Thread(
            target=self._replace_current_worker,
            args=(entry_payload, Path(vault)),
            daemon=True,
        ).start()

    def _replace_current_worker(self, entry_payload, vault):
        vault = Path(vault)
        try:
            entry = self._entry_from_payload(entry_payload)
            self.services.versioner.replace_current(entry, vault)
            self._log_activity("Version Replace", vault.name, "Success", f"From: {entry.path.name}")
            text = "Vault restored from version"
            self._put({"type": "rekey_version_action", "text": text, "error": "", "refresh": True}, timeout=1.0)
            self._post_versions(vault)
            self._put({"type": "batch_done", "text": text}, timeout=1.0)
        except Exception as exc:
            logger.exception("Version replace failed for %s", redact_path(vault))
            self._log_activity("Version Replace", vault.name, "Failed", str(exc))
            self._put({"type": "rekey_version_action", "text": "Replace failed", "error": str(exc), "refresh": False}, timeout=1.0)
            self._put({"type": "batch_done", "text": f"Replace failed: {exc}"}, timeout=1.0)

    def start_delete_version(self, entry_payload, vault):
        threading.Thread(
            target=self._delete_version_worker,
            args=(entry_payload, Path(vault)),
            daemon=True,
        ).start()

    def _delete_version_worker(self, entry_payload, vault):
        vault = Path(vault)
        try:
            entry = self._entry_from_payload(entry_payload)
            self.services.versioner.delete_version(entry)
            self._log_activity("Version Delete", vault.name, "Success", f"File: {entry.path.name}")
            text = "Version deleted"
            self._put({"type": "rekey_version_action", "text": text, "error": "", "refresh": True}, timeout=1.0)
            self._post_versions(vault)
            self._put({"type": "batch_done", "text": text}, timeout=1.0)
        except Exception as exc:
            logger.exception("Version delete failed for %s", redact_path(vault))
            self._log_activity("Version Delete", vault.name, "Failed", str(exc))
            self._put({"type": "rekey_version_action", "text": "Delete failed", "error": str(exc), "refresh": False}, timeout=1.0)
            self._put({"type": "batch_done", "text": f"Delete failed: {exc}"}, timeout=1.0)
