"""Vault decryption controller for the Flet UI.

This module intentionally imports no Flet symbols. It mirrors the legacy
views/decrypt_view.py worker call sequence on a worker thread and reports
progress through the Stage-1 message queue protocol, so it is unit-testable with
real crypto round-trips in a headless environment.
"""
import logging
import os
import queue
import shutil
import tempfile
import threading
from pathlib import Path
from typing import Optional

from app_config import push_recent
from crypto_core import AuthenticationError, OperationCancelledError
from log_hygiene import redact_path

logger = logging.getLogger("RPM_GUI")


class DecryptController:
    """Drives vault decrypt on a worker thread, posting bridge messages.
    FLET-FREE -> unit-testable with real crypto round-trips."""

    def __init__(self, services):
        self.services = services

    def start(self, paths, password, output_dir, recovery_key=None):
        """Spawn the decryption worker."""
        threading.Thread(
            target=self._worker,
            args=(list(paths), password, Path(output_dir), recovery_key),
            daemon=True,
        ).start()

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

    def _wipe_extract_dir(self, extract_dir):
        if extract_dir is None or not extract_dir.exists():
            return
        try:
            self.services.wiper.wipe_folder(extract_dir)
        except Exception:
            shutil.rmtree(extract_dir, ignore_errors=True)

    def _worker(self, paths, password, output_dir, recovery_key=None):
        s = self.services
        crypto, packager, wiper = s.crypto, s.packager, s.wiper
        output_dir = Path(output_dir)
        total = len(paths)
        success = 0
        auth_error = False
        cancelled = False
        cancel_check = lambda: s.cancel_requested

        for idx, raw_path in enumerate(paths, 1):
            if s.cancel_requested:
                cancelled = True
                self._log("Operation cancelled by user")
                break

            path = Path(raw_path)
            temp_zip: Optional[Path] = None
            extract_dir: Optional[Path] = None

            try:
                temp_fd, temp_name = tempfile.mkstemp(
                    prefix=".rpm_pack_",
                    suffix=".zip",
                    dir=tempfile.gettempdir(),
                )
                os.close(temp_fd)
                temp_zip = Path(temp_name)

                with s._temp_files_lock:
                    s._active_temp_files.append(temp_zip)

                self._log(f"[{idx}/{total}] Decrypting -> {path.name}")
                self._put({"type": "progress_start"})

                def prog(done, total_b):
                    self._put(
                        {"type": "progress", "done": done, "total": total_b},
                        timeout=0.01,
                    )

                # CRITICAL (Phase 12 PERF-01): single KDF path. Do not pre-verify
                # metadata. decrypt_file performs the unchanged backend M2
                # constant-work pass and returns the populated header. Calling the
                # metadata verifier first would repeat the same two Argon2
                # derivations, turning decrypt into four KDF calls.
                header = crypto.decrypt_file(
                    path,
                    temp_zip,
                    password,
                    progress_callback=prog,
                    recovery_key=recovery_key,
                    cancel_check=cancel_check,
                )

                filename = header.payload.filename
                self._log(f"[{idx}/{total}] Extracting -> {filename}")
                stem = Path(filename).stem if Path(filename).suffix else filename
                extract_dir = output_dir / stem
                counter = 1
                while extract_dir.exists():
                    extract_dir = output_dir / f"{stem}_{counter}"
                    counter += 1

                packager.extract_archive(
                    temp_zip,
                    extract_dir,
                    cancel_check=cancel_check,
                )

                s.stats.add_decrypted(byte_count=header.payload.original_size)
                s.limiter.record_success()
                push_recent("dec_sources", str(path))
                self._log_activity(
                    "Decrypt",
                    path.name,
                    "Success",
                    f"Output: {extract_dir.name}",
                )
                self._log(f"[{idx}/{total}] Restored -> {extract_dir.name}")
                success += 1

            except OperationCancelledError:
                cancelled = True
                self._log("Cancelling and cleaning up...")
                self._wipe_extract_dir(extract_dir)
                break

            except AuthenticationError:
                auth_error = True
                s.limiter.record_failure()
                self._log_activity("Decrypt", path.name, "Failed", "Authentication Error")
                _, secs = s.limiter.is_locked()
                rem = s.limiter.attempts_remaining()
                if secs:
                    self._log(f"[{idx}/{total}] Wrong password - locked for {secs}s")
                else:
                    self._log(f"[{idx}/{total}] Wrong password - {rem} attempts remaining")
                self._put({"type": "auth_error", "remaining": rem, "lockout": secs})
                break

            except Exception as exc:
                logger.exception("Decryption failed for %s", redact_path(path))
                # Partial plaintext may have been written before the failure.
                self._wipe_extract_dir(extract_dir)
                self._log(f"[{idx}/{total}] FAILED: {exc}")
                self._log_activity("Decrypt", path.name, "Failed", str(exc))

            finally:
                if temp_zip is not None:
                    with s._temp_files_lock:
                        try:
                            s._active_temp_files.remove(temp_zip)
                        except ValueError:
                            pass

                    # temp_zip is the fully decrypted PLAINTEXT archive. Route
                    # removal through the secure wiper (H4 FIX); a bare unlink
                    # leaves a recoverable copy in the output folder's free space.
                    try:
                        if temp_zip.exists():
                            wiper.wipe_file(temp_zip)
                    except Exception as wipe_exc:
                        logger.warning(
                            "Failed to securely wipe temp file %s: %s",
                            redact_path(temp_zip),
                            wipe_exc,
                        )

        s.is_processing = False
        text = (
            f"Cancelled - {success}/{total} done"
            if cancelled
            else (
                f"Wrong password or corrupted vault - {s.limiter.attempts_remaining()} attempts remaining"
                if auth_error
                else f"Batch complete: {success}/{total} decrypted"
            )
        )
        self._put(
            {
                "type": "batch_done",
                "text": text,
                "success": bool(not cancelled and not auth_error and success == total),
            },
            timeout=1.0,
        )
