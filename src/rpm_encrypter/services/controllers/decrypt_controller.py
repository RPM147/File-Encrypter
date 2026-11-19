"""Vault decryption controller for the Flet UI (Flet-free)."""

import logging
import os
import tempfile
from pathlib import Path
from typing import Optional

from rpm_encrypter.core import AuthenticationError, OperationCancelledError
from rpm_encrypter.services.events import (
    AuthErrorEvent,
    BatchDoneEvent,
    ProgressEvent,
    ProgressStartEvent,
)
from rpm_encrypter.storage.config import push_recent
from rpm_encrypter.storage.log_hygiene import redact_path
from .base import BaseController

logger = logging.getLogger("RPM_GUI")


class DecryptController(BaseController):
    """Drives vault decrypt on a worker thread, posting bridge messages."""

    def start(self, paths, password, output_dir, recovery_key=None):
        """Spawn the decryption worker."""
        self._spawn(self._worker, list(paths), password, Path(output_dir), recovery_key)

    def _worker(self, paths, password, output_dir, recovery_key=None):
        s = self.services
        crypto, packager = s.crypto, s.packager
        output_dir = Path(output_dir)
        total = len(paths)
        success = 0
        auth_error = False
        cancelled = False

        for idx, raw_path in enumerate(paths, 1):
            if self._cancel_check():
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
                self._track_temp(temp_zip)

                self._log(f"[{idx}/{total}] Decrypting -> {path.name}")
                self._put(ProgressStartEvent())

                def prog(done, total_b):
                    self._put(
                        ProgressEvent(done=done, total=total_b),
                        timeout=0.01,
                    )

                # Single KDF path: decrypt_file performs the M2 pass and returns header.
                header = crypto.decrypt_file(
                    path,
                    temp_zip,
                    password,
                    progress_callback=prog,
                    recovery_key=recovery_key,
                    cancel_check=self._cancel_check,
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
                    cancel_check=self._cancel_check,
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
                self._wipe_temp_dir(extract_dir)
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
                self._put(AuthErrorEvent(remaining=rem, lockout=secs))
                break

            except Exception as exc:
                logger.exception("Decryption failed for %s", redact_path(path))
                self._wipe_temp_dir(extract_dir)
                self._log(f"[{idx}/{total}] FAILED: {exc}")
                self._log_activity("Decrypt", path.name, "Failed", str(exc))

            finally:
                self._wipe_temp_file(temp_zip)

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
            BatchDoneEvent(
                text=text,
                success=bool(not cancelled and not auth_error and success == total),
            ),
            timeout=1.0,
        )
