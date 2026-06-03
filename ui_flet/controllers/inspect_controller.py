"""Vault Info / Inspect controller for the Flet UI.

This module intentionally imports no Flet symbols. It mirrors the legacy
views/inspect_view.py logic on worker threads and reports results through the
Stage-1 message queue protocol, so it is unit-testable with real vaults in a
headless environment.
"""
import hashlib
import logging
import os
import queue
import shutil
import struct
import tempfile
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from app_config import _load_cfg, _mutate_cfg
from crypto_core import (
    AES_TAG_SIZE,
    AuthenticationError,
    OperationCancelledError,
    VAULT_MAGIC,
    is_supported_vault_version,
)
from log_hygiene import redact_path

logger = logging.getLogger("RPM_GUI")


class InspectController:
    """Drive Vault Info inspect/hash/fingerprint/extract/diff operations."""

    def __init__(self, services):
        self.services = services

    def start_inspect(self, path, password=None, recovery_key=None):
        threading.Thread(
            target=self._inspect_worker,
            args=(Path(path), password, recovery_key),
            daemon=True,
        ).start()

    def start_integrity_check(self, path):
        threading.Thread(
            target=self._integrity_worker,
            args=(Path(path),),
            daemon=True,
        ).start()

    def start_verify_saved(self, path):
        threading.Thread(
            target=self._verify_worker,
            args=(Path(path),),
            daemon=True,
        ).start()

    def start_selective_extract(
        self,
        vault_path,
        password,
        recovery_key,
        selected_files,
        output_dir,
    ):
        threading.Thread(
            target=self._selective_extract_worker,
            args=(Path(vault_path), password, recovery_key, list(selected_files), Path(output_dir)),
            daemon=True,
        ).start()

    def start_vault_diff(self, path_a, password_a, path_b, password_b):
        threading.Thread(
            target=self._vault_diff_worker,
            args=(Path(path_a), password_a, Path(path_b), password_b),
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

    # ------------------------------------------------------------------ inspect
    def _inspect_worker(self, path, password=None, recovery_key=None):
        path = Path(path)
        self._log(f"Inspecting -> {path.name}")
        try:
            metadata = self.services.inspector.inspect(
                path,
                password=password,
                recovery_key=recovery_key,
            )
            self.services.limiter.record_success()
            self._log_activity("Inspect", path.name, "Success")
            self._put(
                {
                    "type": "inspect_result",
                    "path": str(path),
                    "metadata": metadata,
                    "error": "",
                },
                timeout=1.0,
            )
        except AuthenticationError:
            self.services.limiter.record_failure()
            self._log_activity("Inspect", path.name, "Failed", "Authentication Error")
            _, secs = self.services.limiter.is_locked()
            rem = self.services.limiter.attempts_remaining()
            self._put({"type": "auth_error", "remaining": rem, "lockout": secs})
            self._put(
                {
                    "type": "inspect_result",
                    "path": str(path),
                    "metadata": {},
                    "error": "Invalid password or corrupted vault envelope",
                },
                timeout=1.0,
            )
        except Exception as exc:
            logger.exception("Vault inspection failed for %s", redact_path(path))
            self._log_activity("Inspect", path.name, "Failed", str(exc))
            self._put(
                {
                    "type": "inspect_result",
                    "path": str(path),
                    "metadata": {},
                    "error": f"Inspection failed: {exc}",
                },
                timeout=1.0,
            )

    # ---------------------------------------------------------------- integrity
    def _integrity_worker(self, path):
        path = Path(path).resolve()
        self._log("Hashing vault... large files may take a while")
        try:
            ok, msg, sha = self._check_vault_integrity(path)
            if ok and sha:
                self._save_fingerprint(path, sha)
                self._log_activity("Integrity", path.name, "Success")
            self._put(
                {
                    "type": "integrity_result",
                    "path": str(path),
                    "ok": ok,
                    "msg": msg,
                    "sha": sha,
                },
                timeout=1.0,
            )
        except Exception as exc:
            logger.exception("Integrity check failed for %s", redact_path(path))
            self._put(
                {
                    "type": "integrity_result",
                    "path": str(path),
                    "ok": False,
                    "msg": str(exc),
                    "sha": "",
                },
                timeout=1.0,
            )

    # ------------------------------------------------------------------- verify
    def _verify_worker(self, path):
        path = Path(path).resolve()
        try:
            fps = self.load_fingerprints()
            rec = fps.get(str(path))
            if not rec:
                self._put(
                    {
                        "type": "verify_result",
                        "path": str(path),
                        "status": "missing",
                        "current_sha": "",
                        "saved_sha": "",
                        "recorded": "",
                        "filename": path.name,
                        "error": "No saved fingerprint for this vault",
                    },
                    timeout=1.0,
                )
                return

            ok, msg, current_sha = self._check_vault_integrity(path)
            if not ok or not current_sha:
                self._put(
                    {
                        "type": "verify_result",
                        "path": str(path),
                        "status": "error",
                        "current_sha": "",
                        "saved_sha": rec.get("sha256", ""),
                        "recorded": rec.get("recorded", ""),
                        "filename": rec.get("filename", path.name),
                        "error": msg,
                    },
                    timeout=1.0,
                )
                return

            saved_sha = rec.get("sha256", "")
            status = "unchanged" if current_sha == saved_sha else "mismatch"
            self._put(
                {
                    "type": "verify_result",
                    "path": str(path),
                    "status": status,
                    "current_sha": current_sha,
                    "saved_sha": saved_sha,
                    "recorded": rec.get("recorded", ""),
                    "filename": rec.get("filename", path.name),
                    "error": "",
                },
                timeout=1.0,
            )
        except Exception as exc:
            logger.exception("Verify-vs-saved failed for %s", redact_path(path))
            self._put(
                {
                    "type": "verify_result",
                    "path": str(path),
                    "status": "error",
                    "current_sha": "",
                    "saved_sha": "",
                    "recorded": "",
                    "filename": path.name,
                    "error": str(exc),
                },
                timeout=1.0,
            )

    # ---------------------------------------------------------- selective extract
    def _selective_extract_worker(
        self,
        vault_path: Path,
        password: Optional[str],
        recovery_key: Optional[bytes],
        selected_files: List[str],
        output_dir: Path,
    ) -> None:
        temp_zip: Optional[Path] = None
        temp_extract_dir: Optional[Path] = None
        extracted_count = 0
        success = False
        cancel_check = lambda: self.services.cancel_requested
        self._put({"type": "progress_start"})
        try:
            temp_fd, temp_name = tempfile.mkstemp(suffix=".zip", prefix=".rpm_extract_")
            os.close(temp_fd)
            temp_zip = Path(temp_name)
            with self.services._temp_files_lock:
                self.services._active_temp_files.append(temp_zip)

            self._log("Decrypting vault to secure temporary archive...")
            self.services.crypto.decrypt_file(
                vault_path,
                temp_zip,
                password=password,
                recovery_key=recovery_key,
                cancel_check=cancel_check,
            )

            temp_extract_dir = Path(tempfile.mkdtemp(prefix=".rpm_extract_dir_"))
            self._log("Extracting temporary archive...")
            self.services.packager.extract_archive(temp_zip, temp_extract_dir, cancel_check=cancel_check)

            for selected in selected_files:
                src_path = temp_extract_dir / selected
                if not src_path.is_file():
                    continue
                dst_path = output_dir / Path(selected).name
                orig_dst, counter = dst_path, 1
                while dst_path.exists():
                    dst_path = orig_dst.with_name(f"{orig_dst.stem}_{counter}{orig_dst.suffix}")
                    counter += 1
                shutil.copy2(src_path, dst_path)
                extracted_count += 1

            success = True
            msg = f"Successfully extracted {extracted_count} file(s)."
            self._log_activity("Selective Extract", vault_path.name, "Success", msg)
            self._put(
                {
                    "type": "selective_extract_result",
                    "path": str(vault_path),
                    "selected": selected_files,
                    "output_dir": str(output_dir),
                    "count": extracted_count,
                    "error": "",
                },
                timeout=1.0,
            )
        except OperationCancelledError:
            msg = "Cancelled - 0/1 done"
            self._log("Cancelling and cleaning up...")
        except Exception as exc:
            logger.exception("Selective extraction failed for %s", redact_path(vault_path))
            msg = f"Extraction failed: {exc}"
            self._log_activity("Selective Extract", vault_path.name, "Failed", str(exc))
            self._put(
                {
                    "type": "selective_extract_result",
                    "path": str(vault_path),
                    "selected": selected_files,
                    "output_dir": str(output_dir),
                    "count": extracted_count,
                    "error": str(exc),
                },
                timeout=1.0,
            )
        finally:
            self._wipe_temp_file(temp_zip)
            self._wipe_temp_dir(temp_extract_dir)
            self.services.is_processing = False
            self._put({"type": "batch_done", "text": msg, "success": success}, timeout=1.0)

    # ---------------------------------------------------------------- vault diff
    def _vault_diff_worker(self, path_a: Path, password_a: str, path_b: Path, password_b: str) -> None:
        self._put({"type": "progress_start"})
        success = False
        try:
            with open(path_a, "rb") as f:
                header_a = self.services.crypto.verify_password_and_get_header(f, password_a)
            with open(path_b, "rb") as f:
                header_b = self.services.crypto.verify_password_and_get_header(f, password_b)

            files_a = self._files_by_path(header_a.payload.metadata)
            files_b = self._files_by_path(header_b.payload.metadata)
            added, removed, modified = self.diff_manifests(files_a, files_b)
            result_text = self.format_diff_result(path_a, path_b, added, removed, modified)
            success = True
            self._put(
                {
                    "type": "vault_diff_result",
                    "path_a": str(path_a),
                    "path_b": str(path_b),
                    "added": added,
                    "removed": removed,
                    "modified": modified,
                    "text": result_text,
                    "error": "",
                },
                timeout=1.0,
            )
            self._log_activity("Vault Diff", f"{path_a.name} vs {path_b.name}", "Success")
            msg = "Vault Diff complete"
        except Exception as exc:
            logger.exception("Vault Diff failed")
            msg = f"Diff failed: {exc}"
            self._put(
                {
                    "type": "vault_diff_result",
                    "path_a": str(path_a),
                    "path_b": str(path_b),
                    "added": [],
                    "removed": [],
                    "modified": [],
                    "text": msg,
                    "error": str(exc),
                },
                timeout=1.0,
            )
            self._log_activity("Vault Diff", f"{path_a.name} vs {path_b.name}", "Failed", str(exc))
        finally:
            self.services.is_processing = False
            self._put({"type": "batch_done", "text": msg, "success": success}, timeout=1.0)

    @staticmethod
    def _files_by_path(metadata) -> Dict[str, Dict[str, Any]]:
        files = (metadata or {}).get("files", [])
        return {str(item.get("path", "")): item for item in files if item.get("path")}

    @staticmethod
    def diff_manifests(files_a: Dict[str, Dict[str, Any]], files_b: Dict[str, Dict[str, Any]]):
        added = []
        removed = []
        modified = []
        for path in sorted(set(files_a) | set(files_b)):
            if path in files_b and path not in files_a:
                added.append(f"+ {path} ({int(files_b[path].get('size', 0))} bytes)")
            elif path in files_a and path not in files_b:
                removed.append(f"- {path} ({int(files_a[path].get('size', 0))} bytes)")
            else:
                fa = files_a[path]
                fb = files_b[path]
                if fa.get("size") != fb.get("size") or fa.get("mtime") != fb.get("mtime"):
                    modified.append(
                        f"~ {path} (Size: {int(fa.get('size', 0))} -> {int(fb.get('size', 0))})"
                    )
        return added, removed, modified

    @staticmethod
    def format_diff_result(path_a: Path, path_b: Path, added, removed, modified) -> str:
        lines = [
            "=" * 55,
            "VAULT DIFF RESULTS",
            "=" * 55,
            f"Vault A: {Path(path_a).name}",
            f"Vault B: {Path(path_b).name}",
            "-" * 55,
        ]
        if not added and not removed and not modified:
            lines.append("No differences found in manifests.")
        else:
            if added:
                lines += ["", "ADDED:", *[f"  {x}" for x in added]]
            if removed:
                lines += ["", "REMOVED:", *[f"  {x}" for x in removed]]
            if modified:
                lines += ["", "MODIFIED:", *[f"  {x}" for x in modified]]
        lines.append("=" * 55)
        return "\n".join(lines)

    # ------------------------------------------------------- fingerprint config
    @staticmethod
    def _save_fingerprint(path: Path, sha: str) -> None:
        key = str(path.resolve())
        entry = {
            "filename": path.name,
            "sha256": sha,
            "size": path.stat().st_size,
            "recorded": datetime.now().isoformat(timespec="seconds"),
        }

        def _save(cfg):
            fps = cfg.setdefault("fingerprints", {})
            fps[key] = entry
            if len(fps) > 50:
                oldest = sorted(fps, key=lambda k: fps[k]["recorded"])
                for k in oldest[: len(fps) - 50]:
                    del fps[k]

        _mutate_cfg(_save)

    @staticmethod
    def load_fingerprints() -> Dict[str, Any]:
        return _load_cfg().get("fingerprints", {})

    @staticmethod
    def clear_fingerprints() -> None:
        def _clear(cfg):
            cfg["fingerprints"] = {}

        _mutate_cfg(_clear)

    # --------------------------------------------------------- validation helpers
    @staticmethod
    def estimate_selected_size(metadata: Dict[str, Any], selected_files: Iterable[str]) -> int:
        selected = set(selected_files)
        return sum(
            int(item.get("size", 0) or 0)
            for item in metadata.get("files", [])
            if item.get("path") in selected
        )

    @staticmethod
    def temp_space_warning_needed(metadata: Dict[str, Any], free_space_bytes: int) -> bool:
        req_space = int(metadata.get("original_size", metadata.get("total_size", 0)) or 0) * 1.5
        return bool(req_space and free_space_bytes < req_space)

    # --------------------------------------------------------- structure + hash
    @staticmethod
    def _check_vault_integrity(path: Path) -> Tuple[bool, str, str]:
        """Structural + hash check without password. Returns (ok, message, sha)."""
        try:
            path = Path(path)
            sz = path.stat().st_size
            min_sz = len(VAULT_MAGIC) + 1 + 4 + 1 + AES_TAG_SIZE
            if sz < min_sz:
                return False, f"File too small ({sz} bytes < {min_sz} minimum)", ""

            with open(path, "rb") as f:
                magic = f.read(len(VAULT_MAGIC))
                if magic != VAULT_MAGIC:
                    return False, f"Invalid magic bytes: {magic!r}", ""
                (version,) = struct.unpack("!B", f.read(1))
                if not is_supported_vault_version(version):
                    return False, f"Unsupported version: {version}", ""
                (hlen,) = struct.unpack("!I", f.read(4))
                if hlen > sz:
                    return False, f"Header length field ({hlen}) exceeds file size", ""

            h = hashlib.sha256()
            with open(path, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            sha = h.hexdigest()
            msg = f"Structure valid - Size: {sz:,} bytes\nSHA-256: {sha}"
            return True, msg, sha
        except Exception as exc:
            return False, str(exc), ""

    def _wipe_temp_file(self, temp_path: Optional[Path]) -> None:
        if temp_path is None:
            return
        with self.services._temp_files_lock:
            try:
                self.services._active_temp_files.remove(temp_path)
            except ValueError:
                pass
        try:
            if temp_path.exists():
                self.services.wiper.wipe_file(temp_path)
        except Exception:
            try:
                temp_path.unlink(missing_ok=True)
            except Exception:
                pass

    def _wipe_temp_dir(self, temp_dir: Optional[Path]) -> None:
        if temp_dir is None or not temp_dir.exists():
            return
        try:
            self.services.wiper.wipe_folder(temp_dir)
        except Exception:
            shutil.rmtree(temp_dir, ignore_errors=True)
