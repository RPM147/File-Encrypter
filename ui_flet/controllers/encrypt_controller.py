"""Normal and hidden-vault encryption controller for the Flet UI.

This module intentionally imports no Flet symbols. It runs the existing backend
pipeline on a worker thread and reports progress through the Stage-1 message
queue protocol.
"""
import queue
import threading
from pathlib import Path

from app_config import push_recent
from app_constants import container_label_to_mb
from crypto_core import (
    MAX_PAYLOAD_SIZE,
    OperationCancelledError,
    PayloadTooLargeError,
)
from file_handler import atomic_output


class EncryptController:
    """Drive normal and hidden-vault encryption while posting bridge messages."""

    def __init__(self, services):
        self.services = services

    def start(
        self,
        sources,
        password,
        container_mb,
        compress,
        secure_wipe,
        out_dir=None,
        *,
        recovery_key=None,
        hidden_mode=False,
        hidden_password=None,
        hidden_size_label="100 MB",
        hidden_sources=None,
    ):
        """Spawn the encryption worker.

        The positional signature remains compatible with Stage-2 callers. Stage
        11 additions are keyword-only so older tests and integrations keep
        working.
        """
        threading.Thread(
            target=self._worker,
            args=(
                list(sources),
                password,
                int(container_mb or 0),
                bool(compress),
                bool(secure_wipe),
                out_dir,
                recovery_key,
                bool(hidden_mode),
                hidden_password,
                hidden_size_label,
                list(hidden_sources or []),
            ),
            daemon=True,
        ).start()

    def _put(self, msg, timeout=0.1):
        try:
            self.services.msg_queue.put(msg, timeout=timeout)
        except queue.Full:
            pass

    def _log(self, text):
        self._put({"type": "log", "text": text})

    def _worker(
        self,
        sources,
        password,
        container_mb,
        compress,
        secure_wipe,
        out_dir,
        recovery_key=None,
        hidden_mode=False,
        hidden_password=None,
        hidden_size_label="100 MB",
        hidden_sources=None,
    ):
        if hidden_mode:
            self._hidden_worker(
                sources=sources,
                password=password,
                compress=compress,
                secure_wipe=secure_wipe,
                out_dir=out_dir,
                recovery_key=recovery_key,
                hidden_password=hidden_password,
                hidden_size_label=hidden_size_label,
                hidden_sources=hidden_sources or [],
            )
            return

        self._normal_worker(
            sources=sources,
            password=password,
            container_mb=container_mb,
            compress=compress,
            secure_wipe=secure_wipe,
            out_dir=out_dir,
            recovery_key=recovery_key,
        )

    def _normal_worker(
        self,
        sources,
        password,
        container_mb,
        compress,
        secure_wipe,
        out_dir,
        recovery_key=None,
    ):
        s = self.services
        crypto, packager, wiper = s.crypto, s.packager, s.wiper
        container_mb = int(container_mb or 0)
        total = len(sources)
        success = 0
        cancelled = False
        had_error = False
        self._put({"type": "progress_start"})

        for idx, src in enumerate(sources, 1):
            if s.cancel_requested:
                cancelled = True
                self._log("Operation cancelled by user")
                break

            path = Path(src)
            temp_zip = None

            try:
                self._log(f"[{idx}/{total}] Packaging  ->  {path.name}")
                manifest = packager.get_manifest(path)
                manifest_size = int(manifest.get("total_size", 0) or 0)
                if manifest_size > MAX_PAYLOAD_SIZE:
                    detail = f"Payload too large (> 32 GiB): {manifest_size:,} bytes."
                    self._log(f"[{idx}/{total}] FAILED: {detail}")
                    if s.activity_logger:
                        s.activity_logger.log_event("Encrypt", path.name, "Failed", detail)
                    had_error = True
                    continue

                cancel_check = lambda: s.cancel_requested
                temp_zip = (
                    packager.package_folder(
                        path,
                        compress=compress,
                        on_skip=lambda m: self._log(f"Skipped: {m}"),
                        cancel_check=cancel_check,
                    )
                    if path.is_dir()
                    else packager.package_files(
                        [path],
                        compress=compress,
                        on_skip=lambda m: self._log(f"Skipped: {m}"),
                        cancel_check=cancel_check,
                    )
                )
                with s._temp_files_lock:
                    s._active_temp_files.append(temp_zip)

                base_dir = Path(out_dir) if out_dir else path.parent
                out_path = base_dir / f"{path.name}.vault"
                orig_out, counter = out_path, 1
                while out_path.exists():
                    out_path = orig_out.with_name(f"{orig_out.stem}_{counter}{orig_out.suffix}")
                    counter += 1

                def prog(done, total_b):
                    self._put({"type": "progress", "done": done, "total": total_b}, timeout=0.01)

                self._log(f"[{idx}/{total}] Encrypting ->  {path.name}")
                atomic_output(
                    out_path,
                    lambda p: crypto.encrypt_file(
                        temp_zip,
                        p,
                        password,
                        original_filename=path.name,
                        metadata=manifest,
                        progress_callback=prog,
                        recovery_key=recovery_key,
                        target_container_mb=container_mb,
                        cancel_check=cancel_check,
                    ),
                )

                if secure_wipe:
                    self._log(f"[{idx}/{total}] Wiping     ->  {path.name}")
                    if path.is_dir():
                        wiper.wipe_folder(path, on_skip=lambda m: self._log(f"Skipped: {m}"))
                    else:
                        wiper.wipe_file(path, on_skip=lambda m: self._log(f"Skipped: {m}"))

                s.stats.add_encrypted(
                    file_count=manifest.get("file_count", 1),
                    byte_count=manifest.get("total_size", 0),
                )
                push_recent("enc_sources", str(path))
                if s.activity_logger:
                    s.activity_logger.log_event(
                        "Encrypt", path.name, "Success", f"Output: {out_path.name}"
                    )
                self._log(f"[{idx}/{total}] Done       ->  {out_path.name}")
                success += 1

            except OperationCancelledError:
                cancelled = True
                self._log("Cancelling and cleaning up...")
                break
            except Exception as exc:
                had_error = True
                self._log(f"[{idx}/{total}] FAILED: {exc}")
                if s.activity_logger:
                    s.activity_logger.log_event("Encrypt", path.name, "Failed", str(exc))
                self._put({"type": "error", "text": f"{path.name}: {exc}"})
            finally:
                self._wipe_temp(temp_zip)

        s.is_processing = False
        text = (
            f"Cancelled - {success}/{total} done"
            if cancelled
            else f"Batch complete: {success}/{total} encrypted"
        )
        self._put(
            {
                "type": "batch_done",
                "text": text,
                "success": bool(not cancelled and not had_error and success == total),
            },
            timeout=1.0,
        )

    def _hidden_worker(
        self,
        sources,
        password,
        compress,
        secure_wipe,
        out_dir,
        recovery_key,
        hidden_password,
        hidden_size_label,
        hidden_sources,
    ):
        s = self.services
        crypto, packager, wiper = s.crypto, s.packager, s.wiper
        paths = [Path(p) for p in sources]
        h_paths = [Path(p) for p in hidden_sources]
        total = 1
        success = 0
        cancelled = False
        had_error = False
        decoy_tmp = None
        hidden_tmp = None
        self._put({"type": "progress_start"})
        self._log("--- Creating hidden vault ---")
        cancel_check = lambda: s.cancel_requested

        try:
            if not paths:
                raise ValueError("At least one decoy source is required.")
            if not h_paths:
                raise ValueError("At least one hidden source is required.")
            if not hidden_password:
                raise ValueError("Hidden password is required.")

            size_label = hidden_size_label or "100 MB"
            hidden_container_mb = container_label_to_mb(size_label)
            target_size = hidden_container_mb * 1024 * 1024

            if len(paths) == 1 and paths[0].is_dir():
                dec_meta = packager.get_manifest(paths[0], exclude_paths=h_paths)
            elif len(paths) == 1:
                dec_meta = packager.get_manifest(paths[0])
            else:
                dec_meta = packager.get_manifest_multiple(paths, exclude_paths=h_paths)

            if len(h_paths) == 1:
                hid_meta = packager.get_manifest(h_paths[0])
            else:
                hid_meta = packager.get_manifest_multiple(h_paths)

            dec_meta["type"] = "archive"
            hid_meta["type"] = "archive"

            decoy_total_size = int(dec_meta.get("total_size", 0) or 0)
            hidden_total_size = int(hid_meta.get("total_size", 0) or 0)
            if decoy_total_size > MAX_PAYLOAD_SIZE or hidden_total_size > MAX_PAYLOAD_SIZE:
                raise PayloadTooLargeError(
                    "Hidden-vault payload too large (> 32 GiB): "
                    f"decoy={decoy_total_size:,} bytes, hidden={hidden_total_size:,} bytes."
                )

            self._log("Packaging decoy files...")
            if len(paths) == 1 and paths[0].is_dir():
                decoy_tmp = packager.package_folder(
                    paths[0],
                    exclude_paths=h_paths,
                    compress=compress,
                    on_skip=lambda m: self._log(f"Skipped: {m}"),
                    cancel_check=cancel_check,
                )
            else:
                decoy_tmp = packager.package_files(
                    paths,
                    exclude_paths=h_paths,
                    compress=compress,
                    on_skip=lambda m: self._log(f"Skipped: {m}"),
                    cancel_check=cancel_check,
                )
            self._track_temp(decoy_tmp)

            self._log("Packaging hidden files...")
            if len(h_paths) == 1 and h_paths[0].is_dir():
                hidden_tmp = packager.package_folder(
                    h_paths[0],
                    compress=compress,
                    on_skip=lambda m: self._log(f"Skipped: {m}"),
                    cancel_check=cancel_check,
                )
            else:
                hidden_tmp = packager.package_files(
                    h_paths,
                    compress=compress,
                    on_skip=lambda m: self._log(f"Skipped: {m}"),
                    cancel_check=cancel_check,
                )
            self._track_temp(hidden_tmp)

            out_name = f"{paths[0].name}.vault" if len(paths) == 1 else "HiddenArchive.vault"
            base_dir = Path(out_dir) if out_dir else paths[0].parent
            final_vault = base_dir / out_name
            orig_out, counter = final_vault, 1
            while final_vault.exists():
                final_vault = orig_out.with_name(f"{orig_out.stem}_{counter}{orig_out.suffix}")
                counter += 1

            def prog(done, total_b):
                self._put({"type": "progress", "done": done, "total": total_b}, timeout=0.01)

            decoy_filename = paths[0].name if len(paths) == 1 else "DecoyArchive"
            hidden_filename = h_paths[0].name if len(h_paths) == 1 else h_paths[0].parent.name

            self._log(f"Encrypting hidden vault -> {final_vault.name}")

            def _write_hidden_vault(p):
                with open(decoy_tmp, "rb") as dec_in, open(hidden_tmp, "rb") as hid_in, open(p, "wb") as v_out:
                    crypto.encrypt_hidden_vault(
                        dec_in,
                        hid_in,
                        v_out,
                        password_a=password,
                        password_b=hidden_password,
                        target_total_size=target_size,
                        decoy_filename=decoy_filename,
                        hidden_filename=hidden_filename,
                        decoy_metadata=dec_meta,
                        hidden_metadata=hid_meta,
                        progress_callback=prog,
                        recovery_key=recovery_key,
                        target_container_mb=hidden_container_mb,
                        cancel_check=cancel_check,
                    )

            atomic_output(final_vault, _write_hidden_vault)

            if secure_wipe:
                self._log("Securely wiping original sources...")
                for source in paths + h_paths:
                    if source.is_dir():
                        wiper.wipe_folder(source, on_skip=lambda m: self._log(f"Skipped: {m}"))
                    else:
                        wiper.wipe_file(source, on_skip=lambda m: self._log(f"Skipped: {m}"))

            file_count = int(dec_meta.get("file_count", 0) or 0) + int(hid_meta.get("file_count", 0) or 0)
            byte_count = int(dec_meta.get("total_size", 0) or 0) + int(hid_meta.get("total_size", 0) or 0)
            s.stats.add_encrypted(file_count=file_count, byte_count=byte_count)
            for path in paths:
                push_recent("enc_sources", str(path))
            if s.activity_logger:
                s.activity_logger.log_event("Encrypt", "HiddenArchive", "Success", f"Output: {final_vault.name}")
            self._log(f"Hidden vault complete -> {final_vault.name}")
            success = 1

        except OperationCancelledError:
            cancelled = True
            self._log("Cancelling and cleaning up...")
        except Exception as exc:
            had_error = True
            self._log(f"FAILED: {exc}")
            if s.activity_logger:
                s.activity_logger.log_event("Encrypt", "HiddenArchive", "Failed", str(exc))
            self._put({"type": "error", "text": f"Hidden vault: {exc}"})
        finally:
            self._wipe_temp(decoy_tmp)
            self._wipe_temp(hidden_tmp)

        s.is_processing = False
        text = (
            f"Cancelled - {success}/{total} done"
            if cancelled
            else f"Batch complete: {success}/{total} encrypted"
        )
        self._put(
            {
                "type": "batch_done",
                "text": text,
                "success": bool(not cancelled and not had_error and success == total),
            },
            timeout=1.0,
        )

    def _track_temp(self, temp_path):
        if temp_path is None:
            return
        with self.services._temp_files_lock:
            if temp_path not in self.services._active_temp_files:
                self.services._active_temp_files.append(temp_path)

    def _wipe_temp(self, temp_path):
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
