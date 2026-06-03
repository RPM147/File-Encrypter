"""Queue-message dispatcher for the Flet UI bridge.

No Flet imports: tests pass a fake sink, while AppShell implements the same
duck-typed sink methods at runtime.
"""


class EventDispatcher:
    """Maps a worker msg_queue dict to UI-sink calls. No flet import -> testable."""

    def __init__(self, sink):
        self.sink = sink

    def dispatch(self, msg: dict) -> None:
        t = msg.get("type")
        if t == "log":
            self.sink.on_log(msg.get("text", ""))
        elif t == "progress_start":
            self.sink.on_progress_start()
        elif t == "progress":
            self.sink.on_progress(msg.get("done", 0), msg.get("total", 0))
        elif t == "error":
            self.sink.on_error(msg.get("text", "Error"))
        elif t == "auth_error":
            self.sink.on_auth_error(msg.get("remaining", 0), msg.get("lockout", 0))
        elif t == "inspect_result":
            self.sink.on_inspect_result(msg)
        elif t == "integrity_result":
            self.sink.on_integrity_result(msg)
        elif t == "verify_result":
            self.sink.on_verify_result(msg)
        elif t == "selective_extract_result":
            self.sink.on_selective_extract_result(msg)
        elif t == "vault_diff_result":
            self.sink.on_vault_diff_result(msg)
        elif t == "library_results":
            self.sink.on_library_results(msg)
        elif t == "note_decrypted":
            self.sink.on_note_decrypted(msg.get("text", ""))
        elif t == "rekey_versions":
            self.sink.on_rekey_versions(msg)
        elif t == "rekey_password_strength":
            self.sink.on_rekey_password_strength(msg)
        elif t == "rekey_version_action":
            self.sink.on_rekey_version_action(msg)
        elif t == "batch_done":
            if "success" in msg:
                self.sink.on_batch_done(msg.get("text", "Done"), msg.get("success"))
            else:
                self.sink.on_batch_done(msg.get("text", "Done"))
        # Unknown types are ignored (forward-compatible), like the old app.
