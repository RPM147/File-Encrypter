"""Thread/session state helpers for RPM Encrypter: main-thread dev guard,
brute-force AttemptLimiter, and SessionStats.

Phase 26 (ARCH-01) Stage 0: extracted verbatim from gui_app.py. gui_app
re-imports these names, so existing call sites and tests are unaffected.
assert_main_thread keeps logging to the "RPM_GUI" logger (Phase 9 contract).
"""
import os
import time
import threading
import logging
from typing import Tuple, Optional

logger = logging.getLogger("RPM_GUI")

MAX_ATTEMPTS = 5
LOCKOUT_SECS = 30


def assert_main_thread(context: str = "") -> bool:
    """
    Phase 9 (REL-01) developer guard: make future off-main-thread widget
    mutation visible. Returns True on the main thread; otherwise logs a warning
    without interrupting users. Set RPM_STRICT_UI_THREAD=1 to raise during
    development.
    """
    if threading.current_thread() is threading.main_thread():
        return True
    msg = f"Off-main-thread UI mutation: {context} (thread={threading.current_thread().name})"
    logger.warning(msg)
    if os.environ.get("RPM_STRICT_UI_THREAD") == "1":
        raise RuntimeError(msg)
    return False


class AttemptLimiter:
    """
    Thread-safe, per-session lockout counter using monotonic time.
    
    Uses time.monotonic() instead of time.time() to prevent bypass via
    system clock manipulation.
    """

    def __init__(self, max_attempts: int = MAX_ATTEMPTS, lockout_secs: int = LOCKOUT_SECS):
        self._lock         = threading.Lock()
        self._fails        = 0
        self._lockout_start = None  # monotonic time
        self._max          = max_attempts
        self._secs         = lockout_secs

    def is_locked(self) -> Tuple[bool, int]:
        """Returns (locked, seconds_remaining)."""
        with self._lock:
            if self._lockout_start is None:
                return False, 0
            elapsed = time.monotonic() - self._lockout_start
            remaining = self._secs - elapsed
            if remaining > 0:
                return True, int(remaining) + 1
            else:
                # Lockout expired, clear state
                self._lockout_start = None
                self._fails = 0
                return False, 0

    def record_failure(self) -> None:
        with self._lock:
            self._fails += 1
            if self._fails >= self._max:
                self._lockout_start = time.monotonic()
                self._fails = 0

    def record_success(self) -> None:
        with self._lock:
            self._fails = 0
            self._lockout_start = None

    def attempts_remaining(self) -> int:
        with self._lock:
            return max(0, self._max - self._fails)


class SessionStats:
    """Thread-safe session counters with atomic updates."""

    def __init__(self):
        self._lock       = threading.Lock()
        self.encrypted   = 0
        self.decrypted   = 0
        self.rekeyed     = 0
        self.files_total = 0
        self.bytes_total = 0
        self._start: Optional[float] = None

    def mark_start(self) -> None:
        """Call this after the UI is fully built and mainloop is about to start."""
        with self._lock:
            self._start = time.time()

    def add_encrypted(self, file_count: int = 1, byte_count: int = 0) -> None:
        with self._lock:
            self.encrypted   += 1
            self.files_total += file_count
            self.bytes_total += byte_count

    def add_decrypted(self, byte_count: int = 0) -> None:
        with self._lock:
            self.decrypted   += 1
            self.bytes_total += byte_count

    def add_rekeyed(self) -> None:
        with self._lock:
            self.rekeyed += 1

    def snapshot(self) -> dict:
        """Return a consistent snapshot for display (no tearing)."""
        with self._lock:
            return {
                "encrypted":   self.encrypted,
                "decrypted":   self.decrypted,
                "rekeyed":     self.rekeyed,
                "files_total": self.files_total,
                "bytes_total": self.bytes_total,
                "uptime":      self._uptime_unlocked(),
            }

    def _uptime_unlocked(self) -> str:
        if self._start is None:
            return "00:00:00"
        s = int(time.time() - self._start)
        return f"{s // 3600:02d}:{(s % 3600) // 60:02d}:{s % 60:02d}"

    def uptime(self) -> str:
        with self._lock:
            return self._uptime_unlocked()
