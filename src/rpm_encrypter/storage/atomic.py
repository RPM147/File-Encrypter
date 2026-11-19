"""Atomic vault output helper (SEC-04)."""

import os
import tempfile
from pathlib import Path
from typing import Callable


def atomic_output(final_path: Path, write_fn: Callable[[Path], None]) -> None:
    """Write a vault atomically via a same-directory temp file and os.replace."""
    final_path = Path(final_path)
    fd, tmp_name = tempfile.mkstemp(
        prefix=".rpm_vaulttmp_", suffix=".part", dir=str(final_path.parent)
    )
    os.close(fd)
    tmp_path = Path(tmp_name)
    try:
        write_fn(tmp_path)
        os.replace(tmp_path, final_path)
    except BaseException:
        # Temp holds ciphertext only; unlink plainly without secure wipe.
        try:
            tmp_path.unlink()
        except OSError:
            pass
        raise
