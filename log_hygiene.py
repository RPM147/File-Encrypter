"""Privacy-safe logging helpers for RPM Encrypter (Phase 29, LOG-01).

The app is privacy-focused (hidden-vault deniability), so logs must identify
*which* file an operation touched (basename) without ever leaking the user's
home directory, directory structure, or absolute filesystem location.
"""
from pathlib import PureWindowsPath


def redact_path(value) -> str:
    """Reduce a filesystem path to its basename for privacy-safe logging.

    'C:\\Users\\me\\Documents\\secret.txt' -> 'secret.txt'
    Treats both '\\' and '/' as separators on every OS so a path never leaks
    the user's directory structure regardless of host platform. On POSIX this
    may over-redact a legal filename containing a backslash; for a privacy tool,
    that is the safer direction. Never raises.
    """
    try:
        name = PureWindowsPath(str(value)).name
        return name or "<redacted>"
    except Exception:
        return "<redacted>"
