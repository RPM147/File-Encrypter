"""Typed queue events shared between Flet-free workers and the UI dispatcher."""

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class AppEvent:
    """Base marker class for typed worker-to-UI queue events."""


@dataclass(frozen=True)
class LogEvent(AppEvent):
    text: str


@dataclass(frozen=True)
class ProgressStartEvent(AppEvent):
    pass


@dataclass(frozen=True)
class ProgressEvent(AppEvent):
    done: int
    total: int


@dataclass(frozen=True)
class ErrorEvent(AppEvent):
    text: str


@dataclass(frozen=True)
class AuthErrorEvent(AppEvent):
    remaining: int
    lockout: int


@dataclass(frozen=True)
class InspectResultEvent(AppEvent):
    path: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    error: str = ""


@dataclass(frozen=True)
class IntegrityResultEvent(AppEvent):
    path: str = ""
    ok: bool = False
    msg: str = ""
    sha: str = ""


@dataclass(frozen=True)
class VerifyResultEvent(AppEvent):
    path: str = ""
    status: str = ""
    current_sha: str = ""
    saved_sha: str = ""
    recorded: str = ""
    filename: str = ""
    error: str = ""


@dataclass(frozen=True)
class SelectiveExtractResultEvent(AppEvent):
    path: str = ""
    selected: list[str] = field(default_factory=list)
    output_dir: str = ""
    count: int = 0
    error: str = ""


@dataclass(frozen=True)
class VaultDiffResultEvent(AppEvent):
    path_a: str = ""
    path_b: str = ""
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    modified: list[str] = field(default_factory=list)
    text: str = ""
    error: str = ""


@dataclass(frozen=True)
class LibraryResultsEvent(AppEvent):
    data: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""


@dataclass(frozen=True)
class NoteDecryptedEvent(AppEvent):
    text: str


@dataclass(frozen=True)
class RekeyVersionsEvent(AppEvent):
    vault: str = ""
    entries: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""


@dataclass(frozen=True)
class RekeyPasswordStrengthEvent(AppEvent):
    score: int = 0
    crack_time: str = ""


@dataclass(frozen=True)
class RekeyVersionActionEvent(AppEvent):
    text: str = ""
    error: str = ""
    refresh: bool = False


@dataclass(frozen=True)
class UpdateAvailableEvent(AppEvent):
    info: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class BatchDoneEvent(AppEvent):
    text: str = "Done"
    success: bool | None = None


__all__ = [
    "AppEvent",
    "AuthErrorEvent",
    "BatchDoneEvent",
    "ErrorEvent",
    "InspectResultEvent",
    "IntegrityResultEvent",
    "LibraryResultsEvent",
    "LogEvent",
    "NoteDecryptedEvent",
    "ProgressEvent",
    "ProgressStartEvent",
    "RekeyPasswordStrengthEvent",
    "RekeyVersionActionEvent",
    "RekeyVersionsEvent",
    "SelectiveExtractResultEvent",
    "UpdateAvailableEvent",
    "VaultDiffResultEvent",
    "VerifyResultEvent",
]
