"""Launch-intent parsing shared between src/main.py and the desktop shell."""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

CLI_SUBCOMMANDS = frozenset(
    {"encrypt", "decrypt", "inspect", "rekey", "shell-integration"}
)
CLI_FLAGS = frozenset({"-h", "--help", "--version"})


@dataclass(frozen=True)
class LaunchRequest:
    """Normalized launch intent derived from process CLI arguments."""

    mode: Literal["gui", "cli"]
    tab: Literal["encrypt", "decrypt"] | None = None
    paths: tuple[str, ...] = ()
    cli_argv: tuple[str, ...] = ()


def parse_launch_argv(argv: Sequence[str]) -> LaunchRequest:
    """Decide whether argv targets GUI pre-fill, default GUI, or headless CLI."""
    args = list(argv)
    if not args:
        return LaunchRequest(mode="gui")

    head = args[0]
    if head == "--gui-encrypt":
        return LaunchRequest(
            mode="gui",
            tab="encrypt",
            paths=tuple(a for a in args[1:] if a),
        )
    if head == "--gui-decrypt":
        return LaunchRequest(
            mode="gui",
            tab="decrypt",
            paths=tuple(a for a in args[1:] if a),
        )
    if head in CLI_SUBCOMMANDS or head in CLI_FLAGS:
        return LaunchRequest(mode="cli", cli_argv=tuple(args))

    if all(a and not a.startswith("-") for a in args):
        if all(a.lower().endswith(".vault") for a in args):
            return LaunchRequest(mode="gui", tab="decrypt", paths=tuple(args))
        return LaunchRequest(mode="gui", tab="encrypt", paths=tuple(args))

    return LaunchRequest(mode="cli", cli_argv=tuple(args))


__all__ = [
    "CLI_FLAGS",
    "CLI_SUBCOMMANDS",
    "LaunchRequest",
    "parse_launch_argv",
]
