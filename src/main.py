"""Entry point for RPM Encrypter (desktop UI + headless CLI)."""

import sys
from collections.abc import Sequence

from rpm_encrypter.services.launch import parse_launch_argv


def main(argv: Sequence[str] | None = None) -> int:
    """Route process invocation to the headless CLI or the Flet desktop UI."""
    args = sys.argv[1:] if argv is None else list(argv)
    request = parse_launch_argv(args)
    if request.mode == "cli":
        from rpm_encrypter.cli import main as cli_main

        return cli_main(request.cli_argv)

    from rpm_encrypter.ui.app import run

    run(request)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
