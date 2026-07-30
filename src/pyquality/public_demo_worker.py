"""Private subprocess entry point for one bounded public demo execution."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from .demo import run_demo
from .tools import SubprocessRunner


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 1:
        return 2
    if os.name == "nt" and sys.stdin.buffer.read(1) != b"\0":
        return 2
    report = run_demo(
        Path(arguments[0]),
        process_runner=SubprocessRunner(
            inherit_process_group=os.name != "nt",
            abort_inherited_group_on_timeout=os.name != "nt",
        ),
    )
    sys.stdout.write(report.model_dump_json())
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised as a subprocess.
    raise SystemExit(main())
