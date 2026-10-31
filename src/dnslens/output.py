"""Terminal output helpers (no third-party deps, safe on legacy Windows consoles)."""
from __future__ import annotations

import json
import os
import sys
from typing import Any, Iterable, List, Sequence


def _enable_windows_vt() -> bool:
    try:
        import ctypes

        k32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = k32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not k32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(k32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


def supports_color(stream: Any = None) -> bool:
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    if not hasattr(stream, "isatty") or not stream.isatty():
        return False
    if os.name == "nt":
        return _enable_windows_vt()
    return os.environ.get("TERM") != "dumb"


class Style:
    CODES = {"red": "31", "green": "32", "yellow": "33", "blue": "34", "dim": "2", "bold": "1"}
    LEVELS = {"OK": "green", "INFO": "blue", "WARN": "yellow", "FAIL": "red"}

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def paint(self, text: str, color: str) -> str:
        if not self.enabled:
            return text
        return f"\033[{self.CODES[color]}m{text}\033[0m"

    def level(self, level: str) -> str:
        return self.paint(f"{level:<4}", self.LEVELS.get(level, "dim"))


def render_table(headers: Sequence[str], rows: Iterable[Sequence[Any]]) -> str:
    rows_s: List[List[str]] = [[str(c) for c in r] for r in rows]
    widths = [len(h) for h in headers]
    for r in rows_s:
        for i, c in enumerate(r):
            widths[i] = max(widths[i], len(c))
    line = lambda cells: "  ".join(c.ljust(widths[i]) for i, c in enumerate(cells)).rstrip()  # noqa: E731
    out = [line(headers), "  ".join("-" * w for w in widths)]
    out.extend(line(r) for r in rows_s)
    return "\n".join(out)


def emit_json(obj: Any) -> None:
    print(json.dumps(obj, indent=2, sort_keys=False, default=str))


def setup_streams() -> None:
    for s in (sys.stdout, sys.stderr):
        if hasattr(s, "reconfigure"):
            try:
                s.reconfigure(errors="replace")
            except Exception:
                pass
