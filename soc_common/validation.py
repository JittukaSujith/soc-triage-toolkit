"""Input validation and friendly error handling.

Analysts run these tools on files they were handed in the middle of an
incident. A raw Python traceback is useless to them; a clear one-line message
is not. Tools raise ToolError for expected problems and `cli_guard` turns
those into a tidy message plus a non-zero exit code.
"""
from __future__ import annotations

import ipaddress
import os
import sys
from pathlib import Path
from typing import Callable, List, Optional

MAX_FILE_BYTES = 50 * 1024 * 1024  # refuse absurdly large inputs (50 MB)


class ToolError(Exception):
    """An expected, user-fixable problem (bad path, bad option, bad data)."""


def require_file(path, max_bytes: int = MAX_FILE_BYTES) -> Path:
    p = Path(str(path)).expanduser()
    if not p.exists():
        raise ToolError("file not found: %s" % p)
    if not p.is_file():
        raise ToolError("not a file: %s" % p)
    if p.stat().st_size > max_bytes:
        raise ToolError("file is too large (%d MB limit): %s" % (max_bytes // (1024 * 1024), p))
    return p


def read_text_file(path, max_bytes: int = MAX_FILE_BYTES) -> str:
    """Read a text file safely: size limit, binary detection, tolerant decoding."""
    p = require_file(path, max_bytes)
    data = p.read_bytes()
    if b"\x00" in data[:4096]:
        raise ToolError("%s looks like a binary file, not text" % p)
    return data.decode("utf-8", errors="replace")


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(str(value).strip())
        return True
    except ValueError:
        return False


def bounded_int(value, name: str, minimum: int = 1, maximum: Optional[int] = None) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise ToolError("%s must be a whole number, got %r" % (name, value))
    if number < minimum or (maximum is not None and number > maximum):
        limit = ">= %d" % minimum if maximum is None else "between %d and %d" % (minimum, maximum)
        raise ToolError("%s must be %s, got %d" % (name, limit, number))
    return number


def cli_guard(main: Callable[[Optional[List[str]]], int]) -> Callable[[Optional[List[str]]], int]:
    """Wrap a CLI main(argv) so ToolError becomes 'error: message' and exit code 2."""

    def wrapper(argv: Optional[List[str]] = None) -> int:
        try:
            return main(argv)
        except ToolError as exc:
            print("error: %s" % exc, file=sys.stderr)
            return 2
        except KeyboardInterrupt:
            print("interrupted", file=sys.stderr)
            return 130
        except BrokenPipeError:
            # e.g. `... | head`: the reader closed early. Exit quietly instead of a traceback.
            try:
                os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
            except (OSError, ValueError):
                pass
            return 0

    wrapper.__name__ = getattr(main, "__name__", "main")
    wrapper.__doc__ = main.__doc__
    return wrapper
