"""Shared test helpers."""
import contextlib
import io
from datetime import datetime, timedelta, timezone
from pathlib import Path

from soc_common.schema import LogEvent

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "sample_data"
T0 = datetime(2026, 10, 28, 2, 0, 0, tzinfo=timezone.utc)


def login_event(seconds, ip="203.0.113.9", user="root", outcome="failure", action="ssh_login", **extra):
    return LogEvent(timestamp=T0 + timedelta(seconds=seconds), source="auth", message="test", src_ip=ip, user=user,
                    action=action, outcome=outcome, extra=extra)


def run_cli(main, argv):
    """Run a CLI main() and return (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()
