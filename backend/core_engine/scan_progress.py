"""
Progress reporting for one link scan.

The pipeline calls report("sandbox", "running") and so on. When a scan job is listening (see scan_jobs.py) the
call updates that job's live stage list; otherwise (tests, the e-mail pipeline) it does nothing. A ContextVar keeps
each scan's listener separate even though many scans run on different threads at once.
"""
import contextvars
from typing import Callable, Optional

STAGES = [
    ("threat_lists", "Known threat lists"),
    ("link_analysis", "Link analysis"),
    ("reputation", "Reputation check"),
    ("sandbox", "Safe sandbox browser"),
    ("model", "Risk model"),
    ("verdict", "Final verdict"),
]
STAGE_IDS = [s[0] for s in STAGES]
STATUSES = ("pending", "running", "done", "skipped")

_sink: "contextvars.ContextVar[Optional[Callable[[str, str, str], None]]]" = contextvars.ContextVar(
    "trustshield_scan_progress", default=None)


def set_sink(fn: Callable[[str, str, str], None]):
    return _sink.set(fn)


def reset_sink(token) -> None:
    _sink.reset(token)


def report(stage: str, status: str, detail: str = "") -> None:
    """Never raises: progress is a nicety and must not be able to break a scan."""
    fn = _sink.get()
    if fn is None:
        return
    try:
        fn(stage, status, detail)
    except Exception:
        pass
