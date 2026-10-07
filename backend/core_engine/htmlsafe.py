"""
Safe HTML parsing for untrusted pages and emails.

Python's built-in html.parser can take minutes on deliberately malformed markup (catastrophic regex backtracking),
which would let any page hang an analysis worker. lxml parses the same input in milliseconds, so it is used when
installed; the fallback parser only ever sees a small, truncated slice.
"""

from bs4 import BeautifulSoup

try:  # pragma: no cover - depends on the environment
    import lxml  # noqa: F401
    _PARSER = "lxml"
    _LIMIT = 600_000
except ImportError:  # pragma: no cover
    _PARSER = "html.parser"
    _LIMIT = 100_000


def make_soup(html, limit: int = 0) -> BeautifulSoup:
    """Parse untrusted HTML with a hard size cap."""
    if isinstance(html, bytes):
        html = html.decode("utf-8", errors="replace")
    cap = min(limit, _LIMIT) if limit else _LIMIT
    return BeautifulSoup((html or "")[:cap], _PARSER)
