"""
Verdict memory: what TrustShield has already worked out about a link, kept in the database and shared by every user.

The first person to meet a new link waits for the full analysis (about 10 s). Everyone after gets the stored verdict at once
(the Link Gate has already blocked the first person while it was being analysed). A wrong stored verdict would be served to
everybody, so the memory is deliberately strict:

  * Only evidence-backed verdicts are stored: a Dangerous that was not just a model score on a shared host, and a Safe that
    came from a page the sandbox really opened. 'Unverified', capped, uninspected and short-link results are never stored.
  * Entries expire: Safe after a couple of hours (sites get compromised), Dangerous after two days (pages get taken down,
    mistakes should not live for ever). Then the link is analysed again.
  * Entries carry a stamp of the rules and models that produced them; a retrained model or changed rule makes them stale.
  * One record per link ('www.', 'http/https', trailing '/' count as the same link). Only the specific page is remembered,
    never a whole shared-hosting domain.
  * Only the backend writes here. Users cannot submit verdicts.
"""
import copy
import json
import logging
import os
import re
import time
from typing import Any, Callable, Dict, Optional

from scan_jobs import cache_key

logger = logging.getLogger("trustshield.memory")

RULES_VERSION = "2026-10-09.3"          # bump when a change to the rules should invalidate everything remembered
TTL_DANGEROUS_SECONDS = 48 * 3600
TTL_SAFE_SECONDS = 2 * 3600
MAX_RESULT_BYTES = 60_000

_SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly", "t.ly", "cutt.ly", "rb.gy", "shorturl.at",
               "tiny.cc", "rebrand.ly", "x.gd", "clck.ru", "app.link", "page.link", "lnkd.in", "fb.me", "amzn.to")


def current_stamp() -> str:
    """Identifies the rules and the model files in use; stored with every entry and checked on every read."""
    folder = os.environ.get("TRUSTSHIELD_ML_DIR") or os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                                   "core_engine", "trained_models")
    parts = [RULES_VERSION]
    for name in ("lexical_model.joblib", "page_model.joblib"):
        try:
            parts.append(str(int(os.path.getmtime(os.path.join(folder, name)))))
        except OSError:
            parts.append("none")
    return "/".join(parts)


def _host(url: str) -> str:
    m = re.match(r"^[a-z]+://([^/:?#]+)", (url or "").strip().lower())
    return m.group(1) if m else ""


def is_short_link(url: str) -> bool:
    host = _host(url)
    return any(host == s or host.endswith("." + s) for s in _SHORTENERS)


def storable_ttl(url: str, result: Dict[str, Any]) -> Optional[int]:
    """How long this result may be remembered, or None when it must not be remembered at all."""
    if not isinstance(result, dict) or is_short_link(url) or result.get("tier_0_match"):
        return None                                          # a short link hides its target; a threat-list hit is already instant
    if not result.get("decisive") or not result.get("analysis_complete", True):
        return None
    tel = result.get("telemetry") or {}
    if tel.get("ml_capped_no_evidence") or tel.get("ml_capped_uninspected"):
        return None                                          # the verdict rests on the model's score alone
    shown = str(result.get("display_verdict") or "")
    inspected = str(result.get("verification_state") or "") == "verified"
    if shown == "Dangerous" and (inspected or tel.get("hard_override_triggered") or tel.get("known_db_match")):
        return TTL_DANGEROUS_SECONDS
    if shown == "Safe" and inspected:
        return TTL_SAFE_SECONDS                              # Safe only when the sandbox really opened and read the page
    return None


def _compact(result: Dict[str, Any]) -> Optional[str]:
    """The result without heavy or private parts (screenshots, raw HTML), as JSON."""
    def clean(value, depth=0):
        if isinstance(value, dict):
            return {k: clean(v, depth + 1) for k, v in value.items() if not str(k).startswith("_") and depth < 6}
        if isinstance(value, (list, tuple)):
            return [clean(v, depth + 1) for v in list(value)[:50]]
        if isinstance(value, str):
            return value[:2000]
        return value
    text = json.dumps(clean(copy.deepcopy(result)), default=str)
    return text if len(text.encode("utf-8")) <= MAX_RESULT_BYTES else None


class VerdictMemory:
    """`cursor_factory` is app.db_cursor (a context manager yielding a psycopg cursor)."""

    def __init__(self, cursor_factory: Callable[[], Any]):
        self.cursor = cursor_factory
        self.ready = False

    def ensure_table(self) -> None:
        try:
            with self.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS verdict_memory (
                        url_key TEXT PRIMARY KEY,
                        url TEXT NOT NULL,
                        display_verdict VARCHAR(40) NOT NULL,
                        threat_score FLOAT,
                        result_json TEXT NOT NULL,
                        stamp TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT NOW(),
                        expires_at TIMESTAMP NOT NULL,
                        hits INTEGER DEFAULT 0
                    );
                    CREATE INDEX IF NOT EXISTS idx_verdict_memory_expires ON verdict_memory(expires_at);
                """)
            self.ready = True
        except Exception as exc:
            logger.warning("verdict memory unavailable: %s", exc)

    def lookup(self, url: str) -> Optional[Dict[str, Any]]:
        """The stored result for this link if it is still valid, else None. Never raises: a database problem means 'not known'."""
        if not self.ready:
            return None
        try:
            with self.cursor() as cur:
                cur.execute("""UPDATE verdict_memory SET hits = hits + 1 WHERE url_key = %s
                               RETURNING result_json, stamp, expires_at > NOW()""", (cache_key(url),))
                row = cur.fetchone()
                if not row:
                    return None
                result_json, stamp, fresh = row
                if not fresh or stamp != current_stamp():
                    cur.execute("DELETE FROM verdict_memory WHERE url_key = %s", (cache_key(url),))
                    return None
            result = json.loads(result_json)
            result["url"] = url
            result["from_memory"] = True
            return result
        except Exception as exc:
            logger.warning("verdict memory lookup failed: %s", exc)
            return None

    def remember(self, url: str, result: Dict[str, Any]) -> bool:
        """Store the result if it is strong enough; returns whether it was stored. Never raises."""
        if not self.ready:
            return False
        ttl = storable_ttl(url, result)
        if ttl is None:
            return False
        payload = _compact(result)
        if payload is None:
            return False
        try:
            with self.cursor() as cur:
                cur.execute("""
                    INSERT INTO verdict_memory (url_key, url, display_verdict, threat_score, result_json, stamp, expires_at)
                    VALUES (%s, %s, %s, %s, %s, %s, NOW() + (%s || ' seconds')::interval)
                    ON CONFLICT (url_key) DO UPDATE SET url = EXCLUDED.url, display_verdict = EXCLUDED.display_verdict,
                        threat_score = EXCLUDED.threat_score, result_json = EXCLUDED.result_json, stamp = EXCLUDED.stamp,
                        created_at = NOW(), expires_at = EXCLUDED.expires_at, hits = 0
                """, (cache_key(url), url[:2048], str(result.get("display_verdict")), float(result.get("threat_score") or 0),
                      payload, current_stamp(), str(ttl)))
            return True
        except Exception as exc:
            logger.warning("verdict memory store failed: %s", exc)
            return False

    def forget(self, url: str) -> bool:
        """Remove a link (for example after a false positive is reported)."""
        try:
            with self.cursor() as cur:
                cur.execute("DELETE FROM verdict_memory WHERE url_key = %s", (cache_key(url),))
                return cur.rowcount > 0
        except Exception as exc:
            logger.warning("verdict memory forget failed: %s", exc)
            return False

    def purge_expired(self) -> int:
        try:
            with self.cursor() as cur:
                cur.execute("DELETE FROM verdict_memory WHERE expires_at < NOW()")
                return cur.rowcount
        except Exception:
            return 0


if __name__ == "__main__":          # python verdict_memory.py list | forget <url>
    import sys
    from app import db_cursor
    memory = VerdictMemory(db_cursor)
    memory.ensure_table()
    if len(sys.argv) >= 3 and sys.argv[1] == "forget":
        print("removed" if memory.forget(sys.argv[2]) else "not found")
    else:
        with db_cursor() as cur:
            cur.execute("SELECT url, display_verdict, created_at, expires_at, hits FROM verdict_memory ORDER BY created_at DESC LIMIT 50")
            for r in cur.fetchall():
                print(r)
