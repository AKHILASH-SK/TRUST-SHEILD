import json
import logging
import os
import sqlite3
import threading
import time
from collections import deque
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse

import requests
import tldextract

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "vt_cache.db")

DEFINITIVE_TTL = 24 * 3600     # 200 / 404 verdicts
ERROR_TTL = 5 * 60             # transient errors
NEUTRAL_RISK = 35.0
CACHE_VERSION = 2          # bump when the meaning of a cached result changes (v1 treated 2 flags as malicious everywhere)


def required_engines(best_rank: int) -> int:
    """How many VirusTotal engines must flag a domain before it counts as malicious. Popular domains need far more."""
    if best_rank < 10_000:
        return 15
    if best_rank < 100_000:
        return 10
    if best_rank < 1_000_000:
        return 5
    return 3
RATE_LIMITED_PROVIDER = "rate_limited"


class _RateLimiter:
    """Client-side limiter for the VirusTotal free tier (4 req/min, 500 req/day)."""

    def __init__(self, per_minute: int = 4, per_day: int = 500):
        self.per_minute = per_minute
        self.per_day = per_day
        self._lock = threading.Lock()
        self._minute = deque()
        self._day_key = None
        self._day_count = 0
        self._blocked_until = 0.0

    def _roll(self, now: float) -> None:
        while self._minute and now - self._minute[0] >= 60.0:
            self._minute.popleft()
        day_key = time.strftime("%Y-%m-%d", time.gmtime(now))
        if day_key != self._day_key:
            self._day_key = day_key
            self._day_count = 0

    def remaining_minute(self, now: Optional[float] = None) -> int:
        now = time.time() if now is None else now
        with self._lock:
            self._roll(now)
            return max(0, self.per_minute - len(self._minute))

    def try_acquire(self, now: Optional[float] = None) -> bool:
        now = time.time() if now is None else now
        with self._lock:
            self._roll(now)
            if now < self._blocked_until:
                return False
            if len(self._minute) >= self.per_minute or self._day_count >= self.per_day:
                return False
            self._minute.append(now)
            self._day_count += 1
            return True

    def penalize(self, seconds: float = 60.0) -> None:
        """Called on an HTTP 429: stop sending requests for a while."""
        with self._lock:
            self._blocked_until = max(self._blocked_until, time.time() + seconds)


class _VTCache:
    """Thread-safe TTL cache: in-memory dict backed by SQLite (falls back to memory only)."""

    def __init__(self, db_path: Optional[str]):
        self._lock = threading.Lock()
        self._mem: Dict[str, Tuple[float, dict]] = {}
        self._db_path = db_path
        self._disk_ok = False
        if db_path:
            try:
                directory = os.path.dirname(db_path)
                if directory:
                    os.makedirs(directory, exist_ok=True)
                with self._connect() as conn:
                    conn.execute(
                        "CREATE TABLE IF NOT EXISTS vt_cache "
                        "(key TEXT PRIMARY KEY, expires REAL NOT NULL, result TEXT NOT NULL)"
                    )
                self._disk_ok = True
            except Exception as e:
                logger.warning(f"[VT cache] disk cache unavailable, using memory only: {e}")

    def _connect(self):
        return sqlite3.connect(self._db_path, timeout=3.0)

    def get(self, key: str) -> Optional[dict]:
        now = time.time()
        with self._lock:
            entry = self._mem.get(key)
            if entry:
                if entry[0] > now:
                    return dict(entry[1])
                del self._mem[key]
            if self._disk_ok:
                try:
                    conn = self._connect()
                    try:
                        row = conn.execute(
                            "SELECT expires, result FROM vt_cache WHERE key = ?", (key,)
                        ).fetchone()
                    finally:
                        conn.close()
                    if row and row[0] > now:
                        result = json.loads(row[1])
                        self._mem[key] = (row[0], result)
                        return dict(result)
                except Exception as e:
                    logger.debug(f"[VT cache] disk read failed: {e}")
                    self._disk_ok = False
        return None

    def put(self, key: str, result: dict, ttl: float) -> None:
        expires = time.time() + ttl
        with self._lock:
            self._mem[key] = (expires, dict(result))
            if self._disk_ok:
                try:
                    conn = self._connect()
                    try:
                        conn.execute(
                            "INSERT OR REPLACE INTO vt_cache (key, expires, result) VALUES (?, ?, ?)",
                            (key, expires, json.dumps(result)),
                        )
                        conn.commit()
                    finally:
                        conn.close()
                except Exception as e:
                    logger.debug(f"[VT cache] disk write failed: {e}")
                    self._disk_ok = False


class GoodDomainChecker:
    """
    Tier 2.5: API-Driven 'Known Good' Domain Checker.
    Uses VirusTotal's Global Popularity Rankings to determine if a
    domain (or its root domain) is a highly recognized, legitimate website.
    Caches verdicts (24h) in memory + SQLite and rate-limits itself to the free tier.
    """

    def __init__(self, virustotal_api_key, db_path: Optional[str] = DEFAULT_DB_PATH,
                 per_minute: int = 4, per_day: int = 500):
        self.vt_api_key = virustotal_api_key
        self.vt_base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": self.vt_api_key}
        self.timeout = 2.0
        self._cache = _VTCache(db_path)
        self._limiter = _RateLimiter(per_minute, per_day)

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _neutral(provider: str = "") -> dict:
        return {
            "v": CACHE_VERSION,
            "is_whitelisted": False,
            "malicious_count": 0,
            "required_engines": 3,
            "popularity_rank": 99999999,
            "vt_risk_score": NEUTRAL_RISK,
            "provider": provider,
        }

    @staticmethod
    def _split(url: str) -> Tuple[str, str]:
        """Returns (host, registered_domain); both lower-case, www stripped."""
        raw = (url or "").strip()
        parsed = urlparse(raw if "://" in raw else f"http://{raw}")
        host = (parsed.hostname or "").lower().rstrip(".")
        if host.startswith("www."):
            host = host[4:]
        try:
            reg = tldextract.extract(host).registered_domain.lower()
        except Exception:
            reg = ""
        return host, (reg or host)

    def _query(self, domain: str) -> Tuple[dict, Optional[float]]:
        """
        One VT lookup. Returns (result, ttl). ttl None means do not cache
        (rate limited / HTTP 429).
        """
        if not self._limiter.try_acquire():
            logger.info("[Tier 2.5] VT rate limit reached; returning neutral result")
            return self._neutral(RATE_LIMITED_PROVIDER), None

        result = self._neutral()
        try:
            response = requests.get(
                f"{self.vt_base_url}/domains/{domain}",
                headers=self.headers, timeout=self.timeout,
            )
        except Exception as e:
            logger.error(f"[Tier 2.5 API Error] {e}.")
            result["provider"] = "error"
            return result, ERROR_TTL

        status = response.status_code
        if status == 429:
            self._limiter.penalize(60.0)
            return self._neutral(RATE_LIMITED_PROVIDER), None
        if status == 404:
            return result, DEFINITIVE_TTL  # VT has never seen it: neutral, not an error
        if status != 200:
            result["provider"] = "error"
            return result, ERROR_TTL

        try:
            data = response.json().get("data", {}).get("attributes", {})
        except Exception:
            result["provider"] = "error"
            return result, ERROR_TTL

        malicious_count = (data.get("last_analysis_stats") or {}).get("malicious", 0)
        best_rank, winner = 99999999, ""
        for provider, rank_data in (data.get("popularity_ranks") or {}).items():
            rank = (rank_data or {}).get("rank", 99999999)
            if rank < best_rank:
                best_rank, winner = rank, provider
        required = required_engines(best_rank)
        result.update(malicious_count=malicious_count, popularity_rank=best_rank, provider=winner,
                      required_engines=required)

        if malicious_count >= required:
            result["vt_risk_score"] = 95.0
            logger.warning(f"[Tier 2.5] Domain '{domain}' is flagged malicious by {malicious_count} VT engines "
                           f"(needs {required} at rank {best_rank})!")
            return result, DEFINITIVE_TTL

        # A few vendors misfire on huge, well-known domains (google.com shows 1-2 flags), so popularity wins over a
        # small number of detections; an unranked domain with 1-2 flags stays a weak signal only.
        if best_rank < 100000:
            result["is_whitelisted"] = True
            result["vt_risk_score"] = 0.0 if malicious_count == 0 else 10.0
        elif best_rank < 500000 and malicious_count <= 1:
            result["is_whitelisted"] = True
            result["vt_risk_score"] = 10.0
        elif malicious_count > 0:
            result["vt_risk_score"] = 50.0
        return result, DEFINITIVE_TTL

    def _lookup(self, domain: str) -> dict:
        cached = self._cache.get(domain)
        if cached is not None and cached.get("v") == CACHE_VERSION:
            return cached
        result, ttl = self._query(domain)
        if ttl is not None:
            self._cache.put(domain, result, ttl)
        return result

    # --------------------------------------------------------------- public API
    def get_vt_reputation(self, url: str) -> dict:
        """
        Queries VirusTotal (cached, rate limited) and returns:
        - is_whitelisted (bool)
        - malicious_count (int)
        - popularity_rank (int)
        - vt_risk_score (float 0.0 - 100.0)
        - provider (str)   ('rate_limited' when the quota is exhausted)
        Ranking is looked up by registered domain. When the registered domain is not
        ranked and the URL uses a subdomain, the host is also checked for detections.
        """
        host, reg = self._split(url)
        if not reg:
            return self._neutral()

        result = self._lookup(reg)
        if (host and host != reg and not result.get("is_whitelisted")
                and result.get("malicious_count", 0) < result.get("required_engines", 3)
                and result.get("provider") != RATE_LIMITED_PROVIDER
                and (self._cache.get(host) is not None or self._limiter.remaining_minute() >= 2)):
            host_result = self._lookup(host)
            if host_result.get("malicious_count", 0) >= host_result.get("required_engines", 3):
                return host_result
        return result

    def is_known_good_domain(self, url: str) -> bool:
        """
        Checks Global Popularity Rank via VirusTotal API.
        Handles subdomains and endpoints automatically.
        """
        rep = self.get_vt_reputation(url)
        return rep.get("is_whitelisted", False)
