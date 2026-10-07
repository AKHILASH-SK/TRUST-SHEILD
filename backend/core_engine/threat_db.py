"""
TrustShield V2 - Stage 2: Local Threat Database Cache with Auto-Sync
Maintains an ultra-fast (< 2 ms) local SQLite cache of known malicious indicators
(URLs and domains) sourced from public feeds (URLhaus, OpenPhish, PhishTank).
"""

import os
import re
import sqlite3
import logging
from datetime import datetime
from typing import List, Tuple, Optional
from urllib.parse import urlparse
from contextlib import contextmanager
import requests
import tldextract

logger = logging.getLogger(__name__)

# Default location for the embedded SQLite threat cache
DEFAULT_DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
DEFAULT_DB_PATH = os.path.join(DEFAULT_DB_DIR, "threat_intel.db")


def normalize_indicator(val: str) -> str:
    """Normalizes URLs or domains for consistent hashing/indexing."""
    if not val:
        return ""
    clean = val.strip().lower()
    # Strip protocol if domain-only representation
    if clean.endswith('/'):
        clean = clean[:-1]
    return clean


def _is_protected_domain(registered_domain: str) -> bool:
    """Brand domains and shared hosting platforms must never be blocked as a whole domain."""
    try:
        from .link_threat_pipeline import USER_CONTENT_HOSTS, BRAND_FAST_PATH_DOMAINS
        return registered_domain in USER_CONTENT_HOSTS or registered_domain in BRAND_FAST_PATH_DOMAINS
    except Exception:
        return False


class ThreatIntelDB:
    """
    Embedded SQLite Threat Cache for sub-2ms indicator lookups.
    """
    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    @contextmanager
    def _get_connection(self):
        conn = sqlite3.connect(self.db_path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS malicious_indicators (
                    indicator TEXT PRIMARY KEY,
                    source TEXT,
                    date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_indicator ON malicious_indicators(indicator);
            """)
            conn.commit()

    def add_indicators(self, indicators: List[Tuple[str, str]]) -> int:
        """
        Batch-inserts malicious indicators into SQLite.
        indicators: list of (indicator_string, source_name)
        Returns count of new rows inserted.
        """
        if not indicators:
            return 0
            
        rows_to_insert = []
        for ind, src in indicators:
            norm = normalize_indicator(ind)
            if norm:
                rows_to_insert.append((norm, src, datetime.utcnow().isoformat()))
                
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.executemany("""
                INSERT OR IGNORE INTO malicious_indicators (indicator, source, date_added)
                VALUES (?, ?, ?)
            """, rows_to_insert)
            conn.commit()
            return cursor.rowcount

    def add_indicator(self, indicator: str, source: str = "MANUAL") -> bool:
        """Inserts a single malicious indicator into SQLite."""
        count = self.add_indicators([(indicator, source)])
        return count > 0


    @staticmethod
    def _build_lookup_keys(clean_input: str) -> set:
        """Lookup keys: URL with/without scheme, www., trailing slash; host; registered
        domain (unless it is a user-content platform); host+path."""
        keys = set()
        try:
            no_scheme = re.sub(r"^[a-z][a-z0-9+.-]*://", "", clean_input)
            for variant in (clean_input, no_scheme):
                v = normalize_indicator(variant)
                keys.add(v)
                if v.startswith("www."):
                    keys.add(v[4:])
                keys.add(v.split("#")[0].split("?")[0].rstrip("/"))
            keys.add(f"http://{no_scheme.rstrip('/')}")
            keys.add(f"https://{no_scheme.rstrip('/')}")

            parsed = urlparse(clean_input if "://" in clean_input else f"http://{clean_input}")
            host = (parsed.hostname or "").rstrip(".")
            if host:
                keys.add(host)
                bare = host[4:] if host.startswith("www.") else host
                keys.add(bare)
                path = parsed.path.rstrip("/")
                if path:
                    keys.add(f"{host}{path}")
                    keys.add(f"{bare}{path}")

                reg = tldextract.extract(host).registered_domain.lower()
                if reg:
                    # A bad URL on a shared platform must not block the whole platform.
                    try:
                        from .link_threat_pipeline import is_user_content_host
                        shared = is_user_content_host(reg) or is_user_content_host(host)
                    except Exception:
                        shared = False
                    if not shared:
                        keys.add(reg)
        except Exception:
            pass
        keys.discard("")
        return keys

    def count(self) -> int:
        """Total number of indicators stored."""
        return self.get_indicator_count()

    def check_indicator(self, url_or_domain: str) -> bool:
        """
        Queries SQLite to verify if the URL, its hostname, or its registered domain
        exists in the local malicious threat cache (< 2 ms).
        """
        if not url_or_domain:
            return False
            
        clean_input = url_or_domain.strip().lower()
        keys_to_check = self._build_lookup_keys(clean_input)

        keys_list = [k for k in keys_to_check if k]
        if not keys_list:
            return False
            
        placeholders = ",".join(["?"] * len(keys_list))
        query = f"SELECT 1 FROM malicious_indicators WHERE indicator IN ({placeholders}) LIMIT 1;"
        
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, keys_list)
                row = cursor.fetchone()
                return row is not None
        except Exception as e:
            logger.error(f"[ThreatIntelDB] Error querying threat indicators: {e}")
            return False

    def sync_threat_feeds(self, max_records: int = 1500) -> int:
        """
        Fetches daily verified malware & phishing URLs from URLhaus (abuse.ch).
        Executes with a non-blocking timeout and continues gracefully if network is unavailable.
        """
        logger.info("📥 [ThreatIntelDB] Synchronizing local threat database with URLhaus feed...")
        inserted_count = 0
        new_indicators: List[Tuple[str, str]] = []
        
        # 1. Fetch from URLhaus (abuse.ch) JSON API
        try:
            urlhaus_endpoint = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
            urlhaus_headers = {"User-Agent": "trustshield-threat-sync/1.0"}
            if os.getenv("URLHAUS_AUTH_KEY"):
                urlhaus_headers["Auth-Key"] = os.environ["URLHAUS_AUTH_KEY"]
            resp = requests.get(urlhaus_endpoint, timeout=8.0, headers=urlhaus_headers)
            if resp.status_code in (401, 403):
                logger.warning("   [ThreatIntelDB] URLhaus now requires a free auth key: set URLHAUS_AUTH_KEY")
            if resp.status_code == 200:
                data = resp.json()
                urls = data.get('urls', [])[:max_records]
                for item in urls:
                    mal_url = item.get('url')
                    if mal_url:
                        new_indicators.append((mal_url, "URLhaus"))
                        ext = tldextract.extract(mal_url)
                        reg = (getattr(ext, "top_domain_under_public_suffix", None) or ext.registered_domain or "").lower()
                        if reg and not _is_protected_domain(reg):
                            new_indicators.append((reg, "URLhaus_Domain"))
                logger.info(f"   Fetched {len(urls)} live indicators from URLhaus.")
        except Exception as e:
            logger.warning(f"   [ThreatIntelDB] URLhaus live feed sync skipped: {e}")

        # 1b. OpenPhish community feed (plain text, one URL per line)
        try:
            resp = requests.get("https://openphish.com/feed.txt", timeout=8.0,
                                headers={"User-Agent": "trustshield-threat-sync/1.0"})
            if resp.status_code == 200:
                lines = [ln.strip() for ln in resp.text.splitlines() if ln.strip().lower().startswith(("http://", "https://"))]
                for phish_url in lines[:max_records]:
                    new_indicators.append((phish_url, "OpenPhish"))
                logger.info(f"   Fetched {min(len(lines), max_records)} live indicators from OpenPhish.")
        except Exception as e:
            logger.warning(f"   [ThreatIntelDB] OpenPhish feed sync skipped: {e}")

        # 2. Batch insert into SQLite
        if new_indicators:
            try:
                self.add_indicators(new_indicators)
                inserted_count = len(new_indicators)
                logger.info(f"✅ [ThreatIntelDB] Successfully synchronized {inserted_count} indicators.")
            except Exception as e:
                logger.error(f"   [ThreatIntelDB] Database insert failed during feed sync: {e}")
                
        return inserted_count

    def sync_if_stale(self, max_age_hours: float = 12.0) -> int:
        """Syncs the public feeds when the cache is empty or older than max_age_hours."""
        try:
            with self._get_connection() as conn:
                conn.execute("CREATE TABLE IF NOT EXISTS sync_meta (key TEXT PRIMARY KEY, value TEXT)")
                row = conn.execute("SELECT value FROM sync_meta WHERE key = 'last_sync'").fetchone()
            last = datetime.fromisoformat(row[0]) if row else None
        except Exception:
            last = None
        fresh = last is not None and (datetime.utcnow() - last).total_seconds() < max_age_hours * 3600
        if fresh and self.get_indicator_count() > 0:
            return 0
        added = self.sync_threat_feeds()
        if added:
            try:
                with self._get_connection() as conn:
                    conn.execute("INSERT OR REPLACE INTO sync_meta (key, value) VALUES ('last_sync', ?)",
                                 (datetime.utcnow().isoformat(),))
                    conn.commit()
            except Exception as e:
                logger.warning(f"[ThreatIntelDB] Could not record sync time: {e}")
        return added

    def get_indicator_count(self) -> int:
        """Returns the total number of indicators cached in the local database."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM malicious_indicators;")
                return cursor.fetchone()[0]
        except Exception:
            return 0


# Singleton global instance
_global_threat_db: Optional[ThreatIntelDB] = None

def get_threat_db() -> ThreatIntelDB:
    global _global_threat_db
    if _global_threat_db is None:
        _global_threat_db = ThreatIntelDB()
        if os.getenv("ENABLE_THREAT_SYNC", "true").lower() == "true":
            import threading
            threading.Thread(target=_global_threat_db.sync_if_stale, name="threat-sync", daemon=True).start()
    return _global_threat_db
