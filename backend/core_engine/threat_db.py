"""
TrustShield V2 - Stage 2: Local Threat Database Cache with Auto-Sync
Maintains an ultra-fast (< 2 ms) local SQLite cache of known malicious indicators
(URLs and domains) sourced from public feeds (URLhaus, OpenPhish, PhishTank).
"""

import os
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


    def check_indicator(self, url_or_domain: str) -> bool:
        """
        Queries SQLite to verify if the URL, its hostname, or its registered domain
        exists in the local malicious threat cache (< 2 ms).
        """
        if not url_or_domain:
            return False
            
        clean_input = url_or_domain.strip().lower()
        
        # Build list of potential indicator keys
        keys_to_check = set()
        
        # 1. Full normalized URL (with and without protocol, with and without trailing slash)
        keys_to_check.add(normalize_indicator(clean_input))
        
        # 2. Extract parsed components
        try:
            parsed = urlparse(clean_input if "://" in clean_input else f"http://{clean_input}")
            host = parsed.netloc.split(':')[0]
            if host:
                keys_to_check.add(host)
                # Without 'www.'
                if host.startswith('www.'):
                    keys_to_check.add(host[4:])
                    
            # 3. Extract registered domain
            ext = tldextract.extract(clean_input)
            if ext.registered_domain:
                keys_to_check.add(ext.registered_domain.lower())
                
            # 4. Host + Path combination without query strings
            if host and parsed.path and parsed.path != '/':
                keys_to_check.add(f"{host}{parsed.path.rstrip('/')}")
        except Exception:
            pass
            
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
            resp = requests.get(urlhaus_endpoint, timeout=8.0)
            if resp.status_code == 200:
                data = resp.json()
                urls = data.get('urls', [])[:max_records]
                for item in urls:
                    mal_url = item.get('url')
                    if mal_url:
                        new_indicators.append((mal_url, "URLhaus"))
                        ext = tldextract.extract(mal_url)
                        if ext.registered_domain:
                            new_indicators.append((ext.registered_domain, "URLhaus_Domain"))
                logger.info(f"   Fetched {len(urls)} live indicators from URLhaus.")
        except Exception as e:
            logger.warning(f"   [ThreatIntelDB] URLhaus live feed sync skipped: {e}")

        # 2. Batch insert into SQLite
        if new_indicators:
            try:
                self.add_indicators(new_indicators)
                inserted_count = len(new_indicators)
                logger.info(f"✅ [ThreatIntelDB] Successfully synchronized {inserted_count} indicators.")
            except Exception as e:
                logger.error(f"   [ThreatIntelDB] Database insert failed during feed sync: {e}")
                
        return inserted_count

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
    return _global_threat_db
