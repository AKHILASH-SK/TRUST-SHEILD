"""
Phishing Feed Integration Module
Fetches phishing URLs from public threat feeds and stores in database
"""

import psycopg
import requests
import os
import logging
from datetime import datetime
from urllib.parse import urlparse
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

from db_config import DB_CONFIG

# Hosts where anyone can publish content: one bad URL there must never condemn the whole domain
_FALLBACK_USER_CONTENT_HOSTS = {
    "google.com", "sharepoint.com", "windows.net", "github.com", "github.io", "gitlab.com",
    "notion.so", "dropbox.com", "typeform.com", "canva.com", "medium.com", "blogspot.com",
    "weebly.com", "wixsite.com", "herokuapp.com", "netlify.app", "vercel.app", "pages.dev",
    "workers.dev", "web.app", "firebaseapp.com", "t.me", "bit.ly", "tinyurl.com", "cutt.ly",
    "forms.gle", "goo.gl", "t.co", "ow.ly", "is.gd", "rebrand.ly",
}


def _user_content_hosts():
    try:
        from core_engine.link_threat_pipeline import USER_CONTENT_HOSTS
        return set(USER_CONTENT_HOSTS) | _FALLBACK_USER_CONTENT_HOSTS
    except Exception:
        return _FALLBACK_USER_CONTENT_HOSTS


def _is_shared_host(domain):
    """True when the domain (or its registrable parent) is a user-content/hosting platform."""
    if not domain:
        return False
    hosts = _user_content_hosts()
    parts = domain.split(".")
    return any(".".join(parts[i:]) in hosts for i in range(len(parts) - 1))


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("PhishingFeed")

class PhishingFeedImporter:
    """Imports phishing URLs from various threat intelligence sources"""
    
    def __init__(self):
        self.phishtank_api_key = os.getenv('PHISHTANK_API_KEY', '')
    
    # Public feeds that need no account. Each list is newest-first, so the head holds the freshest links.
    PUBLIC_FEEDS = {
        "openphish": ("https://openphish.com/feed.txt", 3000),
        "phishtank": ("https://data.phishtank.com/data/online-valid.csv", 6000),
        "urlhaus": ("https://urlhaus.abuse.ch/downloads/csv_online/", 4000),
        "phishing_database": ("https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt", 6000),
    }

    @staticmethod
    def _download_text(url, timeout=90):
        response = requests.get(url, timeout=timeout, headers={"User-Agent": "phishtank/trustshield-feed"})
        response.raise_for_status()
        return response.text

    @staticmethod
    def _looks_like_url(text):
        t = (text or "").strip()
        return t.lower().startswith(("http://", "https://")) and " " not in t and len(t) <= 2048

    def fetch_from_phishtank(self, limit=6000):
        """PhishTank: the keyed JSON feed when PHISHTANK_API_KEY is set, otherwise the public CSV of verified-online phish."""
        try:
            logger.info("Fetching from PhishTank...")
            if self.phishtank_api_key:
                data = requests.get(f"https://data.phishtank.com/data/{self.phishtank_api_key}/online-valid.json",
                                    timeout=90, headers={"User-Agent": "phishtank/trustshield-feed"}).json()
                items = data if isinstance(data, list) else data.get('results', [])
                urls = [i['url'] for i in items[:limit] if isinstance(i, dict) and i.get('url')]
            else:
                import csv
                import io
                try:
                    text = self._download_text(self.PUBLIC_FEEDS["phishtank"][0], timeout=180)
                except Exception as exc:
                    # PhishTank rate-limits keyless downloads (HTTP 429): fall back to the last copy saved on this machine
                    cached = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ml", "data", "raw", "phishtank.bin")
                    if not os.path.exists(cached):
                        raise
                    logger.warning(f"PhishTank download refused ({exc}); using the saved copy. Set PHISHTANK_API_KEY for live access.")
                    with open(cached, encoding="utf-8", errors="replace") as fh:
                        text = fh.read()
                urls = []
                for row in csv.DictReader(io.StringIO(text)):
                    if self._looks_like_url(row.get("url")):
                        urls.append(row["url"].strip())
                    if len(urls) >= limit:
                        break
            logger.info(f"Retrieved {len(urls)} URLs from PhishTank")
            return urls
        except Exception as e:
            logger.error(f"Error fetching from PhishTank: {e}")
            return []

    def fetch_from_urlhaus(self, limit=4000):
        """URLhaus: public CSV of currently online malware/phishing URLs."""
        try:
            logger.info("Fetching from URLhaus...")
            import csv
            text = self._download_text(self.PUBLIC_FEEDS["urlhaus"][0], timeout=120)
            lines = [ln for ln in text.splitlines() if ln.strip() and not ln.startswith("#")]
            out = []
            for row in csv.reader(lines):      # id,dateadded,url,url_status,last_online,threat,tags,...
                if len(row) >= 6 and self._looks_like_url(row[2]):
                    out.append({"url": row[2].strip(), "threat_type": (row[5] or "malware_download").strip()[:50]})
                if len(out) >= limit:
                    break
            logger.info(f"Retrieved {len(out)} URLs from URLhaus")
            return out
        except Exception as e:
            logger.error(f"Error fetching from URLhaus: {e}")
            return []

    def fetch_from_openpfish(self, limit=3000):
        """OpenPhish community feed (real time)."""
        try:
            logger.info("Fetching from OpenPhish...")
            urls = [u.strip() for u in self._download_text(self.PUBLIC_FEEDS["openphish"][0], timeout=30).splitlines()
                    if self._looks_like_url(u)][:limit]
            logger.info(f"Retrieved {len(urls)} URLs from OpenPhish")
            return urls
        except Exception as e:
            logger.error(f"Error fetching from OpenPhish: {e}")
            return []

    def fetch_from_phishing_database(self, limit=6000):
        """Phishing.Database community list of active phishing links."""
        try:
            logger.info("Fetching from Phishing.Database...")
            urls = [u.strip() for u in self._download_text(self.PUBLIC_FEEDS["phishing_database"][0], timeout=120).splitlines()
                    if self._looks_like_url(u)][:limit]
            logger.info(f"Retrieved {len(urls)} URLs from Phishing.Database")
            return urls
        except Exception as e:
            logger.error(f"Error fetching from Phishing.Database: {e}")
            return []

    def record_source(self, name, url):
        """Keep phishing_feed_sources up to date: when each feed was last fetched and when it is due next."""
        try:
            with psycopg.connect(**DB_CONFIG) as conn:
                conn.execute("""
                    INSERT INTO phishing_feed_sources (name, url, last_fetch, next_fetch, is_active)
                    VALUES (%s, %s, NOW(), NOW() + INTERVAL '6 hours', TRUE)
                    ON CONFLICT (name) DO UPDATE
                        SET url = EXCLUDED.url, last_fetch = NOW(), next_fetch = EXCLUDED.next_fetch, is_active = TRUE
                """, (name, url))
        except Exception as e:
            logger.warning(f"Could not record feed source {name}: {e}")

    def extract_domain(self, url):
        """Extract domain from URL and normalize it"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            # Remove www. prefix for normalized matching
            if domain.startswith('www.'):
                domain = domain[4:]
            return domain if domain else None
        except:
            return None
    
    def store_phishing_urls(self, urls, source='manual', threat_type='phishing'):
        """
        Store phishing URLs in the database in batches (fast even against a remote database).
        If a batch is rejected, its rows are retried one by one so one bad row never loses the rest.
        Returns (inserted, updated); updated counts URLs that already existed.
        """
        rows, seen = [], set()
        for item in urls:
            if isinstance(item, dict):
                url, item_type = item.get('url'), item.get('threat_type') or threat_type
            else:
                url, item_type = item, threat_type
            url = (url or "").strip()
            if not url or len(url) > 2048 or not url.lower().startswith(("http://", "https://")) or url in seen:
                continue
            seen.add(url)
            rows.append((url, self.extract_domain(url), str(item_type)[:50], source))

        if not rows:
            return 0, 0
        sql = """INSERT INTO phishing_links (url, domain, threat_type, source, last_verified)
                 VALUES (%s, %s, %s, %s, NOW())
                 ON CONFLICT (url) DO UPDATE SET last_verified = NOW()"""
        failed = 0
        with psycopg.connect(**DB_CONFIG) as conn:
            before = conn.execute("SELECT COUNT(*) FROM phishing_links").fetchone()[0]
            for start in range(0, len(rows), 1000):
                batch = rows[start:start + 1000]
                try:
                    with conn.transaction():
                        conn.cursor().executemany(sql, batch)
                except psycopg.Error:
                    for row in batch:
                        try:
                            with conn.transaction():
                                conn.execute(sql, row)
                        except psycopg.Error as e:
                            failed += 1
                            logger.debug(f"Skipped {row[0]}: {e}")
            after = conn.execute("SELECT COUNT(*) FROM phishing_links").fetchone()[0]
        inserted = max(0, after - before)
        updated = max(0, len(rows) - failed - inserted)
        logger.info(f"Stored: {inserted} new, {updated} existing, {failed} failed from {source}")
        return inserted, updated

    def import_all_feeds(self):
        """Import every public feed and record each in phishing_feed_sources. One failing feed never stops the others."""
        logger.info("Starting import from all feeds...")
        total_inserted = total_updated = 0
        jobs = [
            ("openphish", self.PUBLIC_FEEDS["openphish"][0], self.fetch_from_openpfish, "phishing"),
            ("phishtank", self.PUBLIC_FEEDS["phishtank"][0], self.fetch_from_phishtank, "phishing"),
            ("urlhaus", self.PUBLIC_FEEDS["urlhaus"][0], self.fetch_from_urlhaus, "malware"),
            ("phishing_database", self.PUBLIC_FEEDS["phishing_database"][0], self.fetch_from_phishing_database, "phishing"),
        ]
        for name, feed_url, fetch, default_type in jobs:
            try:
                items = fetch()
                if not items:
                    continue
                inserted, updated = self.store_phishing_urls(items, source=name, threat_type=default_type)
                total_inserted += inserted
                total_updated += updated
                self.record_source(name, feed_url)
            except Exception as e:
                logger.error(f"Feed {name} failed: {e}")
        logger.info(f"Import complete: {total_inserted} inserted, {total_updated} updated")
        return total_inserted, total_updated

    def check_url_in_database(self, url):
        """
        Check if a URL is in the phishing database.
        Exact URL matches always count. A whole-domain match counts only for domains that are
        not shared hosting / user-content platforms.
        Returns: (is_phishing: bool, threat_type: str, source: str)
        """
        try:
            with psycopg.connect(**DB_CONFIG) as conn:
                bare = url.rstrip("/")
                result = conn.execute(
                    "SELECT threat_type, source FROM phishing_links WHERE url = ANY(%s) LIMIT 1",
                    ([url, bare, bare + "/"],)
                ).fetchone()
                if result:
                    return True, result[0], result[1]

                domain = self.extract_domain(url)
                if domain and not _is_shared_host(domain):
                    result = conn.execute(
                        "SELECT threat_type, source FROM phishing_links WHERE domain = %s OR domain = %s LIMIT 1",
                        (domain, f"www.{domain}")
                    ).fetchone()
                    if result:
                        return True, result[0], result[1]

            return False, None, None

        except Exception as e:
            logger.error(f"Error checking URL: {e}")
            return False, None, None

    def get_database_stats(self):
        """Get statistics about phishing database"""
        try:
            with psycopg.connect(**DB_CONFIG) as conn:
                total = conn.execute("SELECT COUNT(*) FROM phishing_links").fetchone()[0]
                by_type = dict(conn.execute(
                    "SELECT threat_type, COUNT(*) FROM phishing_links GROUP BY threat_type").fetchall())
                by_source = dict(conn.execute(
                    "SELECT source, COUNT(*) FROM phishing_links GROUP BY source").fetchall())

            return {'total': total, 'by_threat_type': by_type, 'by_source': by_source}

        except Exception as e:
            logger.error(f"Error getting stats: {e}")
            return None

if __name__ == "__main__":
    importer = PhishingFeedImporter()
    
    # For testing - import from all feeds
    print("\nStarting phishing feed import...\n")
    importer.import_all_feeds()
    
    # Show stats
    stats = importer.get_database_stats()
    if stats:
        print("\nDatabase Statistics:")
        print(f"Total phishing URLs: {stats['total']}")
        print(f"By threat type: {stats['by_threat_type']}")
        print(f"By source: {stats['by_source']}")
