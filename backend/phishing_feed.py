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
    
    def fetch_from_phishtank(self, limit=1000):
        """
        Fetch from PhishTank (requires API key)
        Register at https://phishtank.com/api_info.php
        """
        try:
            logger.info("📥 Fetching from PhishTank...")
            
            if not self.phishtank_api_key:
                logger.warning("⚠️ PhishTank API key not set. Set PHISHTANK_API_KEY in .env")
                return []
            
            url = f"https://data.phishtank.com/data/{self.phishtank_api_key}/online-valid.json"
            response = requests.get(url, timeout=60, headers={"User-Agent": "trustshield-feed/1.0"})
            response.raise_for_status()

            data = response.json()
            items = data if isinstance(data, list) else data.get('results', [])
            phishing_urls = [item['url'] for item in items[:limit] if isinstance(item, dict) and item.get('url')]
            logger.info(f"✅ Retrieved {len(phishing_urls)} URLs from PhishTank")
            return phishing_urls
            
        except Exception as e:
            logger.error(f"❌ Error fetching from PhishTank: {e}")
            return []
    
    def fetch_from_urlhaus(self, limit=1000):
        """
        Fetch from URLhaus (no API key needed)
        Free hosting malware/phishing detection
        """
        try:
            logger.info("📥 Fetching from URLhaus...")
            
            url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            malicious_urls = []
            
            for item in data.get('urls', [])[:limit]:
                if item.get('threat_type') in ['phishing', 'malware', 'scam']:
                    malicious_urls.append({
                        'url': item.get('url'),
                        'threat_type': item.get('threat_type')
                    })
            
            logger.info(f"✅ Retrieved {len(malicious_urls)} URLs from URLhaus")
            return malicious_urls
            
        except Exception as e:
            logger.error(f"❌ Error fetching from URLhaus: {e}")
            return []
    
    def fetch_from_openpfish(self, limit=1000):
        """
        Fetch from OpenPhish (no API key needed)
        Real-time phishing detection feed
        """
        try:
            logger.info("📥 Fetching from OpenPhish...")
            
            url = "https://openphish.com/feed.txt"
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            urls = response.text.strip().split('\n')[:limit]
            logger.info(f"✅ Retrieved {len(urls)} URLs from OpenPhish")
            return urls
            
        except Exception as e:
            logger.error(f"❌ Error fetching from OpenPhish: {e}")
            return []
    
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
        Store phishing URLs in the database.

        Each row is inserted inside its own savepoint, so one bad row never aborts the batch.
        Returns (inserted, updated) where updated counts URLs that already existed.

        Args:
            urls: List of URLs or list of dicts with url/threat_type
            source: Source name (phishtank, urlhaus, openphish, manual)
            threat_type: Default threat type (phishing, malware, scam)
        """
        inserted = 0
        updated = 0
        failed = 0

        with psycopg.connect(**DB_CONFIG) as conn:
            for item in urls:
                if isinstance(item, dict):
                    url = item.get('url')
                    item_threat_type = item.get('threat_type') or threat_type
                else:
                    url = item
                    item_threat_type = threat_type

                url = (url or "").strip()
                if not url or len(url) > 2048 or not url.lower().startswith(("http://", "https://")):
                    continue

                domain = self.extract_domain(url)

                try:
                    with conn.transaction():
                        row = conn.execute("""
                            INSERT INTO phishing_links
                                (url, domain, threat_type, source, last_verified)
                            VALUES (%s, %s, %s, %s, NOW())
                            ON CONFLICT (url) DO UPDATE SET last_verified = NOW()
                            RETURNING (xmax = 0) AS inserted
                        """, (url, domain, item_threat_type, source)).fetchone()
                    if row and row[0]:
                        inserted += 1
                    else:
                        updated += 1
                except psycopg.Error as e:
                    failed += 1
                    logger.debug(f"Skipped {url}: {e}")

        logger.info(f"Stored: {inserted} new, {updated} existing, {failed} failed from {source}")
        return inserted, updated

    def import_all_feeds(self):
        """Import from all available sources"""
        logger.info("🚀 Starting import from all feeds...")
        
        total_inserted = 0
        total_updated = 0
        
        # Import from OpenPhish (no key needed)
        logger.info("\n--- OpenPhish Feed ---")
        openpfish_urls = self.fetch_from_openpfish(limit=500)
        if openpfish_urls:
            inserted, updated = self.store_phishing_urls(openpfish_urls, source='openpfish')
            total_inserted += inserted
            total_updated += updated
        
        # Import from URLhaus (no key needed)
        logger.info("\n--- URLhaus Feed ---")
        urlhaus_data = self.fetch_from_urlhaus(limit=500)
        if urlhaus_data:
            inserted, updated = self.store_phishing_urls(urlhaus_data, source='urlhaus')
            total_inserted += inserted
            total_updated += updated
        
        # Import from PhishTank (if API key available)
        if self.phishtank_api_key:
            logger.info("\n--- PhishTank Feed ---")
            phishtank_urls = self.fetch_from_phishtank(limit=500)
            if phishtank_urls:
                inserted, updated = self.store_phishing_urls(phishtank_urls, source='phishtank')
                total_inserted += inserted
                total_updated += updated
        
        logger.info(f"\n✅ Import complete: {total_inserted} inserted, {total_updated} updated")
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
                result = conn.execute(
                    "SELECT threat_type, source FROM phishing_links WHERE url = %s LIMIT 1", (url,)
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
    print("\n🔄 Starting phishing feed import...\n")
    importer.import_all_feeds()
    
    # Show stats
    stats = importer.get_database_stats()
    if stats:
        print("\n📊 Database Statistics:")
        print(f"Total phishing URLs: {stats['total']}")
        print(f"By threat type: {stats['by_threat_type']}")
        print(f"By source: {stats['by_source']}")
