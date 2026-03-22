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

# Database configuration
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': int(os.getenv('DB_PORT', '5432')),
    'dbname': os.getenv('DB_NAME', 'trustshield_db'),
    'user': os.getenv('DB_USER', 'postgres'),
    'password': os.getenv('DB_PASSWORD', 'postgres')
}

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
            
            url = f"http://phishtank.com/api/fetch.php?apikey={self.phishtank_api_key}&format=json"
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            phishing_urls = [item['url'] for item in data.get('results', [])[:limit]]
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
        Store phishing URLs in database
        
        Args:
            urls: List of URLs or list of dicts with url/threat_type
            source: Source name (phishtank, urlhaus, openpfish, manual)
            threat_type: Type of threat (phishing, malware, scam)
        """
        try:
            conn = psycopg.connect(**DB_CONFIG)
            cur = conn.cursor()
            
            inserted = 0
            updated = 0
            
            for item in urls:
                # Handle both string URLs and dicts
                if isinstance(item, dict):
                    url = item.get('url')
                    threat_type = item.get('threat_type', 'phishing')
                else:
                    url = item
                
                if not url:
                    continue
                
                domain = self.extract_domain(url)
                
                try:
                    # Try to insert
                    cur.execute("""
                        INSERT INTO phishing_links 
                        (url, domain, threat_type, source, last_verified)
                        VALUES (%s, %s, %s, %s, NOW())
                        ON CONFLICT (url) DO UPDATE SET
                            last_verified = NOW()
                        RETURNING id
                    """, (url, domain, threat_type, source))
                    
                    result = cur.fetchone()
                    if result:
                        inserted += 1
                
                except psycopg.Error as e:
                    logger.debug(f"⚠️ Duplicate or error for {url}: {e}")
                    updated += 1
            
            conn.commit()
            cur.close()
            conn.close()
            
            logger.info(f"✅ Stored: {inserted} new, {updated} updated from {source}")
            return inserted, updated
            
        except Exception as e:
            logger.error(f"❌ Error storing URLs: {e}")
            raise
    
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
        Check if URL exists in phishing database
        Handles domain normalization (with/without www)
        Returns: (is_phishing: bool, threat_type: str, source: str)
        """
        try:
            conn = psycopg.connect(**DB_CONFIG)
            cur = conn.cursor()
            
            # Check exact URL match first
            cur.execute("""
                SELECT threat_type, source FROM phishing_links
                WHERE url = %s
                LIMIT 1
            """, (url,))
            
            result = cur.fetchone()
            if result:
                cur.close()
                conn.close()
                return True, result[0], result[1]
            
            # Extract and normalize domain
            domain = self.extract_domain(url)
            if domain:
                # Check exact normalized domain match
                cur.execute("""
                    SELECT threat_type, source FROM phishing_links
                    WHERE domain = %s
                    LIMIT 1
                """, (domain,))
                
                result = cur.fetchone()
                if result:
                    cur.close()
                    conn.close()
                    return True, result[0], result[1]
                
                # Also check with www prefix in case DB has it
                domain_with_www = f"www.{domain}"
                cur.execute("""
                    SELECT threat_type, source FROM phishing_links
                    WHERE domain = %s OR domain = %s
                    LIMIT 1
                """, (domain, domain_with_www))
                
                result = cur.fetchone()
                if result:
                    cur.close()
                    conn.close()
                    return True, result[0], result[1]
            
            cur.close()
            conn.close()
            return False, None, None
            
        except Exception as e:
            logger.error(f"❌ Error checking URL: {e}")
            return False, None, None
    
    def get_database_stats(self):
        """Get statistics about phishing database"""
        try:
            conn = psycopg.connect(**DB_CONFIG)
            cur = conn.cursor()
            
            # Total URLs (ignore is_active for now since it might not be in all schemas)
            cur.execute("SELECT COUNT(*) FROM phishing_links")
            total = cur.fetchone()[0]
            
            # By threat type
            cur.execute("""
                SELECT threat_type, COUNT(*) 
                FROM phishing_links 
                GROUP BY threat_type
            """)
            by_type = dict(cur.fetchall())
            
            # By source
            cur.execute("""
                SELECT source, COUNT(*) 
                FROM phishing_links 
                GROUP BY source
            """)
            by_source = dict(cur.fetchall())
            
            cur.close()
            conn.close()
            
            return {
                'total': total,
                'by_threat_type': by_type,
                'by_source': by_source
            }
            
        except Exception as e:
            logger.error(f"❌ Error getting stats: {e}")
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
