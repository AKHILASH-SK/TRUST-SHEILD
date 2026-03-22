"""
Database migration script to normalize domains (remove www prefix)
"""
import psycopg
import os
from dotenv import load_dotenv
from urllib.parse import urlparse

load_dotenv()

DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': int(os.getenv('DB_PORT', '5432')),
    'dbname': os.getenv('DB_NAME', 'trustshield_db'),
    'user': os.getenv('DB_USER', 'postgres'),
    'password': os.getenv('DB_PASSWORD', '').strip()
}

def normalize_domain(domain_str):
    """Normalize domain by removing www prefix"""
    if not domain_str:
        return None
    domain = domain_str.lower().strip()
    if domain.startswith('www.'):
        domain = domain[4:]
    return domain

def migrate_domains():
    """Update all domain entries to normalized format"""
    try:
        conn = psycopg.connect(**DB_CONFIG)
        cur = conn.cursor()
        
        print("📊 Fetching all phishing links...")
        cur.execute("SELECT id, domain FROM phishing_links WHERE domain IS NOT NULL")
        all_rows = cur.fetchall()
        
        print(f"Found {len(all_rows)} entries to normalize...")
        
        updated = 0
        for link_id, domain in all_rows:
            normalized = normalize_domain(domain)
            if normalized != domain:
                cur.execute(
                    "UPDATE phishing_links SET domain = %s WHERE id = %s",
                    (normalized, link_id)
                )
                updated += 1
        
        conn.commit()
        print(f"✅ Updated {updated} domain entries to normalized format")
        
        # Show sample
        print("\n📖 Sample normalized domains:")
        cur.execute("SELECT DISTINCT domain FROM phishing_links LIMIT 10")
        for row in cur.fetchall():
            print(f"  - {row[0]}")
        
        cur.close()
        conn.close()
        
    except Exception as e:
        print(f"❌ Error: {e}")
        raise

if __name__ == "__main__":
    migrate_domains()
    print("\n✅ Domain migration complete!")
