"""
Database initialization script for TrustShield
Creates necessary tables including phishing_links table
"""

import psycopg
import os
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

def init_database():
    """Initialize database and create tables"""
    try:
        conn = psycopg.connect(**DB_CONFIG)
        cur = conn.cursor()
        
        print("📊 Creating database tables...")
        
        # Create phishing_links table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS phishing_links (
                id SERIAL PRIMARY KEY,
                url VARCHAR(2048) UNIQUE NOT NULL,
                domain VARCHAR(255),
                threat_type VARCHAR(50),
                source VARCHAR(100),
                confidence FLOAT DEFAULT 1.0,
                date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_verified TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE
            );
        """)
        print("✅ Created phishing_links table")
        
        # Create index on domain for faster lookup
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_phishing_domain 
            ON phishing_links(domain);
        """)
        print("✅ Created index on phishing domain")
        
        # Create index on URL for faster lookup
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_phishing_url 
            ON phishing_links(url);
        """)
        print("✅ Created index on phishing URL")
        
        # Create phishing_feed_sources table (track where data came from)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS phishing_feed_sources (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) UNIQUE,
                url VARCHAR(500),
                last_fetch TIMESTAMP,
                next_fetch TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE
            );
        """)
        print("✅ Created phishing_feed_sources table")
        
        conn.commit()
        cur.close()
        conn.close()
        
        print("\n✅ Database initialized successfully!")
        
    except Exception as e:
        print(f"❌ Error initializing database: {e}")
        raise

if __name__ == "__main__":
    init_database()
