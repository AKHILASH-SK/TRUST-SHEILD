#!/usr/bin/env python3
"""
Database Schema Fix - Expand pin column size
"""
import psycopg
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': int(os.getenv('DB_PORT', '5432')),
    'dbname': os.getenv('DB_NAME', 'trustshield_db'),
    'user': os.getenv('DB_USER', 'postgres'),
    'password': os.getenv('DB_PASSWORD', 'postgres')
}

try:
    print("🔌 Connecting to database...")
    conn = psycopg.connect(**DB_CONFIG)
    cur = conn.cursor()
    
    print("🔧 Fixing PIN column size...")
    
    # Alter the pin column to be larger (bcrypt hashes are 60 chars)
    alter_sql = "ALTER TABLE users ALTER COLUMN pin TYPE varchar(255);"
    cur.execute(alter_sql)
    conn.commit()
    
    print("✅ PIN column fixed! Now accepts hashed PINs (255 chars)")
    print("✅ You can now try registration again!")
    
    cur.close()
    conn.close()
    
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
