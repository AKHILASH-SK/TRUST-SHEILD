#!/usr/bin/env python3
"""
View TrustShield Database - See all users and scans
"""
import psycopg
import os
from dotenv import load_dotenv
from datetime import datetime

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
    print("=" * 80)
    print("🔍 TrustShield Database Viewer")
    print("=" * 80)
    
    conn = psycopg.connect(**DB_CONFIG)
    cur = conn.cursor()
    
    # ====== VIEW USERS ======
    print("\n📋 REGISTERED USERS:")
    print("-" * 80)
    cur.execute("SELECT id, name, last_name, email, phone_number, created_at FROM users ORDER BY id DESC")
    users = cur.fetchall()
    
    if users:
        for user in users:
            print(f"\n✅ User ID: {user[0]}")
            print(f"   Name: {user[1]} {user[2]}")
            print(f"   Email: {user[3]}")
            print(f"   Phone: {user[4]}")
            print(f"   Registered: {user[5]}")
    else:
        print("❌ No users found")
    
    # ====== VIEW LINK SCANS ======
    print("\n\n📊 LINK SCANS:")
    print("-" * 80)
    cur.execute("""
        SELECT 
            ls.id, 
            ls.user_id, 
            u.name, 
            ls.url, 
            ls.risk_level, 
            ls.verdict,
            ls.analyzed_at 
        FROM link_scans ls
        LEFT JOIN users u ON ls.user_id = u.id
        ORDER BY ls.analyzed_at DESC
    """)
    scans = cur.fetchall()
    
    if scans:
        for scan in scans:
            print(f"\n📎 Scan ID: {scan[0]}")
            print(f"   User: {scan[2]} (ID: {scan[1]})")
            print(f"   URL: {scan[3]}")
            print(f"   Risk Level: {scan[4]}")
            print(f"   Verdict: {scan[5]}")
            print(f"   Scanned: {scan[6]}")
    else:
        print("❌ No scans found (expected - link scanning not yet implemented)")
    
    # ====== DATABASE SUMMARY ======
    print("\n\n📈 DATABASE SUMMARY:")
    print("-" * 80)
    cur.execute("SELECT COUNT(*) FROM users")
    user_count = cur.fetchone()[0]
    print(f"✅ Total Users: {user_count}")
    
    cur.execute("SELECT COUNT(*) FROM link_scans")
    scan_count = cur.fetchone()[0]
    print(f"✅ Total Scans: {scan_count}")
    
    cur.close()
    conn.close()
    
    print("\n" + "=" * 80)
    print("✅ Database query complete!")
    print("=" * 80)
    
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
