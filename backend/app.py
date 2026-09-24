import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

import werkzeug
if not hasattr(werkzeug, '__version__'):
    werkzeug.__version__ = "3.0.0"

from flask import Flask, request, jsonify
from flask_cors import CORS

import psycopg
import bcrypt
import os
from dotenv import load_dotenv
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from phishing_feed import PhishingFeedImporter
from core_engine.ml_engine import MultiModalFusionEngine
from core_engine.link_threat_pipeline import get_link_pipeline
import atexit
import sys
from brand_verification import verify_and_add_brand, discover_and_add_brand
import json
import requests
import threading
import time

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Database configuration
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': int(os.getenv('DB_PORT', '5432')),
    'dbname': os.getenv('DB_NAME', 'trustshield_db'),
    'user': os.getenv('DB_USER', 'postgres'),
    'password': os.getenv('DB_PASSWORD', 'postgres')
}

print(f"[*] Connecting to database: {DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['dbname']}")

# Initialize phishing feed importer (Tier 0)
phishing_importer = PhishingFeedImporter()



# Initialize background scheduler for auto-fetching phishing data
scheduler = BackgroundScheduler()

def schedule_phishing_import():
    """Scheduled job to import phishing feeds"""
    print("[*] [Scheduler] Running phishing feed import...")
    try:
        inserted, updated = phishing_importer.import_all_feeds()
        print(f"[+] [Scheduler] Phishing import complete: {inserted} new, {updated} updated")
    except Exception as e:
        print(f"[-] [Scheduler] Error importing phishing feeds: {e}")

# Schedule to run every 6 hours
scheduler.add_job(
    func=schedule_phishing_import,
    trigger="interval",
    hours=6,
    id='phishing_feed_job',
    name='Import phishing feeds',
    replace_existing=True
)

# Start scheduler only when explicitly enabled (prevents multi-thread fork deadlocks in Gunicorn)
if os.environ.get("ENABLE_SCHEDULER", "false").lower() == "true":
    if not scheduler.running:
        scheduler.start()
        print("[+] Phishing feed scheduler started (runs every 6 hours)")

# Shut down the scheduler when exiting the app
atexit.register(lambda: scheduler.shutdown(wait=False) if scheduler.running else None)

# Helper functions
def get_db_connection():
    """Get database connection"""
    return psycopg.connect(**DB_CONFIG)

def hash_pin(pin):
    """Hash PIN using bcrypt"""
    return bcrypt.hashpw(pin.encode(), bcrypt.gensalt()).decode()

def verify_pin(plain_pin, hashed_pin):
    """Verify PIN against hash"""
    return bcrypt.checkpw(plain_pin.encode(), hashed_pin.encode())

# In-memory case cache for ultra-fast access and resilience
FORENSIC_CASE_CACHE = {}

def ensure_forensic_case_table():
    """Ensures forensic_cases table exists in PostgreSQL"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS forensic_cases (
                case_id VARCHAR(50) PRIMARY KEY,
                evidence_hash VARCHAR(64),
                verdict VARCHAR(100),
                threat_score FLOAT,
                sender VARCHAR(255),
                subject VARCHAR(500),
                dossier_json TEXT NOT NULL,
                raw_eml TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_forensic_cases_hash ON forensic_cases(evidence_hash);
            CREATE INDEX IF NOT EXISTS idx_forensic_cases_created ON forensic_cases(created_at DESC);
        """)
        conn.commit()
        cur.close()
        conn.close()
        print("[+] [DB] Verified/created 'forensic_cases' table.")
    except Exception as e:
        print(f"[-] [DB] Note initializing forensic_cases table: {e}")

try:
    ensure_forensic_case_table()
except Exception as e:
    print(f"[-] [DB] Initialization warning: {e}")

def persist_forensic_case(case_id: str, dossier: dict, raw_eml: str = "") -> str:
    """Stores case in in-memory cache and PostgreSQL database"""
    FORENSIC_CASE_CACHE[case_id] = {
        "case_id": case_id,
        "dossier": dossier,
        "raw_eml": raw_eml,
        "created_at": datetime.utcnow().isoformat()
    }
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        evidence_hash = dossier.get("evidence_hash_sha256", "")
        verdict = dossier.get("verdict", "UNKNOWN")
        threat_score = float(dossier.get("overall_threat_score", 0.0))
        meta = dossier.get("metadata", {})
        sender = (meta.get("from", "") or "")[:250]
        subject = (meta.get("subject", "") or "")[:490]
        dossier_str = json.dumps(dossier)
        
        cur.execute("""
            INSERT INTO forensic_cases (case_id, evidence_hash, verdict, threat_score, sender, subject, dossier_json, raw_eml, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (case_id) DO UPDATE SET
                evidence_hash = EXCLUDED.evidence_hash,
                verdict = EXCLUDED.verdict,
                threat_score = EXCLUDED.threat_score,
                sender = EXCLUDED.sender,
                subject = EXCLUDED.subject,
                dossier_json = EXCLUDED.dossier_json,
                raw_eml = EXCLUDED.raw_eml,
                created_at = EXCLUDED.created_at;
        """, (case_id, evidence_hash, verdict, threat_score, sender, subject, dossier_str, raw_eml, datetime.utcnow()))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[-] [DB] Error storing case {case_id}: {e}")
        
    return case_id

def retrieve_forensic_case(case_id: str):
    """Retrieves case by case_id from in-memory cache or PostgreSQL"""
    if case_id in FORENSIC_CASE_CACHE:
        return FORENSIC_CASE_CACHE[case_id]
        
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT case_id, evidence_hash, verdict, threat_score, sender, subject, dossier_json, raw_eml, created_at FROM forensic_cases WHERE case_id = %s", (case_id,))
        row = cur.fetchone()
        cur.close()
        conn.close()
        if row:
            dossier = json.loads(row[6]) if isinstance(row[6], str) else row[6]
            case_data = {
                "case_id": row[0],
                "evidence_hash": row[1],
                "verdict": row[2],
                "threat_score": row[3],
                "sender": row[4],
                "subject": row[5],
                "dossier": dossier,
                "raw_eml": row[7] or "",
                "created_at": row[8].isoformat() if row[8] else ""
            }
            FORENSIC_CASE_CACHE[case_id] = case_data
            return case_data
    except Exception as e:
        print(f"[-] [DB] Error retrieving case {case_id}: {e}")
        
    return None

def retrieve_case_by_hash(evidence_hash: str):
    """Retrieves case by SHA-256 evidence hash from database or cache"""
    clean_hash = (evidence_hash or "").strip().lower()
    if not clean_hash:
        return None
        
    for c_id, c_data in FORENSIC_CASE_CACHE.items():
        h = c_data.get("dossier", {}).get("evidence_hash_sha256", "").lower()
        if h == clean_hash or c_data.get("evidence_hash", "").lower() == clean_hash:
            return c_data
            
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT case_id, evidence_hash, verdict, threat_score, sender, subject, dossier_json, raw_eml, created_at 
            FROM forensic_cases 
            WHERE LOWER(evidence_hash) = %s 
            LIMIT 1
        """, (clean_hash,))
        row = cur.fetchone()
        cur.close()
        conn.close()
        if row:
            dossier = json.loads(row[6]) if isinstance(row[6], str) else row[6]
            case_data = {
                "case_id": row[0],
                "evidence_hash": row[1],
                "verdict": row[2],
                "threat_score": row[3],
                "sender": row[4],
                "subject": row[5],
                "dossier": dossier,
                "raw_eml": row[7] or "",
                "created_at": row[8].isoformat() if row[8] else ""
            }
            FORENSIC_CASE_CACHE[row[0]] = case_data
            return case_data
    except Exception as e:
        print(f"[-] [DB] Error retrieving case by hash {clean_hash}: {e}")
        
    return None

def list_all_forensic_cases(limit: int = 50):
    """Lists recent forensic cases from database or in-memory cache"""
    cases = []
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT case_id, evidence_hash, verdict, threat_score, sender, subject, created_at 
            FROM forensic_cases 
            ORDER BY created_at DESC 
            LIMIT %s
        """, (limit,))
        for row in cur.fetchall():
            cases.append({
                "case_id": row[0],
                "evidence_hash": row[1] or "",
                "verdict": row[2] or "ANALYZED",
                "threat_score": float(row[3] or 0.0),
                "sender": row[4] or "",
                "subject": row[5] or "",
                "created_at": row[6].isoformat() if row[6] else ""
            })
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[-] [DB] Error listing cases: {e}")
        for c_id, c_data in sorted(FORENSIC_CASE_CACHE.items(), key=lambda x: x[1].get("created_at", ""), reverse=True)[:limit]:
            d = c_data.get("dossier", {})
            m = d.get("metadata", {})
            cases.append({
                "case_id": c_id,
                "evidence_hash": d.get("evidence_hash_sha256", c_data.get("evidence_hash", "")),
                "verdict": d.get("verdict", c_data.get("verdict", "ANALYZED")),
                "threat_score": float(d.get("overall_threat_score", c_data.get("threat_score", 0.0))),
                "sender": m.get("from", c_data.get("sender", "")),
                "subject": m.get("subject", c_data.get("subject", "")),
                "created_at": c_data.get("created_at", "")
            })
    return cases

# ==================== ROUTES ====================

def is_short_url(url):
    """Check if URL is from a known URL shortening service"""
    short_url_domains = [
        'tinyurl.com', 'bit.ly', 'bitly.com', 'short.link', 'ow.ly', 
        'goo.gl', 't.co', 'tco.cc', 'tr.im', 'adf.ly', 'buff.ly',
        'is.gd', 'tiny.cc', 'cur.lv', 'easyurl.net', 'ely.by',
        'sh.st', 'shorte.st', 'go.theregister.com', 't.ly', 'shorturl.at',
        'short.onl', 'smarturl.it', 'click.me', 'shortened.me', 'clck.ru'
    ]
    
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc.lower().replace('www.', '')
        return domain in short_url_domains
    except:
        return False

@app.route('/', methods=['GET', 'HEAD'])
@app.route('/health', methods=['GET', 'HEAD'])
@app.route('/healthz', methods=['GET', 'HEAD'])
def health_check():
    """Health check endpoint for Render and local environments"""
    return jsonify({"message": "TrustShield Backend is running", "status": "healthy"}), 200

@app.route('/portal')
@app.route('/portal/')
def serve_portal_index():
    """Serves the SOC Analyst Web Portal"""
    from flask import send_from_directory
    frontend_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend")
    resp = send_from_directory(frontend_dir, "index.html")
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return resp

@app.route('/portal/<path:filename>')
@app.route('/app.js')
@app.route('/index.html')
def serve_portal_assets(filename='app.js'):
    """Serves static assets for the SOC Analyst Web Portal"""
    from flask import send_from_directory
    frontend_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend")
    target = 'app.js' if request.path == '/app.js' else ('index.html' if request.path == '/index.html' else filename)
    resp = send_from_directory(frontend_dir, target)
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return resp



@app.route('/api/brands/official', methods=['GET'])
def get_official_brands():
    """Return all official brands for the Android app to cache"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT name, primary_domain, aliases, trusted_subdomains, trusted_cdns FROM official_brands")
        brands = []
        for row in cur.fetchall():
            brands.append({
                "name": row[0],
                "primaryDomain": row[1],
                "aliases": row[2] if isinstance(row[2], list) else json.loads(row[2] or '[]'),
                "trustedSubdomains": row[3] if isinstance(row[3], list) else json.loads(row[3] or '[]'),
                "trustedCdns": row[4] if isinstance(row[4], list) else json.loads(row[4] or '[]')
            })
        cur.close()
        conn.close()
        return jsonify({"brands": brands}), 200
    except Exception as e:
        print(f"Error fetching official brands: {e}")
        return jsonify({"error": "Failed to fetch brands"}), 500

# ==================== AUTHENTICATION ENDPOINTS ====================

@app.route('/api/auth/register', methods=['POST'])
def register_user():
    """Register a new user"""
    try:
        data = request.get_json()
        
        # Validate input
        required_fields = ['name', 'last_name', 'email', 'phone_number', 'pin']
        if not all(field in data for field in required_fields):
            return jsonify({"error": "Missing required fields"}), 400
        
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Check if email already exists
        cur.execute("SELECT id FROM users WHERE email = %s", (data['email'],))
        if cur.fetchone():
            cur.close()
            conn.close()
            return jsonify({"error": "Email already registered"}), 400
        
        # Check if phone number already exists
        cur.execute("SELECT id FROM users WHERE phone_number = %s", (data['phone_number'],))
        if cur.fetchone():
            cur.close()
            conn.close()
            return jsonify({"error": "Phone number already registered"}), 400
        
        # Hash the PIN
        hashed_pin = hash_pin(data['pin'])
        
        # Insert user
        cur.execute(
            """INSERT INTO users (name, last_name, email, phone_number, pin, created_at, updated_at) 
               VALUES (%s, %s, %s, %s, %s, NOW(), NOW()) 
               RETURNING id, name, email, phone_number, created_at""",
            (data['name'], data['last_name'], data['email'], data['phone_number'], hashed_pin)
        )
        
        user = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        
        return jsonify({
            "id": user[0],
            "name": user[1],
            "email": user[2],
            "phone_number": user[3],
            "created_at": user[4].isoformat()
        }), 201
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login_user():
    """Login user with phone number and PIN"""
    try:
        data = request.get_json()
        
        if not data.get('phone_number') or not data.get('pin'):
            return jsonify({"error": "Missing phone_number or pin"}), 400
        
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Find user by phone number
        cur.execute("SELECT id, name, email, phone_number, pin FROM users WHERE phone_number = %s", 
                   (data['phone_number'],))
        user_row = cur.fetchone()
        
        if not user_row:
            cur.close()
            conn.close()
            return jsonify({"error": "Phone number not found"}), 401
        
        # Verify PIN
        if not verify_pin(data['pin'], user_row[4]):
            cur.close()
            conn.close()
            return jsonify({"error": "Incorrect PIN"}), 401
        
        cur.close()
        conn.close()
        
        return jsonify({
            "id": user_row[0],
            "name": user_row[1],
            "email": user_row[2],
            "phone_number": user_row[3],
            "message": "Login successful"
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==================== EXTENSION ENDPOINTS ====================

@app.route('/api/extension/analyze', methods=['POST', 'OPTIONS'])
def analyze_extension_email():
    """
    Endpoint for the TrustShield Chrome Extension.
    Accepts { subject, sender, body, links } and runs the Unified Forensic Pipeline.
    """
    if request.method == 'OPTIONS':
        return '', 200

    try:
        data = request.get_json() or {}
        subject = data.get('subject', '').strip()
        sender = data.get('sender', '').strip()
        body = data.get('body', '').strip()
        links = data.get('links', [])
        if isinstance(links, str):
            links = [links]

        if not subject and not body and not links:
            return jsonify({"error": "No content to analyze"}), 400

        # Synthesize standard RFC-5322 MIME envelope from webmail scrape with HTML parts containing links
        import random
        from datetime import datetime
        now_utc = datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S +0000")
        sender_domain = sender.split("@")[-1] if "@" in sender else "external-mail.net"
        boundary = f"----=_Part_Ext_{int(datetime.utcnow().timestamp())}_{random.randint(1000, 9999)}"
        
        # Build HTML links block so email_forensics.py parser extracts all hyperlinks
        html_links_tags = ""
        for url in links:
            html_links_tags += f'<p><a href="{url}">{url}</a></p>\n'

        eml_str = (
            f"Delivered-To: recipient.user@corporate.com\r\n"
            f"Received: from mail-relay.{sender_domain} (unknown [209.85.220.41])\r\n"
            f"\tby mx.google.com with ESMTP id a21si891024plm.12;\r\n"
            f"\t{now_utc}\r\n"
            f"Return-Path: <{sender or 'security-alert@external-mail.net'}>\r\n"
            f"From: {sender or 'Security Alert <security@external-mail.net>'}\r\n"
            f"To: recipient.user@corporate.com\r\n"
            f"Subject: {subject or 'Security Notification'}\r\n"
            f"Date: {now_utc}\r\n"
            f"Message-ID: <{int(datetime.utcnow().timestamp())}@{sender_domain}>\r\n"
            f"MIME-Version: 1.0\r\n"
            f"Content-Type: multipart/alternative; boundary=\"{boundary}\"\r\n\r\n"
            f"--{boundary}\r\n"
            f"Content-Type: text/plain; charset=UTF-8\r\n"
            f"Content-Transfer-Encoding: 7bit\r\n\r\n"
            f"{body}\r\n"
            + ("\n\nEmbedded URLs:\n" + "\n".join(links) if links else "") +
            f"\r\n\r\n"
            f"--{boundary}\r\n"
            f"Content-Type: text/html; charset=UTF-8\r\n"
            f"Content-Transfer-Encoding: 7bit\r\n\r\n"
            f"<html><body><div>{body}</div>\n{html_links_tags}</body></html>\r\n"
            f"--{boundary}--\r\n"
        )
        eml_bytes = eml_str.encode('utf-8')

        from core_engine.unified_email_pipeline import analyze_email_pipeline
        dossier = analyze_email_pipeline(eml_bytes, skip_link_sandbox=False)

        # Generate unique case ID and persist to database & memory cache
        case_id = f"TSF-{random.randint(100000, 999999)}"
        persist_forensic_case(case_id, dossier, eml_str)

        return jsonify({
            "status": "success",
            "case_id": case_id,
            "verdict": dossier.get("verdict"),
            "final_threat_score": dossier.get("overall_threat_score"),
            "text_verdict": dossier.get("threat_attribution", {}).get("type", "Analyzed"),
            "links_found": len(dossier.get("link_investigation", [])),
            "threat_attribution": dossier.get("threat_attribution", {}),
            "full_dossier": dossier,
            "raw_eml": eml_str
        }), 200

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# ==================== LINK SCAN ENDPOINTS ====================
@app.route('/api/sandbox-check', methods=['POST'])
def sandbox_check():
    """
    Tier 3: Sandbox check called by Android SandboxChecker.kt
    Executes V2 Link Threat Pipeline (Headless Sandbox + Meta-Classifier + Gemini)
    """
    try:
        print("\n" + "="*80)
        print("🔬 [API] /api/sandbox-check REQUEST RECEIVED")
        print("="*80)
        data = request.get_json(silent=True) or {}
        url = data.get('url', '').strip()
        print(f"   Target URL: {url}")
        sys.stdout.flush()
        
        if not url:
            return jsonify({
                "verdict": "UNKNOWN",
                "confidence": 0,
                "details": "Missing url in request body"
            }), 400
            
        print(f"🚀 [V2 LINK PIPELINE] Executing Deep Analysis on {url}...")
        sys.stdout.flush()
        pipeline = get_link_pipeline()
        pipeline_res = pipeline.analyze_url(url)
        v2_verdict = pipeline_res.get('verdict', 'SAFE')
        threat_score = int(pipeline_res.get('threat_score', 0))
        summary = pipeline_res.get('summary', '')
        
        if 'CRITICAL' in v2_verdict or 'PHISHING' in v2_verdict or 'DANGEROUS' in v2_verdict or threat_score >= 60:
            android_verdict = 'DANGEROUS'
            malicious_count = 1
            suspicious_count = 0
        elif 'SUSPICIOUS' in v2_verdict or threat_score >= 40:
            android_verdict = 'SUSPICIOUS'
            malicious_count = 0
            suspicious_count = 1
        else:
            android_verdict = 'SAFE'
            malicious_count = 0
            suspicious_count = 0
            
        print(f"✅ [TIER 3 SANDBOX RESULT] Verdict: {android_verdict} (Score: {threat_score})")
        sys.stdout.flush()
        
        return jsonify({
            "verdict": android_verdict,
            "confidence": threat_score,
            "details": summary or f"TrustShield V2 Pipeline: {v2_verdict} (Score: {threat_score}/100)",
            "summary": summary,
            "engines_count": 4,
            "malicious_count": malicious_count,
            "suspicious_count": suspicious_count
        }), 200
            
    except Exception as e:
        print(f"❌ [TIER 3 SANDBOX ERROR]: {e}")
        sys.stdout.flush()
        return jsonify({
            "verdict": "UNKNOWN",
            "confidence": 0,
            "details": f"Analysis failed: {str(e)}"
        }), 500

@app.route('/api/links/scan', methods=['POST'])
def save_link_scan():
    """
    Save a scanned link to database
    Tier 0: Check phishing database first for instant verdict
    """
    try:
        print("\n" + "="*80)
        print("🔔 [API] /api/links/scan REQUEST RECEIVED")
        print("="*80)
        
        data = request.get_json()
        url = data.get('url')
        user_id = data.get('user_id')
        
        print(f"📋 Request Data:")
        print(f"   User ID: {user_id}")
        print(f"   URL: {url}")
        print(f"   Risk Level: {data.get('risk_level')}")
        print(f"   Verdict: {data.get('verdict')}")
        print(f"   Reasons: {data.get('reasons')}")
        import sys
        sys.stdout.flush()
        
        if not user_id or not url:
            print(f"❌ Missing required fields")
            sys.stdout.flush()
            return jsonify({"error": "Missing user_id or url"}), 400
        
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Verify user exists
        cur.execute("SELECT id FROM users WHERE id = %s", (user_id,))
        user = cur.fetchone()
        if not user:
            cur.close()
            conn.close()
            print(f"❌ User {user_id} not found")
            sys.stdout.flush()
            return jsonify({"error": "User not found"}), 404
        
        print(f"✅ User {user_id} verified")
        sys.stdout.flush()
        
        # ===== TIER 0: Check phishing database =====
        print(f"🔍 [TIER 0] Checking phishing database for: {url}")
        sys.stdout.flush()
        
        is_phishing, threat_type, db_source = phishing_importer.check_url_in_database(url)
        is_short = is_short_url(url)  # Check if URL is shortener service
        
        print(f"   Short URL Service: {is_short}")
        sys.stdout.flush()
        
        # Initialize verdict from app
        verdict = data.get('verdict', 'SAFE')
        risk_level = data.get('risk_level', 'SAFE')
        reasons = data.get('reasons', 'Link analyzed')
        tier_analyzed = 'TIER_0'
        
        # Intercept Brand Abuse logic
        if verdict == 'DANGEROUS' and 'Abuses' in reasons and 'brand - This is fake' in reasons:
            try:
                # Extract brand name: "🔴 DANGEROUS: Abuses ChatGPT brand - This is fake"
                brand_name = reasons.split('Abuses ')[1].split(' brand')[0]
                from urllib.parse import urlparse
                domain_to_check = urlparse(url).netloc.lower().replace('www.', '')
                
                print(f"[DYNAMIC VERIFICATION] Android app flagged {domain_to_check} as abusing {brand_name}. Checking Clearbit...")
                is_official = verify_and_add_brand(brand_name, domain_to_check)
                if is_official:
                    verdict = 'SAFE'
                    risk_level = 'SAFE'
                    reasons = f"Dynamically verified {domain_to_check} as an official domain for {brand_name}"
                    print(f"   ✓ OVERRIDE: Clearbit confirmed {domain_to_check} is SAFE. Overriding Android app's verdict.")
            except Exception as e:
                print(f"Error during dynamic brand verification: {e}")
        
        
        if is_phishing and not is_short:
            # Found in database AND it's NOT a short URL → Trust database verdict (permanent URLs don't change)
            verdict = 'DANGEROUS'
            risk_level = 'DANGEROUS'
            reasons = f"Found in {db_source} phishing database ({threat_type})"
            tier_analyzed = 'TIER_0'
            print(f"⚠️  [TIER 0 MATCH] {url} is KNOWN PHISHING (Non-short URL)")
            print(f"   Source: {db_source}")
            print(f"   Threat Type: {threat_type}")
            print(f"   Verdict: DANGEROUS (trusted database, not a short URL)")
            sys.stdout.flush()
        elif is_phishing and is_short:
            # Found in database BUT it's a short URL → Don't trust database alone, run Tier 3
            # (because short URLs get reused and the real danger is in the destination)
            print(f"⚠️  [TIER 0 MATCH] {url} is in {db_source} database (phishing)")
            print(f"   Source: {db_source}")
            print(f"   Threat Type: {threat_type}")
            print(f"   BUT: This is a SHORT URL (can be reused/reassigned)")
            print(f"   ➡️  Proceeding to Tier 3 to analyze final destination...")
            verdict = 'SUSPICIOUS'  # Force Tier 3 analysis
            risk_level = 'SUSPICIOUS'
            reasons = f"Short URL found in {db_source} database - requires Tier 3 verification"
            sys.stdout.flush()
        else:
            print(f"✓ [TIER 0] No match in phishing database - Using app verdict: {verdict}")
            sys.stdout.flush()
        
        # ===== TRUSTSHIELD V2 UNIFIED PIPELINE (Heuristics -> ThreatDB -> VirusTotal -> Sandbox -> MetaClassifier & Gemini) =====
        is_official = 'Verified official domain' in str(reasons) or 'Dynamically verified' in str(reasons)
        
        print(f"\n🔬 [V2 PIPELINE] Running Multi-Modal Threat Pipeline on: {url}...")
        sys.stdout.flush()
        
        try:
            pipeline = get_link_pipeline()
            pipeline_res = pipeline.analyze_url(url)
            
            pipeline_verdict = pipeline_res.get('verdict', 'SAFE')
            threat_score = pipeline_res.get('threat_score', 0)
            gemini_summary = pipeline_res.get('summary', '')
            
            print(f"✅ [V2 PIPELINE COMPLETE] Verdict: {pipeline_verdict} (Threat Score: {threat_score}/100)")
            sys.stdout.flush()
            
            if 'CRITICAL' in pipeline_verdict or 'PHISHING' in pipeline_verdict or 'DANGEROUS' in pipeline_verdict or threat_score >= 60:
                verdict = 'DANGEROUS'
                risk_level = 'DANGEROUS'
            elif 'SUSPICIOUS' in pipeline_verdict or threat_score >= 40:
                verdict = 'SUSPICIOUS'
                risk_level = 'SUSPICIOUS'
            else:
                verdict = 'SAFE'
                risk_level = 'SAFE'
                
            reasons = gemini_summary if gemini_summary else f"TrustShield V2 Engine: {verdict} (Score: {threat_score}/100)"
            tier_analyzed = 'V2_LINK_PIPELINE'
            
        except Exception as e:
            print(f"❌ [V2 PIPELINE ERROR] Analysis failed: {str(e)}")
            sys.stdout.flush()
        
        sys.stdout.flush()
        
        # ===== DYNAMIC BRAND DISCOVERY =====
        # If the final verdict is SAFE (either from Tier 0/1 or after Sandbox analysis cleared it)
        # and it's not already a verified brand, check if Clearbit recognizes it
        if verdict == 'SAFE' and 'Verified official domain' not in reasons:
            try:
                from urllib.parse import urlparse
                domain_to_check = urlparse(url).netloc.lower().replace('www.', '')
                discovered_brand = discover_and_add_brand(domain_to_check)
                if discovered_brand:
                    # Update reasons to reflect discovery
                    reasons = f"Dynamically discovered and verified as official domain for {discovered_brand}"
                    print(f"   ✓ DYNAMIC DISCOVERY: Recognized as {discovered_brand}")
            except Exception as e:
                print(f"Error in dynamic brand discovery: {e}")
        
        # Insert link scan
        print(f"💾 [DB] Saving to database...")
        cur.execute(
            """INSERT INTO link_scans (user_id, url, risk_level, reasons, verdict, analyzed_at) 
               VALUES (%s, %s, %s, %s, %s, NOW()) 
               RETURNING id, user_id, url, risk_level, reasons, verdict, analyzed_at""",
            (user_id, url, risk_level, reasons, verdict)
        )
        
        scan = cur.fetchone()
        conn.commit()
            
        cur.close()
        conn.close()
        
        scan_id = scan[0]
        print(f"✅ [DB SUCCESS] Scan saved with ID: {scan_id}")
        print(f"   Verdict: {verdict}")
        print(f"   Risk Level: {risk_level}")
        print("="*80 + "\n")
        sys.stdout.flush()
        
        return jsonify({
            "id": scan_id,
            "user_id": scan[1],
            "url": scan[2],
            "risk_level": scan[3],
            "reasons": scan[4],
            "verdict": scan[5],
            "analyzed_at": scan[6].isoformat(),
            "tier_0_match": is_phishing,
            "tier_analyzed": tier_analyzed
        }), 201
        
    except Exception as e:
        import traceback
        print(f"❌ [ERROR] Exception in save_link_scan: {e}")
        print(traceback.format_exc())
        import sys
        sys.stdout.flush()
        return jsonify({"error": str(e)}), 500

@app.route('/api/links/explain', methods=['POST'])
def explain_link():
    """
    On-Demand / Detail View Gemini AI Forensic Report Generation
    Called when the user clicks on a link item in Android app or requests an AI forensic breakdown.
    """
    try:
        data = request.get_json(silent=True) or {}
        url = data.get('url', '').strip()
        scan_id = data.get('scan_id')
        
        if not url and not scan_id:
            return jsonify({"error": "Missing url or scan_id"}), 400
            
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Check if existing scan has Gemini summary in reasons
        existing_reasons = None
        existing_verdict = "DANGEROUS"
        existing_risk = "DANGEROUS"
        
        if scan_id:
            cur.execute("SELECT id, url, risk_level, reasons, verdict FROM link_scans WHERE id = %s", (scan_id,))
            row = cur.fetchone()
            if row:
                if not url:
                    url = row[1]
                existing_risk = row[2]
                existing_reasons = row[3]
                existing_verdict = row[4]
        elif url:
            cur.execute("SELECT id, url, risk_level, reasons, verdict FROM link_scans WHERE url = %s ORDER BY analyzed_at DESC LIMIT 1", (url,))
            row = cur.fetchone()
            if row:
                scan_id = row[0]
                existing_risk = row[2]
                existing_reasons = row[3]
                existing_verdict = row[4]
                
        # If existing reasons already contains a Gemini 3-bullet summary, return it immediately (< 5ms)
        if existing_reasons and ("• Threat Summary" in existing_reasons or "Threat Summary:" in existing_reasons):
            cur.close()
            conn.close()
            return jsonify({
                "status": "success",
                "url": url,
                "scan_id": scan_id,
                "verdict": existing_verdict or "SAFE",
                "threat_score": 90.0 if existing_verdict == "DANGEROUS" else (50.0 if existing_verdict == "SUSPICIOUS" else 0.0),
                "summary": existing_reasons
            }), 200
            
        # Otherwise, run link pipeline to synthesize fresh Gemini forensic report
        pipeline = get_link_pipeline()
        pipeline_res = pipeline.analyze_url(url)
        summary = pipeline_res.get("summary", "")
        threat_score = pipeline_res.get("threat_score", 0.0)
        verdict = pipeline_res.get("verdict", "SAFE")
        
        # Normalize verdict
        if "CRITICAL" in verdict or "PHISHING" in verdict or "DANGEROUS" in verdict or threat_score >= 60:
            norm_verdict = "DANGEROUS"
        elif "SUSPICIOUS" in verdict or threat_score >= 40:
            norm_verdict = "SUSPICIOUS"
        else:
            norm_verdict = "SAFE"
            
        # Update database record if scan_id exists
        if scan_id:
            cur.execute("UPDATE link_scans SET reasons = %s, verdict = %s, risk_level = %s WHERE id = %s",
                        (summary, norm_verdict, norm_verdict, scan_id))
            conn.commit()
        elif url:
            cur.execute("UPDATE link_scans SET reasons = %s, verdict = %s, risk_level = %s WHERE url = %s",
                        (summary, norm_verdict, norm_verdict, url))
            conn.commit()
            
        cur.close()
        conn.close()
        
        return jsonify({
            "status": "success",
            "url": url,
            "scan_id": scan_id,
            "verdict": norm_verdict,
            "threat_score": threat_score,
            "summary": summary
        }), 200
        
    except Exception as e:
        print(f"❌ [API EXPLAIN ERROR]: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route('/api/links/history/<int:user_id>', methods=['GET'])
def get_user_link_history(user_id):
    """Get all scanned links for a user"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Verify user exists
        cur.execute("SELECT id FROM users WHERE id = %s", (user_id,))
        if not cur.fetchone():
            cur.close()
            conn.close()
            return jsonify({"error": "User not found"}), 404
        
        # Get all scans but only the latest one per unique URL (Deduplication for UI)
        cur.execute(
            """WITH RankedScans AS (
                   SELECT id, user_id, url, risk_level, reasons, verdict, analyzed_at,
                          ROW_NUMBER() OVER(PARTITION BY url ORDER BY analyzed_at DESC) as rn
                   FROM link_scans 
                   WHERE user_id = %s
               )
               SELECT id, user_id, url, risk_level, reasons, verdict, analyzed_at 
               FROM RankedScans 
               WHERE rn = 1 
               ORDER BY analyzed_at DESC""",
            (user_id,)
        )
        
        scans = cur.fetchall()
        cur.close()
        conn.close()
        
        # Convert to dictionaries
        scan_list = []
        for scan in scans:
            scan_list.append({
                "id": scan[0],
                "user_id": scan[1],
                "url": scan[2],
                "risk_level": scan[3],
                "reasons": scan[4],
                "verdict": scan[5],
                "analyzed_at": scan[6].isoformat() if scan[6] else None
            })
        
        return jsonify({
            "user_id": user_id,
            "total_scans": len(scan_list),
            "scans": scan_list
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/health', methods=['GET'])
def api_health():
    """Health check for API"""
    return jsonify({"status": "healthy", "message": "Backend is running"}), 200

# ==================== PHISHING DATABASE ENDPOINTS ====================

@app.route('/api/phishing/check', methods=['POST'])
def check_phishing_url():
    """
    Check if a URL is in the phishing database
    Returns: {is_phishing: bool, threat_type: str, source: str}
    """
    try:
        data = request.get_json()
        url = data.get('url')
        
        if not url:
            return jsonify({"error": "Missing URL"}), 400
        
        is_phishing, threat_type, source = phishing_importer.check_url_in_database(url)
        
        return jsonify({
            "url": url,
            "is_phishing": is_phishing,
            "threat_type": threat_type,
            "source": source,
            "confidence": 1.0 if is_phishing else 0.0
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/phishing/samples', methods=['GET'])
def get_phishing_samples():
    """
    Get sample phishing URLs from database for testing
    Query params: limit (default 10), random (true/false)
    """
    try:
        limit = request.args.get('limit', 10, type=int)
        random_order = request.args.get('random', 'true').lower() == 'true'
        
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Get sample URLs
        order_clause = "ORDER BY RANDOM()" if random_order else "ORDER BY id DESC"
        cur.execute(f"""
            SELECT id, url, domain, threat_type, source, date_added
            FROM phishing_links
            {order_clause}
            LIMIT %s
        """, (limit,))
        
        samples = cur.fetchall()
        cur.close()
        conn.close()
        
        results = []
        for row in samples:
            results.append({
                "id": row[0],
                "url": row[1],
                "domain": row[2],
                "threat_type": row[3],
                "source": row[4],
                "date_added": row[5].isoformat() if row[5] else None
            })
        
        return jsonify({
            "total_returned": len(results),
            "samples": results,
            "note": "⚠️ These are KNOWN PHISHING URLs. Do NOT click them!"
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/phishing/import', methods=['POST'])
def import_phishing_manual():
    """
    Manually import phishing URLs
    Expects: {urls: [list of URLs], source: "manual", threat_type: "phishing"}
    """
    try:
        data = request.get_json()
        urls = data.get('urls', [])
        source = data.get('source', 'manual')
        threat_type = data.get('threat_type', 'phishing')
        
        if not urls:
            return jsonify({"error": "No URLs provided"}), 400
        
        inserted, updated = phishing_importer.store_phishing_urls(urls, source, threat_type)
        
        return jsonify({
            "message": "URLs imported successfully",
            "inserted": inserted,
            "updated": updated,
            "total": inserted + updated
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/phishing/import-feeds', methods=['POST'])
def import_phishing_feeds():
    """
    Trigger import from all available feeds
    (PhishTank, URLhaus, OpenPhish)
    """
    try:
        inserted, updated = phishing_importer.import_all_feeds()
        
        return jsonify({
            "message": "Feeds imported successfully",
            "inserted": inserted,
            "updated": updated,
            "total": inserted + updated
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/phishing/stats', methods=['GET'])
def phishing_database_stats():
    """Get statistics about phishing database"""
    try:
        stats = phishing_importer.get_database_stats()
        
        return jsonify({
            "total_urls": stats['total'],
            "by_threat_type": stats['by_threat_type'],
            "by_source": stats['by_source']
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ============================================================================
# GREEN-API WHATSAPP THREAT SIMULATION (HACKATHON DEMO)
# ============================================================================

GREEN_API_URL = os.getenv('GREEN_API_URL', 'https://7107.api.greenapi.com')
GREEN_API_ID_INSTANCE = os.getenv('GREEN_API_ID_INSTANCE', '710722716935')
GREEN_API_TOKEN_INSTANCE = os.getenv('GREEN_API_TOKEN_INSTANCE', '2b0cbefc3bfa4c43ae04961a61dc556ed69cc9e8c81c41d0b8')

def send_whatsapp_message(phone_number: str, message_text: str) -> bool:
    """Send a real WhatsApp message to a phone number using Green-API"""
    try:
        # Strip non-digits
        clean_digits = "".join(ch for ch in str(phone_number) if ch.isdigit())
        # If 10-digit Indian number without country code, add 91
        if len(clean_digits) == 10:
            clean_digits = f"91{clean_digits}"
        
        chat_id = f"{clean_digits}@c.us"
        endpoint = f"{GREEN_API_URL}/waInstance{GREEN_API_ID_INSTANCE}/sendMessage/{GREEN_API_TOKEN_INSTANCE}"
        
        payload = {
            "chatId": chat_id,
            "message": message_text
        }
        headers = {"Content-Type": "application/json"}
        
        print(f"📤 [Green-API] Dispatching message to {chat_id}...")
        resp = requests.post(endpoint, json=payload, headers=headers, timeout=15)
        print(f"✅ [Green-API] Response {resp.status_code}: {resp.text}")
        return resp.status_code == 200
    except Exception as e:
        print(f"❌ [Green-API] Error sending WhatsApp message: {e}")
        return False

def _run_hackathon_simulation_sequence(phone_number: str):
    """
    Executes the 2-message simulation sequence:
    1. Sends phishing attack: https://paypal-confirm.com
    2. Waits 15 seconds
    3. Sends verified safe link: https://www.amazon.in/
    """
    print(f"🚀 [Simulation] Starting live attack demo for phone: {phone_number}")
    
    # 1. First Message: Phishing Link
    phishing_message = (
        "🚨 [URGENT Security Alert] Your PayPal account access has been restricted due to suspicious login attempts.\n"
        "Please confirm your account identity immediately to prevent suspension:\n"
        "https://paypal-confirm.com"
    )
    send_whatsapp_message(phone_number, phishing_message)
    print("⏳ [Simulation] Message 1 (Phishing) dispatched! Waiting 15 seconds for Message 2...")
    
    # 2. Wait 15 seconds
    time.sleep(15)
    
    # 3. Second Message: Safe Link
    safe_message = (
        "🛒 [Amazon India Notification] Your exclusive deal recommendation is ready.\n"
        "Check out top deals and order status on Amazon:\n"
        "https://www.amazon.in/"
    )
    send_whatsapp_message(phone_number, safe_message)
    print("✅ [Simulation] Message 2 (Safe link) dispatched successfully!")

@app.route('/api/simulate/run', methods=['POST'])
def trigger_live_simulation():
    """
    Trigger Live Hackathon Demo Simulation:
    Sends phishing link (https://paypal-confirm.com), then waits 15 seconds and sends safe link (https://www.amazon.in/)
    """
    try:
        data = request.get_json() or {}
        phone_number = data.get('phone_number')
        
        if not phone_number:
            return jsonify({"error": "phone_number is required"}), 400
            
        # Run asynchronous background thread so client gets immediate HTTP 200
        threading.Thread(
            target=_run_hackathon_simulation_sequence, 
            args=(phone_number,), 
            daemon=True
        ).start()
        
        return jsonify({
            "status": "success",
            "message": "Live simulation triggered! Phishing link sent immediately; safe link arriving in 15 seconds.",
            "phone_number": phone_number,
            "phishing_link": "https://paypal-confirm.com",
            "safe_link": "https://www.amazon.in/"
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/forensics/analyze-eml', methods=['POST'])
def analyze_eml_endpoint():
    """
    Ingests an uploaded .eml file (multipart/form-data with 'file' or raw bytes),
    runs the Unified EML Forensic Orchestrator, and returns court-ready JSON telemetry
    with Leaflet route maps and overall threat verdicts.
    """
    try:
        eml_bytes = b""
        if 'file' in request.files:
            eml_bytes = request.files['file'].read()
        elif request.data:
            eml_bytes = request.data

        if not eml_bytes:
            return jsonify({"error": "No .eml file or data uploaded. Send as multipart/form-data ('file') or raw body."}), 400

        skip_sandbox = request.args.get('skip_sandbox', 'false').lower() in ('true', '1')
        from core_engine.unified_email_pipeline import analyze_email_pipeline
        result = analyze_email_pipeline(eml_bytes, skip_link_sandbox=skip_sandbox)
        
        # Persist case to database and in-memory cache
        import random
        case_id = f"TSF-{random.randint(100000, 999999)}"
        eml_text = eml_bytes.decode('utf-8', errors='replace')
        persist_forensic_case(case_id, result, eml_text)
        result["case_id"] = case_id

        return jsonify(result), 200

    except Exception as e:
        print(f"❌ [Forensics API] Error processing .eml: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/forensics/case/<case_id>', methods=['GET'])
def get_forensic_case_by_id(case_id):
    """
    Retrieves a previously analyzed forensic incident dossier by Case ID.
    Enables seamless cross-origin loading from Chrome Extension into the SOC Portal.
    """
    try:
        clean_id = (case_id or "").strip()
        case_data = retrieve_forensic_case(clean_id)
        if not case_data:
            return jsonify({"error": f"Case ID '{case_id}' not found."}), 404
            
        return jsonify({
            "status": "success",
            "case_id": case_data["case_id"],
            "dossier": case_data["dossier"],
            "raw_eml": case_data.get("raw_eml", ""),
            "created_at": case_data.get("created_at", "")
        }), 200
    except Exception as e:
        print(f"❌ [Forensics Case Lookup] Error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/forensics/cases', methods=['GET'])
def get_all_forensic_cases():
    """
    Returns list of all registered forensic cases in the database vault
    for the SOC Analyst searchable case history view.
    """
    try:
        limit = int(request.args.get('limit', 50))
        cases = list_all_forensic_cases(limit=limit)
        return jsonify({
            "status": "success",
            "total": len(cases),
            "cases": cases
        }), 200
    except Exception as e:
        print(f"❌ [Forensics Cases List] Error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/forensics/verify-hash', methods=['POST'])
def verify_forensic_hash():
    """
    Verifies a SHA-256 hash or Case ID against the database vault.
    Returns cryptographic integrity and chain-of-custody verification.
    """
    try:
        data = request.get_json() or {}
        query = data.get('query', '').strip()
        if not query:
            return jsonify({"error": "Missing 'query' parameter (SHA-256 hash or Case ID)"}), 400

        case_data = None
        if query.upper().startswith("TSF-"):
            case_data = retrieve_forensic_case(query.upper())
        if not case_data:
            case_data = retrieve_case_by_hash(query)
        if not case_data:
            case_data = retrieve_forensic_case(query)

        if case_data:
            return jsonify({
                "status": "success",
                "matched": True,
                "integrity_verdict": "UNTAMPERED & AUTHENTIC",
                "judicial_compliance": "Section 63, Bharatiya Sakshya Adhiniyam (BSA, 2023) / Section 65B IEA",
                "case_id": case_data["case_id"],
                "evidence_hash": case_data.get("evidence_hash") or case_data.get("dossier", {}).get("evidence_hash_sha256", ""),
                "sender": case_data.get("sender", ""),
                "subject": case_data.get("subject", ""),
                "verdict": case_data.get("verdict", ""),
                "threat_score": case_data.get("threat_score", 0.0),
                "created_at": case_data.get("created_at", ""),
                "dossier": case_data.get("dossier", {}),
                "raw_eml": case_data.get("raw_eml", "")
            }), 200
        else:
            return jsonify({
                "status": "not_found",
                "matched": False,
                "integrity_verdict": "UNREGISTERED EVIDENCE HASH",
                "query": query,
                "message": "SHA-256 fingerprint not found in cryptographic vault. The file has not been ingested yet or was altered after seizure."
            }), 404
    except Exception as e:
        print(f"❌ [Hash Verification] Error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/forensics/verify-file', methods=['POST'])
def verify_forensic_file():
    """
    Ingests an uploaded evidence file, computes its SHA-256 hash live,
    and checks if it exists untampered in the database vault.
    """
    try:
        eml_bytes = b""
        if 'file' in request.files:
            eml_bytes = request.files['file'].read()
        elif request.data:
            eml_bytes = request.data

        if not eml_bytes:
            return jsonify({"error": "No file uploaded for tamper verification"}), 400

        import hashlib
        computed_hash = hashlib.sha256(eml_bytes).hexdigest()
        case_data = retrieve_case_by_hash(computed_hash)

        if case_data:
            return jsonify({
                "status": "success",
                "matched": True,
                "computed_hash": computed_hash,
                "integrity_verdict": "100% UNTAMPERED & AUTHENTIC",
                "judicial_compliance": "Sec. 63 Bharatiya Sakshya Adhiniyam (BSA, 2023)",
                "case_id": case_data["case_id"],
                "evidence_hash": case_data.get("evidence_hash") or computed_hash,
                "sender": case_data.get("sender", ""),
                "subject": case_data.get("subject", ""),
                "verdict": case_data.get("verdict", ""),
                "threat_score": case_data.get("threat_score", 0.0),
                "sealed_at": case_data.get("created_at", ""),
                "dossier": case_data.get("dossier", {}),
                "raw_eml": case_data.get("raw_eml", "")
            }), 200
        else:
            return jsonify({
                "status": "unregistered",
                "matched": False,
                "computed_hash": computed_hash,
                "integrity_verdict": "UNREGISTERED OR MODIFIED FILE",
                "message": "SHA-256 fingerprint not found in database. The file has either not been ingested yet or was modified after seizure."
            }), 200
    except Exception as e:
        print(f"❌ [File Verification] Error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/forensics/export-pdf', methods=['POST'])
def export_forensic_pdf_endpoint():
    """
    Exports a court-admissible forensic PDF dossier.
    Accepts either raw .eml file (multipart/form-data) OR pre-analyzed JSON dossier.
    Returns the binary PDF file for direct browser download.
    """
    try:
        from flask import send_file
        from core_engine.report_generator import generate_pdf_dossier
        import tempfile

        report_json = None
        if 'file' in request.files:
            eml_bytes = request.files['file'].read()
            from core_engine.unified_email_pipeline import analyze_email_pipeline
            report_json = analyze_email_pipeline(eml_bytes)
        elif request.is_json:
            report_json = request.get_json()

        if not report_json:
            return jsonify({"error": "No .eml file or JSON dossier provided"}), 400

        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp_pdf:
            tmp_path = tmp_pdf.name

        generate_pdf_dossier(report_json, output_path=tmp_path)
        evidence_hash = report_json.get("evidence_hash_sha256", "dossier")[:12]
        download_name = f"TrustShield_Forensic_Dossier_{evidence_hash}.pdf"

        return send_file(
            tmp_path,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=download_name
        )
    except Exception as e:
        print(f"❌ [Forensics PDF Export] Error: {e}")
        return jsonify({"error": str(e)}), 500



# ===========================================================================
# GRAPH CORRELATION ENDPOINTS
# ===========================================================================

@app.route('/api/graph', methods=['GET'])
def get_threat_graph():
    """
    Returns the current global threat infrastructure graph in D3.js format.
    Frontend can render this as a force-directed graph showing relationships
    between sender domains, IPs, ASNs, URLs, and email addresses.

    Query params:
        format: 'full' (default) | 'stats' — return only summary stats
    """
    try:
        from core_engine.graph_correlation import get_graph_d3_data, get_global_graph
        fmt = request.args.get('format', 'full')
        if fmt == 'stats':
            return jsonify({
                "status": "success",
                "stats": get_global_graph().get_stats()
            }), 200
        graph_data = get_graph_d3_data()
        return jsonify({
            "status": "success",
            "graph": graph_data
        }), 200
    except Exception as e:
        print(f"❌ [Graph API] Error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/graph/shared-infra', methods=['POST'])
def find_shared_infrastructure():
    """
    Given an IP or domain, returns all nodes sharing that infrastructure
    (campaign-level correlation — 'who else uses this server?').

    Body: { "ip": "1.2.3.4" } OR { "domain": "phish.com" }
    """
    try:
        from core_engine.graph_correlation import get_global_graph
        data = request.get_json() or {}
        ip = data.get('ip', '')
        domain = data.get('domain', '')
        if not ip and not domain:
            return jsonify({"error": "Provide 'ip' or 'domain' in request body"}), 400
        graph = get_global_graph()
        connected = graph.find_shared_infrastructure(target_ip=ip, target_domain=domain)
        return jsonify({
            "status": "success",
            "query": {"ip": ip, "domain": domain},
            "connected_nodes": connected,
            "total_connected": len(connected)
        }), 200
    except Exception as e:
        print(f"❌ [Graph Shared Infra] Error: {e}")
        return jsonify({"error": str(e)}), 500


# ===========================================================================
# CAMPAIGN CASE MANAGEMENT ENDPOINTS
# ===========================================================================

@app.route('/api/campaigns', methods=['GET'])
def get_all_campaigns():
    """
    Returns all incident campaigns grouped by shared infrastructure fingerprint.
    Used by the SOC portal Case Management Console.

    Query params:
        min_incidents: int (default 1) — filter campaigns with at least N incidents
        limit: int (default 50)
    """
    try:
        from core_engine.campaign_manager import get_case_manager
        min_inc = int(request.args.get('min_incidents', 1))
        limit = int(request.args.get('limit', 50))
        cm = get_case_manager()
        campaigns = cm.get_all_campaigns(min_incidents=min_inc)[:limit]
        stats = cm.get_stats()
        return jsonify({
            "status": "success",
            "stats": stats,
            "total": len(campaigns),
            "campaigns": campaigns
        }), 200
    except Exception as e:
        print(f"❌ [Campaigns API] Error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/campaigns/search', methods=['GET'])
def search_campaigns():
    """
    Searches campaigns by IP, domain, registrar, campaign name, or campaign ID.

    Query params:
        q: str — search query
    """
    try:
        from core_engine.campaign_manager import get_case_manager
        query = request.args.get('q', '').strip()
        cm = get_case_manager()
        results = cm.search_campaigns(query)
        return jsonify({
            "status": "success",
            "query": query,
            "total": len(results),
            "campaigns": results
        }), 200
    except Exception as e:
        print(f"❌ [Campaigns Search] Error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/campaigns/<campaign_id>', methods=['GET'])
def get_campaign_detail(campaign_id):
    """Returns full detail of a specific campaign including all incidents."""
    try:
        from core_engine.campaign_manager import get_case_manager
        camp = get_case_manager().get_campaign(campaign_id)
        if not camp:
            return jsonify({"error": f"Campaign '{campaign_id}' not found"}), 404
        return jsonify({"status": "success", "campaign": camp}), 200
    except Exception as e:
        print(f"❌ [Campaign Detail] Error: {e}")
        return jsonify({"error": str(e)}), 500


# ===========================================================================
# STANDALONE NLP / BEC ANALYSIS ENDPOINT
# ===========================================================================

@app.route('/api/forensics/nlp-analyze', methods=['POST'])
def nlp_analyze_text():
    """
    Standalone NLP & BEC analysis on raw email text.
    Classifies into 5-class taxonomy: LEGITIMATE / SUSPICIOUS / IMPERSONATED / PHISHING / BEC_FRAUD
    Useful for quick body-text checks without uploading a full .eml file.

    Body (JSON): { "subject": "...", "body": "...", "sender": "..." }
    """
    try:
        from core_engine.bec_nlp_analyser import analyse_email_body
        data = request.get_json() or {}
        subject = data.get('subject', '')
        body = data.get('body', '')
        sender = data.get('sender', '')

        if not subject and not body:
            return jsonify({"error": "Provide at least 'subject' or 'body' in request body"}), 400

        result = analyse_email_body(
            subject=subject,
            body=body,
            sender_display_name=sender
        )
        return jsonify({
            "status": "success",
            "nlp_analysis": result
        }), 200
    except Exception as e:
        print(f"❌ [NLP Analyze] Error: {e}")
        return jsonify({"error": str(e)}), 500


# ===========================================================================
# STANDALONE WHOIS LOOKUP ENDPOINT
# ===========================================================================

@app.route('/api/forensics/whois', methods=['GET', 'POST'])
def whois_lookup_endpoint():
    """
    Performs WHOIS & domain intelligence lookup on any domain.
    Returns domain age, registrar, privacy shield status, DNS anomalies,
    and a WHOIS risk score (0-100).

    Body (JSON) or Query: { "domain": "phish.example.com" } or ?domain=phish.example.com
    """
    try:
        from core_engine.whois_intel import lookup_whois
        if request.method == 'POST':
            data = request.get_json(silent=True) or {}
            domain = data.get('domain', '') or request.args.get('domain', '')
        else:
            domain = request.args.get('domain', '')
        domain = domain.strip().lower()
        if not domain:
            return jsonify({"error": "Provide 'domain' via query param or JSON body"}), 400

        # Strip protocol if accidentally included
        domain = domain.replace('https://', '').replace('http://', '').split('/')[0]

        result = lookup_whois(domain)
        return jsonify({
            "status": "success",
            "whois_intelligence": result
        }), 200
    except Exception as e:
        print(f"❌ [WHOIS Lookup] Error: {e}")
        return jsonify({"error": str(e)}), 500


# ===========================================================================
# STANDALONE ATTACHMENT ANALYSIS ENDPOINT
# ===========================================================================

@app.route('/api/forensics/attachment-check', methods=['POST'])
def attachment_check_endpoint():
    """
    Analyses attachments in an uploaded .eml file for dangerous file types:
    executables, macro-enabled Office documents, archive wrappers,
    double-extension camouflage, and MIME/extension mismatches.

    Upload: multipart/form-data with 'file' field containing the .eml
    """
    try:
        from core_engine.attachment_analyser import analyse_attachments
        if 'file' not in request.files:
            return jsonify({"error": "Upload .eml as multipart/form-data with key 'file'"}), 400

        eml_bytes = request.files['file'].read()
        if not eml_bytes:
            return jsonify({"error": "Uploaded file is empty"}), 400

        result = analyse_attachments(eml_bytes)
        return jsonify({
            "status": "success",
            "attachment_analysis": result
        }), 200
    except Exception as e:
        print(f"❌ [Attachment Check] Error: {e}")
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=False)






