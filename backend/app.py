from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg
import bcrypt
import os
from dotenv import load_dotenv
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from phishing_feed import PhishingFeedImporter
from sandbox_analyzer import SandboxAnalyzer
import atexit
import sys

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

print(f"🔌 Connecting to database: {DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['dbname']}")

# Initialize phishing feed importer (Tier 0)
phishing_importer = PhishingFeedImporter()

# Initialize Tier 3 Sandbox Analyzer
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
if VIRUSTOTAL_API_KEY:
    sandbox_analyzer = SandboxAnalyzer(VIRUSTOTAL_API_KEY)
    print(f"✅ VirusTotal Tier 3 Sandbox Analyzer initialized")
    print(f"   API Key: {VIRUSTOTAL_API_KEY[:30]}..." if len(VIRUSTOTAL_API_KEY) > 30 else f"   API Key found")
    sys.stdout.flush()
else:
    sandbox_analyzer = None
    print(f"❌ VirusTotal API key NOT found in environment - Tier 3 analysis DISABLED")
    print(f"   Add VIRUSTOTAL_API_KEY to .env file")
    sys.stdout.flush()

sys.stdout.flush()

# Initialize background scheduler for auto-fetching phishing data
scheduler = BackgroundScheduler()

def schedule_phishing_import():
    """Scheduled job to import phishing feeds"""
    print("📥 [Scheduler] Running phishing feed import...")
    try:
        inserted, updated = phishing_importer.import_all_feeds()
        print(f"✅ [Scheduler] Phishing import complete: {inserted} new, {updated} updated")
    except Exception as e:
        print(f"❌ [Scheduler] Error importing phishing feeds: {e}")

# Schedule to run every 6 hours
scheduler.add_job(
    func=schedule_phishing_import,
    trigger="interval",
    hours=6,
    id='phishing_feed_job',
    name='Import phishing feeds',
    replace_existing=True
)

# Start scheduler
if not scheduler.running:
    scheduler.start()
    print("✅ Phishing feed scheduler started (runs every 6 hours)")

# Shut down the scheduler when exiting the app
atexit.register(lambda: scheduler.shutdown())

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

@app.route('/', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({"message": "TrustShield Backend is running", "status": "healthy"}), 200

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

# ==================== LINK SCAN ENDPOINTS ====================

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
        
        # ===== TIER 3: Sandbox Analysis =====
        # Run Tier 3 if:
        # 1. App verdict is SUSPICIOUS, OR
        # 2. Found in database as phishing AND it's a short URL (need to check final destination)
        should_run_tier3 = (verdict == 'SUSPICIOUS') and sandbox_analyzer
        
        if should_run_tier3:
            print(f"\n🔬 [TIER 3] Running sandbox analysis...")
            sys.stdout.flush()
            
            try:
                sandbox_result = sandbox_analyzer.analyze_url(url)
                
                sandbox_verdict = sandbox_result.get('verdict', 'SAFE')
                sandbox_score = sandbox_result.get('score', 0)
                sandbox_confidence = sandbox_result.get('confidence', 0)
                
                print(f"\n✅ [TIER 3 COMPLETE] Sandbox verdict: {sandbox_verdict} (Score: {sandbox_score}, Confidence: {sandbox_confidence}%)")
                sys.stdout.flush()
                
                # Tier 3 is final - it overrides Tier 0 and Tier 1
                if sandbox_verdict == 'DANGEROUS':
                    verdict = 'DANGEROUS'
                    risk_level = 'DANGEROUS'
                    if is_phishing and is_short:
                        reasons = f"Tier 0: Found in {db_source} database. Tier 3: CONFIRMED PHISHING via sandbox analysis (Score: {sandbox_score}/100, Confidence: {sandbox_confidence}%)"
                    else:
                        reasons = f"Sandbox analysis detected phishing (Score: {sandbox_score}/100, Confidence: {sandbox_confidence}%)"
                    tier_analyzed = 'TIER_3'
                    print(f"   🚨 VERDICT: DANGEROUS - Confirmed by Tier 3 analysis")
                elif sandbox_verdict == 'SUSPICIOUS':
                    verdict = 'SUSPICIOUS'
                    risk_level = 'SUSPICIOUS'
                    if is_phishing and is_short:
                        reasons = f"Tier 0: Short URL in {db_source} database. Tier 3: Analysis is SUSPICIOUS (Score: {sandbox_score}/100, Confidence: {sandbox_confidence}%)"
                    else:
                        reasons = f"Sandbox analysis: SUSPICIOUS (Score: {sandbox_score}/100, Confidence: {sandbox_confidence}%)"
                    tier_analyzed = 'TIER_3'
                    print(f"   ⚠️  VERDICT: SUSPICIOUS - Based on Tier 3 analysis")
                else:
                    # Sandbox says SAFE
                    verdict = 'SAFE'
                    risk_level = 'SAFE'
                    if is_phishing and is_short:
                        reasons = f"Tier 0: Short URL in {db_source} database (old/reused entry). Tier 3: Destination is SAFE (Score: {sandbox_score}/100, Confidence: {sandbox_confidence}%)"
                        print(f"   ✓ OVERRIDE: Short URL was in database but points to SAFE destination")
                    else:
                        reasons = f"Sandbox analysis cleared URL (Score: {sandbox_score}/100, Confidence: {sandbox_confidence}%)"
                    tier_analyzed = 'TIER_3'
                    print(f"   ✓ VERDICT: SAFE - Tier 3 analysis confirms safe")
                
                sys.stdout.flush()
                
            except Exception as e:
                print(f"❌ [TIER 3 ERROR] Sandbox analysis failed: {str(e)}")
                if is_phishing and is_short:
                    # Tier 3 failed but we can't trust database alone for short URLs
                    # Keep as SUSPICIOUS to be safe
                    verdict = 'SUSPICIOUS'
                    risk_level = 'SUSPICIOUS'
                    reasons = f"Tier 0: Short URL in {db_source} database. Tier 3 verification failed: {str(e)}"
                    tier_analyzed = 'TIER_0'
                    print(f"   ⚠️  VERDICT: SUSPICIOUS - Tier 3 failed but database entry is unreliable for short URLs")
                else:
                    print(f"   Keeping original verdict: {verdict}")
                sys.stdout.flush()
        elif verdict == 'SUSPICIOUS' and not sandbox_analyzer:
            print(f"⚠️  [TIER 3] Sandbox analyzer not available (check VirusTotal API key)")
            print(f"   Keeping verdict as SUSPICIOUS")
            sys.stdout.flush()
        
        sys.stdout.flush()
        
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
        
        # Get all scans
        cur.execute(
            """SELECT id, user_id, url, risk_level, reasons, verdict, analyzed_at 
               FROM link_scans WHERE user_id = %s 
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
