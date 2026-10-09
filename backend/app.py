import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

import werkzeug
if not hasattr(werkzeug, '__version__'):
    werkzeug.__version__ = "3.0.0"

from flask import Flask, request, jsonify, g
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.exceptions import HTTPException

import psycopg
import bcrypt
import os
from dotenv import load_dotenv
from datetime import datetime, timezone
from apscheduler.schedulers.background import BackgroundScheduler
from phishing_feed import PhishingFeedImporter
from core_engine.link_threat_pipeline import get_link_pipeline
import atexit
import sys
from brand_verification import verify_and_add_brand, discover_and_add_brand
import json
import logging
import re
import secrets
import threading
import time
import copy
from contextlib import contextmanager

# Load environment variables
load_dotenv()

from security import (
    IS_PRODUCTION, require_auth, optional_auth, require_admin, rate_limit, issue_token,
    is_locked_out, record_login_failure, clear_login_failures, server_error,
    sanitize_header_value, is_valid_pin, is_valid_phone, is_valid_email
)
import evidence_seal
from core_engine.url_safety import is_public_url

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

# Initialize Flask app
app = Flask(__name__)
# Trust exactly one proxy hop (Render/Fly/Railway) so request.remote_addr is the real client IP
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("MAX_UPLOAD_BYTES", str(10 * 1024 * 1024)))

@app.errorhandler(HTTPException)
def handle_http_exception(exc):
    """Every framework-level error (404, 405, 413 ...) is returned as JSON with its real status code."""
    return server_error(exc)


class _QuietPolling(logging.Filter):
    """The phone polls scan progress every second; keep those routine lines out of the terminal so the [SCAN] lines
    (what the pipeline is actually doing) stay readable."""
    NOISY = ("GET /api/links/scan-jobs/", "GET /api/links/history/", "GET /health")

    def filter(self, record):
        message = record.getMessage()
        return not any(n in message for n in self.NOISY)


logging.getLogger("werkzeug").addFilter(_QuietPolling())

# CORS: only the portal origins, the Chrome extension and local development
_default_origins = "https://akhilash-sk.github.io,http://localhost:3000,http://localhost:5173,http://localhost:8000,http://127.0.0.1:8000"
def parse_cors_origins(raw):
    """
    Accepts 'a,b' or a JSON-style list '["a", "b"]'. Entries that are not valid patterns are dropped, because a single
    broken entry would otherwise make every browser request fail inside the CORS layer.
    """
    raw = (raw or "").strip()
    if raw.startswith("["):
        try:
            items = json.loads(raw)
        except ValueError:
            items = raw.strip("[]").split(",")
    else:
        items = raw.split(",")
    origins = []
    for item in items:
        origin = str(item).strip().strip("'\"").strip()
        if not origin:
            continue
        try:
            re.compile(origin)
        except re.error:
            logging.getLogger("trustshield.security").warning("Ignoring invalid CORS origin %r", origin)
            continue
        origins.append(origin)
    return origins


_cors_origins = parse_cors_origins(os.getenv("CORS_ORIGINS", _default_origins))
_cors_origins.append(r"chrome-extension://.*")
CORS(app, origins=_cors_origins, allow_headers=["Content-Type", "Authorization", "X-Admin-Key"])

# Database configuration
from db_config import DB_CONFIG

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

def start_feed_sync():
    """Keep the phishing database fed: one import right now (background thread), then every 6 hours."""
    if not scheduler.running:
        scheduler.start()
        print("[+] Phishing feed scheduler started (runs every 6 hours)")
    threading.Thread(target=schedule_phishing_import, daemon=True, name="phishing-first-import").start()


# Gunicorn forks workers, so there the scheduler is opt-in (ENABLE_SCHEDULER=true); a plain `python app.py`
# starts it by default (see the bottom of this file).
if os.environ.get("ENABLE_SCHEDULER", "false").lower() == "true":
    start_feed_sync()

# Shut down the scheduler when exiting the app
atexit.register(lambda: scheduler.shutdown(wait=False) if scheduler.running else None)

# Helper functions
def get_db_connection():
    """Get database connection"""
    return psycopg.connect(**DB_CONFIG)

@contextmanager
def db_cursor():
    """Open a connection + cursor, commit on success, roll back on error, always close."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def hash_pin(pin):
    """Hash PIN using bcrypt"""
    return bcrypt.hashpw(pin.encode(), bcrypt.gensalt()).decode()

def verify_pin(plain_pin, hashed_pin):
    """Verify PIN against hash"""
    return bcrypt.checkpw(plain_pin.encode(), hashed_pin.encode())

# ---------------------------------------------------------------------------
# Forensic case vault (sealed, insert-only)
# ---------------------------------------------------------------------------
from collections import OrderedDict

FORENSIC_CASE_CACHE = OrderedDict()   # small LRU in front of the database
_CASE_CACHE_MAX = 200

CASE_COLUMNS = ("case_id, evidence_hash, verdict, threat_score, sender, subject, dossier_json, "
                "created_at, owner_user_id, signature, sealed_at")


def _cache_put(case_id, case_data):
    FORENSIC_CASE_CACHE[case_id] = case_data
    FORENSIC_CASE_CACHE.move_to_end(case_id)
    while len(FORENSIC_CASE_CACHE) > _CASE_CACHE_MAX:
        FORENSIC_CASE_CACHE.popitem(last=False)


def new_case_id() -> str:
    return "TSF-" + secrets.token_hex(8).upper()


def ensure_forensic_case_table():
    """Ensures the forensic_cases table exists with sealing columns"""
    try:
        with db_cursor() as cur:
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
                ALTER TABLE forensic_cases ADD COLUMN IF NOT EXISTS owner_user_id INTEGER;
                ALTER TABLE forensic_cases ADD COLUMN IF NOT EXISTS signature VARCHAR(64);
                ALTER TABLE forensic_cases ADD COLUMN IF NOT EXISTS sealed_at VARCHAR(40);
                ALTER TABLE forensic_cases ADD COLUMN IF NOT EXISTS raw_eml_bytes BYTEA;
                CREATE INDEX IF NOT EXISTS idx_forensic_cases_hash ON forensic_cases(evidence_hash);
                CREATE INDEX IF NOT EXISTS idx_forensic_cases_created ON forensic_cases(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_forensic_cases_owner ON forensic_cases(owner_user_id);
            """)
        print("[+] [DB] Verified/created 'forensic_cases' table.")
    except Exception as e:
        print(f"[-] [DB] Note initializing forensic_cases table: {e}")

try:
    ensure_forensic_case_table()
except Exception as e:
    print(f"[-] [DB] Initialization warning: {e}")


def persist_forensic_case(case_id: str, dossier: dict, raw_bytes: bytes = b"", owner_user_id=None) -> dict:
    """
    Seals and stores a case (insert-only). Raises if the database write fails so the
    caller never hands out a case id that is not durably stored.
    Returns the stored case record (without raw bytes).
    """
    if isinstance(raw_bytes, str):
        raw_bytes = raw_bytes.encode("utf-8")
    raw_bytes = raw_bytes or b""

    evidence_hash = evidence_seal.sha256_hex(raw_bytes)
    dossier["evidence_hash_sha256"] = evidence_hash
    dossier_json = evidence_seal.canonical_json(dossier)
    sealed_at = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    signature = evidence_seal.seal(case_id, evidence_hash, dossier_json, sealed_at)

    meta = dossier.get("metadata", {}) or {}
    verdict = str(dossier.get("verdict", "UNKNOWN"))[:100]
    threat_score = float(dossier.get("overall_threat_score", 0.0) or 0.0)
    sender = (meta.get("from", "") or "")[:250]
    subject = (meta.get("subject", "") or "")[:490]
    created_at = datetime.now(timezone.utc).replace(tzinfo=None)

    with db_cursor() as cur:
        cur.execute("""
            INSERT INTO forensic_cases
                (case_id, evidence_hash, verdict, threat_score, sender, subject, dossier_json,
                 raw_eml_bytes, created_at, owner_user_id, signature, sealed_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (case_id, evidence_hash, verdict, threat_score, sender, subject, dossier_json,
              raw_bytes, created_at, owner_user_id, signature, sealed_at))

    record = _build_case_record((case_id, evidence_hash, verdict, threat_score, sender, subject,
                                 dossier_json, created_at, owner_user_id, signature, sealed_at))
    _cache_put(case_id, record)
    return record


def _build_case_record(row) -> dict:
    """Builds a case record from a DB row and re-verifies its seal on every read."""
    (case_id, evidence_hash, verdict, threat_score, sender, subject, dossier_json,
     created_at, owner_user_id, signature, sealed_at) = row
    dossier = json.loads(dossier_json) if isinstance(dossier_json, str) else dossier_json
    if not signature:
        status = "NOT SEALED"
    elif evidence_seal.verify_seal(case_id, evidence_hash, dossier_json, sealed_at or "", signature):
        status = "VERIFIED"
    else:
        status = "TAMPERED"
    dossier["integrity"] = evidence_seal.integrity_block(status, signature, sealed_at)
    return {
        "case_id": case_id,
        "evidence_hash": evidence_hash,
        "verdict": verdict,
        "threat_score": float(threat_score or 0.0),
        "sender": sender,
        "subject": subject,
        "dossier": dossier,
        "created_at": (created_at.isoformat() if hasattr(created_at, "isoformat") else str(created_at or "")),
        "owner_user_id": owner_user_id,
        "integrity_status": status,
    }


def retrieve_forensic_case(case_id: str):
    """Retrieves a case by id from the LRU cache or PostgreSQL"""
    if case_id in FORENSIC_CASE_CACHE:
        FORENSIC_CASE_CACHE.move_to_end(case_id)
        return FORENSIC_CASE_CACHE[case_id]
    try:
        with db_cursor() as cur:
            cur.execute(f"SELECT {CASE_COLUMNS} FROM forensic_cases WHERE case_id = %s", (case_id,))
            row = cur.fetchone()
        if row:
            record = _build_case_record(row)
            _cache_put(case_id, record)
            return record
    except Exception as e:
        print(f"[-] [DB] Error retrieving case {case_id}: {e}")
    return None


def retrieve_case_by_hash(evidence_hash: str):
    """Retrieves a case by the SHA-256 of the original evidence file"""
    clean_hash = (evidence_hash or "").strip().lower()
    if len(clean_hash) != 64:
        return None
    try:
        with db_cursor() as cur:
            cur.execute(f"SELECT {CASE_COLUMNS} FROM forensic_cases WHERE LOWER(evidence_hash) = %s "
                        "ORDER BY created_at ASC LIMIT 1", (clean_hash,))
            row = cur.fetchone()
        if row:
            return _build_case_record(row)
    except Exception as e:
        print(f"[-] [DB] Error retrieving case by hash: {e}")
    return None


def fetch_case_raw_bytes(case_id: str) -> bytes:
    try:
        with db_cursor() as cur:
            cur.execute("SELECT raw_eml_bytes FROM forensic_cases WHERE case_id = %s", (case_id,))
            row = cur.fetchone()
        return bytes(row[0]) if row and row[0] else b""
    except Exception as e:
        print(f"[-] [DB] Error reading raw bytes for case {case_id}: {e}")
        return b""


def list_forensic_cases_for_user(user_id: int, limit: int = 50):
    """Lists the caller's own recent forensic cases"""
    limit = max(1, min(int(limit), 200))
    cases = []
    with db_cursor() as cur:
        cur.execute("""
            SELECT case_id, evidence_hash, verdict, threat_score, sender, subject, created_at
            FROM forensic_cases WHERE owner_user_id = %s
            ORDER BY created_at DESC LIMIT %s
        """, (user_id, limit))
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
@rate_limit("brands", 30, 60)
def get_official_brands():
    """Return all official brands for the Android app to cache"""
    try:
        with db_cursor() as cur:
            cur.execute("SELECT name, primary_domain, aliases, trusted_subdomains, trusted_cdns FROM official_brands")
            rows = cur.fetchall()
        brands = []
        for row in rows:
            brands.append({
                "name": row[0],
                "primaryDomain": row[1],
                "aliases": row[2] if isinstance(row[2], list) else json.loads(row[2] or '[]'),
                "trustedSubdomains": row[3] if isinstance(row[3], list) else json.loads(row[3] or '[]'),
                "trustedCdns": row[4] if isinstance(row[4], list) else json.loads(row[4] or '[]')
            })
        return jsonify({"brands": brands}), 200
    except Exception as e:
        print(f"Error fetching official brands: {e}")
        return jsonify({"error": "Failed to fetch brands"}), 500

# ==================== AUTHENTICATION ENDPOINTS ====================

@app.route('/api/auth/register', methods=['POST'])
@rate_limit("register", 5, 600)
def register_user():
    """Register a new user"""
    try:
        data = request.get_json(silent=True) or {}

        name = str(data.get('name', '')).strip()
        last_name = str(data.get('last_name', '')).strip()
        email = str(data.get('email', '')).strip().lower()
        phone_number = str(data.get('phone_number', '')).strip()
        pin = data.get('pin')

        if not (name and last_name and email and phone_number and pin):
            return jsonify({"error": "Missing required fields"}), 400
        if len(name) > 100 or len(last_name) > 100:
            return jsonify({"error": "Name is too long"}), 400
        if not is_valid_email(email):
            return jsonify({"error": "Invalid email address"}), 400
        if not is_valid_phone(phone_number):
            return jsonify({"error": "Invalid phone number"}), 400
        if not is_valid_pin(pin):
            return jsonify({"error": "PIN must be 4 to 8 digits"}), 400

        hashed_pin = hash_pin(pin)

        with db_cursor() as cur:
            cur.execute("SELECT 1 FROM users WHERE email = %s OR phone_number = %s", (email, phone_number))
            if cur.fetchone():
                return jsonify({"error": "An account with this email or phone number already exists"}), 409

            cur.execute(
                """INSERT INTO users (name, last_name, email, phone_number, pin, created_at, updated_at)
                   VALUES (%s, %s, %s, %s, %s, NOW(), NOW())
                   RETURNING id, name, email, phone_number, created_at""",
                (name, last_name, email, phone_number, hashed_pin)
            )
            user = cur.fetchone()

        return jsonify({
            "id": user[0],
            "name": user[1],
            "email": user[2],
            "phone_number": user[3],
            "created_at": user[4].isoformat(),
            "token": issue_token(user[0])
        }), 201

    except Exception as e:
        return server_error(e)

@app.route('/api/auth/login', methods=['POST'])
@rate_limit("login", 20, 60)
def login_user():
    """Login user with phone number and PIN. Returns a signed bearer token."""
    try:
        data = request.get_json(silent=True) or {}
        phone_number = str(data.get('phone_number', '')).strip()
        pin = data.get('pin')

        if not phone_number or not isinstance(pin, str) or not pin:
            return jsonify({"error": "Missing phone_number or pin"}), 400

        if is_locked_out(phone_number):
            return jsonify({"error": "Too many failed attempts. Try again in 15 minutes."}), 429

        with db_cursor() as cur:
            cur.execute("SELECT id, name, email, phone_number, pin FROM users WHERE phone_number = %s",
                        (phone_number,))
            user_row = cur.fetchone()

        # Same response for unknown number and wrong PIN (no account enumeration)
        stored_hash = user_row[4] if user_row else hash_pin("000000")
        pin_ok = False
        try:
            pin_ok = verify_pin(pin, stored_hash)
        except ValueError:
            pin_ok = False

        if not user_row or not pin_ok:
            record_login_failure(phone_number)
            return jsonify({"error": "Invalid phone number or PIN"}), 401

        clear_login_failures(phone_number)
        return jsonify({
            "id": user_row[0],
            "name": user_row[1],
            "email": user_row[2],
            "phone_number": user_row[3],
            "token": issue_token(user_row[0]),
            "message": "Login successful"
        }), 200

    except Exception as e:
        return server_error(e)

@app.route('/api/auth/me', methods=['GET'])
@require_auth
def auth_me():
    """Return the profile of the authenticated user"""
    try:
        with db_cursor() as cur:
            cur.execute("SELECT id, name, last_name, email, phone_number FROM users WHERE id = %s", (g.user_id,))
            row = cur.fetchone()
        if not row:
            return jsonify({"error": "User not found"}), 404
        return jsonify({"id": row[0], "name": row[1], "last_name": row[2],
                        "email": row[3], "phone_number": row[4]}), 200
    except Exception as e:
        return server_error(e)

# ==================== SHARED ANALYSIS HELPERS ====================

MAX_URL_LENGTH = 2048
_analysis_slots = threading.BoundedSemaphore(int(os.getenv("MAX_CONCURRENT_ANALYSES", "4")))


def normalize_input_url(raw):
    """Validate and normalise a client-supplied URL. Returns None if unusable."""
    url = str(raw or "").strip()
    if not url or len(url) > MAX_URL_LENGTH or any(ch in url for ch in ("\r", "\n", " ")):
        return None
    if "://" not in url:
        # "javascript:...", "data:...", "mailto:...", "tel:..." are schemes, not hosts ("example.com:8080/x" is fine)
        if re.match(r"^[a-z][a-z0-9+.\-]*:(?!\d+(?:/|$))", url, re.I):
            return None
        url = "http://" + url
    if not url.lower().startswith(("http://", "https://")):
        return None
    return url


def to_client_verdict(pipeline_res):
    """Maps the pipeline result to the three levels the apps understand."""
    display = str(pipeline_res.get('display_verdict', ''))
    if display:
        return {'Dangerous': 'DANGEROUS', 'Safe': 'SAFE'}.get(display, 'SUSPICIOUS')     # 'Unverified - open with care'
    verdict = str(pipeline_res.get('verdict', '')).upper()
    score = float(pipeline_res.get('threat_score', 0) or 0)
    if 'CRITICAL' in verdict or 'PHISHING' in verdict or 'DANGEROUS' in verdict or score >= 80:
        return 'DANGEROUS'
    if 'SUSPICIOUS' in verdict or score >= 50:
        return 'SUSPICIOUS'
    return 'SAFE'


import scan_jobs
from core_engine import scan_progress


def _scan_runner(url):
    """
    The one analysis every entry point shares: known-threat database first (instant), then the full pipeline.
    Progress is reported to whichever scan job is listening.
    """
    scan_progress.report("threat_lists", "running")
    try:
        is_phishing, threat_type, db_source = phishing_importer.check_url_in_database(url)
    except Exception:
        is_phishing, threat_type, db_source = False, None, None
    if is_phishing and not is_short_url(url):
        scan_progress.report("threat_lists", "done", f"listed by {db_source}")
        for stage in ("link_analysis", "reputation", "sandbox", "model"):
            scan_progress.report(stage, "skipped", "already known as dangerous")
        return {
            "url": url, "verdict": "CRITICAL FRAUD / PHISHING", "threat_score": 100.0, "display_verdict": "Dangerous",
            "decisive": True, "analysis_complete": True, "tier_0_match": True, "tier_analyzed": "TIER_0",
            "summary": (f"\u2022 Threat Summary: This link is on a public phishing list ({db_source}, {threat_type}).\n"
                        f"\u2022 Key Forensic Evidence: Known phishing link reported by {db_source}.\n"
                        "\u2022 Recommended Action: Do not open this link."),
            "telemetry": {"known_db_match": 1, "status": "KNOWN_THREAT", "phishing_feed_source": db_source,
                          "threat_type": threat_type, "analysis_complete": True},
        }
    result = get_link_pipeline().analyze_url(url, defer_ai=True)        # the AI second opinion must never delay the verdict
    if isinstance(result, dict):
        result.setdefault("tier_analyzed", "V2_LINK_PIPELINE")
        result.setdefault("tier_0_match", False)
    return result


def _job_result_payload(result):
    """What a client needs from a finished scan."""
    return {
        "verdict": to_client_verdict(result),
        "display_verdict": result.get("display_verdict"),
        "decisive": result.get("decisive"),
        "threat_score": float(result.get("threat_score", 0) or 0),
        "analysis_complete": bool(result.get("analysis_complete", True)),
        "reasons": result.get("summary", ""),
        "tier_0_match": bool(result.get("tier_0_match")),
        "ai_pending": bool((result.get("telemetry") or {}).get("ai_pending")),
    }


def _url_spellings(url):
    """'https://www.x.org/', 'https://x.org' ... all count as the same link."""
    bare = url.rstrip("/")
    spellings = {url, bare, bare + "/"}
    for u in list(spellings):
        spellings.add(u.replace("://www.", "://", 1) if "://www." in u else u.replace("://", "://www.", 1))
    return sorted(spellings)


def _record_job_scan(user_id, url, result, source_app):
    """
    Save a scan made through a scan job (a tap in the Link Gate) to the user's history.
    - The link is not in that user's history yet: a new record is added.
    - It is already there (for example from the notification scan of the same message) with the SAME verdict: nothing is
      added a second time.
    - It is already there but the new analysis reached a DIFFERENT verdict (for example it was fixed or the page changed):
      the old record is updated, so the history never keeps showing a stale answer.
    'www.' and trailing-slash spellings of the link count as the same link.
    """
    spellings = _url_spellings(url)
    verdict = to_client_verdict(result)
    reasons = str(result.get("summary", ""))[:4000]
    score = float(result.get("threat_score", 0) or 0)
    complete = bool(result.get("analysis_complete", True))
    with db_cursor() as cur:
        cur.execute("SELECT id, risk_level FROM link_scans WHERE user_id = %s AND url = ANY(%s) ORDER BY id DESC LIMIT 1",
                    (user_id, spellings))
        existing = cur.fetchone()
        if existing and existing[1] == verdict:
            return None
        if existing:
            scan_id = existing[0]
            cur.execute("""UPDATE link_scans SET risk_level = %s, verdict = %s, reasons = %s, threat_score = %s,
                                  analysis_complete = %s, analyzed_at = NOW(), source_app = COALESCE(%s, source_app)
                           WHERE id = %s""", (verdict, verdict, reasons, score, complete, source_app, scan_id))
            cur.execute("DELETE FROM scan_features WHERE scan_id = %s", (scan_id,))
        else:
            cur.execute(
                """INSERT INTO link_scans (user_id, url, risk_level, reasons, verdict, analyzed_at,
                                           source_app, threat_score, analysis_complete)
                   VALUES (%s, %s, %s, %s, %s, NOW(), %s, %s, %s) RETURNING id""",
                (user_id, url, verdict, reasons, verdict, source_app, score, complete))
            scan_id = cur.fetchone()[0]
    try:
        rows = scan_feature_rows(result, result.get("tier_analyzed", "V2_LINK_PIPELINE"))
        with db_cursor() as cur:
            cur.executemany("INSERT INTO scan_features (scan_id, feature_name, feature_value) VALUES (%s, %s, %s)",
                            [(scan_id, n, v) for n, v in rows])
    except Exception as e:
        logging.getLogger("trustshield.scan").warning("could not store scan features: %s", e)
    return scan_id


def _on_scan_job_finished(job):
    for user_id, source_app in list(job.watchers):
        try:
            _record_job_scan(user_id, job.url, job.result, source_app)
        except Exception as e:
            logging.getLogger("trustshield.scan").warning("could not record scan for user %s: %s", user_id, e)


def _refine_scan(result, context):
    from core_engine.link_threat_pipeline import refine_result
    return refine_result(result, context)


def _on_scan_refined(job, before):
    """
    The AI second opinion finished after the verdict was already delivered. Bring every history record that was saved with the
    first (fast) verdict up to date, so the history, the details screen and later alerts show the refined answer.
    """
    result = job.result
    old_verdict, new_verdict = to_client_verdict(before), to_client_verdict(result)
    with db_cursor() as cur:
        cur.execute("""UPDATE link_scans SET risk_level = %s, verdict = %s, reasons = %s, threat_score = %s, analysis_complete = %s
                       WHERE url = ANY(%s) AND risk_level = %s AND analyzed_at > NOW() - INTERVAL '30 minutes' RETURNING id""",
                    (new_verdict, new_verdict, str(result.get("summary", ""))[:4000], float(result.get("threat_score", 0) or 0),
                     bool(result.get("analysis_complete", True)), _url_spellings(job.url), old_verdict))
        ids = [r[0] for r in cur.fetchall()]
    rows = scan_feature_rows(result, result.get("tier_analyzed", "V2_LINK_PIPELINE"))
    for scan_id in ids:
        with db_cursor() as cur:
            cur.execute("DELETE FROM scan_features WHERE scan_id = %s", (scan_id,))
            cur.executemany("INSERT INTO scan_features (scan_id, feature_name, feature_value) VALUES (%s, %s, %s)",
                            [(scan_id, n, v) for n, v in rows])


scan_jobs_manager = scan_jobs.JobManager(_scan_runner, slots=_analysis_slots, on_finish=_on_scan_job_finished,
                                         refiner=_refine_scan, on_refined=_on_scan_refined)


def run_link_pipeline(url):
    """
    Analyse a link through the shared scan jobs. Returns None if the server is busy or the analysis failed.
    If the same link is already being analysed (by a notification scan, a Link Gate tap, the extension...) this joins
    that job instead of starting a second one; a recent decisive answer is returned instantly.
    """
    job, _ = scan_jobs_manager.start_or_join(url)
    if not job.wait(scan_jobs.JOB_WAIT_SECONDS) or job.state != "done":
        return None
    return scan_jobs_manager.result_copy(job)


def scan_feature_rows(pipeline_res, tier_analyzed, db_source=None):
    """Flatten what the analysis found into (name, value) rows for the scan_features table."""
    rows = [("tier_analyzed", tier_analyzed)]
    if db_source:
        rows.append(("phishing_feed_source", db_source))
    if pipeline_res:
        for name in ("verdict", "threat_score", "display_verdict", "decisive", "analysis_complete"):
            if pipeline_res.get(name) is not None:
                rows.append((name, pipeline_res[name]))
        def add(prefix, value, depth=0):
            if isinstance(value, dict):
                if depth < 3:
                    for sub_name, sub_value in value.items():
                        add(f"{prefix}.{sub_name}", sub_value, depth + 1)
            elif isinstance(value, (list, tuple)):
                if value:
                    rows.append((prefix, ", ".join(str(v) for v in value[:12])))
            elif value is not None:
                rows.append((prefix, value))

        for name, value in (pipeline_res.get("telemetry") or {}).items():
            add(name, value)
    return [(str(n)[:255], str(v)[:500]) for n, v in rows][:200]


def ensure_link_scan_columns():
    """Adds portal-facing columns to link_scans if missing"""
    try:
        with db_cursor() as cur:
            cur.execute("""
                ALTER TABLE link_scans ADD COLUMN IF NOT EXISTS source_app VARCHAR(100);
                ALTER TABLE link_scans ADD COLUMN IF NOT EXISTS threat_score FLOAT;
                ALTER TABLE link_scans ADD COLUMN IF NOT EXISTS analysis_complete BOOLEAN;
                CREATE INDEX IF NOT EXISTS idx_link_scans_user_time ON link_scans(user_id, analyzed_at DESC);
            """)
    except Exception as e:
        print(f"[-] [DB] Note adding link_scans columns: {e}")

try:
    ensure_link_scan_columns()
except Exception as e:
    print(f"[-] [DB] Initialization warning: {e}")

# ==================== EXTENSION ENDPOINTS ====================

@app.route('/api/extension/analyze', methods=['POST', 'OPTIONS'])
@optional_auth
@rate_limit("extension_analyze", 10, 60)
def analyze_extension_email():
    """
    Endpoint for the TrustShield Chrome Extension.
    Accepts { subject, sender, body, links } and runs the Unified Forensic Pipeline.
    The email is scraped from a webmail page, so it carries no real transport headers.
    """
    if request.method == 'OPTIONS':
        return '', 200

    try:
        from html import escape
        data = request.get_json(silent=True) or {}
        subject = sanitize_header_value(data.get('subject', ''))
        sender = sanitize_header_value(data.get('sender', ''))
        body = str(data.get('body', '') or '')[:50000].strip()
        links = data.get('links', [])
        if isinstance(links, str):
            links = [links]
        links = [str(u).strip() for u in links if isinstance(u, str)][:50]
        links = [u for u in links if u.lower().startswith(("http://", "https://")) and len(u) <= MAX_URL_LENGTH
                 and not any(ch in u for ch in ("\r", "\n", " ", '"', "<", ">"))]

        if not subject and not body and not links:
            return jsonify({"error": "No content to analyze"}), 400

        now_utc = datetime.now(timezone.utc).replace(tzinfo=None).strftime("%a, %d %b %Y %H:%M:%S +0000")
        sender_domain = sender.split("@")[-1].strip("> ") if "@" in sender else "external-mail.net"
        boundary = f"----=_Part_Ext_{secrets.token_hex(8)}"

        html_links_tags = "".join(
            f'<p><a href="{escape(u, quote=True)}">{escape(u)}</a></p>\n' for u in links
        )
        safe_body = body.replace("\r", "")

        eml_str = (
            f"X-TrustShield-Source: chrome-extension-webmail-scrape\r\n"
            f"Return-Path: <{sender or 'security-alert@external-mail.net'}>\r\n"
            f"From: {sender or 'Security Alert <security@external-mail.net>'}\r\n"
            f"To: recipient.user@corporate.com\r\n"
            f"Subject: {subject or 'Security Notification'}\r\n"
            f"Date: {now_utc}\r\n"
            f"Message-ID: <{secrets.token_hex(8)}@{sender_domain}>\r\n"
            f"MIME-Version: 1.0\r\n"
            f"Content-Type: multipart/alternative; boundary=\"{boundary}\"\r\n\r\n"
            f"--{boundary}\r\n"
            f"Content-Type: text/plain; charset=UTF-8\r\n"
            f"Content-Transfer-Encoding: 8bit\r\n\r\n"
            f"{safe_body}\r\n"
            + ("\r\nEmbedded URLs:\r\n" + "\r\n".join(links) + "\r\n" if links else "") +
            f"\r\n"
            f"--{boundary}\r\n"
            f"Content-Type: text/html; charset=UTF-8\r\n"
            f"Content-Transfer-Encoding: 8bit\r\n\r\n"
            f"<html><body><div>{escape(safe_body)}</div>\n{html_links_tags}</body></html>\r\n"
            f"--{boundary}--\r\n"
        )
        eml_bytes = eml_str.encode('utf-8')

        from core_engine.unified_email_pipeline import analyze_email_pipeline
        if not _analysis_slots.acquire(timeout=20):
            return jsonify({"error": "Server is busy, please retry shortly"}), 503
        try:
            dossier = analyze_email_pipeline(eml_bytes, skip_link_sandbox=False)
        finally:
            _analysis_slots.release()

        case_id = new_case_id()
        record = persist_forensic_case(case_id, dossier, eml_bytes, owner_user_id=g.user_id)
        dossier = record["dossier"]

        return jsonify({
            "status": "success",
            "case_id": case_id,
            "verdict": dossier.get("verdict"),
            "final_threat_score": dossier.get("overall_threat_score"),
            "text_verdict": dossier.get("threat_attribution", {}).get("type", "Analyzed"),
            "links_found": len(dossier.get("link_investigation", [])),
            "threat_attribution": dossier.get("threat_attribution", {}),
            "full_dossier": dossier
        }), 200

    except Exception as e:
        return server_error(e)

@app.route('/api/sandbox-check', methods=['POST'])
@require_auth
@rate_limit("sandbox_check", 30, 60, per_user=True)
def sandbox_check():
    """
    Tier 3: Sandbox check called by the Android app.
    Runs the V2 Link Threat Pipeline (heuristics, threat DB, whitelist/VirusTotal, sandbox, fusion).
    """
    try:
        data = request.get_json(silent=True) or {}
        url = normalize_input_url(data.get('url'))
        if not url:
            return jsonify({"verdict": "UNKNOWN", "confidence": 0, "details": "A valid http(s) url is required"}), 400

        pipeline_res = run_link_pipeline(url)
        if pipeline_res is None:
            return jsonify({"verdict": "UNKNOWN", "confidence": 0, "details": "Analysis service is busy"}), 503

        android_verdict = to_client_verdict(pipeline_res)
        threat_score = int(pipeline_res.get('threat_score', 0) or 0)
        summary = pipeline_res.get('summary', '')

        return jsonify({
            "verdict": android_verdict,
            "confidence": threat_score,
            "details": summary or f"TrustShield pipeline: {pipeline_res.get('verdict')} (Score: {threat_score}/100)",
            "summary": summary,
            "analysis_complete": bool(pipeline_res.get('analysis_complete', True)),
            "display_verdict": pipeline_res.get('display_verdict'),
            "decisive": pipeline_res.get('decisive'),
            "engines_count": 4,
            "malicious_count": 1 if android_verdict == 'DANGEROUS' else 0,
            "suspicious_count": 1 if android_verdict == 'SUSPICIOUS' else 0
        }), 200

    except Exception as e:
        return server_error(e, "Analysis failed")

# ==================== LINK SCAN ENDPOINTS ====================

@app.route('/api/links/scan', methods=['POST'])
@require_auth
@rate_limit("links_scan", 30, 60, per_user=True)
def save_link_scan():
    """
    Analyse a link for the authenticated user and save it to their history.
    Tier 0: known-phishing database for an instant verdict, then the V2 pipeline.
    """
    try:
        data = request.get_json(silent=True) or {}
        user_id = g.user_id
        if data.get('user_id') not in (None, user_id):
            return jsonify({"error": "Forbidden"}), 403

        url = normalize_input_url(data.get('url'))
        if not url:
            return jsonify({"error": "A valid http(s) url is required"}), 400
        source_app = sanitize_header_value(data.get('source_app', ''), 100) or None

        # Client-side tier result is only a fallback hint if server analysis cannot run
        verdict = str(data.get('verdict', 'SUSPICIOUS')).upper()
        if verdict not in ('SAFE', 'SUSPICIOUS', 'DANGEROUS'):
            verdict = 'SUSPICIOUS'
        risk_level = verdict
        reasons = str(data.get('reasons', 'Link analyzed on device'))[:4000]
        tier_analyzed = 'CLIENT_ONLY'
        threat_score = None
        analysis_complete = False
        display_verdict, decisive = None, None
        pipeline_res = None

        # ===== TIER 0: phishing database =====
        is_phishing, threat_type, db_source = phishing_importer.check_url_in_database(url)
        is_short = is_short_url(url)
        if is_phishing and not is_short:
            verdict = risk_level = 'DANGEROUS'
            reasons = f"Found in {db_source} phishing database ({threat_type})"
            tier_analyzed = 'TIER_0'
            threat_score = 100.0
            analysis_complete = True
            display_verdict, decisive = "Dangerous", True
        else:
            try:
                pipeline_res = run_link_pipeline(url)
                if pipeline_res is not None:
                    verdict = risk_level = to_client_verdict(pipeline_res)
                    summary = pipeline_res.get('summary', '')
                    threat_score = float(pipeline_res.get('threat_score', 0) or 0)
                    analysis_complete = bool(pipeline_res.get('analysis_complete', True))
                    display_verdict, decisive = pipeline_res.get('display_verdict'), pipeline_res.get('decisive')
                    reasons = summary or f"TrustShield V2 Engine: {verdict} (Score: {threat_score}/100)"
                    tier_analyzed = 'V2_LINK_PIPELINE'
            except Exception as e:
                logging.getLogger("trustshield.scan").exception("V2 pipeline failed: %s", e)

        # ===== Dynamic brand discovery for domains the pipeline cleared =====
        if verdict == 'SAFE' and tier_analyzed == 'V2_LINK_PIPELINE':
            try:
                from urllib.parse import urlparse
                domain_to_check = urlparse(url).netloc.lower().replace('www.', '')
                discovered_brand = discover_and_add_brand(domain_to_check)
                if discovered_brand:
                    reasons = f"Dynamically discovered and verified as official domain for {discovered_brand}"
            except Exception as e:
                print(f"Error in dynamic brand discovery: {e}")

        with db_cursor() as cur:
            cur.execute("SELECT 1 FROM users WHERE id = %s", (user_id,))
            if not cur.fetchone():
                return jsonify({"error": "User not found"}), 404
            cur.execute(
                """INSERT INTO link_scans (user_id, url, risk_level, reasons, verdict, analyzed_at,
                                           source_app, threat_score, analysis_complete)
                   VALUES (%s, %s, %s, %s, %s, NOW(), %s, %s, %s)
                   RETURNING id, user_id, url, risk_level, reasons, verdict, analyzed_at""",
                (user_id, url, risk_level, reasons, verdict, source_app, threat_score, analysis_complete)
            )
            scan = cur.fetchone()

        try:      # evidence for later learning and for the portal; never allowed to break the scan itself
            feature_rows = scan_feature_rows(pipeline_res, tier_analyzed, db_source if is_phishing else None)
            with db_cursor() as cur:
                cur.executemany(
                    "INSERT INTO scan_features (scan_id, feature_name, feature_value) VALUES (%s, %s, %s)",
                    [(scan[0], n, v) for n, v in feature_rows])
        except Exception as e:
            logging.getLogger("trustshield.scan").warning("could not store scan features: %s", e)

        return jsonify({
            "id": scan[0],
            "user_id": scan[1],
            "url": scan[2],
            "risk_level": scan[3],
            "reasons": scan[4],
            "verdict": scan[5],
            "analyzed_at": scan[6].isoformat(),
            "threat_score": threat_score,
            "analysis_complete": analysis_complete,
            "display_verdict": display_verdict,
            "decisive": decisive,
            "tier_0_match": bool(is_phishing),
            "tier_analyzed": tier_analyzed,
            "ai_pending": bool(pipeline_res and (pipeline_res.get("telemetry") or {}).get("ai_pending"))
        }), 201

    except Exception as e:
        return server_error(e)

@app.route('/api/links/scan-jobs', methods=['POST'])
@require_auth
@rate_limit("scan_jobs", 60, 60, per_user=True)
def start_scan_job():
    """
    Start a scan, or JOIN the scan of the same link that is already running (for example the one the notification
    scanner started when the message arrived). Returns at once with the live stage progress; poll the job for updates.
    A finished recent scan is returned immediately with its result.
    """
    try:
        data = request.get_json(silent=True) or {}
        url = normalize_input_url(data.get('url'))
        if not url:
            return jsonify({"error": "A valid http(s) url is required"}), 400
        source_app = sanitize_header_value(data.get('source_app', ''), 100) or None
        record = data.get('record', True) is not False

        job, how = scan_jobs_manager.start_or_join(url)
        scan_id = None
        if record:
            if not job.add_watcher(g.user_id, source_app):         # the job already finished: record right now
                try:
                    scan_id = _record_job_scan(g.user_id, url, job.result, source_app)
                except Exception as e:
                    logging.getLogger("trustshield.scan").warning("could not record scan: %s", e)
        snap = job.snapshot(joined=(how != "started"))
        snap["how"] = how
        if job.state == "done":
            snap["result"] = _job_result_payload(job.result)
            snap["result"]["ai_pending"] = job.refining
            snap["scan_id"] = scan_id
            return jsonify(snap), 200
        return jsonify(snap), 202
    except Exception as e:
        return server_error(e)


@app.route('/api/links/scan-jobs/<job_id>', methods=['GET'])
@require_auth
@rate_limit("scan_job_poll", 240, 60, per_user=True)
def scan_job_status(job_id):
    """Live progress of a scan job, and its result once it is done."""
    try:
        job = scan_jobs_manager.get(job_id)
        if job is None:
            return jsonify({"error": "Unknown or expired scan"}), 404
        snap = job.snapshot()
        if job.state == "done":
            snap["result"] = _job_result_payload(job.result)
            snap["result"]["ai_pending"] = job.refining
        return jsonify(snap), 200
    except Exception as e:
        return server_error(e)


@app.route('/api/links/scans/<int:scan_id>', methods=['GET'])
@require_auth
@rate_limit("scan_state", 120, 60, per_user=True)
def scan_state(scan_id):
    """Current verdict of one of the caller's saved scans, and whether the AI second opinion is still running."""
    try:
        with db_cursor() as cur:
            cur.execute("SELECT id, url, risk_level, reasons, threat_score FROM link_scans WHERE id = %s AND user_id = %s",
                        (scan_id, g.user_id))
            row = cur.fetchone()
        if not row:
            return jsonify({"error": "Scan not found"}), 404
        job, how = (None, None)
        try:
            job = scan_jobs_manager.peek(row[1])
        except Exception:
            job = None
        return jsonify({"id": row[0], "url": row[1], "verdict": row[2], "reasons": row[3], "threat_score": row[4],
                        "ai_pending": bool(job is not None and job.refining)}), 200
    except Exception as e:
        return server_error(e)


@app.route('/api/links/explain', methods=['POST'])
@require_auth
@rate_limit("links_explain", 20, 60, per_user=True)
def explain_link():
    """
    The explanation of one of the caller's scans: what the sandbox saw, what (if anything) looked suspicious, why the
    verdict was reached. Built from that scan's own stored evidence, so it is different for every scan; Gemini writes it when
    available (from the facts only), otherwise rules do. It is stored with the scan, so Gemini is used once per scan.
    """
    try:
        from core_engine import explainer
        data = request.get_json(silent=True) or {}
        scan_id = data.get('scan_id')
        url = normalize_input_url(data.get('url')) if data.get('url') else None
        refresh = data.get('refresh') is True or (scan_id is None and url is not None)      # the app's Refresh button
        quick = data.get('quick') is True       # "give me something instantly": rule-based text now, Gemini version via a second call

        if not url and not scan_id:
            return jsonify({"error": "Missing url or scan_id"}), 400

        row = None
        with db_cursor() as cur:
            if scan_id:
                cur.execute("SELECT id, url, verdict, threat_score FROM link_scans WHERE id = %s AND user_id = %s",
                            (scan_id, g.user_id))
            else:
                cur.execute("SELECT id, url, verdict, threat_score FROM link_scans WHERE url = %s AND user_id = %s "
                            "ORDER BY analyzed_at DESC LIMIT 1", (url, g.user_id))
            row = cur.fetchone()
        if row is None and scan_id:
            return jsonify({"error": "Scan not found"}), 404

        features, result = {}, None
        if row:
            scan_id, url, verdict, score = row[0], row[1], row[2] or "SAFE", row[3]
            with db_cursor() as cur:
                cur.execute("SELECT feature_name, feature_value FROM scan_features WHERE scan_id = %s ORDER BY id", (scan_id,))
                features = {n: v for n, v in cur.fetchall()}
        else:                                                   # a link that was never scanned by this user
            verdict, score = "SAFE", None

        cached = features.get("ai_explanation")
        if cached and not refresh:
            try:
                saved = json.loads(cached)
                return jsonify({"status": "success", "url": url, "scan_id": scan_id, "verdict": verdict,
                                "threat_score": score, "summary": saved["summary"], "source": saved.get("source", "rules"),
                                "model": saved.get("model", "")}), 200
            except Exception:
                pass

        if len(features) < 5 and not quick:                     # older scan without stored evidence: use the (shared) analysis
            result = run_link_pipeline(url)
            if result is None:
                return jsonify({"error": "Analysis service is busy"}), 503
            verdict, score = to_client_verdict(result), float(result.get("threat_score", 0) or 0)
            features = {n: v for n, v in scan_feature_rows(result, result.get("tier_analyzed", "V2_LINK_PIPELINE"))}

        facts = explainer.facts_from_features(features, url, verdict, score)
        if quick:
            from core_engine import llm_reviewer as _llm
            text, _ = explainer.explain(facts, use_ai=False)
            return jsonify({"status": "success", "url": url, "scan_id": scan_id, "verdict": verdict, "threat_score": score,
                            "summary": text, "source": "rules", "model": "Quick summary (AI version loading)",
                            "ai_pending": bool(_llm.is_enabled())}), 200
        summary, source = explainer.explain(facts)
        label = "Written by Google Gemini" if source == "gemini" else "Summary from the analysis"

        if scan_id:
            try:
                with db_cursor() as cur:
                    cur.execute("DELETE FROM scan_features WHERE scan_id = %s AND feature_name = 'ai_explanation'", (scan_id,))
                    cur.execute("INSERT INTO scan_features (scan_id, feature_name, feature_value) VALUES (%s, %s, %s)",
                                (scan_id, "ai_explanation", json.dumps({"summary": summary, "source": source, "model": label})))
            except Exception as e:
                logging.getLogger("trustshield.scan").warning("could not store the explanation: %s", e)

        return jsonify({"status": "success", "url": url, "scan_id": scan_id, "verdict": verdict, "threat_score": score,
                        "summary": summary, "source": source, "model": label}), 200

    except Exception as e:
        return server_error(e)

@app.route('/api/links/history/<int:user_id>', methods=['GET'])
@require_auth
def get_user_link_history(user_id):
    """Scanned links for the authenticated user (latest scan per URL)"""
    try:
        if user_id != g.user_id:
            return jsonify({"error": "Forbidden"}), 403

        limit = max(1, min(request.args.get('limit', 500, type=int), 2000))
        offset = max(0, request.args.get('offset', 0, type=int))
        verdict_filter = request.args.get('verdict', '').upper()
        if verdict_filter not in ('SAFE', 'SUSPICIOUS', 'DANGEROUS'):
            verdict_filter = ''
        search = request.args.get('q', '').strip()[:200]

        with db_cursor() as cur:
            cur.execute(
                """WITH RankedScans AS (
                       SELECT id, user_id, url, risk_level, reasons, verdict, analyzed_at, source_app, threat_score,
                              ROW_NUMBER() OVER(PARTITION BY url ORDER BY analyzed_at DESC) as rn
                       FROM link_scans
                       WHERE user_id = %s
                         AND (%s = '' OR verdict = %s)
                         AND (%s = '' OR url ILIKE %s)
                   )
                   SELECT id, user_id, url, risk_level, reasons, verdict, analyzed_at, source_app, threat_score
                   FROM RankedScans
                   WHERE rn = 1
                   ORDER BY analyzed_at DESC
                   LIMIT %s OFFSET %s""",
                (user_id, verdict_filter, verdict_filter, search, f"%{search}%", limit, offset)
            )
            scans = cur.fetchall()

        scan_list = [{
            "id": scan[0], "user_id": scan[1], "url": scan[2], "risk_level": scan[3],
            "reasons": scan[4], "verdict": scan[5],
            "analyzed_at": scan[6].isoformat() if scan[6] else None,
            "source_app": scan[7], "threat_score": scan[8]
        } for scan in scans]

        return jsonify({"user_id": user_id, "total_scans": len(scan_list), "scans": scan_list}), 200

    except Exception as e:
        return server_error(e)

@app.route('/api/health', methods=['GET'])
def api_health():
    """Health check for API"""
    return jsonify({"status": "healthy", "message": "Backend is running"}), 200

# ==================== PHISHING DATABASE ENDPOINTS ====================

@app.route('/api/phishing/check', methods=['POST'])
@rate_limit("phishing_check", 60, 60)
def check_phishing_url():
    """
    Check if a URL is in the phishing database
    Returns: {is_phishing: bool, threat_type: str, source: str}
    """
    try:
        data = request.get_json(silent=True) or {}
        url = normalize_input_url(data.get('url'))
        if not url:
            return jsonify({"error": "A valid http(s) url is required"}), 400

        is_phishing, threat_type, source = phishing_importer.check_url_in_database(url)

        return jsonify({
            "url": url,
            "is_phishing": is_phishing,
            "threat_type": threat_type,
            "source": source,
            "confidence": 1.0 if is_phishing else 0.0
        }), 200

    except Exception as e:
        return server_error(e)

@app.route('/api/phishing/samples', methods=['GET'])
@require_admin
def get_phishing_samples():
    """
    Admin only. Sample phishing URLs from the database for testing.
    Query params: limit (default 10, max 100), random (true/false)
    """
    try:
        limit = max(1, min(request.args.get('limit', 10, type=int), 100))
        random_order = request.args.get('random', 'true').lower() == 'true'
        order_clause = "ORDER BY RANDOM()" if random_order else "ORDER BY id DESC"

        with db_cursor() as cur:
            cur.execute(f"""
                SELECT id, url, domain, threat_type, source, date_added
                FROM phishing_links
                {order_clause}
                LIMIT %s
            """, (limit,))
            samples = cur.fetchall()

        results = [{
            "id": row[0], "url": row[1], "domain": row[2], "threat_type": row[3],
            "source": row[4], "date_added": row[5].isoformat() if row[5] else None
        } for row in samples]

        return jsonify({
            "total_returned": len(results),
            "samples": results,
            "note": "These are KNOWN PHISHING URLs. Do NOT click them!"
        }), 200

    except Exception as e:
        return server_error(e)

@app.route('/api/phishing/import', methods=['POST'])
@require_admin
def import_phishing_manual():
    """
    Admin only. Manually import phishing URLs
    Expects: {urls: [list of URLs], source: "manual", threat_type: "phishing"}
    """
    try:
        data = request.get_json(silent=True) or {}
        raw_urls = data.get('urls', [])
        if not isinstance(raw_urls, list):
            return jsonify({"error": "'urls' must be a list"}), 400
        if len(raw_urls) > 5000:
            return jsonify({"error": "At most 5000 URLs per request"}), 400
        urls = [u.strip() for u in raw_urls if isinstance(u, str) and 0 < len(u.strip()) <= MAX_URL_LENGTH]
        source = sanitize_header_value(data.get('source', 'manual'), 50) or 'manual'
        threat_type = sanitize_header_value(data.get('threat_type', 'phishing'), 50) or 'phishing'

        if not urls:
            return jsonify({"error": "No valid URLs provided"}), 400

        inserted, updated = phishing_importer.store_phishing_urls(urls, source, threat_type)

        return jsonify({
            "message": "URLs imported successfully",
            "inserted": inserted,
            "updated": updated,
            "total": inserted + updated
        }), 200

    except Exception as e:
        return server_error(e)

@app.route('/api/phishing/import-feeds', methods=['POST'])
@require_admin
def import_phishing_feeds():
    """
    Admin only. Trigger import from all available feeds (PhishTank, URLhaus, OpenPhish)
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
        return server_error(e)

@app.route('/api/phishing/stats', methods=['GET'])
def phishing_database_stats():
    """Get statistics about phishing database"""
    try:
        stats = phishing_importer.get_database_stats()
        if not stats:
            return jsonify({"error": "Statistics are temporarily unavailable"}), 503

        return jsonify({
            "total_urls": stats['total'],
            "by_threat_type": stats['by_threat_type'],
            "by_source": stats['by_source']
        }), 200
        
    except Exception as e:
        return server_error(e)

import re as _re
_CASE_ID_RE = _re.compile(r'^TSF-[0-9A-F]{16}$')


def _read_uploaded_bytes():
    """Reads an uploaded evidence file (multipart 'file' or raw body)."""
    if 'file' in request.files:
        return request.files['file'].read()
    return request.get_data() or b""


def _public_case_view(record, include_dossier=True):
    view = {
        "case_id": record["case_id"],
        "evidence_hash": record.get("evidence_hash", ""),
        "verdict": record.get("verdict", ""),
        "threat_score": record.get("threat_score", 0.0),
        "sender": record.get("sender", ""),
        "subject": record.get("subject", ""),
        "created_at": record.get("created_at", ""),
        "integrity_status": record.get("integrity_status", "NOT SEALED"),
    }
    if include_dossier:
        view["dossier"] = record.get("dossier", {})
    return view


@app.route('/api/forensics/analyze-eml', methods=['POST'])
@optional_auth
@rate_limit("analyze_eml", 10, 60)
def analyze_eml_endpoint():
    """
    Ingests an uploaded .eml file (multipart/form-data with 'file' or raw bytes),
    runs the Unified EML Forensic Orchestrator, seals the case, and returns the dossier.
    """
    try:
        eml_bytes = _read_uploaded_bytes()
        if not eml_bytes:
            return jsonify({"error": "No .eml file or data uploaded. Send as multipart/form-data ('file') or raw body."}), 400

        skip_sandbox = request.args.get('skip_sandbox', 'false').lower() in ('true', '1')
        from core_engine.unified_email_pipeline import analyze_email_pipeline
        if not _analysis_slots.acquire(timeout=20):
            return jsonify({"error": "Server is busy, please retry shortly"}), 503
        try:
            result = analyze_email_pipeline(eml_bytes, skip_link_sandbox=skip_sandbox)
        finally:
            _analysis_slots.release()

        case_id = new_case_id()
        record = persist_forensic_case(case_id, result, eml_bytes, owner_user_id=g.user_id)
        response = record["dossier"]
        response["case_id"] = case_id
        return jsonify(response), 200

    except Exception as e:
        return server_error(e)


@app.route('/api/forensics/case/<case_id>', methods=['GET'])
@rate_limit("case_lookup", 60, 60)
def get_forensic_case_by_id(case_id):
    """
    Retrieves a sealed forensic dossier by its (unguessable) Case ID.
    The raw evidence file is not returned here; the owner downloads it separately.
    """
    try:
        clean_id = (case_id or "").strip().upper()
        if not _CASE_ID_RE.match(clean_id):
            return jsonify({"error": "Case not found"}), 404
        record = retrieve_forensic_case(clean_id)
        if not record:
            return jsonify({"error": "Case not found"}), 404
        view = _public_case_view(record)
        view["status"] = "success"
        return jsonify(view), 200
    except Exception as e:
        return server_error(e)


@app.route('/api/forensics/case/<case_id>/evidence', methods=['GET'])
@require_auth
def download_case_evidence(case_id):
    """Owner-only download of the original evidence file, byte for byte."""
    try:
        from flask import Response
        clean_id = (case_id or "").strip().upper()
        record = retrieve_forensic_case(clean_id) if _CASE_ID_RE.match(clean_id) else None
        if not record or record.get("owner_user_id") != g.user_id:
            return jsonify({"error": "Case not found"}), 404
        raw = fetch_case_raw_bytes(clean_id)
        if not raw:
            return jsonify({"error": "No evidence file stored for this case"}), 404
        return Response(raw, mimetype="message/rfc822",
                        headers={"Content-Disposition": f'attachment; filename="{clean_id}.eml"'})
    except Exception as e:
        return server_error(e)


@app.route('/api/forensics/cases', methods=['GET'])
@require_auth
def get_all_forensic_cases():
    """The authenticated user's own forensic cases, newest first."""
    try:
        cases = list_forensic_cases_for_user(g.user_id, limit=request.args.get('limit', 50, type=int))
        return jsonify({"status": "success", "total": len(cases), "cases": cases}), 200
    except Exception as e:
        return server_error(e)


@app.route('/api/forensics/verify-hash', methods=['POST'])
@rate_limit("verify_hash", 30, 60)
def verify_forensic_hash():
    """
    Verifies a SHA-256 evidence hash or Case ID against the vault and re-checks its seal.
    Returns the seal status and summary fields only (no dossier, no raw evidence).
    """
    try:
        data = request.get_json(silent=True) or {}
        query = str(data.get('query', '')).strip()
        if not query:
            return jsonify({"error": "Missing 'query' parameter (SHA-256 hash or Case ID)"}), 400

        record = None
        if query.upper().startswith("TSF-") and _CASE_ID_RE.match(query.upper()):
            record = retrieve_forensic_case(query.upper())
        if not record:
            record = retrieve_case_by_hash(query)

        if not record:
            return jsonify({
                "status": "not_found",
                "matched": False,
                "integrity_verdict": "NOT FOUND",
                "query": query[:80],
                "message": "No sealed record matches this identifier."
            }), 404

        status = record.get("integrity_status", "NOT SEALED")
        verdict_text = {
            "VERIFIED": "SEAL VALID: record unchanged since it was sealed",
            "TAMPERED": "SEAL INVALID: the stored record was altered after sealing",
        }.get(status, "RECORD NOT SEALED")
        return jsonify({
            "status": "success",
            "matched": True,
            "integrity_status": status,
            "integrity_verdict": verdict_text,
            "seal_algorithm": evidence_seal.SEAL_ALGORITHM,
            "case_id": record["case_id"],
            "evidence_hash": record.get("evidence_hash", ""),
            "sender": record.get("sender", ""),
            "subject": record.get("subject", ""),
            "verdict": record.get("verdict", ""),
            "threat_score": record.get("threat_score", 0.0),
            "created_at": record.get("created_at", "")
        }), 200
    except Exception as e:
        return server_error(e)


@app.route('/api/forensics/verify-file', methods=['POST'])
@rate_limit("verify_file", 20, 60)
def verify_forensic_file():
    """
    Hashes an uploaded evidence file and checks whether this exact file was sealed.
    A file that differs by even one byte will not match.
    """
    try:
        eml_bytes = _read_uploaded_bytes()
        if not eml_bytes:
            return jsonify({"error": "No file uploaded for verification"}), 400

        computed_hash = evidence_seal.sha256_hex(eml_bytes)
        record = retrieve_case_by_hash(computed_hash)

        if not record:
            return jsonify({
                "status": "unregistered",
                "matched": False,
                "computed_hash": computed_hash,
                "integrity_verdict": "NO MATCH: this file was not sealed here, or it differs from the sealed original",
            }), 200

        status = record.get("integrity_status", "NOT SEALED")
        return jsonify({
            "status": "success",
            "matched": True,
            "computed_hash": computed_hash,
            "integrity_status": status,
            "integrity_verdict": ("MATCH: file is identical to the sealed original and the seal is valid"
                                  if status == "VERIFIED" else
                                  "MATCH on hash, but the stored record's seal is " + status),
            "case_id": record["case_id"],
            "sender": record.get("sender", ""),
            "subject": record.get("subject", ""),
            "verdict": record.get("verdict", ""),
            "threat_score": record.get("threat_score", 0.0),
            "sealed_at": record.get("created_at", "")
        }), 200
    except Exception as e:
        return server_error(e)


@app.route('/api/forensics/export-pdf', methods=['POST'])
@optional_auth
@rate_limit("export_pdf", 10, 60)
def export_forensic_pdf_endpoint():
    """
    Exports a PDF dossier for a stored case ({"case_id": "..."}) or for an uploaded .eml.
    The PDF is generated from the server's stored, sealed record, never from client-supplied JSON.
    """
    try:
        from flask import send_file
        from core_engine.report_generator import generate_pdf_dossier_bytes
        import io

        dossier = None
        if 'file' in request.files:
            eml_bytes = request.files['file'].read()
            from core_engine.unified_email_pipeline import analyze_email_pipeline
            if not _analysis_slots.acquire(timeout=20):
                return jsonify({"error": "Server is busy, please retry shortly"}), 503
            try:
                dossier = analyze_email_pipeline(eml_bytes)
            finally:
                _analysis_slots.release()
            dossier["integrity"] = evidence_seal.integrity_block("NOT SEALED", None, None)
        else:
            payload = request.get_json(silent=True) or {}
            case_id = str(payload.get('case_id', '')).strip().upper()
            record = retrieve_forensic_case(case_id) if _CASE_ID_RE.match(case_id) else None
            if not record:
                return jsonify({"error": "Provide a valid case_id or upload an .eml file"}), 400
            dossier = record["dossier"]

        pdf_bytes = generate_pdf_dossier_bytes(dossier)
        evidence_hash = str(dossier.get("evidence_hash_sha256", "dossier"))[:12]
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"TrustShield_Forensic_Dossier_{evidence_hash}.pdf"
        )
    except Exception as e:
        return server_error(e)



# ===========================================================================
# GRAPH CORRELATION ENDPOINTS
# ===========================================================================

@app.route('/api/graph', methods=['GET'])
@require_auth
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
        return server_error(e)


@app.route('/api/graph/shared-infra', methods=['POST'])
@require_auth
@rate_limit("graph_query", 30, 60, per_user=True)
def find_shared_infrastructure():
    """
    Given an IP or domain, returns all nodes sharing that infrastructure
    (campaign-level correlation — 'who else uses this server?').

    Body: { "ip": "1.2.3.4" } OR { "domain": "phish.com" }
    """
    try:
        from core_engine.graph_correlation import get_global_graph
        data = request.get_json(silent=True) or {}
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
        return server_error(e)


# ===========================================================================
# CAMPAIGN CASE MANAGEMENT ENDPOINTS
# ===========================================================================

@app.route('/api/campaigns', methods=['GET'])
@require_auth
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
        min_inc = max(1, request.args.get('min_incidents', 1, type=int))
        limit = max(1, min(request.args.get('limit', 50, type=int), 200))
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
        return server_error(e)


@app.route('/api/campaigns/search', methods=['GET'])
@require_auth
@rate_limit("campaign_search", 30, 60, per_user=True)
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
        return server_error(e)


@app.route('/api/campaigns/<campaign_id>', methods=['GET'])
@require_auth
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
        return server_error(e)


# ===========================================================================
# STANDALONE NLP / BEC ANALYSIS ENDPOINT
# ===========================================================================

@app.route('/api/forensics/nlp-analyze', methods=['POST'])
@rate_limit("nlp_analyze", 20, 60)
def nlp_analyze_text():
    """
    Standalone NLP & BEC analysis on raw email text.
    Classifies into 5-class taxonomy: LEGITIMATE / SUSPICIOUS / IMPERSONATED / PHISHING / BEC_FRAUD
    Useful for quick body-text checks without uploading a full .eml file.

    Body (JSON): { "subject": "...", "body": "...", "sender": "..." }
    """
    try:
        from core_engine.bec_nlp_analyser import analyse_email_body
        data = request.get_json(silent=True) or {}
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
        return server_error(e)


# ===========================================================================
# STANDALONE WHOIS LOOKUP ENDPOINT
# ===========================================================================

@app.route('/api/forensics/whois', methods=['GET', 'POST'])
@rate_limit("whois", 20, 60)
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
        return server_error(e)


# ===========================================================================
# STANDALONE ATTACHMENT ANALYSIS ENDPOINT
# ===========================================================================

@app.route('/api/forensics/attachment-check', methods=['POST'])
@rate_limit("attachment_check", 10, 60)
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
        return server_error(e)


if __name__ == '__main__':
    if os.environ.get("ENABLE_SCHEDULER", "true").lower() == "true" and not scheduler.running:
        start_feed_sync()
    app.run(host='0.0.0.0', port=8000, debug=False)






