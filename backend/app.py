from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg
import bcrypt
import os
from dotenv import load_dotenv
from datetime import datetime

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
    """Save a scanned link to database"""
    try:
        data = request.get_json()
        
        if not data.get('user_id') or not data.get('url'):
            return jsonify({"error": "Missing user_id or url"}), 400
        
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Verify user exists
        cur.execute("SELECT id FROM users WHERE id = %s", (data['user_id'],))
        if not cur.fetchone():
            cur.close()
            conn.close()
            return jsonify({"error": "User not found"}), 404
        
        # Insert link scan
        cur.execute(
            """INSERT INTO link_scans (user_id, url, risk_level, reasons, verdict, analyzed_at) 
               VALUES (%s, %s, %s, %s, %s, NOW()) 
               RETURNING id, user_id, url, risk_level, reasons, verdict, analyzed_at""",
            (data['user_id'], data['url'], "SAFE", "Initial scan", "Safe link")
        )
        
        scan = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        
        return jsonify({
            "id": scan[0],
            "user_id": scan[1],
            "url": scan[2],
            "risk_level": scan[3],
            "reasons": scan[4],
            "verdict": scan[5],
            "analyzed_at": scan[6].isoformat()
        }), 201
        
    except Exception as e:
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
