"""
TrustShield Sandbox Analysis Backend
Tier 3 Analysis: URL Sandbox Check via VirusTotal API

Usage:
1. Set VIRUSTOTAL_API_KEY environment variable
2. Run: python app.py
3. Send POST request to http://localhost:5000/api/sandbox-check
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import logging
import os
from sandbox_analyzer import SandboxAnalyzer, URLFeatureAnalyzer
from datetime import datetime

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for Android app

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize VirusTotal API key
# Get free key from: https://www.virustotal.com/gui/
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', 'YOUR_API_KEY_HERE')

# Initialize sandbox analyzer
sandbox = SandboxAnalyzer(VIRUSTOTAL_API_KEY)

# Statistics
stats = {
    "total_checks": 0,
    "dangerous_count": 0,
    "suspicious_count": 0,
    "safe_count": 0
}


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "service": "TrustShield Sandbox Analysis",
        "timestamp": datetime.now().isoformat(),
        "api_configured": VIRUSTOTAL_API_KEY != 'YOUR_API_KEY_HERE'
    }), 200


@app.route('/api/sandbox-check', methods=['POST'])
def sandbox_check():
    """
    Tier 3 Analysis: Sandbox check for unknown URLs
    
    Request:
    {
        "url": "https://suspicious-link.com"
    }
    
    Response:
    {
        "url": "https://suspicious-link.com",
        "verdict": "DANGEROUS" | "SUSPICIOUS" | "SAFE",
        "confidence": 0-100,
        "details": "Malicious: 5, Suspicious: 2, Safe: 83",
        "engines_count": 90,
        "malicious_count": 5,
        "suspicious_count": 2,
        "features": {...},
        "timestamp": "2026-01-31T12:34:56"
    }
    """
    try:
        # Get URL from request
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({
                "error": "Missing 'url' parameter"
            }), 400
        
        url = data.get('url', '').strip()
        if not url:
            return jsonify({
                "error": "URL cannot be empty"
            }), 400
        
        logger.info(f"Sandbox check request for: {url}")
        
        # Extract URL features
        features = URLFeatureAnalyzer.extract_features(url)
        logger.info(f"URL Features: {features}")
        
        # Perform sandbox analysis
        verdict = sandbox.analyze_url(url)
        
        # Update statistics
        stats["total_checks"] += 1
        if verdict["verdict"] == "DANGEROUS":
            stats["dangerous_count"] += 1
        elif verdict["verdict"] == "SUSPICIOUS":
            stats["suspicious_count"] += 1
        else:
            stats["safe_count"] += 1
        
        # Add features to response
        verdict["features"] = features
        verdict["timestamp"] = datetime.now().isoformat()
        
        # Determine HTTP status based on verdict
        status_code = 200
        if verdict["verdict"] == "DANGEROUS":
            status_code = 200  # Still 200 but app will handle verdict
        
        logger.info(f"Verdict: {verdict['verdict']} (Confidence: {verdict['confidence']}%)")
        return jsonify(verdict), status_code
        
    except Exception as e:
        logger.error(f"Error in sandbox_check: {str(e)}")
        return jsonify({
            "error": f"Analysis failed: {str(e)}",
            "verdict": "UNKNOWN"
        }), 500


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get analysis statistics"""
    return jsonify({
        "total_checks": stats["total_checks"],
        "dangerous_count": stats["dangerous_count"],
        "suspicious_count": stats["suspicious_count"],
        "safe_count": stats["safe_count"],
        "timestamp": datetime.now().isoformat()
    }), 200


@app.route('/api/test', methods=['GET'])
def test_endpoint():
    """Test endpoint to verify backend is working"""
    return jsonify({
        "message": "TrustShield Sandbox Backend is running!",
        "version": "1.0",
        "endpoints": [
            "GET /health - Health check",
            "POST /api/sandbox-check - Analyze URL",
            "GET /api/stats - Get statistics",
            "GET /api/test - Test endpoint"
        ]
    }), 200


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({
        "error": "Endpoint not found",
        "available_endpoints": [
            "/health",
            "/api/sandbox-check (POST)",
            "/api/stats",
            "/api/test"
        ]
    }), 404


@app.errorhandler(500)
def server_error(error):
    """Handle 500 errors"""
    return jsonify({
        "error": "Internal server error",
        "message": str(error)
    }), 500


if __name__ == '__main__':
    # Check if API key is configured
    if VIRUSTOTAL_API_KEY == 'YOUR_API_KEY_HERE':
        logger.warning("⚠️  VIRUSTOTAL_API_KEY not configured!")
        logger.warning("Get a free key from: https://www.virustotal.com/gui/")
        logger.warning("Set environment variable: VIRUSTOTAL_API_KEY=your_key")
        logger.warning("Backend will work but sandbox analysis will fail")
    else:
        logger.info("✅ VirusTotal API key configured")
    
    # Run Flask app
    logger.info("🚀 Starting TrustShield Sandbox Backend...")
    logger.info("📍 Running on http://0.0.0.0:5000")
    logger.info("📱 Android app should connect to this backend")
    
    app.run(
        host='0.0.0.0',  # Listen on all interfaces (for WiFi access)
        port=5000,
        debug=True
    )
