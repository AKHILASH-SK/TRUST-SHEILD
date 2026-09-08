import sys
from pathlib import Path
from io import BytesIO

backend_dir = Path(__file__).resolve().parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

import werkzeug
if not hasattr(werkzeug, '__version__'):
    werkzeug.__version__ = "3.0.0"

from app import app
from core_engine.test_email_forensics import generate_synthetic_phishing_eml


def run_tests():
    print("=" * 80)
    print("🌐 TESTING TRUSTSHIELD V2 SOC ANALYST PORTAL & ASSET INTEGRATION")
    print("=" * 80)

    client = app.test_client()

    # Test 1: Portal HTML serving
    res_portal = client.get('/portal')
    assert res_portal.status_code == 200, f"Expected 200, got {res_portal.status_code}"
    assert b"TrustShield V2" in res_portal.data, "Missing TrustShield in portal HTML"
    print("  [✓] GET /portal served successfully (HTTP 200)")

    # Test 2: Portal JS asset serving
    res_js = client.get('/portal/app.js')
    assert res_js.status_code == 200, f"Expected 200, got {res_js.status_code}"
    assert b"processEmlFile" in res_js.data, "Missing JS content"
    print("  [✓] GET /portal/app.js served successfully (HTTP 200)")

    # Test 3: EML Ingestion API
    eml_bytes = generate_synthetic_phishing_eml()
    data = {'file': (BytesIO(eml_bytes), 'phishing_sample.eml')}
    res_api = client.post('/api/forensics/analyze-eml?skip_sandbox=true', data=data, content_type='multipart/form-data')
    assert res_api.status_code == 200, f"Expected 200, got {res_api.status_code}"
    json_data = res_api.get_json()
    assert 'overall_threat_score' in json_data

    assert 'origin_intelligence' in json_data
    assert 'threat_attribution' in json_data
    score = json_data.get('overall_threat_score')
    verdict = json_data.get('verdict')
    print(f"  [✓] POST /api/forensics/analyze-eml succeeded: Score={score}/100.0 ({verdict})")

    # Test 4: PDF Export API
    res_pdf = client.post('/api/forensics/export-pdf', json=json_data)
    assert res_pdf.status_code == 200, f"Expected 200, got {res_pdf.status_code}"
    assert res_pdf.mimetype == 'application/pdf', f"Expected application/pdf, got {res_pdf.mimetype}"
    assert len(res_pdf.data) > 1000, "PDF size too small"
    print(f"  [✓] POST /api/forensics/export-pdf succeeded: PDF Size={len(res_pdf.data)} bytes")

    print("\n" + "=" * 80)
    print("🎯 ALL SOC ANALYST PORTAL SERVING & API ENDPOINTS VERIFIED 100%!")
    print("=" * 80)

if __name__ == "__main__":
    run_tests()
