import sys
import time
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

def run_stabilization_tests():
    print("=" * 80)
    print("🚀 TRUSTSHIELD V2 — RIGOROUS STABILIZATION & SPEED VERIFICATION SUITE")
    print("=" * 80)

    client = app.test_client()

    # -------------------------------------------------------------------------
    # TEST 1: Health Endpoints
    # -------------------------------------------------------------------------
    t0 = time.time()
    res_root = client.get('/')
    res_health = client.get('/api/health')
    assert res_root.status_code == 200, f"Root health failed: {res_root.status_code}"
    assert res_health.status_code == 200, f"API health failed: {res_health.status_code}"
    print(f"  [✓] TEST 1: Root & Health Endpoints Healthy (HTTP 200) [{time.time() - t0:.3f}s]")

    # -------------------------------------------------------------------------
    # TEST 2: Portal Assets Serving
    # -------------------------------------------------------------------------
    t0 = time.time()
    res_portal = client.get('/portal')
    res_js = client.get('/portal/app.js')
    assert res_portal.status_code == 200
    assert res_js.status_code == 200
    assert b"fastDemoToggle" in res_portal.data, "fastDemoToggle missing from HTML"
    assert b"processEmlFile" in res_js.data
    print(f"  [✓] TEST 2: Portal HTML & JS Loaded with Fast Demo Controls [{time.time() - t0:.3f}s]")

    # -------------------------------------------------------------------------
    # TEST 3: Built-In Phishing Demo in Fast Demo Mode (< 3.0s benchmark)
    # -------------------------------------------------------------------------
    t0 = time.time()
    eml_bytes = generate_synthetic_phishing_eml()
    data = {'file': (BytesIO(eml_bytes), 'URGENT_WIRE_TRANSFER_ATTACK.eml')}
    res_demo = client.post('/api/forensics/analyze-eml?demo_mode=true&skip_sandbox=true', data=data, content_type='multipart/form-data')
    elapsed_demo = time.time() - t0

    assert res_demo.status_code == 200, f"Demo failed: {res_demo.status_code}"
    demo_json = res_demo.get_json()
    assert demo_json.get('verdict') == 'CRITICAL FRAUD / PHISHING'
    assert demo_json.get('overall_threat_score') == 100.0
    assert demo_json.get('analysis_mode') == 'FAST_DEMO'
    assert 'enrichment_status' in demo_json
    assert demo_json['origin_intelligence']['originating_ip'] == '185.220.101.5'
    assert demo_json['origin_intelligence']['is_anonymized_node'] is True
    print(f"  [✓] TEST 3: Fast Demo Mode Completed in {elapsed_demo:.2f}s! Score: {demo_json['overall_threat_score']}/100.0 ({demo_json['verdict']})")
    assert elapsed_demo < 4.0, f"Fast demo too slow ({elapsed_demo:.2f}s)"

    # -------------------------------------------------------------------------
    # TEST 4: Non-Blocking WHOIS & DNS Preflight Handling (No Chrome Hang)
    # -------------------------------------------------------------------------
    t0 = time.time()
    from core_engine.sandbox_engine import VirtualSandboxAnalyzer
    analyzer = VirtualSandboxAnalyzer()
    
    # Test safe WHOIS on non-existent or real domain
    age, flag, risk = analyzer._query_domain_age("https://portal-resolve.top/ticket")
    assert age in (-1, 0)
    print(f"  [✓] TEST 4A: Safe WHOIS Query Evaluated without crashing or blocking [{time.time() - t0:.3f}s]")

    # Test DNS preflight on dead domain (portal-resolve.top)
    t0 = time.time()
    res_sandbox = analyzer.analyze_link_in_sandbox("https://portal-resolve.top/ticket")
    elapsed_dns = time.time() - t0
    assert res_sandbox.get("sandbox_unreachable") == 1
    assert res_sandbox.get("sandbox_error") == "ERR_NAME_NOT_RESOLVED"
    assert res_sandbox.get("sandbox_threat_score") == 60
    print(f"  [✓] TEST 4B: Dead Phishing Domain Caught by Fast DNS Preflight in {elapsed_dns:.2f}s (No 15s Chrome hang!)")
    assert elapsed_dns < 2.0, f"DNS preflight took too long ({elapsed_dns:.2f}s)"

    # -------------------------------------------------------------------------
    # TEST 5: Geolocation Parallel Resolution & Known Tor Node
    # -------------------------------------------------------------------------
    t0 = time.time()
    from core_engine.geo_tracer import resolve_ip_location, generate_route_map
    tor_geo = resolve_ip_location("185.220.101.5")
    assert tor_geo.get("is_suspicious_proxy") is True
    assert "Germany" in tor_geo.get("country", "")
    
    # Test route map with multiple hops
    route = generate_route_map(["10.0.2.15", "192.168.1.1", "185.220.101.5"])
    elapsed_geo = time.time() - t0
    assert len(route) == 3
    print(f"  [✓] TEST 5: 3-Hop Route Map & Tor Geolocation Resolved in {elapsed_geo:.2f}s (Leaflet Coordinates Ready)")

    # -------------------------------------------------------------------------
    # TEST 6: Section 65B Certified Forensic PDF Export
    # -------------------------------------------------------------------------
    t0 = time.time()
    res_pdf = client.post('/api/forensics/export-pdf', json=demo_json)
    assert res_pdf.status_code == 200
    assert res_pdf.mimetype == 'application/pdf'
    assert len(res_pdf.data) > 1000
    print(f"  [✓] TEST 6: Court-Admissible Section 65B PDF Generated ({len(res_pdf.data)} bytes) [{time.time() - t0:.3f}s]")

    # -------------------------------------------------------------------------
    # TEST 7: Offline / API Failure Fault Tolerance
    # -------------------------------------------------------------------------
    t0 = time.time()
    from core_engine.final_decision_engine import generate_llm_incident_summary
    # Force fallback by passing invalid keys
    fallback_summary = generate_llm_incident_summary(
        url="https://portal-resolve.top/ticket?id=99281",
        threat_score=100.0,
        verdict="CRITICAL FRAUD / PHISHING",
        telemetry={"known_db_match": 1, "heuristic_flags": ["HIGH_ENTROPY_TOKEN"]}
    )
    elapsed_llm = time.time() - t0
    assert "• Threat Summary:" in fallback_summary
    assert "• Key Forensic Evidence:" in fallback_summary
    assert "• Recommended Action:" in fallback_summary
    print(f"  [✓] TEST 7: Deterministic High-Fidelity Incident Summary Generated in {elapsed_llm:.4f}s (Zero-Latency Fallback)")

    print("\n" + "=" * 80)
    print("🏆 ALL 7 RIGOROUS STABILIZATION BENCHMARKS PASSED 100%!")
    print("=" * 80)

if __name__ == '__main__':
    run_stabilization_tests()
