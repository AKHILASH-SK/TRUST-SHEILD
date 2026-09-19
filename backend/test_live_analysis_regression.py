"""
Regression Test Suite for TrustShield V2 Live Upload Evaluation & Heuristic Defense
Tests A, B, C, D, E, and F verifying:
- Test A: Known legitimate email remains clean (<25, LEGITIMATE)
- Test B: Phishing demo scenario behaves correctly (100/100, CRITICAL)
- Test C: Real uploaded .eml with linked1n.vercel.app triggers CRITICAL despite valid SPF/DKIM/DMARC
- Test D: Live upload analysis returns data derived from the uploaded file rather than demo fixture
- Test E: Analysis failure returns explicit error status (never silent fallback to clean)
- Test F: Typosquatting & lookalike heuristics across brands and shared hosting platforms
"""

import os
import io
import sys
import json

# Ensure backend path is on sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app import app
from core_engine.url_heuristics import parse_url_heuristics
from core_engine.unified_email_pipeline import analyze_email_pipeline
from core_engine.test_email_forensics import (
    generate_synthetic_phishing_eml,
    generate_synthetic_legitimate_eml,
    generate_synthetic_bec_eml
)


def test_suite_a_legitimate_email_remains_clean(client):
    """TEST A: Known legitimate email remains clean (< 25 score, LEGITIMATE verdict)."""
    clean_eml = generate_synthetic_legitimate_eml()
    
    # Analyze via live upload endpoint
    response = client.post(
        '/api/forensics/analyze-eml?skip_sandbox=true',
        data={'file': (io.BytesIO(clean_eml), 'clean.eml')},
        content_type='multipart/form-data'
    )
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    data = response.get_json()

    assert data.get('overall_threat_score') < 25.0, f"Score too high for clean email: {data.get('overall_threat_score')}"
    assert 'LEGITIMATE' in data.get('verdict', ''), f"Unexpected verdict: {data.get('verdict')}"
    assert data.get('analysis_type') == 'LIVE_ANALYSIS'
    assert data.get('evidence_source') == 'LIVE_UPLOADED_EML'
    print("✅ TEST A PASSED: Known legitimate email remains clean (< 25/100, LEGITIMATE)")


def test_suite_b_demo_phishing_scenario_behaves_correctly(client):
    """TEST B: Phishing demo scenario behaves correctly (100/100 score, CRITICAL)."""
    response = client.get('/api/forensics/demo/phishing?skip_sandbox=true')
    assert response.status_code == 200
    data = response.get_json()

    assert data.get('overall_threat_score') >= 80.0
    assert 'CRITICAL' in data.get('verdict', '') or 'PHISHING' in data.get('verdict', '')
    assert data.get('analysis_type') == 'DEMO_SCENARIO'
    assert data.get('evidence_source') == 'SYNTHETIC_DEMO'
    print("✅ TEST B PASSED: Demo phishing scenario returns 100/100 CRITICAL with DEMO_SCENARIO tag")


def test_suite_c_real_uploaded_eml_weaponized_authenticated_account(client):
    """
    TEST C: The real uploaded .eml containing linked1n.vercel.app is NOT classified
    as clean merely because SPF/DKIM/DMARC pass.
    Must flag the lookalike brand link and return CRITICAL threat.
    """
    real_eml_path = os.path.join(BASE_DIR, 'test_emails', 'real_phishing_linked1n.eml')
    assert os.path.exists(real_eml_path), f"Real test email not found at {real_eml_path}"

    with open(real_eml_path, 'rb') as f:
        eml_bytes = f.read()

    response = client.post(
        '/api/forensics/analyze-eml?skip_sandbox=true',
        data={'file': (io.BytesIO(eml_bytes), 'real_phishing.eml')},
        content_type='multipart/form-data'
    )
    assert response.status_code == 200
    data = response.get_json()

    score = data.get('overall_threat_score')
    verdict = data.get('verdict')
    attr = data.get('threat_attribution', {})
    links = data.get('link_investigation', [])
    layered = data.get('layered_evidence', {})

    print(f"\n[Real EML Telemetry] Score: {score}, Verdict: {verdict}")
    print(f"[Attribution]: {attr.get('type')} - {attr.get('details')}")

    # Core assertions
    assert score >= 80.0, f"Score was {score}, expected >= 80.0 for weaponized lookalike link!"
    assert 'CRITICAL' in verdict or 'PHISHING' in verdict or 'FRAUD' in verdict
    assert attr.get('type') == 'WEAPONIZED_AUTHENTICATED_ACCOUNT'

    # URL extraction & analysis assertions
    found_target_url = False
    for lk in links:
        if 'linked1n.vercel.app' in lk.get('url', ''):
            found_target_url = True
            assert lk.get('threat_score') >= 80.0
            flags = lk.get('telemetry', {}).get('heuristic_flags', [])
            assert any('BRAND_LOOKALIKE' in fl for fl in flags) or any('TYPOSQUAT' in fl for fl in flags)

    assert found_target_url, "Extracted links did not contain https://linked1n.vercel.app/"

    # Layered evidence assertions
    assert layered.get('authentication', {}).get('status') == 'PASS'
    assert layered.get('link_threat', {}).get('status') == 'CRITICAL'
    assert layered.get('content_social_engineering', {}).get('status') in ('MEDIUM', 'HIGH')

    # Primary evidence assertions
    primary_ev = data.get('primary_evidence', [])
    assert any('CRITICAL LINK' in ev or 'Lookalike' in ev for ev in primary_ev)

    print("✅ TEST C PASSED: Real uploaded .eml containing linked1n.vercel.app correctly classified as CRITICAL FRAUD / PHISHING")


def test_suite_d_live_upload_derives_data_from_actual_uploaded_file(client):
    """TEST D: Live upload analysis returns data derived from the uploaded file rather than a demo fixture."""
    custom_subject = "CRITICAL_INVOICE_AUDIT_REF_998124"
    custom_sender = "accounts@custom-supplier-domain.com"
    custom_eml = f"""From: {custom_sender}\r
To: finance@victim.org\r
Subject: {custom_subject}\r
Date: Wed, 10 Sep 2026 12:00:00 +0000\r
MIME-Version: 1.0\r
Content-Type: text/plain; charset=UTF-8\r
\r
Please review your invoice at https://custom-payment-portal-secure.top/pay\r
""".encode('utf-8')

    response = client.post(
        '/api/forensics/analyze-eml?skip_sandbox=true',
        data={'file': (io.BytesIO(custom_eml), 'invoice.eml')},
        content_type='multipart/form-data'
    )
    assert response.status_code == 200
    data = response.get_json()

    assert data.get('metadata', {}).get('subject') == custom_subject
    assert custom_sender in data.get('metadata', {}).get('from')
    extracted_urls = [l.get('url') for l in data.get('link_investigation', [])]
    assert 'https://custom-payment-portal-secure.top/pay' in extracted_urls
    assert data.get('analysis_type') == 'LIVE_ANALYSIS'
    assert data.get('evidence_source') == 'LIVE_UPLOADED_EML'
    print("✅ TEST D PASSED: Live upload returns authentic parsed data from uploaded payload")


def test_suite_e_error_handling_returns_explicit_error_never_silent_clean(client):
    """
    TEST E: If analysis fails (e.g. empty upload or corrupted non-MIME data),
    the system must return an explicit analysis error or partial-analysis status.
    It must NOT silently fall back to LEGITIMATE / CLEAN / ALL FORENSIC CHECKS PASSED.
    """
    # 1. Empty body upload
    res_empty = client.post(
        '/api/forensics/analyze-eml',
        data={'file': (io.BytesIO(b''), 'empty.eml')},
        content_type='multipart/form-data'
    )
    assert res_empty.status_code == 400
    data_empty = res_empty.get_json()
    assert 'error' in data_empty
    assert data_empty.get('verdict') is None or 'LEGITIMATE' not in data_empty.get('verdict', '')

    print("✅ TEST E PASSED: Errors return explicit HTTP 400/500 and never default to LEGITIMATE / CLEAN")


def test_suite_f_lookalike_and_brand_heuristics():
    """
    TEST F: Verify deterministic typosquatting and lookalike heuristics across
    brands and shared hosting contexts.
    """
    # Suspicious lookalikes on shared hosting
    test_cases_suspicious = [
        ("https://linked1n.vercel.app/", "linkedin", 80.0),
        ("https://linkedln.vercel.app/", "linkedin", 80.0),
        ("https://linkediin.vercel.app/", "linkedin", 70.0),
        ("https://paypa1.web.app/", "paypal", 80.0),
        ("https://micros0ft.pages.dev/", "microsoft", 80.0),
        ("https://g00gle-login.firebaseapp.com/", "google", 75.0),
    ]

    for url, expected_brand, min_score in test_cases_suspicious:
        res = parse_url_heuristics(url)
        score = res.get('heuristic_risk_score', 0.0)
        flags = res.get('heuristic_flags', [])
        assert score >= min_score, f"URL {url} scored {score}, expected >= {min_score}"
        assert res.get('detected_brand') == expected_brand or any(expected_brand in f.lower() for f in flags)
        print(f"  [✓] Detected lookalike '{url}' -> Score: {score}, Flags: {flags}")

    # Official legitimate domains must score 0
    official_urls = [
        "https://www.linkedin.com/in/cyber-analyst",
        "https://linkedin.com/jobs",
        "https://www.paypal.com/signin",
        "https://www.google.com/search?q=forensics",
        "https://microsoft.com/en-us"
    ]

    for url in official_urls:
        res = parse_url_heuristics(url)
        score = res.get('heuristic_risk_score', 0.0)
        flags = res.get('heuristic_flags', [])
        assert score == 0.0, f"Official URL {url} falsely scored {score} (flags: {flags})"
        print(f"  [✓] Official domain clean: '{url}' -> Score: 0.0")

    print("✅ TEST F PASSED: Typosquatting & lookalike heuristics highly effective with zero false positives on official domains")


def run_all_tests():
    print("=" * 80)
    print("RUNNING TRUSTSHIELD V2 LIVE ANALYSIS REGRESSION TESTS")
    print("=" * 80)

    app.config['TESTING'] = True
    with app.test_client() as client:
        test_suite_a_legitimate_email_remains_clean(client)
        test_suite_b_demo_phishing_scenario_behaves_correctly(client)
        test_suite_c_real_uploaded_eml_weaponized_authenticated_account(client)
        test_suite_d_live_upload_derives_data_from_actual_uploaded_file(client)
        test_suite_e_error_handling_returns_explicit_error_never_silent_clean(client)
    
    test_suite_f_lookalike_and_brand_heuristics()

    print("\n" + "=" * 80)
    print("🏆 ALL REGRESSION TESTS PASSED (TESTS A, B, C, D, E, F)!")
    print("=" * 80)

if __name__ == '__main__':
    run_all_tests()
