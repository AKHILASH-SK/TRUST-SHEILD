"""
TrustShield V2 - Unified EML Forensic Orchestrator Test (test_unified_email_pipeline.py)
Validates:
1. End-to-end multi-engine execution on raw .eml bytes.
2. Hop extraction & GeoLocation route map generation.
3. Link threat sandbox investigation.
4. Fused incident threat score calculation (Authentication + BEC + Tor Origin + Links).
5. Comprehensive SOC dossier output schema.
"""

import sys
import json
from pathlib import Path

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from core_engine.unified_email_pipeline import analyze_email_pipeline
from core_engine.test_email_forensics import generate_synthetic_phishing_eml


def test_unified_pipeline():
    print("=" * 80)
    print("🛡️  TESTING TRUSTSHIELD V2: UNIFIED EML FORENSIC ORCHESTRATOR")
    print("=" * 80)

    # 1. Generate Synthetic Phishing Email
    raw_eml = generate_synthetic_phishing_eml()
    print(f"\n[+] Generated Synthetic Raw .eml ({len(raw_eml)} bytes)")

    # 2. Run Unified Forensic Pipeline (using skip_link_sandbox=True for deterministic offline link testing)
    print("\n[+] Executing Unified Pipeline...")
    result = analyze_email_pipeline(raw_eml, skip_link_sandbox=True)

    # 3. Pretty Print Output
    print("\n[+] Unified Forensic Dossier:")
    print(json.dumps(result, indent=2))

    # 4. Assertions
    print("\n" + "=" * 80)
    print("🔍 VALIDATING UNIFIED ORCHESTRATOR SPECIFICATIONS")
    print("=" * 80)

    # Check 1: Evidence Hash
    sha256 = result.get("evidence_hash_sha256")
    assert sha256 and len(sha256) == 64, f"Invalid SHA-256 hash: {sha256}"
    print(f"  [✓] Chain-of-Custody SHA-256: {sha256[:16]}...{sha256[-8:]}")

    # Check 2: Metadata & BEC Spoofing
    meta = result.get("metadata", {})
    assert meta.get("reply_to_mismatch") is True, "BEC Reply-to mismatch must be True"
    print(f"  [✓] Metadata extracted: Subject='{meta.get('subject')}'")
    print(f"  [✓] BEC Indicator: reply_to_mismatch = {meta.get('reply_to_mismatch')}")

    # Check 3: Authentication Failures
    auth = result.get("authentication", {})
    assert auth.get("spf_pass") is False, "SPF should be False"
    assert auth.get("dmarc_pass") is False, "DMARC should be False"
    print(f"  [✓] Authentication Audited: SPF={auth.get('spf_pass')}, DMARC={auth.get('dmarc_pass')}")

    # Check 4: Origin Intelligence & Tor / Proxy Detection
    origin = result.get("origin_intelligence", {})
    assert origin.get("originating_ip") == "185.220.101.5", f"Unexpected origin IP: {origin.get('originating_ip')}"
    assert origin.get("is_anonymized_node") is True, "Origin IP 185.220.101.5 should be flagged as Tor/Proxy node"
    assert isinstance(origin.get("route_map"), list) and len(origin.get("route_map")) > 0
    print(f"  [✓] Origin IP: {origin.get('originating_ip')} ({origin.get('origin_country')})")
    print(f"  [✓] Anonymized Proxy / Tor Detected: is_anonymized_node = {origin.get('is_anonymized_node')}")
    print(f"  [✓] Route Map Hops Mapped for Leaflet: {len(origin.get('route_map'))} hops")

    # Check 5: Link Investigation
    links = result.get("link_investigation", [])
    assert len(links) >= 1, "Extracted links should be analyzed"
    print(f"  [✓] Link Investigation: Analyzed {len(links)} embedded link(s)")

    # Check 6: Overall Threat Score & Final Verdict
    # Indicators:
    # - SPF & DMARC fail (+30)
    # - BEC Reply-To mismatch (+35)
    # - Tor / Proxy Origin (+20)
    # Total from email headers alone = 85.0 -> Capped/Scored >= 85.0 (Critical Fraud)

    overall_score = result.get("overall_threat_score")
    verdict = result.get("verdict")

    assert overall_score >= 80.0, f"Expected critical score >= 80.0, got {overall_score}"
    assert verdict == "CRITICAL FRAUD / PHISHING", f"Expected 'CRITICAL FRAUD / PHISHING', got '{verdict}'"
    print(f"  [✓] Overall Threat Score: {overall_score}/100.0")
    print(f"  [✓] Final Verdict: {verdict}")

    # Check 7: Sender Domain MX Intelligence
    sender_mx = result.get("sender_domain_intelligence", {})
    assert "has_mx_records" in sender_mx, "Missing has_mx_records in sender_domain_intelligence"
    print(f"  [✓] Sender Domain MX Intelligence: {sender_mx.get('from_domain')} | has_mx={sender_mx.get('has_mx_records')} | primary_mx={sender_mx.get('primary_mx')}")

    # Check 8: Threat Actor Attribution
    attr = result.get("threat_attribution", {})
    assert attr.get("type") == "ANONYMIZED_INFRASTRUCTURE", f"Expected ANONYMIZED_INFRASTRUCTURE, got {attr.get('type')}"
    assert attr.get("confidence") == "HIGH", f"Expected HIGH confidence, got {attr.get('confidence')}"
    print(f"  [✓] Threat Actor Attribution: {attr.get('type')} (Confidence: {attr.get('confidence')})")
    print(f"      Rationale: {attr.get('details')}")

    # Check 9: Executive Incident Summary
    summary = result.get("incident_summary", "")
    assert "Threat Summary:" in summary
    assert "Key Forensic Evidence:" in summary
    assert "Recommended Action:" in summary
    print(f"\n[+] Generated Incident Summary:\n{summary}")

    # Check 10: Verify 100.0 score when an explicit phishing link is present
    print("\n[+] Testing Email with High-Threat Embedded Link...")
    from core_engine.threat_db import get_threat_db
    threat_db = get_threat_db()
    # Add a mock indicator
    malicious_url = "https://example.com/phish"
    threat_db.add_indicator(malicious_url, "PHISHING_TEST")

    result_malicious_link = analyze_email_pipeline(raw_eml, skip_link_sandbox=True)
    assert result_malicious_link["overall_threat_score"] == 100.0, (
        f"Expected 100.0, got {result_malicious_link['overall_threat_score']}"
    )
    assert result_malicious_link["verdict"] == "CRITICAL FRAUD / PHISHING"
    print(f"  [✓] Overall Score with Known Phishing Link: {result_malicious_link['overall_threat_score']}/100.0 (CRITICAL FRAUD / PHISHING)")

    # Check 11: Court-Admissible PDF Dossier Generation
    print("\n[+] Generating Court-Admissible PDF Dossier (forensic_report.pdf)...")
    from core_engine.report_generator import generate_pdf_dossier
    import os

    pdf_output = os.path.join(str(backend_dir), "forensic_report.pdf")
    generated_path = generate_pdf_dossier(result_malicious_link, output_path=pdf_output)
    
    assert os.path.exists(generated_path), f"PDF file was not created at {generated_path}"
    pdf_size = os.path.getsize(generated_path)
    assert pdf_size > 1000, f"Generated PDF is unexpectedly small: {pdf_size} bytes"
    print(f"  [✓] Court-Admissible PDF Dossier generated: {generated_path} ({pdf_size} bytes)")

    print("\n" + "=" * 80)
    print("🎯 ALL UNIFIED PIPELINE & FORENSIC DOSSIER CHECKS PASSED!")
    print("=" * 80)


if __name__ == "__main__":
    test_unified_pipeline()

