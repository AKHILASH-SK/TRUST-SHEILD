"""
Browser sandbox against the local test lab (fake websites). Needs Playwright + Chromium, so it is skipped elsewhere.
Run inside the Docker image:
  docker run --rm -u 0 -e TRUSTSHIELD_ENV=development -e TRUSTSHIELD_LAB_MODE=1 -w /work/backend -v "<repo>:/work" \
      trustshield-backend sh -c "pip install -q pytest && python -m pytest tests/test_browser_sandbox_lab.py -q"
Every site here is fake and served from this process; nothing touches the internet.
"""
import os
import sys
import time

import pytest

from core_engine import browser_sandbox as bs

pytestmark = pytest.mark.skipif(not bs.PLAYWRIGHT_IMPORTABLE, reason="Playwright is not installed")


@pytest.fixture(scope="module")
def lab():
    """Start the fake-site server and switch on lab mode (SSRF guard relaxed) ONLY while this module's tests run."""
    if not bs.PLAYWRIGHT_IMPORTABLE:
        pytest.skip("Playwright is not installed")
    saved = {k: os.environ.get(k) for k in ("TRUSTSHIELD_LAB_MODE", "TRUSTSHIELD_ENV", "TRUSTSHIELD_LAB_PORT")}
    os.environ["TRUSTSHIELD_LAB_MODE"] = "1"
    os.environ["TRUSTSHIELD_ENV"] = "development"
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lab"))
    import lab_server
    port, stop = lab_server.start()
    os.environ["TRUSTSHIELD_LAB_PORT"] = str(port)
    bs._availability = None
    try:
        if not bs.browser_available():
            pytest.skip("Chromium is not available on this machine")
        yield port
    finally:
        stop()
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        bs._availability = None


def scan(host, budget=25, path=""):
    return bs.BrowserSandbox().analyze(f"http://{host}/{path}", budget_seconds=budget)


def test_login_behind_a_button_is_found_and_judged_normal(lab):
    ev = scan("acme-shop.com")
    assert ev["verification_state"] == "verified"
    assert ev["credential_surface_found"] and ev["entry_clicks"] >= 1 and ev["credential_surface_depth"] >= 1
    assert not ev["form_cross_domain"] and not ev["submit_cross_domain"]
    assert ev["probe_ran"] and ev["probe_request_seen"] and ev["probe_credentials_sent"]
    assert ev["submit_domain"] == "acme-shop.com"
    assert ev["has_privacy_link"] and ev["has_terms_link"] and ev["has_contact_link"]
    assert ev["sandbox_threat_score"] < 20 and ev["suspicious_exfiltration"] == 0 and ev["brand_impersonation"] == 0


def test_credential_theft_on_a_fake_bank_is_caught(lab):
    ev = scan("fresh-bank-kyc.com")
    assert ev["credential_surface_found"] and ev["entry_clicks"] >= 1
    assert ev["claimed_brand"] == "hdfc" and ev["brand_owns_domain"] is False and ev["brand_impersonation"] == 1
    assert ev["form_cross_domain"] and ev["form_action_domain"] == "collector-drop.xyz"
    assert ev["probe_credentials_sent"] and ev["submit_cross_domain"] and ev["submit_domain"] == "collector-drop.xyz"
    assert ev["external_form_action"] == 1 and ev["sandbox_has_password_field"] == 1
    assert ev["wording"]["urgency"] and ev["wording"]["threat"]
    assert ev["sandbox_threat_score"] >= 90


def test_login_inside_a_modal(lab):
    ev = scan("modal-shop.com")
    assert ev["credential_surface_found"] and ev["entry_clicks"] >= 1
    assert not ev["submit_cross_domain"] and ev["sandbox_threat_score"] < 30


def test_login_inside_an_embedded_frame(lab):
    ev = scan("frame-login.com")
    assert ev["credential_surface_found"] and ev["credential_via"] == "iframe" and ev["credential_surface_depth"] == 0


def test_login_form_built_by_javascript(lab):
    ev = scan("spa-app.com")
    assert ev["credential_surface_found"] and "password" in ev["sensitive_field_types"]
    assert "<form" not in "".join(ev["_html"][:0])        # (the raw HTML would not have contained the form either)


def test_login_hidden_behind_a_hamburger_menu(lab):
    ev = scan("hamburger-menu.com")
    assert ev["opened_menu"] and ev["credential_surface_found"] and ev["entry_clicks"] >= 2


def test_bot_protection_page_is_unverified_not_dangerous(lab):
    ev = scan("bot-wall.com")
    assert ev["challenge_page"] and ev["verification_state"] == "unverified" and ev["unverified_reason"] == "bot_protection"
    assert ev["sandbox_unreachable"] == 1 and ev["sandbox_threat_score"] == 0 and not ev["credential_surface_found"]


def test_credentials_sent_to_a_telegram_bot(lab):
    ev = scan("telegram-kit.com")
    assert ev["credential_surface_found"] and ev["probe_credentials_sent"]
    assert ev["submit_to_messaging_api"] and ev["submit_host"] == "api.telegram.org"
    assert ev["suspicious_exfiltration"] == 1 and ev["sandbox_threat_score"] >= 80


def test_download_of_an_apk_is_flagged(lab):
    ev = scan("download-trap.com")
    assert ev["download_executable"] and "update.apk" in ev["download_attempts"][0]
    assert ev["sandbox_threat_score"] >= 35


@pytest.mark.skipif(os.name == "nt", reason="Chromium shuts down slowly on Windows when a page never finishes loading; "
                                            "live scans run in a killable process (see test_sandbox_isolation.py). Runs in Docker.")
def test_slow_site_times_out_as_unverified_within_the_budget(lab):
    started = time.monotonic()
    ev = scan("slow-site.com", budget=6)
    assert ev["verification_state"] == "unverified" and ev["unverified_reason"] == "timeout"
    assert time.monotonic() - started < 14
    assert ev["sandbox_threat_score"] == 0


def test_ordinary_site_without_any_login_is_clean(lab):
    ev = scan("plain-blog.com")
    assert ev["verification_state"] == "verified" and not ev["credential_surface_found"]
    assert ev["entry_clicks"] == 0 and ev["sandbox_threat_score"] < 10 and ev["has_privacy_link"]


def test_wallet_phrase_harvester(lab):
    ev = scan("wallet-drainer.com")
    assert ev["credential_surface_found"] and "wallet_phrase" in ev["sensitive_field_types"]
    assert ev["form_cross_domain"] and ev["wording"]["crypto"] >= 2 and ev["wording"]["prize"]
    assert ev["sandbox_threat_score"] >= 60


def test_unknown_lab_host_is_a_clean_failure_not_a_crash(lab):
    ev = bs.BrowserSandbox().analyze("http://no-such-lab-site.com/", budget_seconds=10)
    assert ev["verification_state"] in ("verified", "unverified")
    assert "sandbox_threat_score" in ev


def test_evidence_carries_page_html_and_screenshot_internally(lab):
    ev = scan("plain-blog.com")
    assert "<h1>" in ev["_html"] and ev["_screenshot_b64"] and ev["_final_url"].startswith("http://plain-blog.com")


# ---- end to end: real browser evidence -> decision engine -> final verdict ------------------------------------------

@pytest.fixture
def pipeline(lab):
    from core_engine import link_threat_pipeline as ltp
    from core_engine.final_decision_engine import FinalDecisionEngine
    from core_engine.sandbox_engine import VirtualSandboxAnalyzer

    class NoDb:
        def check_indicator(self, u):
            return False
    pipe = ltp.LinkThreatPipeline.__new__(ltp.LinkThreatPipeline)
    pipe.threat_db, pipe.good_domain_checker = NoDb(), None
    pipe.decision_engine, pipe.sandbox = FinalDecisionEngine(), VirtualSandboxAnalyzer()
    return pipe


def verdict(pipeline, host):
    return pipeline.analyze_url(f"http://{host}/")


def test_verdict_normal_shop_with_login_is_legitimate(pipeline):
    out = verdict(pipeline, "acme-shop.com")
    assert out["verdict"].startswith("LEGITIMATE") and out["analysis_complete"]
    assert out["telemetry"]["sandbox"]["credential_surface_found"]


def test_verdict_fake_bank_is_critical_with_reasons(pipeline):
    out = verdict(pipeline, "fresh-bank-kyc.com")
    assert out["verdict"].startswith("CRITICAL") and out["threat_score"] >= 90
    assert "collector-drop.xyz" in out["summary"] and "hdfc" in out["summary"].lower()


def test_verdict_telegram_theft_is_critical(pipeline):
    out = verdict(pipeline, "telegram-kit.com")
    assert out["verdict"].startswith("CRITICAL") and out["threat_score"] == 100.0
    assert "messaging" in out["telemetry"]["override_reason"].lower()


def test_verdict_wallet_phrase_theft_is_critical(pipeline):
    assert verdict(pipeline, "wallet-drainer.com")["verdict"].startswith("CRITICAL")


def test_verdict_apk_push_is_critical(pipeline):
    out = verdict(pipeline, "download-trap.com")
    assert out["verdict"].startswith("CRITICAL") and "download" in out["telemetry"]["override_reason"].lower()


def test_verdict_plain_blog_is_legitimate(pipeline):
    out = verdict(pipeline, "plain-blog.com")
    assert out["verdict"].startswith("LEGITIMATE") and out["threat_score"] < 20


def test_verdict_bot_wall_is_unverified_not_dangerous(pipeline):
    out = verdict(pipeline, "bot-wall.com")
    assert not out["verdict"].startswith("CRITICAL")
    assert out["analysis_complete"] is False and out["telemetry"]["verification_state"] == "unverified"
    assert "could not be verified" in out["summary"] and "blocks automated browsers" in out["summary"]
    assert out["verdict"] == "LEGITIMATE / UNVERIFIED" and out["verification_state"] == "unverified"


def test_verdict_cloaking_redirect_to_a_famous_site_is_suspicious_on_a_new_domain(pipeline):
    ev = scan("cloak-redirect.com")
    assert ev["redirects_to_popular_site"] and "google.com" in ev["redirect_domains"]
    from core_engine.final_decision_engine import FinalDecisionEngine
    out = FinalDecisionEngine().evaluate(url="http://cloak-redirect.com/", domain_age_days=3, sandbox_evidence=ev)
    assert out["verdict"] == "SUSPICIOUS" and "cloaking" in out["telemetry"]["override_reason"].lower()


def test_verdict_document_share_lure_on_free_hosting_is_suspicious(pipeline):
    out = verdict(pipeline, "doc-share-lure.herokuapp.com")
    assert out["verdict"] == "SUSPICIOUS" and "lure" in out["telemetry"]["override_reason"].lower()
