import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from core_engine import link_threat_pipeline as ltp
from core_engine.link_threat_pipeline import (
    BRAND_FAST_PATH_DOMAINS, GLOBAL_CLEAN_DOMAINS, USER_CONTENT_HOSTS,
    LinkThreatPipeline, is_brand_fast_path, is_user_content_host,
)


class StubDB:
    def check_indicator(self, url):
        return False


CLEAN_SANDBOX = {
    "sandbox_has_password_field": 0, "external_form_action": 0, "suspicious_exfiltration": 0,
    "domain_age_days": -1, "domain_risk_score": 0, "brand_impersonation": 0,
    "sandbox_hidden_iframes": 0, "sandbox_title_mismatch": 0, "sandbox_unreachable": 0,
    "sandbox_threat_score": 0,
}


class FakeVT:
    def __init__(self, rep):
        self.rep = rep

    def get_vt_reputation(self, url):
        return self.rep

    def is_known_good_domain(self, url):
        return self.rep.get("is_whitelisted", False)


@pytest.fixture
def pipeline(monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    p = LinkThreatPipeline(threat_db=StubDB())
    p.calls = []

    def fake_sandbox(url):
        p.calls.append(url)
        return dict(CLEAN_SANDBOX)

    p.sandbox.analyze_link_in_sandbox = fake_sandbox
    return p


@pytest.mark.parametrize("url", [
    "https://docs.google.com/forms/d/abc", "https://forms.gle/xyz", "https://drive.google.com/x",
    "https://evil.sharepoint.com/page", "https://foo.blob.core.windows.net/x", "https://github.com/a/b",
    "https://bit.ly/abc", "https://t.me/scam", "https://user.github.io/", "https://x.blogspot.com/",
])
def test_user_content_is_not_fast_path(url):
    assert is_user_content_host(url)
    assert not is_brand_fast_path(url)


@pytest.mark.parametrize("url", ["https://google.com/", "https://www.paypal.com/signin", "https://mail.google.com/x"])
def test_brand_is_fast_path(url):
    assert is_brand_fast_path(url)
    assert not is_user_content_host(url)


def test_sets_are_disjoint_by_registered_domain_and_exported():
    assert not (BRAND_FAST_PATH_DOMAINS & USER_CONTENT_HOSTS)
    assert GLOBAL_CLEAN_DOMAINS == BRAND_FAST_PATH_DOMAINS
    assert "github.com" not in GLOBAL_CLEAN_DOMAINS and "sharepoint.com" not in GLOBAL_CLEAN_DOMAINS


def test_brand_skips_sandbox_with_zero_score(pipeline):
    r = pipeline.analyze_url("https://google.com/")
    assert r["threat_score"] == 0.0 and r["verdict"] == "LEGITIMATE / CLEAN"
    assert pipeline.calls == []


def test_user_content_goes_through_sandbox(pipeline):
    r = pipeline.analyze_url("https://docs.google.com/forms/d/abc")
    assert pipeline.calls, "docs.google.com must be sandboxed"
    assert r["telemetry"].get("status") != "WHITELISTED"


def test_vt_rank_does_not_whitelist_user_content(pipeline):
    pipeline.good_domain_checker = FakeVT({"is_whitelisted": True, "vt_risk_score": 0.0, "malicious_count": 0})
    pipeline.analyze_url("https://evil.sharepoint.com/login")
    assert pipeline.calls
    assert not pipeline.is_globally_whitelisted("https://evil.sharepoint.com/login")


def test_vt_rank_whitelists_unknown_non_user_content(pipeline):
    pipeline.good_domain_checker = FakeVT({"is_whitelisted": True, "vt_risk_score": 0.0, "malicious_count": 0})
    r = pipeline.analyze_url("https://some-popular-site.example.org/")
    assert r["threat_score"] == 0.0 and pipeline.calls == []


def test_brand_stays_clean_when_vt_rate_limited(pipeline):
    pipeline.good_domain_checker = FakeVT({"is_whitelisted": False, "vt_risk_score": 35.0,
                                           "malicious_count": 0, "provider": "rate_limited"})
    r = pipeline.analyze_url("https://www.amazon.com/")
    assert r["threat_score"] == 0.0 and pipeline.calls == []


def test_brand_with_vt_malicious_is_not_fast_path(pipeline):
    pipeline.good_domain_checker = FakeVT({"is_whitelisted": False, "vt_risk_score": 95.0, "malicious_count": 5})
    r = pipeline.analyze_url("https://www.amazon.com/")
    assert pipeline.calls
    assert r["threat_score"] >= 90


def test_unreachable_passes_through_to_decision(pipeline):
    pipeline.sandbox.analyze_link_in_sandbox = lambda url: dict(CLEAN_SANDBOX, sandbox_unreachable=1,
                                                                 sandbox_threat_score=40)
    r = pipeline.analyze_url("https://unknown-site.example.net/")
    assert r["analysis_complete"] is False
    assert r["telemetry"]["analysis_complete"] is False


def test_free_hosting_subdomains_are_never_vouched_for_by_the_platform_rank():
    from core_engine.link_threat_pipeline import is_user_content_host, is_brand_fast_path
    for url in ("https://evil-login.vercel.app/", "http://x.pages.dev/a", "https://a.b.netlify.app/", "https://z.onrender.com/"):
        assert is_user_content_host(url)
        assert not is_brand_fast_path(url)


def test_brand_domain_stays_clean_when_virustotal_shows_a_few_flags(monkeypatch):
    """Regression: VirusTotal lists ~2 engines against google.com; the pipeline once turned that into 'phishing'."""
    from core_engine import link_threat_pipeline as ltp
    from core_engine.final_decision_engine import FinalDecisionEngine

    class FakeVT:
        def get_vt_reputation(self, url):
            return {"is_whitelisted": True, "malicious_count": 2, "required_engines": 15,
                    "popularity_rank": 1, "vt_risk_score": 10.0}

    class NoDb:
        def check_indicator(self, u):
            return False
    pipe = ltp.LinkThreatPipeline.__new__(ltp.LinkThreatPipeline)
    pipe.threat_db, pipe.good_domain_checker, pipe.decision_engine = NoDb(), FakeVT(), FinalDecisionEngine()
    pipe.sandbox = None            # must not even be needed: brand fast path
    out = pipe.analyze_url("https://www.google.com/")
    assert out["verdict"].startswith("LEGITIMATE") and out["threat_score"] == 0.0
