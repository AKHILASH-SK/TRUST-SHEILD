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


def test_site_builders_go_through_the_sandbox(pipeline):
    # every tenant of a site builder is a different website: the platform's reputation says nothing about the page
    r = pipeline.analyze_url("https://sites.google.com/view/fake-login")
    assert pipeline.calls, "sites.google.com must be sandboxed"
    assert r["telemetry"].get("status") != "WHITELISTED"


def test_vt_rank_does_not_whitelist_site_builders_or_free_hosting(pipeline):
    pipeline.good_domain_checker = FakeVT({"is_whitelisted": True, "vt_risk_score": 0.0, "malicious_count": 0})
    pipeline.analyze_url("https://evil.vercel.app/login")
    assert pipeline.calls


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


# ---- VirusTotal gives a proportional score; the sandbox decides unless the engines are in consensus ----

def _pipeline_with(vt_dict, sandbox_features):
    from core_engine import link_threat_pipeline as ltp
    from core_engine.final_decision_engine import FinalDecisionEngine

    class FakeVT:
        def get_vt_reputation(self, url):
            return vt_dict

    class FakeSandbox:
        def analyze_link_in_sandbox(self, url):
            return dict(sandbox_features)

    class NoDb:
        def check_indicator(self, u):
            return False
    pipe = ltp.LinkThreatPipeline.__new__(ltp.LinkThreatPipeline)
    pipe.threat_db, pipe.good_domain_checker = NoDb(), FakeVT()
    pipe.decision_engine, pipe.sandbox = FinalDecisionEngine(), FakeSandbox()
    return pipe


CLEAN_PAGE = {"sandbox_has_password_field": 0, "external_form_action": 0, "suspicious_exfiltration": 0,
              "domain_age_days": 900, "domain_risk_score": 0, "sandbox_threat_score": 0, "sandbox_unreachable": 0}


def test_two_of_seventy_goes_to_the_sandbox_and_a_clean_page_clears_it():
    vt = {"is_whitelisted": False, "malicious_count": 2, "suspicious_count": 0, "total_engines": 70,
          "detection_ratio": 0.0286, "vt_risk_score": 45.7, "popularity_rank": 99999999}
    out = _pipeline_with(vt, CLEAN_PAGE).analyze_url("https://small-business.example/contact")
    assert out["verdict"].startswith("LEGITIMATE")
    assert out["telemetry"]["vt_detections"] == 2 and out["telemetry"]["vt_engines"] == 70
    assert "VirusTotal: 2 of 70 engines" in out["summary"]


def test_two_of_seventy_plus_a_credential_trap_in_the_sandbox_is_dangerous():
    vt = {"is_whitelisted": False, "malicious_count": 2, "suspicious_count": 0, "total_engines": 70,
          "detection_ratio": 0.0286, "vt_risk_score": 45.7, "popularity_rank": 99999999}
    page = {**CLEAN_PAGE, "sandbox_has_password_field": 1, "suspicious_exfiltration": 1, "sandbox_threat_score": 100,
            "domain_age_days": 3, "domain_risk_score": 90}
    out = _pipeline_with(vt, page).analyze_url("https://secure-bank-login.example/verify")
    assert out["verdict"].startswith("CRITICAL")


def test_consensus_of_engines_blocks_without_needing_the_sandbox():
    vt = {"is_whitelisted": False, "malicious_count": 35, "suspicious_count": 0, "total_engines": 70,
          "detection_ratio": 0.5, "vt_risk_score": 95.0, "popularity_rank": 99999999}
    out = _pipeline_with(vt, CLEAN_PAGE).analyze_url("https://known-bad.example/")
    assert out["threat_score"] >= 90 and "VirusTotal" in out["summary"]


@pytest.mark.parametrize("url", [
    "https://docs.google.com/spreadsheets/d/1AbC/edit#gid=0", "https://docs.google.com/document/d/1AbC/edit",
    "https://docs.google.com/u/0/presentation/d/1AbC/edit", "https://drive.google.com/file/d/1AbC/view",
    "https://drive.google.com/drive/folders/1AbC", "https://github.com/torvalds/linux",
])
def test_pages_that_only_show_a_document_or_repository_skip_the_sandbox(pipeline, url):
    assert ltp.is_trusted_view_page(url)
    out = pipeline.analyze_url(url)
    assert out["display_verdict"] == "Dangerous" or out["display_verdict"] == "Safe"
    assert out["display_verdict"] == "Safe" and pipeline.calls == []


@pytest.mark.parametrize("url", [
    "https://docs.google.com/forms/d/e/1FAIpQLSabc/viewform",       # can collect a login
    "https://sites.google.com/view/fake-login", "https://script.google.com/macros/s/abc/exec", "https://forms.gle/xyz",
    "https://github.com/a/b/releases/download/v1/setup.exe", "https://github.com/login",
    "https://evil-docs.google.com.example.xyz/spreadsheets/d/1",   # not Google at all
])
def test_pages_that_can_collect_a_login_or_deliver_a_file_are_still_sandboxed(url):
    assert not ltp.is_trusted_view_page(url) and not is_brand_fast_path(url)


def test_a_sub_domain_of_a_top_ranked_company_is_recognised_without_virustotal(pipeline):
    assert "stackoverflow.com" in ltp.TOP_DOMAINS or "wikipedia.org" in ltp.TOP_DOMAINS
    for url in ("https://learn.microsoft.com/en-us/azure/", "https://aws.amazon.com/ec2/", "https://meet.google.com/abc-defg-hij"):
        assert is_brand_fast_path(url)
    out = pipeline.analyze_url("https://learn.microsoft.com/en-us/azure/")
    assert out["display_verdict"] == "Safe" and pipeline.calls == []


def test_the_top_domain_list_never_vouches_for_hosting_platforms():
    for host in ("blogspot.com", "github.io", "vercel.app", "weebly.com", "bit.ly", "duckdns.org", "000webhostapp.com"):
        assert host not in ltp.TOP_DOMAINS and not is_brand_fast_path(f"https://x.{host}/")


@pytest.mark.parametrize("url", [
    "https://www.google.com/url?q=https://evil.example/login", "https://l.facebook.com/l.php?u=https%3A%2F%2Fevil.example%2F",
    "https://accounts.google.com/signin?continue=https://evil.example/",
])
def test_a_trusted_site_forwarding_to_another_domain_is_still_sandboxed(url):
    assert ltp.has_foreign_redirect(url) and not is_brand_fast_path(url)
    assert not ltp.has_foreign_redirect("https://accounts.google.com/signin?continue=https://mail.google.com/")


@pytest.mark.parametrize("url", [
    "https://docs.google.com/forms/d/e/1FAIpQLSeIbAwwDmGz1fDpICAXPkFVG9wbWPjcg1BpphK84NgkAI48UA/viewform",
    "https://forms.gle/abc123", "https://forms.office.com/r/abc", "https://acme.sharepoint.com/sites/x/doc.aspx",
    "https://www.typeform.com/to/abc", "https://github.com/a/b/releases/download/v1/x.zip", "https://medium.com/@x/post",
])
def test_pages_on_trusted_collaboration_platforms_skip_the_sandbox(pipeline, url):
    assert ltp.is_collab_platform(url)
    out = pipeline.analyze_url(url)
    assert out["display_verdict"] == "Safe" and pipeline.calls == []


@pytest.mark.parametrize("url", [
    "https://sites.google.com/view/fake-login", "https://script.google.com/macros/s/abc/exec", "https://user.github.io/",
    "https://x.blogspot.com/", "https://app.vercel.app/", "https://bit.ly/abc", "https://storage.googleapis.com/b/x.html",
    "https://docs.google.com.evil.xyz/forms/d/e/1/viewform",
    "https://www.google.com/url?q=https://evil.example/", "https://forms.gle/x?continue=https://evil.example/login",
])
def test_site_builders_shorteners_file_hosts_and_forwarding_links_stay_sandboxed(pipeline, url):
    assert not ltp.is_collab_platform(url)
    pipeline.analyze_url(url)
    assert pipeline.calls == [url]


def test_trusting_collaboration_platforms_can_be_switched_off(pipeline, monkeypatch):
    monkeypatch.setattr(ltp, "TRUST_COLLAB_PLATFORMS", False)
    url = "https://forms.gle/abc123"
    assert not ltp.is_collab_platform(url)
    pipeline.analyze_url(url)
    assert pipeline.calls == [url]


def test_virustotal_consensus_still_beats_a_trusted_platform(pipeline):
    pipeline.good_domain_checker = FakeVT({"vt_risk_score": 95.0, "malicious_count": 20, "suspicious_count": 0,
                                           "total_engines": 70, "detection_ratio": 0.3, "is_whitelisted": False})
    pipeline.analyze_url("https://forms.gle/abc123")
    assert pipeline.calls == ["https://forms.gle/abc123"]


@pytest.mark.parametrize("url", ["https://www.hdfcbank.com/login", "https://netbanking.hdfcbank.com/", "https://www.paypal.com/signin",
                                 "https://secure.icicibank.com/"])
def test_official_domains_of_the_known_brands_are_trusted_and_lookalikes_are_not(url):
    assert is_brand_fast_path(url)


@pytest.mark.parametrize("url", ["https://hdfcbank-secure-login.com/", "https://hdfcbank.com.evil.example/", "https://paypal-verify.top/",
                                 "https://hdfc-bank.xyz/"])
def test_lookalikes_of_brand_domains_are_not_trusted(url):
    assert not is_brand_fast_path(url)
