"""Verified-clean pages, repeatable verdicts, scan evidence rows and the public phishing feeds (no network, no database)."""
import app as backend_app
from core_engine.final_decision_engine import FinalDecisionEngine
from phishing_feed import PhishingFeedImporter

CLEAN_EVIDENCE = {"verification_state": "verified", "credential_surface_found": False, "sensitive_field_types": []}
MODERATE_ML = {"score": 55.0, "probability": 0.67, "band": "SUSPICIOUS", "model": "page", "signals": ["ev n links"]}


def evaluate(evidence, ml=MODERATE_ML, **kwargs):
    return FinalDecisionEngine().evaluate(url="https://small-shop.example/", ml=ml, sandbox_evidence=evidence,
                                          domain_age_days=-1, **kwargs)


# ---- verified-clean rule ------------------------------------------------------------------------------------------

def test_clean_inspected_page_is_not_made_suspicious_by_a_moderate_model_score():
    out = evaluate(CLEAN_EVIDENCE)
    assert out["verdict"] == "LEGITIMATE / CLEAN" and out["threat_score"] <= 25


def test_the_rule_does_not_apply_when_the_page_has_a_login_form_or_flags_or_is_uninspected():
    assert evaluate({**CLEAN_EVIDENCE, "credential_surface_found": True})["verdict"].startswith("SUSPICIOUS")
    assert evaluate(CLEAN_EVIDENCE, heuristic_flags=["SUSPICIOUS_TLD"])["verdict"].startswith("SUSPICIOUS")
    assert evaluate({**CLEAN_EVIDENCE, "verification_state": "partial"})["verdict"].startswith("SUSPICIOUS")
    assert evaluate(CLEAN_EVIDENCE, free_hosting=True)["verdict"].startswith("SUSPICIOUS")
    assert evaluate(CLEAN_EVIDENCE, vt_risk_score=45.7)["verdict"].startswith(("SUSPICIOUS", "CRITICAL"))


def test_a_confident_model_still_wins_on_a_clean_looking_page():
    confident = {**MODERATE_ML, "score": 92.0, "probability": 0.95}
    assert evaluate(CLEAN_EVIDENCE, ml=confident)["verdict"].startswith("CRITICAL")


# ---- the same link always gets the same answer --------------------------------------------------------------------

def test_decisive_verdict_is_reused_for_every_spelling_of_the_link(monkeypatch):
    calls = []

    class FakePipeline:
        def analyze_url(self, url):
            calls.append(url)
            return {"verdict": "LEGITIMATE / CLEAN", "threat_score": 4.0, "decisive": True, "display_verdict": "Safe"}

    monkeypatch.setattr(backend_app, "get_link_pipeline", lambda: FakePipeline())
    backend_app._verdict_cache.clear()
    first = backend_app.run_link_pipeline("https://sqlite.org/")
    again = backend_app.run_link_pipeline("http://www.sqlite.org")
    assert first == again and len(calls) == 1


def test_uncertain_verdict_is_never_cached(monkeypatch):
    calls = []

    class FakePipeline:
        def analyze_url(self, url):
            calls.append(url)
            return {"verdict": "SUSPICIOUS", "threat_score": 55.0, "decisive": False, "display_verdict": "Unverified - open with care"}

    monkeypatch.setattr(backend_app, "get_link_pipeline", lambda: FakePipeline())
    backend_app._verdict_cache.clear()
    backend_app.run_link_pipeline("https://unsure.example/")
    backend_app.run_link_pipeline("https://unsure.example/")
    assert len(calls) == 2


# ---- evidence rows for scan_features ----------------------------------------------------------------------------------

def test_scan_feature_rows_capture_the_analysis():
    res = {"verdict": "LEGITIMATE / CLEAN", "threat_score": 4.0, "decisive": True, "display_verdict": "Safe",
           "analysis_complete": True,
           "telemetry": {"ml_model": "page", "ml_probability": 0.12, "heuristic_flags": ["A", "B"], "missing": None,
                         "llm_review": {"verdict": "SAFE", "confidence": 0.9}}}
    rows = dict(backend_app.scan_feature_rows(res, "V2_LINK_PIPELINE"))
    assert rows["tier_analyzed"] == "V2_LINK_PIPELINE" and rows["ml_model"] == "page" and rows["ml_probability"] == "0.12"
    assert rows["heuristic_flags"] == "A, B" and rows["llm_review.verdict"] == "SAFE" and "missing" not in rows
    assert dict(backend_app.scan_feature_rows(None, "TIER_0", "phishtank"))["phishing_feed_source"] == "phishtank"


# ---- public feeds --------------------------------------------------------------------------------------------------------

def test_public_feeds_are_parsed_without_an_account(monkeypatch):
    importer = PhishingFeedImporter()
    importer.phishtank_api_key = ""
    texts = {
        "openphish.com": "https://bad-one.example/login\nnot a url\nhttp://bad-two.example/\n",
        "phishtank": "phish_id,url,phish_detail_url\n1,https://pt-bad.example/a,x\n2,javascript:alert(1),x\n",
        "urlhaus": "# comment\n1,2026-10-09,http://malware.example/x.exe,online,,malware_download,tag,link,rep\n",
        "Phishing.Database": "https://db-bad.example/p\n",
    }

    def fake_download(url, timeout=90):
        return next(text for key, text in texts.items() if key.lower() in url.lower())

    monkeypatch.setattr(importer, "_download_text", fake_download)
    assert importer.fetch_from_openpfish() == ["https://bad-one.example/login", "http://bad-two.example/"]
    assert importer.fetch_from_phishtank() == ["https://pt-bad.example/a"]
    assert importer.fetch_from_urlhaus() == [{"url": "http://malware.example/x.exe", "threat_type": "malware_download"}]
    assert importer.fetch_from_phishing_database() == ["https://db-bad.example/p"]


def test_one_failing_feed_does_not_stop_the_others(monkeypatch):
    importer = PhishingFeedImporter()
    stored = []
    monkeypatch.setattr(importer, "fetch_from_openpfish", lambda: (_ for _ in ()).throw(RuntimeError("down")))
    monkeypatch.setattr(importer, "fetch_from_phishtank", lambda: ["https://a.example/"])
    monkeypatch.setattr(importer, "fetch_from_urlhaus", lambda: [])
    monkeypatch.setattr(importer, "fetch_from_phishing_database", lambda: ["https://b.example/"])
    monkeypatch.setattr(importer, "store_phishing_urls", lambda items, source, threat_type: stored.append(source) or (len(items), 0))
    monkeypatch.setattr(importer, "record_source", lambda name, url: None)
    assert importer.import_all_feeds() == (2, 0)
    assert stored == ["phishtank", "phishing_database"]


# ---- CORS setting written as a JSON list must not break the server -------------------------------------------------------

def test_cors_origins_accept_a_json_style_list_and_drop_broken_entries():
    parse = backend_app.parse_cors_origins
    assert parse('["http://localhost:8000", "http://localhost:3000"]') == ["http://localhost:8000", "http://localhost:3000"]
    assert parse("http://a.example, http://b.example") == ["http://a.example", "http://b.example"]
    assert parse('["http://ok.example", "[broken"]') == ["http://ok.example"]
    assert parse("") == []


# ---- an unusual-looking link whose page could not be opened is not proof of phishing -------------------------------------

LEXICAL_ALARM = {"score": 97.3, "probability": 0.998, "band": "DANGEROUS", "model": "lexical", "signals": ["has port"]}
TIMED_OUT = {"verification_state": "unverified", "unverified_reason": "timeout"}


def test_uninspected_link_condemned_only_by_the_link_text_model_stays_unverified():
    out = FinalDecisionEngine().evaluate(url="http://tool.corp.example:5173/p/1", ml=LEXICAL_ALARM, sandbox_unreachable=1,
                                         sandbox_evidence=TIMED_OUT, domain_age_days=-1, heuristic_risk=30.0,
                                         heuristic_flags=["HIGH_SHANNON_ENTROPY"])
    assert out["verdict"].startswith("SUSPICIOUS") and out["threat_score"] < 80
    assert out["telemetry"]["ml_capped_uninspected"] is True and "could not be opened" in out["summary"]


def test_independent_evidence_keeps_the_dangerous_verdict_even_when_the_page_could_not_be_opened():
    for extra in ({"vt_risk_score": 45.7}, {"heuristic_risk": 45.0}, {"free_hosting": True}, {"domain_age_days": 10}):
        kwargs = {"domain_age_days": -1, **extra}
        out = FinalDecisionEngine().evaluate(url="http://x.example/", ml=LEXICAL_ALARM, sandbox_unreachable=1,
                                             sandbox_evidence=TIMED_OUT, **kwargs)
        assert out["threat_score"] >= 80, extra


def test_no_ai_guess_for_a_link_nobody_could_open():
    from core_engine.link_threat_pipeline import DISPLAY_UNVERIFIED, finalize_verdict

    class Boom:
        def review(self, *a, **k):
            raise AssertionError("the reviewer must not be asked")
        decide = staticmethod(lambda lean, res: None)

    result = {"verdict": "SUSPICIOUS", "threat_score": 55.0, "analysis_complete": False, "summary": "s",
              "telemetry": {"hard_override_triggered": False, "ml_capped_uninspected": True,
                            "verification_state": "unverified", "unverified_reason": "timeout"}}
    assert finalize_verdict(result, url="http://x/", reviewer=Boom())["display_verdict"] == DISPLAY_UNVERIFIED


# ---- platforms that host other people's pages never vouch for a page on them -------------------------------------------------

def test_user_content_platforms_seen_hosting_phishing_are_not_fast_path_whitelisted():
    from core_engine.link_threat_pipeline import is_brand_fast_path, is_user_content_host
    for url in ("https://secure-page-editor--x.replit.app/", "https://new.express.adobe.com/webpage/abc",
                "https://q-r.to/bfUXPY", "https://l.ead.me/bgbvF8", "https://2ffkjk.share-eu1.hsforms.com/2V",
                "https://pichincha-x.lovable.app/", "https://us11.campaign-archive.com/?u=1"):
        assert is_user_content_host(url), url
        assert not is_brand_fast_path(url), url
    assert is_brand_fast_path("https://www.adobe.com/")           # the brand's own site is still trusted
