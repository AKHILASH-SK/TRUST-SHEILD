"""Verified-clean pages, repeatable verdicts, scan evidence rows and the public phishing feeds (no network, no database)."""
import json

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


def test_a_confident_model_alone_no_longer_convicts_a_clean_looking_page():
    # changed on purpose: with nothing concrete found by the sandbox, the model's score alone stays "Unverified"
    confident = {**MODERATE_ML, "score": 92.0, "probability": 0.95}
    out = evaluate(CLEAN_EVIDENCE, ml=confident)
    assert out["verdict"].startswith("SUSPICIOUS") and out["telemetry"]["ml_capped_no_evidence"] is True


# ---- the same link always gets the same answer --------------------------------------------------------------------

def _fake_pipeline(monkeypatch, calls, result):
    class FakePipeline:
        def analyze_url(self, url, **kwargs):
            calls.append(url)
            return dict(result)
    monkeypatch.setattr(backend_app, "get_link_pipeline", lambda: FakePipeline())
    monkeypatch.setattr(backend_app.phishing_importer, "check_url_in_database", lambda u: (False, None, None))
    backend_app.scan_jobs_manager.clear()


def test_decisive_verdict_is_reused_for_every_spelling_of_the_link(monkeypatch):
    calls = []
    _fake_pipeline(monkeypatch, calls, {"verdict": "LEGITIMATE / CLEAN", "threat_score": 4.0, "decisive": True,
                                        "display_verdict": "Safe"})
    first = backend_app.run_link_pipeline("https://sqlite.org/")
    again = backend_app.run_link_pipeline("http://www.sqlite.org")
    assert first == again and len(calls) == 1


def test_uncertain_verdict_is_kept_only_briefly(monkeypatch):
    import scan_jobs
    calls = []
    _fake_pipeline(monkeypatch, calls, {"verdict": "SUSPICIOUS", "threat_score": 55.0, "decisive": False,
                                        "display_verdict": "Unverified - open with care"})
    monkeypatch.setattr(scan_jobs, "TTL_UNVERIFIED", 0)
    backend_app.run_link_pipeline("https://unsure.example/")
    backend_app.run_link_pipeline("https://unsure.example/")
    assert len(calls) == 2


# ---- one scan per link: a second asker joins the running job and sees the same progress --------------------------------

def test_a_second_asker_joins_the_running_scan_instead_of_starting_again():
    import threading
    import time
    import scan_jobs
    from core_engine import scan_progress

    runs, gate = [], threading.Event()

    def runner(url):
        runs.append(url)
        scan_progress.report("threat_lists", "done")
        scan_progress.report("sandbox", "running", "opening the page")
        gate.wait(5)
        return {"display_verdict": "Safe", "verdict": "LEGITIMATE / CLEAN", "decisive": True}

    manager = scan_jobs.JobManager(runner)
    first, how1 = manager.start_or_join("https://shop.example/")
    time.sleep(0.2)
    second, how2 = manager.start_or_join("http://www.shop.example")          # e.g. the user taps while the scan runs
    assert (how1, how2) == ("started", "joined") and first is second
    snap = second.snapshot(joined=True)
    assert snap["joined"] is True and 0 < snap["progress"] < 100
    stages = {s["id"]: s["status"] for s in snap["stages"]}
    assert stages["threat_lists"] == "done" and stages["sandbox"] == "running" and stages["verdict"] == "pending"
    gate.set()
    assert first.wait(5) and first.state == "done" and len(runs) == 1
    assert first.snapshot()["progress"] == 100
    _, how3 = manager.start_or_join("https://shop.example/")
    assert how3 == "cached" and len(runs) == 1


def test_a_failing_scan_never_leaves_a_job_hanging():
    import scan_jobs

    def runner(url):
        raise RuntimeError("boom")

    job, _ = scan_jobs.JobManager(runner).start_or_join("https://x.example/")
    assert job.wait(5) and job.state == "error" and job.error


def test_watchers_are_recorded_when_the_job_finishes_and_late_askers_are_told_to_record_now():
    import scan_jobs
    recorded = []
    manager = scan_jobs.JobManager(lambda url: {"display_verdict": "Safe", "decisive": True},
                                   on_finish=lambda job: recorded.extend(job.watchers))
    job, _ = manager.start_or_join("https://w.example/")
    assert job.wait(5)
    assert job.add_watcher(7, "WhatsApp") is False           # already finished: the caller records immediately


def test_known_phishing_link_answers_instantly_and_skips_the_slow_stages(monkeypatch):
    monkeypatch.setattr(backend_app.phishing_importer, "check_url_in_database", lambda u: (True, "phishing", "openphish"))
    backend_app.scan_jobs_manager.clear()
    job, _ = backend_app.scan_jobs_manager.start_or_join("https://known-bad.example/login")
    assert job.wait(10) and job.result["display_verdict"] == "Dangerous" and job.result["tier_0_match"] is True
    states = {s["id"]: s["status"] for s in job.snapshot()["stages"]}
    assert states["sandbox"] == "skipped" and states["threat_lists"] == "done"


def test_pipeline_reports_its_stages_to_the_listening_job():
    from core_engine import scan_progress
    from core_engine.link_threat_pipeline import LinkThreatPipeline
    seen = []
    token = scan_progress.set_sink(lambda stage, status, detail="": seen.append((stage, status)))
    try:
        LinkThreatPipeline().analyze_url("https://www.google.com/")        # trusted domain: short path
    finally:
        scan_progress.reset_sink(token)
    assert ("link_analysis", "done") in seen and ("threat_lists", "done") in seen and ("reputation", "done") in seen
    assert ("sandbox", "skipped") in seen


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
    for extra in ({"vt_risk_score": 45.7}, {"heuristic_risk": 45.0}, {"domain_age_days": 10}):
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


# ---- a brand mentioned in the body is not a claim to BE that brand ------------------------------------------------------------

def test_a_company_login_page_that_says_sign_in_with_google_is_not_a_fake_google_page():
    from core_engine.browser_sandbox import detect_brand
    state = {"title": "Rakuten Group - New Graduate Recruitment", "ogSite": "", "ogTitle": "", "logoAlts": [],
             "text": "Sign in with Google. " * 12 + "Protected by reCAPTCHA. Google Privacy Policy and Terms."}
    result = detect_brand(state, "i-webs.jp")
    assert result["claimed_brand"] == "" and result["brand_owns_domain"] is None


def test_a_page_titled_like_a_brand_on_the_wrong_domain_is_still_caught():
    from core_engine.browser_sandbox import detect_brand
    state = {"title": "Sign in to your Google Account", "ogSite": "", "ogTitle": "", "logoAlts": ["Google"], "text": "Email or phone"}
    result = detect_brand(state, "secure-login-check.xyz")
    assert result["claimed_brand"] == "google" and result["brand_owns_domain"] is False and result["brand_claim_in_headline"]


def test_shorteners_and_multi_tenant_platforms_are_never_trusted_for_their_popularity():
    from core_engine.link_threat_pipeline import is_brand_fast_path, is_user_content_host
    for url in ("https://x.gd/vlkxb", "https://t.ly/abc", "https://mypage.3010.i-webs.jp/entry/login"):
        assert is_user_content_host(url) and not is_brand_fast_path(url), url


def test_a_sign_in_with_google_button_image_is_not_the_page_claiming_to_be_google():
    from core_engine.browser_sandbox import detect_brand
    state = {"title": "Rakuten Group New Graduate Recruitment", "ogSite": "", "ogTitle": "",
             "logoAlts": ["google", "rakuten"], "text": "Log in"}
    assert detect_brand(state, "i-webs.jp")["claimed_brand"] == ""


def test_a_model_only_conviction_of_an_inspected_page_without_concrete_evidence_is_not_announced_as_dangerous():
    page_alarm = {"score": 100.0, "probability": 1.0, "band": "DANGEROUS", "model": "page", "signals": ["ev n links"]}
    verified = {"verification_state": "verified", "credential_surface_found": True, "sensitive_field_types": [], "wording": {}}
    out = FinalDecisionEngine().evaluate(url="https://tenant.platform.example/login", ml=page_alarm, sandbox_evidence=verified,
                                         domain_age_days=-1)
    assert out["verdict"].startswith("SUSPICIOUS") and out["telemetry"]["ml_capped_no_evidence"] is True


def test_concrete_evidence_keeps_the_dangerous_verdict():
    page_alarm = {"score": 100.0, "probability": 1.0, "band": "DANGEROUS", "model": "page", "signals": []}
    verified = {"verification_state": "verified", "credential_surface_found": True, "sensitive_field_types": [], "wording": {}}
    for extra in ({"brand_impersonation": 1}, {"vt_risk_score": 45.0}, {"domain_age_days": 5}, {"heuristic_risk": 50.0},
                  {"suspicious_exfiltration": 1}):
        kwargs = {"domain_age_days": -1, **extra}
        out = FinalDecisionEngine().evaluate(url="https://x.example/", ml=page_alarm, sandbox_evidence=verified, **kwargs)
        assert out["threat_score"] >= 80, extra


def test_when_the_model_alone_accuses_the_reviewer_can_clear_the_link_but_never_convict_it():
    from core_engine.link_threat_pipeline import DISPLAY_DANGEROUS, DISPLAY_SAFE, DISPLAY_UNVERIFIED, finalize_verdict

    class Reviewer:
        MIN_CONFIDENCE = 0.75

        def __init__(self, verdict, confidence):
            self.answer = {"verdict": verdict, "confidence": confidence, "reasons": ["read the page"], "impersonated_brand": ""}

        def review(self, *a, **k):
            return self.answer

        decide = staticmethod(lambda lean, res: None)

    def result():
        return {"verdict": "SUSPICIOUS", "threat_score": 70.0, "analysis_complete": True, "summary": "s",
                "telemetry": {"hard_override_triggered": False, "ml_capped_no_evidence": True}}

    ml = {"probability": 1.0}
    assert finalize_verdict(result(), url="http://x/", ml_result=ml, reviewer=Reviewer("SAFE", 0.9))["display_verdict"] == DISPLAY_SAFE
    # the reviewer cannot convict on soft evidence alone: DANGEROUS stays "Unverified"
    assert finalize_verdict(result(), url="http://x/", ml_result=ml, reviewer=Reviewer("DANGEROUS", 0.95))["display_verdict"] == DISPLAY_UNVERIFIED
    assert finalize_verdict(result(), url="http://x/", ml_result=ml, reviewer=Reviewer("SAFE", 0.5))["display_verdict"] == DISPLAY_UNVERIFIED


def test_shared_hosting_is_not_evidence_and_a_hosted_page_needs_concrete_evidence():
    # model says only "suspicious" (score 65) for a page on shared hosting, the sandbox found nothing concrete
    suspicious = {"score": 65.0, "probability": 0.7, "band": "SUSPICIOUS", "model": "page", "signals": ["host len"]}
    out = evaluate(CLEAN_EVIDENCE, ml=suspicious, free_hosting=True)
    assert out["telemetry"]["ml_capped_no_evidence"] is True and out["telemetry"]["hosted_name_ignored"] is True
    # ...but the same score on an ordinary domain is left alone
    plain = evaluate({**CLEAN_EVIDENCE, "credential_surface_found": True}, ml=suspicious, free_hosting=False)
    assert plain["telemetry"]["ml_capped_no_evidence"] is False
    # an uninspected hosted page is no longer convicted by its host name
    uninspected = FinalDecisionEngine().evaluate(url="https://app.vercel.app/", ml=LEXICAL_ALARM, sandbox_unreachable=1,
                                                 sandbox_evidence=TIMED_OUT, domain_age_days=-1, free_hosting=True)
    assert uninspected["threat_score"] < 80
    # concrete evidence on a hosted page still convicts
    hosted_bad = evaluate({**CLEAN_EVIDENCE, "submit_cross_domain": True}, ml=suspicious, free_hosting=True, brand_impersonation=1)
    assert hosted_bad["telemetry"]["ml_capped_no_evidence"] is False


# ---- the per-scan explanation is built from that scan's own facts ------------------------------------------------------------

DATUM_FEATURES = {
    "display_verdict": "Safe", "threat_score": "30.0", "tier_analyzed": "V2_LINK_PIPELINE", "verification_state": "verified",
    "sandbox.page_title": "DATUM - Planning-to-Execution Bridge", "sandbox.credential_surface_found": "True",
    "sandbox.credential_field_types": "other, password", "sandbox.probe_ran": "True", "sandbox.submit_cross_domain": "False",
    "sandbox.blocked_internal_requests": "4", "vt_detections": "0", "vt_engines": "92", "free_hosting": "True",
    "ml_model": "page", "ml_probability": "1.0", "ml_signals": "link text looks suspicious, ev n links, host len",
    "ml_capped_no_evidence": "True", "llm_review.verdict": "SAFE", "llm_review.confidence": "0.85",
}
PHISH_FEATURES = {
    "display_verdict": "Dangerous", "threat_score": "100.0", "verification_state": "verified", "sandbox.page_title": "Sign in",
    "sandbox.credential_surface_found": "True", "sandbox.probe_ran": "True", "sandbox.submit_cross_domain": "True",
    "sandbox.submit_domain": "evil-collector.xyz", "sandbox.claimed_brand": "microsoft", "sandbox.brand_owns_domain": "False",
    "override_reason": "Login form sends the typed credentials to a different site", "vt_detections": "3", "vt_engines": "92",
}


def test_each_scan_gets_its_own_specific_explanation():
    from core_engine import explainer
    safe_text, safe_source = explainer.explain(explainer.facts_from_features(DATUM_FEATURES, "https://datum-ashy-beta.vercel.app", "SAFE", 30.0), use_ai=False)
    bad_text, _ = explainer.explain(explainer.facts_from_features(PHISH_FEATURES, "http://login-check.xyz/", "DANGEROUS", 100.0), use_ai=False)
    assert safe_source == "rules" and safe_text != bad_text
    # the safe page: specific facts, and what made it look suspicious, and why it still is safe
    assert "stayed on the same site" in safe_text and "4 times" in safe_text and "shared hosting platform" in safe_text
    assert "100% likely" in safe_text and "treated as safe" in safe_text and "credential harvesting" not in safe_text.lower()
    # the phishing page: concrete findings, never the safe page's facts
    assert "evil-collector.xyz" in bad_text and "microsoft" in bad_text and "Do not open" in bad_text and "shared hosting" not in bad_text


def test_an_unverified_page_that_was_not_opened_says_so_and_claims_no_checks_it_did_not_make():
    from core_engine import explainer
    facts = explainer.facts_from_features({"display_verdict": "Unverified - open with care", "verification_state": "unverified",
                                           "unverified_reason": "timeout"}, "http://tool.corp.example:5173/p", "SUSPICIOUS", 55.0)
    text, _ = explainer.explain(facts, use_ai=False)
    assert "could not open the page" in text and "timeout" in text and "No login or payment form" not in text


def test_gemini_text_is_used_when_valid_but_cannot_change_the_action_or_break_the_format(monkeypatch):
    from core_engine import explainer
    monkeypatch.setenv("GEMINI_API_KEY", "test")
    monkeypatch.setenv("ENABLE_LLM_REVIEW", "true")
    facts = explainer.facts_from_features(PHISH_FEATURES, "http://login-check.xyz/", "DANGEROUS", 100.0)
    good = json.dumps({"headline": "Fake Microsoft login", "what_we_saw": ["A login page copying Microsoft."],
                       "why_suspicious": ["It sends passwords elsewhere."], "why_this_verdict": "Passwords would go to a stranger.",
                       "what_to_do": "It is fine to open."})
    text, source = explainer.explain(facts, writer=lambda *a: good)
    assert source == "gemini" and "Fake Microsoft login" in text and "Do not open this link" in text and "fine to open" not in text
    assert text.count("•") == 3                                           # the three sections the app displays
    # garbage or a failing writer falls back to the rule text
    assert explainer.explain(facts, writer=lambda *a: "not json")[1] == "rules"
    def boom(*a):
        raise RuntimeError("quota")
    assert explainer.explain(facts, writer=boom)[1] == "rules"


# ---- history: new link is added, same verdict is not repeated, a changed verdict updates the old record -----------------------

class _FakeCursor:
    def __init__(self, script):
        self.script, self.calls, self._next = script, [], None

    def execute(self, sql, params=None):
        self.calls.append((" ".join(sql.split()), params))
        self._next = self.script.pop(0) if self.script else None

    def executemany(self, sql, rows):
        self.calls.append((" ".join(sql.split()), list(rows)))

    def fetchone(self):
        return self._next


def _run_record(monkeypatch, existing_row, verdict_result):
    import contextlib
    cur = _FakeCursor([None, (99,)] if existing_row is None else [existing_row, None, None])

    @contextlib.contextmanager
    def fake_db():
        yield cur
    monkeypatch.setattr(backend_app, "db_cursor", fake_db)
    return backend_app._record_job_scan(8, "https://www.site.example/", verdict_result, "Link Gate (x)"), cur.calls


SAFE_RESULT = {"verdict": "LEGITIMATE / CLEAN", "threat_score": 4.0, "display_verdict": "Safe", "summary": "ok", "telemetry": {}}


def test_history_adds_a_new_link(monkeypatch):
    scan_id, calls = _run_record(monkeypatch, None, SAFE_RESULT)
    assert scan_id == 99 and any(c[0].startswith("INSERT INTO link_scans") for c in calls)


def test_history_does_not_repeat_the_same_verdict(monkeypatch):
    scan_id, calls = _run_record(monkeypatch, (5, "SAFE"), SAFE_RESULT)
    assert scan_id is None and not any(c[0].startswith(("INSERT", "UPDATE")) for c in calls)


def test_history_updates_a_stale_verdict_instead_of_keeping_it(monkeypatch):
    scan_id, calls = _run_record(monkeypatch, (5, "DANGEROUS"), SAFE_RESULT)
    assert scan_id == 5
    assert any(c[0].startswith("UPDATE link_scans") for c in calls) and not any(c[0].startswith("INSERT INTO link_scans") for c in calls)
    assert any(c[0].startswith("DELETE FROM scan_features") for c in calls)
    lookup = calls[0][1][1]                                      # both spellings are searched
    assert "https://www.site.example/" in lookup and "https://site.example" in lookup


def test_a_known_phishing_link_is_explained_without_waiting_for_the_writer():
    from core_engine import explainer

    def must_not_be_called(*a):
        raise AssertionError("the writer must not be asked for a link on a public phishing list")
    facts = explainer.facts_from_features({"display_verdict": "Dangerous", "status": "KNOWN_THREAT", "phishing_feed_source": "openphish"},
                                          "https://x.example/app", "DANGEROUS", 100.0)
    text, source = explainer.explain(facts, writer=must_not_be_called)
    assert source == "rules" and "public phishing list" in text


def test_the_reviewer_is_not_anchored_by_the_model_score_when_only_the_model_is_alarmed():
    from core_engine.link_threat_pipeline import finalize_verdict
    seen = {}

    class Spy:
        MIN_CONFIDENCE = 0.75

        def review(self, url, evidence, text, lean, vt=None, ml=None, **k):
            seen.update(lean=lean, ml=ml)
            return None

        decide = staticmethod(lambda lean, res: None)

    result = {"verdict": "SUSPICIOUS", "threat_score": 70.0, "analysis_complete": True, "summary": "s",
              "telemetry": {"hard_override_triggered": False, "ml_capped_no_evidence": True}}
    finalize_verdict(result, url="http://x/", ml_result={"probability": 1.0}, reviewer=Spy())
    assert seen == {"lean": "UNDECIDED", "ml": None}


# ---- the AI second opinion must never delay the verdict ---------------------------------------------------------------------

def test_the_verdict_is_delivered_before_the_ai_second_opinion_and_refined_afterwards():
    import threading
    import time
    import scan_jobs

    ai_started, ai_release, hooks = threading.Event(), threading.Event(), []

    def runner(url):
        return {"verdict": "SUSPICIOUS", "display_verdict": "Unverified - open with care", "threat_score": 70.0,
                "decisive": False, "telemetry": {"ai_pending": True}, "_ai_context": {"url": url}}

    def refiner(result, context):
        ai_started.set()
        ai_release.wait(5)                                         # the slow Gemini call
        result.update(verdict="LEGITIMATE / CLEAN", display_verdict="Safe", threat_score=30.0, decisive=True)
        result["telemetry"]["ai_pending"] = False
        return result

    manager = scan_jobs.JobManager(runner, refiner=refiner, on_refined=lambda job, before: hooks.append((before["display_verdict"], job.result["display_verdict"])))
    started = time.time()
    job, _ = manager.start_or_join("https://ambiguous.example/")
    assert job.wait(3) and time.time() - started < 2                # released at once, long before the AI finishes
    assert job.result["display_verdict"] == "Unverified - open with care" and job.refining is True
    assert "_ai_context" not in job.result and job.snapshot()["refining"] is True
    assert ai_started.wait(3) and not hooks                         # the AI is running in the background
    # a second asker meanwhile gets the same fast answer and the same pending flag
    again, how = manager.start_or_join("https://www.ambiguous.example")
    assert how == "cached" and again is job and again.refining
    ai_release.set()
    for _ in range(50):
        if not job.refining:
            break
        time.sleep(0.1)
    assert job.result["display_verdict"] == "Safe" and job.version == 1 and hooks == [("Unverified - open with care", "Safe")]
    assert manager.peek("https://ambiguous.example/") is job


def test_a_failing_ai_second_opinion_keeps_the_first_verdict():
    import time
    import scan_jobs

    def runner(url):
        return {"verdict": "SUSPICIOUS", "display_verdict": "Unverified - open with care", "threat_score": 70.0,
                "telemetry": {"ai_pending": True}, "_ai_context": {"url": url}}

    def refiner(result, context):
        raise RuntimeError("Gemini unavailable")

    manager = scan_jobs.JobManager(runner, refiner=refiner)
    job, _ = manager.start_or_join("https://x.example/")
    job.wait(3)
    for _ in range(50):
        if not job.refining:
            break
        time.sleep(0.1)
    assert job.refining is False and job.result["display_verdict"] == "Unverified - open with care" and job.version == 0


def test_the_pipeline_defers_the_ai_and_the_refinement_finishes_the_job():
    from core_engine.link_threat_pipeline import DISPLAY_SAFE, DISPLAY_UNVERIFIED, finalize_verdict, refine_result

    class Reviewer:
        MIN_CONFIDENCE = 0.75
        calls = 0

        def is_enabled(self):
            return True

        def review(self, *a, **k):
            Reviewer.calls += 1
            return {"verdict": "SAFE", "confidence": 0.9, "reasons": ["ordinary page"], "impersonated_brand": ""}

        decide = staticmethod(lambda lean, res: None)

    result = {"verdict": "SUSPICIOUS", "threat_score": 70.0, "analysis_complete": True, "summary": "s",
              "telemetry": {"hard_override_triggered": False, "ml_capped_no_evidence": True}}
    fast = finalize_verdict(result, url="http://x/", ml_result={"probability": 1.0}, reviewer=Reviewer(), defer_ai=True)
    assert Reviewer.calls == 0 and fast["display_verdict"] == DISPLAY_UNVERIFIED and fast["telemetry"]["ai_pending"] is True
    ctx = fast.pop("_ai_context")
    final = refine_result(fast, ctx, reviewer=Reviewer())
    assert Reviewer.calls == 1 and final["display_verdict"] == DISPLAY_SAFE and final["telemetry"]["ai_pending"] is False
    # hard-rule results never wait for, or involve, the AI
    hard = {"verdict": "CRITICAL FRAUD / PHISHING", "threat_score": 100.0, "analysis_complete": True, "summary": "",
            "telemetry": {"hard_override_triggered": True}}
    assert "_ai_context" not in finalize_verdict(hard, url="http://x/", reviewer=Reviewer(), defer_ai=True)


def test_quick_explanation_answers_without_waiting_for_the_writer(monkeypatch):
    import contextlib
    from core_engine import explainer
    # the quick path must never call the writer: prove it by making the writer explode
    monkeypatch.setattr(explainer.llm_reviewer, "generate_json", lambda *a, **k: (_ for _ in ()).throw(AssertionError("writer called")))
    facts = explainer.facts_from_features(DATUM_FEATURES, "https://datum-ashy-beta.vercel.app", "SAFE", 30.0)
    text, source = explainer.explain(facts, use_ai=False)
    assert source == "rules" and "Threat Summary" in text


def test_a_hosted_page_titled_as_a_big_brand_it_does_not_own_is_convicted_only_when_the_model_agrees():
    critical = {"score": 100.0, "probability": 1.0, "band": "DANGEROUS", "model": "page", "signals": ["page title claims a brand"]}
    mild = {"score": 30.0, "probability": 0.3, "band": "SAFE", "model": "page", "signals": []}
    fake = {**CLEAN_EVIDENCE, "claimed_brand": "facebook", "brand_owns_domain": False}
    out = evaluate(fake, ml=critical, free_hosting=True)
    assert out["telemetry"]["ml_capped_no_evidence"] is False and out["threat_score"] >= 80
    # the same claim without the model's agreement is not enough (a blog that merely mentions Facebook)
    assert evaluate(fake, ml=mild, free_hosting=True)["threat_score"] < 60
    # no brand claim: the model alone on a hosted page is still capped
    assert evaluate(CLEAN_EVIDENCE, ml=critical, free_hosting=True)["telemetry"]["ml_capped_no_evidence"] is True
