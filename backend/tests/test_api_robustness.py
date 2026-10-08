"""API robustness: clean 4xx errors, the Android sandbox-check contract, and 'analysis failed' never counted as a threat."""
import contextlib
import io

import pytest

import app as backend_app
from core_engine import email_forensics as ef
from core_engine import unified_email_pipeline as uep
from security import issue_token


@pytest.fixture
def client():
    return backend_app.app.test_client()


def auth():
    return {"Authorization": f"Bearer {issue_token(5)}"}


# ---- uploads and malformed requests return clean client errors, never 500 -------------------

BIG = b"A" * (11 * 1024 * 1024)   # limit is 10 MB


@pytest.mark.parametrize("path", [
    "/api/forensics/analyze-eml", "/api/forensics/verify-file", "/api/forensics/attachment-check",
])
def test_oversized_upload_is_413_json(client, path):
    resp = client.post(path, data={"file": (io.BytesIO(BIG), "big.eml")}, content_type="multipart/form-data")
    assert resp.status_code == 413
    assert resp.is_json and resp.get_json()["error"] == "Upload too large"


def test_oversized_raw_body_is_413(client):
    resp = client.post("/api/forensics/analyze-eml", data=BIG, content_type="message/rfc822")
    assert resp.status_code == 413


@pytest.mark.parametrize("path", [
    "/api/forensics/nlp-analyze", "/api/phishing/check", "/api/auth/login", "/api/auth/register",
    "/api/extension/analyze", "/api/forensics/verify-hash", "/api/forensics/whois",
])
def test_malformed_json_is_400_not_500(client, path):
    resp = client.post(path, data="{not json", content_type="application/json")
    assert resp.status_code in (400, 429)       # 429 only if an earlier test exhausted this route's limit
    assert resp.is_json
    assert "reference" not in resp.get_json()   # no server-error reference id: this is the client's mistake


def test_unknown_route_and_wrong_method_are_json(client):
    nf = client.get("/api/does-not-exist")
    assert nf.status_code == 404 and nf.is_json
    wrong = client.get("/api/auth/login")
    assert wrong.status_code == 405 and wrong.is_json


@pytest.mark.parametrize("path,body", [
    ("/api/auth/login", {}),
    ("/api/auth/register", {"name": "A"}),
    ("/api/forensics/verify-hash", {}),
    ("/api/extension/analyze", {}),
    ("/api/forensics/nlp-analyze", {}),
])
def test_missing_fields_are_400(client, path, body):
    assert client.post(path, json=body).status_code in (400, 429)


def test_scan_and_sandbox_check_need_a_url(client, monkeypatch):
    @contextlib.contextmanager
    def no_db():
        raise AssertionError("must reject before touching the database")
        yield
    monkeypatch.setattr(backend_app, "db_cursor", no_db)
    assert client.post("/api/links/scan", json={}, headers=auth()).status_code == 400
    assert client.post("/api/sandbox-check", json={}, headers=auth()).status_code == 400
    assert client.post("/api/sandbox-check", json={"url": "javascript:alert(1)"}, headers=auth()).status_code == 400


# ---- the contract the Android SandboxChecker depends on ---------------------------------------

CONTRACT_KEYS = {"verdict", "confidence", "details", "summary", "analysis_complete",
                 "engines_count", "malicious_count", "suspicious_count"}


@pytest.mark.parametrize("pipeline_result,expected", [
    ({"verdict": "CRITICAL FRAUD / PHISHING", "threat_score": 97.0, "summary": "s", "analysis_complete": True}, "DANGEROUS"),
    ({"verdict": "SUSPICIOUS", "threat_score": 63.0, "summary": "s", "analysis_complete": True}, "SUSPICIOUS"),
    ({"verdict": "LEGITIMATE / CLEAN", "threat_score": 4.0, "summary": "s", "analysis_complete": False}, "SAFE"),
])
def test_sandbox_check_response_contract(client, monkeypatch, pipeline_result, expected):
    monkeypatch.setattr(backend_app, "run_link_pipeline", lambda url: pipeline_result)
    resp = client.post("/api/sandbox-check", json={"url": "https://example.test/x"}, headers=auth())
    assert resp.status_code == 200
    body = resp.get_json()
    assert CONTRACT_KEYS <= set(body)
    assert body["verdict"] == expected
    assert isinstance(body["confidence"], int)
    assert body["analysis_complete"] is pipeline_result["analysis_complete"]


def test_sandbox_check_reports_busy_with_503(client, monkeypatch):
    monkeypatch.setattr(backend_app, "run_link_pipeline", lambda url: None)
    resp = client.post("/api/sandbox-check", json={"url": "https://example.test/"}, headers=auth())
    assert resp.status_code == 503 and resp.get_json()["verdict"] == "UNKNOWN"


def test_sandbox_check_pipeline_crash_is_generic_500(client, monkeypatch):
    def boom(url):
        raise RuntimeError("secret internals")
    monkeypatch.setattr(backend_app, "run_link_pipeline", boom)
    resp = client.post("/api/sandbox-check", json={"url": "https://example.test/"}, headers=auth())
    assert resp.status_code == 500 and "secret internals" not in resp.get_data(as_text=True)


# ---- a failed analysis is "unavailable", never threat evidence --------------------------------

def _offline_pipeline(monkeypatch, analyze):
    monkeypatch.setattr(ef, "_dns_lookup", lambda *a, **k: [])
    monkeypatch.setattr(uep, "generate_route_map", lambda hops: [])
    monkeypatch.setattr(uep, "lookup_whois", lambda d: {})
    monkeypatch.setattr(uep, "analyze_url", analyze)


def test_link_analysis_failure_is_not_scored_as_a_threat(monkeypatch):
    def broken(url, **kwargs):
        raise RuntimeError("sandbox crashed")
    _offline_pipeline(monkeypatch, broken)
    raw = b"From: a@example.com\r\nTo: x@y.test\r\nSubject: hi\r\n\r\nplease see http://plain.example.com/page"
    res = uep.analyze_email_pipeline(raw, skip_link_sandbox=True)
    entry = res["link_investigation"][0]
    assert entry["threat_score"] == 0.0
    assert entry["verdict"] == "ANALYSIS UNAVAILABLE"
    assert entry["analysis_unavailable"] is True
    assert "NOT evidence" in entry["summary"]
    assert res["analysis_complete"] is False
    assert any("Link analysis failed" in e for e in res["analysis_errors"])
    assert not str(res["verdict"]).startswith("CRITICAL")


def test_heuristic_failure_is_not_scored_as_a_threat(monkeypatch):
    def broken_heuristics(url):
        raise ValueError("bad parse")
    _offline_pipeline(monkeypatch, lambda url, **k: {"threat_score": 1.0, "verdict": "OK", "summary": "", "telemetry": {}})
    monkeypatch.setattr(uep, "parse_url_heuristics", broken_heuristics)
    raw = b"From: a@example.com\r\nTo: x@y.test\r\nSubject: hi\r\n\r\nlink http://plain.example.com/page"
    res = uep.analyze_email_pipeline(raw, skip_link_sandbox=True)
    assert all(float(item["threat_score"]) < 50.0 for item in res["link_investigation"])
    assert any("heuristics failed" in e for e in res["analysis_errors"])


def test_offline_end_to_end_email_case_has_hash_and_complete_schema(monkeypatch):
    _offline_pipeline(monkeypatch, lambda url, **k: {"threat_score": 90.0, "verdict": "CRITICAL FRAUD / PHISHING",
                                                      "summary": "bad", "telemetry": {"analysis_complete": True}})
    raw = (b"From: Billing <billing@paypa1-secure.example>\r\nReply-To: attacker@other.example\r\nTo: victim@y.test\r\n"
           b"Subject: Urgent: verify your account\r\n\r\nVerify now: http://paypa1-secure.example/login")
    res = uep.analyze_email_pipeline(raw, skip_link_sandbox=True)
    import hashlib
    assert res["evidence_hash_sha256"] == hashlib.sha256(raw).hexdigest()
    for key in ("verdict", "overall_threat_score", "metadata", "link_investigation", "threat_attribution",
                "analysis_complete", "analysis_errors"):
        assert key in res
    assert res["overall_threat_score"] >= 50.0           # critical link + reply-to mismatch
    assert res["metadata"]["reply_to_mismatch"] is True


@pytest.mark.parametrize("raw,ok", [
    ("https://example.com/a?b=1", True), ("example.com/path", True), ("example.com:8080/x", True),
    ("javascript:alert(1)", False), ("data:text/html,<script>1</script>", False), ("mailto:a@b.c", False),
    ("tel:+911234567890", False), ("file:///etc/passwd", False), ("ftp://example.com/x", False),
    ("http://exa mple.com", False), ("http://a.com/\r\nHost: evil", False), ("", False), (None, False),
    ("http://" + "a" * 2100 + ".com", False),
])
def test_url_normaliser_accepts_only_web_links(raw, ok):
    assert (backend_app.normalize_input_url(raw) is not None) is ok


# ---- the sandbox keeps working when the real browser is unavailable or crashes --------------------

PAGE = "<html><head><title>Hello</title></head><body><form action='/go'><input type='password'></form></body></html>"


def _sandbox(monkeypatch):
    from core_engine import sandbox_engine as se
    monkeypatch.setattr(se, "assert_public_url", lambda u: u)
    monkeypatch.setattr(se.VirtualSandboxAnalyzer, "_query_domain_age", lambda self, url: (-1, 0, 0))
    monkeypatch.setattr(se.VirtualSandboxAnalyzer, "_safe_fetch", lambda self, url: (url, PAGE, []))
    return se


def test_no_browser_on_render_uses_http_fallback_without_starting_one(monkeypatch):
    se = _sandbox(monkeypatch)
    monkeypatch.setattr(se, "browser_available", lambda: False)

    class MustNotStart:
        def __init__(self, *a, **k):
            raise AssertionError("the browser sandbox must not be created on a host without a browser")
    monkeypatch.setattr(se, "BrowserSandbox", MustNotStart)
    out = se.VirtualSandboxAnalyzer().analyze_link_in_sandbox("https://login.example.test/")
    assert out["engine"] == "http_fallback" and out["sandbox_unreachable"] == 0 and out["sandbox_has_password_field"] == 1
    assert "_html" in out and out["_final_url"].startswith("https://login.example.test")


def test_browser_crash_falls_back_to_http_analysis(monkeypatch):
    se = _sandbox(monkeypatch)
    monkeypatch.setattr(se, "browser_available", lambda: True)

    class Crashing:
        def analyze(self, url, budget_seconds=30):
            return {"verification_state": "unverified", "unverified_reason": "crashed", "sandbox_unreachable": 1}
    monkeypatch.setattr(se, "BrowserSandbox", Crashing)
    out = se.VirtualSandboxAnalyzer().analyze_link_in_sandbox("https://login.example.test/")
    assert out["engine"] == "http_fallback" and out["sandbox_has_password_field"] == 1


def test_browser_result_is_used_when_the_browser_works(monkeypatch):
    se = _sandbox(monkeypatch)
    monkeypatch.setattr(se, "browser_available", lambda: True)

    class Works:
        def analyze(self, url, budget_seconds=30):
            return {"engine": "browser_v2", "verification_state": "verified", "unverified_reason": "",
                    "credential_surface_found": True, "sandbox_unreachable": 0, "sandbox_has_password_field": 1,
                    "sandbox_threat_score": 12, "_html": "<html></html>"}
    monkeypatch.setattr(se, "BrowserSandbox", Works)
    out = se.VirtualSandboxAnalyzer().analyze_link_in_sandbox("https://login.example.test/")
    assert out["engine"] == "browser_v2" and out["credential_surface_found"] and out["domain_age_days"] == -1


def test_pipeline_never_leaks_raw_page_evidence(monkeypatch):
    from core_engine import link_threat_pipeline as ltp, sandbox_engine as se
    se_obj = _sandbox(monkeypatch)
    monkeypatch.setenv("FORCE_CLOUD_SANDBOX", "1")
    monkeypatch.setattr(se, "browser_available", lambda: False)
    pipe = ltp.LinkThreatPipeline.__new__(ltp.LinkThreatPipeline)

    class EmptyDb:
        def check_indicator(self, u):
            return False
    from core_engine.final_decision_engine import FinalDecisionEngine
    pipe.threat_db, pipe.sandbox, pipe.decision_engine, pipe.good_domain_checker = EmptyDb(), se.VirtualSandboxAnalyzer(), FinalDecisionEngine(), None
    result = pipe.analyze_url("https://unknown-login.example.test/")
    assert "_html" not in str(result) and "_final_url" not in result["telemetry"]
    assert result["verdict"] and "analysis_complete" in result
