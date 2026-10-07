"""Geo, unified pipeline, WHOIS, PDF, campaign and attachment tests. No network."""
import dns.exception
import pytest
import requests
from email.message import EmailMessage

from core_engine import geo_tracer, whois_intel, report_generator
from core_engine import unified_email_pipeline as uep
from core_engine import email_forensics as ef
from core_engine.campaign_manager import CaseManager
from core_engine.attachment_analyser import analyse_attachments


class Resp:
    def __init__(self, status=200, payload=None, headers=None):
        self.status_code = status
        self._p = payload
        self.headers = headers or {}

    def json(self):
        return self._p


# ---------------------------------------------------------------- geo
def test_route_map_carries_proxy_flags_and_caps_hops(monkeypatch):
    geo_tracer.clear_geo_cache()

    def fake_get(url, timeout=None, **kw):
        if "ipwho.is" in url:
            raise requests.ConnectionError("down")
        return Resp(200, {"status": "success", "country": "X", "city": "Y", "lat": 1.0, "lon": 2.0,
                          "isp": "Evil Hosting", "as": "AS64500 Evil", "proxy": True, "hosting": True})

    monkeypatch.setattr(geo_tracer.requests, "get", fake_get)
    hops = [{"public_ips": [f"93.184.216.{i}"]} for i in range(1, 21)]
    rm = geo_tracer.generate_route_map(hops)
    assert len(rm) == 15
    assert all(h["is_proxy"] and h["is_hosting"] and h["is_suspicious_proxy"] for h in rm)
    assert all(h["hops_truncated"] for h in rm)


def test_cloud_hosting_not_cleared_by_name_substring():
    assert geo_tracer._is_known_legitimate_mail_provider("Amazon.com", "AS16509") is False
    assert geo_tracer._is_known_legitimate_mail_provider("Google LLC", "AS15169 Google") is True
    assert geo_tracer._is_known_legitimate_mail_provider("Amazon", "AS16509", "a1.amazonses.com") is True


# ---------------------------------------------------------------- unified pipeline: links
def test_links_beyond_eight_are_analysed_and_reported(monkeypatch):
    monkeypatch.setattr(ef, "_dns_lookup", lambda *a, **k: [])
    monkeypatch.setattr(uep, "generate_route_map", lambda hops: [])
    monkeypatch.setattr(uep, "lookup_whois", lambda d: {})
    analysed = []

    def fake_analyze(url, email_text_context="", skip_sandbox=False):
        analysed.append(url)
        return {"threat_score": 10.0, "verdict": "OK", "summary": "", "telemetry": {}}

    monkeypatch.setattr(uep, "analyze_url", fake_analyze)
    monkeypatch.setattr(uep, "parse_url_heuristics",
                        lambda u: {"heuristic_risk_score": 90.0 if "bad" in u else 1.0,
                                   "heuristic_flags": ["X"] if "bad" in u else []})
    body = " ".join(f"http://site{i}.example.com/p" for i in range(20)) + " http://bad-late.example.com/login"
    raw = ("From: a@example.com\r\nTo: x@y.test\r\nSubject: s\r\n\r\n" + body).encode()
    res = uep.analyze_email_pipeline(raw, skip_link_sandbox=True)
    assert res["links_total"] == 21
    assert res["links_analyzed"] == 12 and res["links_skipped"] == 9
    assert len(res["link_investigation"]) == 21
    assert "http://bad-late.example.com/login" in analysed  # riskiest link analysed despite being last
    assert "analysis_complete" in res


def test_incomplete_analysis_not_reported_clean():
    s = uep.generate_incident_summary("LEGITIMATE / AUTHENTICATED", 0.0, {"subject": "s", "from": "f"}, {}, {},
                                      [], [], {"type": "BENIGN_AUTHENTICATED"}, analysis_complete=False)
    assert "ANALYSIS INCOMPLETE" in s


# ---------------------------------------------------------------- whois
@pytest.fixture
def rdap(monkeypatch):
    calls = []
    cfg = {"bootstrap": {"services": [[["com"], ["https://rdap.verisign.com/"]]]}, "status": 404}

    def fake_get(url, headers=None, timeout=None, allow_redirects=True):
        calls.append(url)
        if "data.iana.org" in url:
            return Resp(200, cfg["bootstrap"])
        return Resp(cfg["status"], {"events": [], "entities": []})

    class DnsFail:
        def __init__(self, *a, **k):
            pass

        def resolve(self, *a, **k):
            raise dns.exception.Timeout()

    monkeypatch.setattr(whois_intel, "assert_public_url", lambda u: u)
    monkeypatch.setattr(whois_intel.requests, "get", fake_get)
    monkeypatch.setattr(whois_intel.dns.resolver, "Resolver", DnsFail)
    whois_intel._bootstrap_cache.update(tlds=None, fetched=0.0)
    return calls, cfg


def test_whois_rejects_invalid_domain_without_request(rdap):
    calls, _ = rdap
    for bad in ("a/b.com", "evil.com/../../x", "exa mple.com", "localhost", "a..com", ""):
        r = whois_intel.lookup_whois(bad)
        assert r["whois_available"] is False and r["registrable_domain"] is None
    assert calls == []


def test_whois_reduces_subdomain_and_404_on_rdap_tld_is_unregistered(rdap):
    calls, _ = rdap
    r = whois_intel.lookup_whois("mail.sub.nonexistent-zzz.com")
    assert any(u == "https://rdap.org/domain/nonexistent-zzz.com" for u in calls)
    assert any(f.startswith("UNREGISTERED_DOMAIN") for f in r["whois_risk_flags"])


def test_whois_404_on_tld_without_rdap_is_unknown(rdap):
    _, _ = rdap
    r = whois_intel.lookup_whois("something.zz-unsupported.xyz")
    assert not any(f.startswith("UNREGISTERED_DOMAIN") for f in r["whois_risk_flags"])
    assert r["whois_available"] is False


def test_whois_registrar_not_penalised(rdap):
    _, cfg = rdap
    cfg["status"] = 200
    r = whois_intel.lookup_whois("example.com")
    assert r["is_suspicious_registrar"] is False


# ---------------------------------------------------------------- PDF
def test_pdf_survives_malicious_markup_and_has_no_court_claims(monkeypatch):
    monkeypatch.setattr("reportlab.rl_config.pageCompression", 0)
    dossier = {
        "evidence_hash_sha256": 12345678901234,
        "metadata": {"subject": "<b>x</i><para><img src='http://evil/x'/>&nbsp; " + "A" * 4000,
                     "from": "<script>alert(1)</script>"},
        "link_investigation": [{"url": "http://a.example/" + "B" * 3000, "threat_score": "oops", "verdict": "<x>"}],
        "incident_summary": "line <b>1\nline 2 </unclosed",
    }
    pdf = report_generator.generate_pdf_dossier_bytes(dossier)
    assert isinstance(pdf, bytes) and pdf.startswith(b"%PDF")
    for forbidden in (b"Court Admissibility", b"SEALED & IMMUTABLE", b"SHA-256 VERIFIED"):
        assert forbidden not in pdf
    assert b"NOT SEALED" in pdf


def test_pdf_renders_integrity_from_dossier(monkeypatch):
    monkeypatch.setattr("reportlab.rl_config.pageCompression", 0)
    pdf = report_generator.generate_pdf_dossier_bytes(
        {"integrity": {"status": "VERIFIED", "signature": "ab12", "sealed_at": "2026-01-01T00:00:00Z",
                       "algorithm": "HMAC-SHA256"}})
    assert b"VERIFIED" in pdf and b"ab12" in pdf and b"NOT SEALED" not in pdf


# ---------------------------------------------------------------- campaigns
def _incident(score=80.0, ip="93.184.216.5", domain="evil.example"):
    return {"overall_threat_score": score, "verdict": "CRITICAL FRAUD / PHISHING",
            "origin_intelligence": {"originating_ip": ip, "origin_isp": "Evil Hosting"},
            "metadata": {"from_domain": domain}, "link_investigation": [], "nlp_analysis": {}}


def test_campaign_and_incident_ids_unique_and_min_score():
    cm = CaseManager()
    camp_ids, inc_ids = set(), set()
    for i in range(300):
        r = cm.ingest_incident(_incident(ip=f"93.184.216.{i % 250}", domain=f"d{i}.example"))
        camp_ids.add(r["campaign_id"])
        inc_ids.add(r["incident_id"])
    assert len(inc_ids) == 300 and len(camp_ids) > 200
    low = cm.ingest_incident(_incident(score=10.0))
    assert low["ingested"] is False and low["campaign_id"] is None


def test_campaign_skips_shared_mail_provider_ip_and_caps():
    cm = CaseManager()
    a = cm.ingest_incident(_incident(ip="142.250.1.1", domain="a.example") | {
        "origin_intelligence": {"originating_ip": "142.250.1.1", "origin_isp": "Google LLC"}})
    b = cm.ingest_incident(_incident(domain="b.example") | {
        "origin_intelligence": {"originating_ip": "142.250.1.1", "origin_isp": "Google LLC"}})
    assert a["campaign_id"] != b["campaign_id"]  # shared Gmail relay IP does not merge unrelated senders
    for i in range(600):
        cm.ingest_incident(_incident(domain=f"x{i}.example", ip=f"198.51.{i // 250}.{i % 250}"))
    assert cm.get_stats()["total_campaigns"] <= 500


# ---------------------------------------------------------------- attachments
def _eml_with(filename, data=b"MZ\x90\x00payload", mime=("application", "octet-stream")):
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = "a@example.com", "b@example.com", "s"
    m.set_content("hello")
    m.add_attachment(data, maintype=mime[0], subtype=mime[1], filename=filename)
    return m.as_bytes()


def test_rtlo_filename_flagged_and_sha256_present():
    res = analyse_attachments(_eml_with("invoice‮fdp.exe"))
    att = res["attachments"][0]
    assert res["has_rtlo_filename"] is True
    assert any(f.startswith("RTLO_FILENAME_SPOOFING") for f in att["flags"])
    assert att["extension"] == ".exe"
    import hashlib
    assert att["sha256"] == hashlib.sha256(b"MZ\x90\x00payload").hexdigest()
    assert res["suspicious_attachments"] == 1


def test_iso_high_risk_and_trailing_dot_stripped_and_benign_not_counted():
    res = analyse_attachments(_eml_with("disk.iso. "))
    assert res["attachments"][0]["risk_category"] == "CRITICAL" and res["attachments"][0]["extension"] == ".iso"
    res2 = analyse_attachments(_eml_with("photo.png", b"\x89PNG", ("image", "png")))
    assert res2["total_attachments"] == 1 and res2["suspicious_attachments"] == 0


def test_unnamed_non_text_part_is_inspected():
    m = EmailMessage()
    m["From"], m["To"] = "a@example.com", "b@example.com"
    m.set_content("x")
    m.add_attachment(b"abc", maintype="application", subtype="x-msdownload")
    res = analyse_attachments(m.as_bytes())
    assert res["total_attachments"] == 1 and res["has_high_risk_attachment"]
