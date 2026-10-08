import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import good_domain_checker as gdc
from good_domain_checker import GoodDomainChecker


class Resp:
    def __init__(self, status, payload=None):
        self.status_code = status
        self._payload = payload or {}

    def json(self):
        return self._payload


def vt_payload(malicious=0, rank=None, suspicious=0, total=70):
    attrs = {"last_analysis_stats": {"malicious": malicious, "suspicious": suspicious,
                                     "harmless": max(0, total - malicious - suspicious - 4), "undetected": 4}}
    if rank is not None:
        attrs["popularity_ranks"] = {"Tranco": {"rank": rank}}
    return {"data": {"attributes": attrs}}


def make(tmp_path, **kw):
    return GoodDomainChecker("key", db_path=str(tmp_path / "vt.db"), **kw)


def patch_get(monkeypatch, responder):
    calls = []

    def fake_get(url, **kwargs):
        calls.append(url)
        return responder(url)

    monkeypatch.setattr(gdc.requests, "get", fake_get)
    return calls


def test_whitelisted_result_is_cached(tmp_path, monkeypatch):
    calls = patch_get(monkeypatch, lambda u: Resp(200, vt_payload(0, 50)))
    c = make(tmp_path)
    assert c.get_vt_reputation("https://www.example.com/a")["is_whitelisted"]
    assert c.get_vt_reputation("https://example.com/b")["is_whitelisted"]
    assert c.is_known_good_domain("http://example.com")
    assert len(calls) == 1


def test_malicious_result_is_cached(tmp_path, monkeypatch):
    calls = patch_get(monkeypatch, lambda u: Resp(200, vt_payload(30)))
    c = make(tmp_path)
    assert c.get_vt_reputation("https://bad.example.net")["vt_risk_score"] == 95.0
    c.get_vt_reputation("https://bad.example.net")
    assert len(calls) == 1


def test_429_is_not_cached_as_verdict(tmp_path, monkeypatch):
    state = {"status": 429}

    def responder(u):
        return Resp(state["status"], vt_payload(0, 10))

    calls = patch_get(monkeypatch, responder)
    c = make(tmp_path)
    first = c.get_vt_reputation("https://example.com")
    assert first["provider"] == "rate_limited" and first["vt_risk_score"] == 35.0
    assert not first["is_whitelisted"]
    # client backs off after a 429; once the backoff expires a retry hits the API again
    c._limiter._blocked_until = 0
    state["status"] = 200
    assert c.get_vt_reputation("https://example.com")["is_whitelisted"]
    assert len(calls) == 2


def test_server_error_cached_only_briefly(tmp_path, monkeypatch):
    calls = patch_get(monkeypatch, lambda u: Resp(500))
    c = make(tmp_path)
    c.get_vt_reputation("https://example.com")
    c.get_vt_reputation("https://example.com")
    assert len(calls) == 1  # short error TTL
    real = gdc.time.time
    monkeypatch.setattr(gdc.time, "time", lambda: real() + gdc.ERROR_TTL + 5)
    c.get_vt_reputation("https://example.com")
    assert len(calls) == 2


def test_rate_limiter_returns_neutral_without_calling(tmp_path, monkeypatch):
    calls = patch_get(monkeypatch, lambda u: Resp(200, vt_payload(0, 10)))
    c = make(tmp_path, per_minute=2)
    for d in ("a-site.com", "b-site.com"):
        c.get_vt_reputation(f"https://{d}")
    r = c.get_vt_reputation("https://c-site.com")
    assert len(calls) == 2
    assert r["provider"] == "rate_limited" and r["vt_risk_score"] == 35.0 and not r["is_whitelisted"]
    # the limited result was not cached: a cached domain still answers, the new one is not stored
    assert c._cache.get("c-site.com") is None


def test_daily_limit(tmp_path, monkeypatch):
    patch_get(monkeypatch, lambda u: Resp(200, vt_payload(0, 10)))
    c = make(tmp_path, per_minute=100, per_day=1)
    c.get_vt_reputation("https://a-site.com")
    assert c.get_vt_reputation("https://b-site.com")["provider"] == "rate_limited"


def test_persistent_cache_survives_new_instance(tmp_path, monkeypatch):
    calls = patch_get(monkeypatch, lambda u: Resp(200, vt_payload(0, 10)))
    make(tmp_path).get_vt_reputation("https://example.com")
    assert make(tmp_path).get_vt_reputation("https://example.com")["is_whitelisted"]
    assert len(calls) == 1


def test_falls_back_to_memory_when_disk_fails(tmp_path, monkeypatch):
    calls = patch_get(monkeypatch, lambda u: Resp(200, vt_payload(0, 10)))
    blocker = tmp_path / "file"
    blocker.write_text("x")
    c = GoodDomainChecker("key", db_path=str(blocker / "sub" / "vt.db"))  # parent is a file
    c.get_vt_reputation("https://example.com")
    c.get_vt_reputation("https://example.com")
    assert len(calls) == 1


def test_vt_malicious_two_engines_reaches_suspicious_or_higher():
    from core_engine.final_decision_engine import FinalDecisionEngine, SUSPICIOUS_THRESHOLD
    r = FinalDecisionEngine().evaluate(url="https://bad.example.net/", vt_risk_score=95.0)
    assert r["threat_score"] >= 90
    assert r["verdict"] != "LEGITIMATE / CLEAN" and r["threat_score"] >= SUSPICIOUS_THRESHOLD


# ---- proportional scoring: "N of ~70 engines" becomes a score; only a consensus blocks by itself ----

def test_score_scales_with_the_share_of_engines():
    r = gdc.risk_from_detections
    assert r(0, 0, 70) == 20.0
    assert r(0, 0, 5) == gdc.NEUTRAL_RISK                     # little VirusTotal data: stay neutral
    two_of_70 = r(2, 0, 70)
    assert 40 <= two_of_70 < 50                                # weak signal, nowhere near a verdict
    assert 50 <= r(5, 0, 70) < 70
    assert 70 <= r(14, 0, 70) < 90
    assert r(25, 0, 70) == 95.0 and r(15, 0, 200) == 95.0      # majority/consensus or 15+ engines
    values = [r(m, 0, 70) for m in range(0, 30)]
    assert values == sorted(values)                            # more detections never lowers the score


def test_suspicious_engines_count_half(tmp_path):
    assert gdc.risk_from_detections(0, 4, 70) == gdc.risk_from_detections(2, 0, 70)


def test_two_of_seventy_is_a_weak_signal_not_a_verdict(tmp_path, monkeypatch):
    patch_get(monkeypatch, lambda u: Resp(200, vt_payload(2, total=70)))
    rep = make(tmp_path).get_vt_reputation("https://odd-new-site.example/")
    assert 40 <= rep["vt_risk_score"] < 50 and not rep["is_whitelisted"]
    assert (rep["malicious_count"], rep["total_engines"]) == (2, 70)
    assert rep["vt_risk_score"] < 90                           # the pipeline sends this to the sandbox


def test_majority_of_engines_is_a_block_level_score(tmp_path, monkeypatch):
    patch_get(monkeypatch, lambda u: Resp(200, vt_payload(30, total=70)))
    assert make(tmp_path).get_vt_reputation("https://bad-site.example/")["vt_risk_score"] == 95.0


def test_popular_domain_with_two_flags_is_still_trusted(tmp_path, monkeypatch):
    patch_get(monkeypatch, lambda u: Resp(200, vt_payload(2, rank=1)))
    rep = make(tmp_path).get_vt_reputation("https://www.google.com/")
    assert rep["is_whitelisted"] and rep["vt_risk_score"] <= 10.0 and rep["malicious_count"] == 2


def test_popular_domain_is_not_whitelisted_when_many_engines_flag_it(tmp_path, monkeypatch):
    patch_get(monkeypatch, lambda u: Resp(200, vt_payload(10, rank=5000)))      # 14% of engines
    rep = make(tmp_path).get_vt_reputation("https://hijacked-giant.example/")
    assert not rep["is_whitelisted"] and rep["vt_risk_score"] >= 70


def test_moderately_popular_domain_with_flags_goes_to_the_sandbox(tmp_path, monkeypatch):
    patch_get(monkeypatch, lambda u: Resp(200, vt_payload(2, rank=300000)))
    rep = make(tmp_path).get_vt_reputation("https://mid-site.example/")
    assert not rep["is_whitelisted"] and rep["vt_risk_score"] < 90


def test_old_cache_entries_from_earlier_rules_are_ignored(tmp_path, monkeypatch):
    c = make(tmp_path)
    c._cache.put("google.com", {"is_whitelisted": False, "malicious_count": 2, "popularity_rank": 99999999,
                                "vt_risk_score": 95.0, "provider": ""}, 3600)   # an old entry (no version field)
    patch_get(monkeypatch, lambda u: Resp(200, vt_payload(2, rank=1)))
    assert c.get_vt_reputation("https://www.google.com/")["is_whitelisted"]
