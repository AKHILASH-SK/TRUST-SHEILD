import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from core_engine.final_decision_engine import (
    CRITICAL_THRESHOLD, SUSPICIOUS_THRESHOLD, FinalDecisionEngine,
)
from core_engine.url_heuristics import parse_url_heuristics
from core_engine.threat_db import ThreatIntelDB


def run(url, **kw):
    h = parse_url_heuristics(url)
    return FinalDecisionEngine().evaluate(
        url=url, heuristic_risk=h["heuristic_risk_score"], heuristic_flags=h["heuristic_flags"],
        url_entropy_risk=h["url_entropy_risk"], typosquat_risk=1 if h["suspicious_subdomain_brand"] else 0, **kw)


def test_constants():
    assert SUSPICIOUS_THRESHOLD == 50 and CRITICAL_THRESHOLD == 80


def test_raw_ip_login_url_is_at_least_60():
    r = run("http://192.0.2.10/login/verify")
    assert r["threat_score"] >= 60 and r["verdict"] != "LEGITIMATE / CLEAN"
    assert r["telemetry"]["override_reason"]


def test_raw_ip_non_standard_port_is_at_least_60():
    assert run("http://192.0.2.10:8080/")["threat_score"] >= 60


def test_brand_in_subdomain_is_at_least_70():
    r = run("https://paypal.secure-check.example.net/")
    assert r["threat_score"] >= 70 and r["verdict"] in ("SUSPICIOUS", "CRITICAL FRAUD / PHISHING")


def test_at_spoofing_is_at_least_65():
    assert run("https://www.paypal.com@evil.example.net/")["threat_score"] >= 65


def test_at_in_path_is_not_spoofing():
    h = parse_url_heuristics("https://medium.com/@someone/post")
    assert not h["has_at_symbol"]


def test_legit_brand_subdomains_not_flagged():
    for u in ("https://aws.amazon.com/", "https://outlook.office.com/mail", "https://workspace.google.com/"):
        assert not parse_url_heuristics(u)["suspicious_subdomain_brand"], u


def test_aws_keyword_needs_word_boundary_in_subdomain():
    assert not parse_url_heuristics("https://laws.example.org/")["suspicious_subdomain_brand"]
    assert parse_url_heuristics("https://aws.example.org/")["suspicious_subdomain_brand"]


def test_unreachable_with_no_other_signal_stays_low_but_incomplete():
    r = run("https://plain-site.example.org/", sandbox_unreachable=1, sandbox_threat=40)
    assert r["analysis_complete"] is False and r["telemetry"]["analysis_complete"] is False
    assert r["threat_score"] < SUSPICIOUS_THRESHOLD
    assert "could not be inspected" in r["summary"]


def test_unreachable_with_young_domain_floors_to_50():
    r = run("https://plain-site.example.org/", sandbox_unreachable=1, domain_age_days=5)
    assert r["threat_score"] >= 50 and r["verdict"] != "LEGITIMATE / CLEAN"


def test_ssrf_blocked_counts_as_incomplete():
    r = run("https://plain-site.example.org/", sandbox_blocked=1)
    assert r["analysis_complete"] is False


def test_complete_analysis_flag_true_by_default():
    r = run("https://plain-site.example.org/")
    assert r["analysis_complete"] is True and r["telemetry"]["analysis_complete"] is True


def test_known_good_unreachable_is_complete():
    r = run("https://plain-site.example.org/", sandbox_unreachable=1, known_good=True)
    assert r["analysis_complete"] is True


# ---- threat_db key building --------------------------------------------------
def test_threat_db_lookup_variants(tmp_path):
    db = ThreatIntelDB(str(tmp_path / "t.db"))
    db.add_indicator("evil.example.net/phish", "t")
    db.add_indicator("badhost.example.org", "t")
    assert db.count() == 2
    assert db.check_indicator("https://www.evil.example.net/phish/?x=1")
    assert db.check_indicator("http://evil.example.net/phish")
    assert db.check_indicator("https://badhost.example.org/any/path")
    assert not db.check_indicator("https://good.example.net/")


def test_threat_db_does_not_block_user_content_platform(tmp_path):
    db = ThreatIntelDB(str(tmp_path / "t.db"))
    db.add_indicators([("blogspot.com", "feed"), ("evil.github.io/x", "feed"), ("github.io", "feed"),
                       ("sharepoint.com", "feed")])
    assert not db.check_indicator("https://harmless.blogspot.com/post")
    assert not db.check_indicator("https://tenant.sharepoint.com/sites/a")
    assert not db.check_indicator("https://other.github.io/")
    assert db.check_indicator("https://evil.github.io/x")  # exact URL still matches
