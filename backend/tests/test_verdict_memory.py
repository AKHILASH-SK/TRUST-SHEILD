"""The shared verdict memory: what is strong enough to remember, expiry stamps, and the instant answer path."""
import app as backend_app
import verdict_memory as vm


def result(display, **kw):
    base = {"display_verdict": display, "decisive": True, "analysis_complete": True, "verification_state": "verified",
            "threat_score": 100.0 if display == "Dangerous" else 5.0, "summary": "s",
            "telemetry": {"ml_capped_no_evidence": False, "ml_capped_uninspected": False, "hard_override_triggered": False}}
    base.update(kw)
    return base


def test_only_evidence_backed_verdicts_are_remembered():
    url = "https://fake-bank-login.example/verify"
    assert vm.storable_ttl(url, result("Dangerous")) == vm.TTL_DANGEROUS_SECONDS
    assert vm.storable_ttl(url, result("Safe")) == vm.TTL_SAFE_SECONDS
    assert vm.TTL_SAFE_SECONDS < vm.TTL_DANGEROUS_SECONDS
    # uncertain, undecided, incomplete: never
    assert vm.storable_ttl(url, result("Unverified - open with care", decisive=False)) is None
    assert vm.storable_ttl(url, result("Dangerous", decisive=False)) is None
    assert vm.storable_ttl(url, result("Dangerous", analysis_complete=False)) is None
    # a verdict that rests on the model's score alone is not remembered
    capped = result("Dangerous")
    capped["telemetry"]["ml_capped_no_evidence"] = True
    assert vm.storable_ttl(url, capped) is None
    # a Safe from a page the sandbox never opened is not remembered
    assert vm.storable_ttl(url, result("Safe", verification_state="unverified")) is None
    # a Dangerous without an inspected page needs a hard rule behind it
    assert vm.storable_ttl(url, result("Dangerous", verification_state="unverified")) is None
    hard = result("Dangerous", verification_state="unverified")
    hard["telemetry"]["hard_override_triggered"] = True
    assert vm.storable_ttl(url, hard) == vm.TTL_DANGEROUS_SECONDS


def test_short_links_and_threat_list_hits_are_not_remembered():
    assert vm.storable_ttl("https://bit.ly/abc", result("Dangerous")) is None        # hides its real target
    assert vm.storable_ttl("https://app.link/xyz", result("Safe")) is None
    assert vm.storable_ttl("https://evil.example/", result("Dangerous", tier_0_match=True)) is None   # already instant


def test_the_stamp_changes_with_the_model_files_and_the_rules(tmp_path, monkeypatch):
    monkeypatch.setenv("TRUSTSHIELD_ML_DIR", str(tmp_path))
    (tmp_path / "lexical_model.joblib").write_bytes(b"a")
    (tmp_path / "page_model.joblib").write_bytes(b"b")
    first = vm.current_stamp()
    import os
    os.utime(tmp_path / "page_model.joblib", (1_700_000_000, 1_700_000_000))          # a retrained model
    assert vm.current_stamp() != first
    monkeypatch.setattr(vm, "RULES_VERSION", "changed-rules")
    assert vm.current_stamp().startswith("changed-rules")


def test_stored_copy_drops_screenshots_and_private_parts():
    compact = vm._compact({"display_verdict": "Safe", "telemetry": {"_screenshot_b64": "x" * 5000, "ml_model": "page"}, "_html": "<p>"})
    assert "_screenshot_b64" not in compact and "_html" not in compact and "ml_model" in compact


def test_a_remembered_verdict_is_answered_without_running_any_analysis(monkeypatch):
    stored = result("Dangerous", url="https://fake-bank-login.example/verify")
    monkeypatch.setattr(backend_app.verdict_store, "lookup", lambda url: dict(stored))
    monkeypatch.setattr(backend_app, "get_link_pipeline",
                        lambda: (_ for _ in ()).throw(AssertionError("the pipeline must not run for a remembered link")))
    out = backend_app._scan_runner("https://fake-bank-login.example/verify")
    assert out["display_verdict"] == "Dangerous" and out["tier_analyzed"] == "VERDICT_MEMORY"


def test_nothing_is_stored_or_read_when_the_database_is_down():
    memory = vm.VerdictMemory(lambda: (_ for _ in ()).throw(RuntimeError("db down")))
    assert memory.lookup("https://x.example/") is None and memory.remember("https://x.example/", result("Safe")) is False
    memory.ready = True
    assert memory.lookup("https://x.example/") is None and memory.remember("https://x.example/", result("Safe")) is False
