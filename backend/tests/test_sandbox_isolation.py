"""A page that hangs the browser must never block the caller: the worker process is killed at the hard limit."""
import sys
import time

from core_engine.browser_sandbox import analyze_isolated


def test_hung_worker_is_killed_and_reported_unverified():
    start = time.time()
    ev = analyze_isolated("http://x.example/", hard_timeout=2, worker_cmd=[sys.executable, "-c", "import time; time.sleep(60)"])
    assert time.time() - start < 15
    assert ev["verification_state"] == "unverified" and ev["unverified_reason"] == "timeout"


def test_crashing_worker_is_reported_unverified():
    ev = analyze_isolated("http://x.example/", hard_timeout=10, worker_cmd=[sys.executable, "-c", "import sys; sys.exit(3)"])
    assert ev["verification_state"] == "unverified" and ev["unverified_reason"] == "crashed"


def test_good_worker_result_is_passed_through():
    code = "import json,sys; json.dump({'verification_state':'verified','marker':1}, open(sys.argv[-1],'w'))"
    ev = analyze_isolated("http://x.example/", hard_timeout=10, worker_cmd=[sys.executable, "-c", code])
    assert ev["verification_state"] == "verified" and ev["marker"] == 1
