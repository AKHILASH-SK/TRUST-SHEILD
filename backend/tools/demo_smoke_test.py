"""
TrustShield demo smoke test: walks the flows you will show judges and prints PASS/FAIL for each step.

    python backend/tools/demo_smoke_test.py                         # against http://127.0.0.1:8000
    python backend/tools/demo_smoke_test.py --base https://<your-host>
    python backend/tools/demo_smoke_test.py --phone 9XXXXXXXXX --pin 1234   # use an existing account instead of creating one

Needs a running backend with its database. Exit code is 0 only if every step passed, so it can gate a deployment.
Safe by design: it scans only well-known harmless links and a bundled sample phishing email (never opens malicious sites).
"""
import argparse
import hashlib
import os
import random
import sys
import time

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE_EML = os.path.join(os.path.dirname(HERE), "LIVE_COIMBATORE_ATTACK.eml")

results = []


def step(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  - {detail}" if detail else ""), flush=True)
    return ok


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8000")
    ap.add_argument("--phone")
    ap.add_argument("--pin")
    ap.add_argument("--timeout", type=float, default=90.0)
    args = ap.parse_args()
    base, T = args.base.rstrip("/"), args.timeout
    s = requests.Session()

    def call(method, path, **kw):
        kw.setdefault("timeout", T)
        return s.request(method, base + path, **kw)

    # ---- 0. service up (a sleeping Render server needs ~50 s; allow for it)
    started = time.time()
    try:
        r = call("GET", "/health")
        step("server is up", r.status_code == 200, f"{time.time() - started:.1f}s")
    except Exception as exc:
        step("server is up", False, str(exc)[:120])
        return 1
    r = call("GET", "/portal/")
    step("portal page is served", r.status_code == 200 and "TrustShield" in r.text)

    # ---- 1. account and token
    if args.phone and args.pin:
        phone, pin = args.phone, args.pin
    else:
        phone = "9" + "".join(random.choice("0123456789") for _ in range(9))
        pin = "4321"
        r = call("POST", "/api/auth/register", json={"name": "Smoke", "last_name": "Test", "phone_number": phone,
                                                     "email": f"smoke{phone}@example.com", "pin": pin})
        step("register new test user", r.status_code == 201, f"HTTP {r.status_code}")
    r = call("POST", "/api/auth/login", json={"phone_number": phone, "pin": pin})
    ok = r.status_code == 200 and r.json().get("token")
    step("login returns a token", ok, f"HTTP {r.status_code}")
    if not ok:
        return 1
    token, uid = r.json()["token"], r.json()["id"]
    auth = {"Authorization": f"Bearer {token}"}
    step("wrong PIN is rejected", call("POST", "/api/auth/login", json={"phone_number": phone, "pin": "0000"}).status_code == 401)

    # ---- 2. access control
    step("history without token is refused", call("GET", f"/api/links/history/{uid}").status_code == 401)
    step("another user's history is refused", call("GET", f"/api/links/history/{uid + 100000}", headers=auth).status_code == 403)
    step("admin endpoint is closed", call("POST", "/api/phishing/import", json={"urls": ["http://x.example"]}).status_code == 403)

    # ---- 3. link scan flow (harmless links only)
    for url, expect in (("https://www.google.com/", "SAFE"), ("https://www.amazon.in/", "SAFE")):
        t = time.time()
        r = call("POST", "/api/links/scan", json={"url": url, "source_app": "smoke-test"}, headers=auth)
        v = r.json().get("verdict") if r.ok else None
        step(f"scan {url} -> {expect}", r.status_code == 201 and v == expect, f"got {v} in {time.time() - t:.1f}s")
    r = call("POST", "/api/links/scan", json={"url": "http://127.0.0.1:8000/"}, headers=auth)
    step("internal address is not fetched (SSRF guard)", r.status_code in (201, 400) and
         (r.status_code == 400 or r.json().get("analysis_complete") is not True or r.json().get("verdict") != "SAFE"),
         f"HTTP {r.status_code}")
    r = call("POST", "/api/links/scan", json={"url": "javascript:alert(1)"}, headers=auth)
    step("non-web link is rejected", r.status_code == 400)
    r = call("GET", f"/api/links/history/{uid}", headers=auth)
    step("history lists the scans with source app", r.ok and r.json().get("total_scans", 0) >= 2 and
         any(x.get("source_app") == "smoke-test" for x in r.json().get("scans", [])))
    r = call("POST", "/api/sandbox-check", json={"url": "https://www.google.com/"}, headers=auth)
    keys = {"verdict", "confidence", "details", "analysis_complete"}
    step("sandbox-check keeps the Android contract", r.ok and keys <= set(r.json()))

    # ---- 4. forensic case flow with the bundled sample email
    if not os.path.exists(SAMPLE_EML):
        step("sample .eml present", False, SAMPLE_EML)
        return 1
    raw = open(SAMPLE_EML, "rb").read()
    t = time.time()
    r = call("POST", "/api/forensics/analyze-eml", data=raw, headers={**auth, "Content-Type": "message/rfc822"},
             params={"skip_sandbox": "true"})
    ok = r.status_code == 200 and r.json().get("case_id")
    step("email analysed and case created", ok, f"HTTP {r.status_code} in {time.time() - t:.1f}s")
    if not ok:
        return 1
    case = r.json()
    cid = case["case_id"]
    step("verdict and score present", bool(case.get("verdict")) and "overall_threat_score" in case,
         f"{case.get('verdict')} {case.get('overall_threat_score')}")
    step("evidence hash is SHA-256 of the uploaded file", case.get("evidence_hash_sha256") == hashlib.sha256(raw).hexdigest())
    step("case is sealed", case.get("integrity", {}).get("status") == "VERIFIED")
    step("route map and link evidence present", "route_map" in case.get("origin_intelligence", {}) and "link_investigation" in case)
    r = call("GET", f"/api/forensics/case/{cid}")
    step("case can be reopened by its id", r.ok and r.json().get("case_id") == cid and "raw_eml" not in r.json())
    r = call("POST", "/api/forensics/verify-hash", json={"query": cid})
    step("verify-hash says seal valid", r.ok and r.json().get("integrity_status") == "VERIFIED")
    r = call("POST", "/api/forensics/verify-file", data=raw, headers={"Content-Type": "message/rfc822"})
    step("verify-file matches the original file", r.ok and r.json().get("matched") is True)
    r = call("POST", "/api/forensics/verify-file", data=raw + b"\n", headers={"Content-Type": "message/rfc822"})
    step("a one-byte change is NOT a match", r.ok and r.json().get("matched") is False)
    r = call("POST", "/api/forensics/export-pdf", json={"case_id": cid})
    step("PDF dossier downloads", r.status_code == 200 and r.content.startswith(b"%PDF"), f"{len(r.content)} bytes")
    r = call("GET", "/api/forensics/cases", headers=auth)
    step("case appears in the owner's list", r.ok and any(c["case_id"] == cid for c in r.json().get("cases", [])))
    r = call("GET", "/api/forensics/cases")
    step("case list without token is refused", r.status_code == 401)

    # ---- 5. hostile input is handled cleanly
    r = call("POST", "/api/forensics/analyze-eml", data=b"A" * (11 * 1024 * 1024), headers={"Content-Type": "message/rfc822"})
    step("oversized upload gives 413", r.status_code == 413)
    r = call("POST", "/api/forensics/nlp-analyze", data="{bad json", headers={"Content-Type": "application/json"})
    step("malformed JSON gives 400", r.status_code == 400)

    failed = [n for n, ok, _ in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} steps passed" + (f"; FAILED: {failed}" if failed else " - demo flow is healthy"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
