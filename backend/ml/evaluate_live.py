"""
TrustShield ML - live accuracy test of the whole link pipeline.

Pulls the FRESHEST phishing links and a random set of legitimate sites that no model trained on, runs each through the
real pipeline (heuristics -> sandbox -> ML -> final verdict) and prints how often the verdict is right.
This is the number to show: it measures new links, not memorised ones. Run it inside Docker for the real
JavaScript-capable sandbox:

    docker run --rm --shm-size=1g --memory=6g -w /srv/backend \
        -v "<repo>/backend/ml/data:/srv/backend/ml/data" trustshield-backend \
        python -m ml.evaluate_live --n-malicious 150 --n-benign 150 --workers 4

By default the threat-database lookup and VirusTotal are switched OFF so only the dynamic analysis is tested.
Add --with-threat-db / --with-virustotal to measure the full product.
"""

import argparse
import collections
import concurrent.futures as cf
import json
import os
import random
import sys
import tempfile
import time
from typing import Dict, List, Tuple

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

os.environ.setdefault("ENABLE_THREAT_SYNC", "false")

from ml import datasets, trainlib  # noqa: E402
from ml.features import group_key  # noqa: E402


def fresh_malicious(n: int, rng: random.Random, exclude_hashes: set, exclude_urls: set, exclude_groups: set) -> List[str]:
    """Newest first: OpenPhish is real-time, PhishTank rows are ordered by submission time."""
    pool: List[str] = []
    pool += datasets.load_openphish(refresh=True)
    pt = datasets.load_phishtank(refresh=True)
    pool += pt[:4000]          # head of the file = most recently verified
    seen, out = set(), []
    for u in pool:
        if u in seen or u in exclude_urls or trainlib.url_hash(u) in exclude_hashes or group_key(u) in exclude_groups:
            continue
        seen.add(u)
        out.append(u)
    rng.shuffle(out)
    per_group: Dict[str, int] = collections.Counter()
    final = []
    for u in out:
        g = group_key(u)
        if per_group[g] >= 2:
            continue
        per_group[g] += 1
        final.append(u)
        if len(final) >= n:
            break
    return final


def fresh_benign(n: int, rng: random.Random, exclude_hashes: set, exclude_urls: set, exclude_groups: set) -> List[str]:
    tr = [d for rank, d in datasets.load_tranco() if 2_000 <= rank <= 300_000]   # long tail, not just household names
    rng.shuffle(tr)
    out = []
    for d in tr:
        u = f"https://{d}/"
        if u in exclude_urls or trainlib.url_hash(u) in exclude_hashes or group_key(u) in exclude_groups:
            continue
        out.append(u)
        if len(out) >= n:
            break
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="Measure verdict accuracy of the live pipeline on fresh links")
    ap.add_argument("--n-malicious", type=int, default=150)
    ap.add_argument("--n-benign", type=int, default=150)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--seed", type=int, default=21)
    ap.add_argument("--max-minutes", type=int, default=60, help="stop and report after this many minutes")
    ap.add_argument("--with-threat-db", action="store_true", help="also use the known-threat database (full product)")
    ap.add_argument("--with-virustotal", action="store_true", help="also use VirusTotal (needs VIRUSTOTAL_API_KEY; slow on the free tier)")
    ap.add_argument("--no-llm", action="store_true", help="switch the Gemini second opinion off (measure the model + rules only)")
    ap.add_argument("--pages", default=os.path.join(datasets.DATA_DIR, "pages.jsonl"))
    ap.add_argument("--report", default=os.path.join(datasets.DATA_DIR, "eval_report.json"))
    args = ap.parse_args()
    rng = random.Random(args.seed)

    if not args.with_virustotal:
        os.environ.pop("VIRUSTOTAL_API_KEY", None)
    if args.no_llm:
        os.environ["ENABLE_LLM_REVIEW"] = "false"

    exclude_hashes = trainlib.load_url_hashes("lexical")
    exclude_urls, exclude_groups = set(), set()
    if os.path.exists(args.pages):
        with open(args.pages, encoding="utf-8") as fh:
            for line in fh:
                try:
                    u = json.loads(line)["url"]
                    exclude_urls.add(u)
                    exclude_groups.add(group_key(u))
                except Exception:
                    pass

    mal = fresh_malicious(args.n_malicious, rng, exclude_hashes, exclude_urls, exclude_groups)
    ben = fresh_benign(args.n_benign, rng, exclude_hashes, exclude_urls, exclude_groups)
    jobs: List[Tuple[str, int]] = [(u, 1) for u in mal] + [(u, 0) for u in ben]
    rng.shuffle(jobs)
    print(f"[eval] {len(mal)} fresh malicious + {len(ben)} unseen benign links "
          f"(excluded {len(exclude_hashes):,d} training URLs)", flush=True)

    from core_engine.link_threat_pipeline import LinkThreatPipeline
    from core_engine.threat_db import ThreatIntelDB, get_threat_db
    from ml.model_runtime import get_runtime

    runtime = get_runtime()
    print(f"[eval] ML models available: {runtime.available()} "
          f"(lexical {runtime.lexical.get('version') if runtime.lexical else None}, "
          f"page {runtime.page.get('version') if runtime.page else None})", flush=True)
    threat_db = get_threat_db() if args.with_threat_db else ThreatIntelDB(os.path.join(tempfile.mkdtemp(), "empty.db"))
    pipeline = LinkThreatPipeline(threat_db=threat_db)

    def run(job: Tuple[str, int]) -> Dict:
        url, label = job
        t = time.time()
        try:
            res = pipeline.analyze_url(url)
            verdict = res["verdict"]
            shown = res.get("display_verdict")
            if shown:      # the three words the app shows; "SUSPICIOUS" below means "Unverified - open with care"
                band = {"Dangerous": "DANGEROUS", "Safe": "SAFE"}.get(shown, "SUSPICIOUS")
            else:
                band = "DANGEROUS" if verdict.startswith("CRITICAL") else ("SUSPICIOUS" if verdict.startswith("SUSPICIOUS") else "SAFE")
            tel = res.get("telemetry", {})
            return {"url": url, "label": label, "band": band, "score": res["threat_score"],
                    "complete": res.get("analysis_complete"), "ml_model": tel.get("ml_model"),
                    "ml_p": tel.get("ml_probability"), "reason": tel.get("override_reason") or ", ".join(tel.get("ml_signals", [])),
                    "seconds": round(time.time() - t, 1)}
        except Exception as exc:
            return {"url": url, "label": label, "band": "ERROR", "score": 0, "reason": str(exc)[:100], "seconds": round(time.time() - t, 1)}

    # Results are counted as they FINISH (not in submission order), every browser scan has a hard time limit, and
    # Ctrl+C still prints the numbers for everything that completed.
    rows: List[Dict] = []
    pool = cf.ThreadPoolExecutor(max_workers=args.workers)
    futures = [pool.submit(run, job) for job in jobs]
    try:
        for i, fut in enumerate(cf.as_completed(futures, timeout=args.max_minutes * 60), 1):
            rows.append(fut.result())
            if i % 10 == 0:
                print(f"[eval] {i}/{len(jobs)} done", flush=True)
    except KeyboardInterrupt:
        print("\n[eval] stopped by you: reporting what finished so far", flush=True)
    except cf.TimeoutError:
        print(f"\n[eval] time limit of {args.max_minutes} minutes reached: reporting what finished", flush=True)
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    if not rows:
        print("[eval] nothing finished, no report")
        return

    mal_rows = [r for r in rows if r["label"] == 1 and r["band"] != "ERROR"]
    ben_rows = [r for r in rows if r["label"] == 0 and r["band"] != "ERROR"]

    def pct(part: int, whole: int) -> str:
        return f"{100 * part / whole:5.1f}%" if whole else "  n/a"

    print("\n================ LIVE RESULT (links the models never trained on) ================")
    for name, group in (("MALICIOUS links", mal_rows), ("BENIGN links   ", ben_rows)):
        c = collections.Counter(r["band"] for r in group)
        print(f"{name} n={len(group):<4d} -> SAFE {pct(c['SAFE'], len(group))}   "
              f"SUSPICIOUS {pct(c['SUSPICIOUS'], len(group))}   DANGEROUS {pct(c['DANGEROUS'], len(group))}")
    caught = sum(r["band"] != "SAFE" for r in mal_rows)
    blocked_hard = sum(r["band"] == "DANGEROUS" for r in mal_rows)
    false_alarm = sum(r["band"] != "SAFE" for r in ben_rows)
    wrongly_blocked = sum(r["band"] == "DANGEROUS" for r in ben_rows)
    print(f"\nphishing caught (flagged suspicious or dangerous): {pct(caught, len(mal_rows))}")
    print(f"phishing marked DANGEROUS:                          {pct(blocked_hard, len(mal_rows))}")
    print(f"legitimate sites wrongly flagged at all:            {pct(false_alarm, len(ben_rows))}")
    print(f"legitimate sites wrongly marked DANGEROUS:          {pct(wrongly_blocked, len(ben_rows))}")
    total = len(mal_rows) + len(ben_rows)
    correct = sum((r["label"] == 1 and r["band"] == "DANGEROUS") or (r["label"] == 0 and r["band"] == "SAFE") for r in mal_rows + ben_rows)
    print(f"strict accuracy (DANGEROUS for phishing, SAFE for legitimate): {pct(correct, total)}")
    decisive = sum(r["band"] in ("SAFE", "DANGEROUS") for r in mal_rows + ben_rows)
    print(f"decisive verdicts (Safe or Dangerous, not 'Unverified - open with care'): {pct(decisive, total)}   (target 95%+)")
    secs = sorted(r["seconds"] for r in rows)
    print(f"verdict time: median {secs[len(secs)//2]}s, 90th percentile {secs[int(len(secs)*0.9)]}s, "
          f"errors {sum(r['band'] == 'ERROR' for r in rows)}")

    print("\n-- phishing the pipeline called SAFE (misses):")
    for r in [r for r in mal_rows if r["band"] == "SAFE"][:15]:
        print(f"   {r['url'][:85]}  p={r.get('ml_p')} complete={r.get('complete')}")
    print("-- legitimate sites flagged (false alarms):")
    for r in [r for r in ben_rows if r["band"] != "SAFE"][:15]:
        print(f"   {r['band']:10s} {r['url'][:60]}  p={r.get('ml_p')}  {r.get('reason', '')[:60]}")

    os.makedirs(os.path.dirname(args.report), exist_ok=True)
    with open(args.report, "w", encoding="utf-8") as fh:
        json.dump({"when": time.strftime("%Y-%m-%d %H:%M"), "with_threat_db": args.with_threat_db,
                   "with_virustotal": args.with_virustotal, "rows": rows}, fh, indent=1)
    print(f"\nfull report saved to {args.report}", flush=True)
    os._exit(0)          # do not wait for scans that were still running when we stopped


if __name__ == "__main__":
    main()
