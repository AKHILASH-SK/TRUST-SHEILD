"""
TrustShield ML - live page collector.

Visits URLs with the same sandbox the product uses and stores what it saw (sandbox features plus the
compressed HTML), so page features can be recomputed later without re-fetching pages that have since
been taken down. Run it INSIDE Docker: it opens real malicious pages in headless Chromium.

    docker run --rm --cap-drop=ALL --security-opt no-new-privileges --shm-size=1g --memory=6g \
        -v "<repo>/backend/ml/data:/srv/backend/ml/data" trustshield-backend \
        python -m ml.collect_dataset --n-malicious 3000 --n-benign 3000 --workers 4

Resumable: URLs already present in the output file are skipped, so you can stop (Ctrl+C) and run again.
Label convention: 1 = malicious (phishing or malware), 0 = benign.
"""

import argparse
import base64
import collections
import concurrent.futures as cf
import json
import os
import random
import sys
import threading
import time
import zlib
from typing import Dict, List, Optional, Tuple

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from ml import datasets  # noqa: E402
from ml.features import group_key, split_url  # noqa: E402

DEFAULT_OUT = os.path.join(datasets.DATA_DIR, "pages.jsonl")
KEEP_SANDBOX_KEYS = [
    "sandbox_num_redirects", "newly_registered_domain", "domain_age_days", "domain_risk_score",
    "sandbox_has_password_field", "external_form_action", "suspicious_exfiltration", "sandbox_hidden_iframes",
    "sandbox_title_mismatch", "brand_impersonation", "sandbox_threat_score", "sandbox_unreachable",
    "sandbox_blocked_unsafe_url",
]
MAX_PER_GROUP = 4          # at most this many URLs per site, so one hosting platform cannot dominate
MALICIOUS_MIX = {"phishtank": 0.40, "phishing_database": 0.25, "openphish": 0.20, "urlhaus": 0.15}
RANK_BUCKETS = [(1, 1_000), (1_001, 10_000), (10_001, 100_000), (100_001, 1_000_000)]


def pack_html(html: str) -> str:
    return base64.b64encode(zlib.compress((html or "")[:250_000].encode("utf-8", errors="replace"), 6)).decode("ascii")


def unpack_html(blob: str) -> str:
    return zlib.decompress(base64.b64decode(blob)).decode("utf-8", errors="replace") if blob else ""


def load_seen(path: str) -> set:
    seen = set()
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                try:
                    seen.add(json.loads(line)["url"])
                except Exception:
                    continue
    return seen


def pick_malicious(n: int, rng: random.Random, seen: set, refresh: bool) -> List[Tuple[str, str]]:
    pools: Dict[str, List[str]] = {
        "phishtank": datasets.load_phishtank(refresh),
        "phishing_database": datasets.load_phishing_database(refresh),
        "openphish": datasets.load_openphish(refresh),
        "urlhaus": datasets.load_urlhaus(refresh),
    }
    per_group: Dict[str, int] = collections.Counter()
    chosen: List[Tuple[str, str]] = []
    for source, share in MALICIOUS_MIX.items():
        pool = [u for u in pools[source] if u not in seen]
        # fresh feeds are most likely to still be online; archives are shuffled
        if source != "openphish":
            rng.shuffle(pool)
        want = int(n * share)
        taken = 0
        for url in pool:
            key = group_key(url)
            if per_group[key] >= MAX_PER_GROUP:
                continue
            per_group[key] += 1
            chosen.append((url, source))
            taken += 1
            if taken >= want:
                break
    rng.shuffle(chosen)
    return chosen


def pick_benign(n: int, rng: random.Random, seen: set, refresh: bool) -> List[Tuple[str, str]]:
    tranco = datasets.load_tranco(refresh)
    chosen: List[Tuple[str, str]] = []
    per_bucket = n // len(RANK_BUCKETS)
    for lo, hi in RANK_BUCKETS:
        bucket = [d for rank, d in tranco if lo <= rank <= hi]
        rng.shuffle(bucket)
        taken = 0
        for domain in bucket:
            url = f"https://{domain}/"
            if url in seen:
                continue
            chosen.append((url, f"tranco_{lo}_{hi}"))
            taken += 1
            if taken >= per_bucket:
                break
    rng.shuffle(chosen)
    return chosen


def visit(sandbox, url: str, label: int, source: str) -> Dict:
    started = time.time()
    try:
        feats = sandbox.analyze_link_in_sandbox(url)
    except Exception as exc:  # a crash must never stop the whole run
        return {"url": url, "label": label, "source": source, "ts": int(started), "status": "error",
                "error": str(exc)[:200], "sandbox": {}, "html_gz_b64": "", "final_url": url}
    html = feats.get("_html") or ""
    status = "ok"
    if feats.get("sandbox_blocked_unsafe_url"):
        status = "blocked"
    elif feats.get("sandbox_unreachable") or not html:
        status = "unreachable"
    return {
        "url": url, "label": label, "source": source, "ts": int(started),
        "elapsed": round(time.time() - started, 2), "status": status,
        "final_url": feats.get("_final_url") or url,
        "sandbox": {k: feats.get(k) for k in KEEP_SANDBOX_KEYS},
        "html_gz_b64": pack_html(html) if status == "ok" else "",
    }


def deep_links(html: str, base_url: str, limit: int = 2) -> List[str]:
    """Same-site internal links from a benign page: benign URLs that also have paths."""
    from bs4 import BeautifulSoup
    from urllib.parse import urljoin
    base_reg = split_url(base_url)["registered"]
    out: List[str] = []
    for a in BeautifulSoup(html[:300_000], "html.parser").find_all("a", href=True):
        href = urljoin(base_url, a["href"].strip())
        parts = split_url(href)
        if href.startswith(("http://", "https://")) and parts["registered"] == base_reg \
                and len(parts["parsed"].path) > 3 and href not in out and "#" not in href:
            out.append(href)
        if len(out) >= limit:
            break
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="Collect live page evidence for model training")
    ap.add_argument("--n-malicious", type=int, default=3000)
    ap.add_argument("--n-benign", type=int, default=3000)
    ap.add_argument("--deep-links", type=int, default=2, help="internal links to add per reachable benign page")
    ap.add_argument("--workers", type=int, default=4, help="parallel browsers (each Chromium uses ~300-400 MB)")
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--refresh", action="store_true", help="re-download the feeds")
    ap.add_argument("--max-minutes", type=float, default=0, help="stop after this many minutes (0 = no limit)")
    args = ap.parse_args()

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    rng = random.Random(args.seed)
    seen = load_seen(args.out)
    print(f"[collect] {len(seen):,d} URLs already collected in {args.out}", flush=True)

    from core_engine.sandbox_engine import VirtualSandboxAnalyzer, is_chrome_available
    print(f"[collect] browser sandbox: {'real Chromium (JavaScript runs)' if is_chrome_available() else 'HTTP-only fallback (no JavaScript)'}",
          flush=True)
    sandbox = VirtualSandboxAnalyzer()

    jobs: List[Tuple[str, int, str]] = []
    jobs += [(u, 1, s) for u, s in pick_malicious(args.n_malicious, rng, seen, args.refresh)]
    jobs += [(u, 0, s) for u, s in pick_benign(args.n_benign, rng, seen, args.refresh)]
    rng.shuffle(jobs)
    print(f"[collect] queued {len(jobs):,d} URLs ({sum(1 for j in jobs if j[1] == 1):,d} malicious, "
          f"{sum(1 for j in jobs if j[1] == 0):,d} benign)", flush=True)

    lock = threading.Lock()
    stats = collections.Counter()
    deadline = time.time() + args.max_minutes * 60 if args.max_minutes else None
    stop = threading.Event()
    extra: List[Tuple[str, int, str]] = []

    def write(rec: Dict, fh) -> None:
        with lock:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            fh.flush()
            stats[(rec["label"], rec["status"])] += 1
            done = sum(stats.values())
            if done % 25 == 0:
                summary = ", ".join(f"{'mal' if k[0] else 'ben'}/{k[1]}={v}" for k, v in sorted(stats.items()))
                print(f"[collect] {done:,d} done  ({summary})", flush=True)

    def worker(job: Tuple[str, int, str], fh) -> None:
        if stop.is_set() or (deadline and time.time() > deadline):
            return
        url, label, source = job
        rec = visit(sandbox, url, label, source)
        write(rec, fh)
        if label == 0 and rec["status"] == "ok" and args.deep_links and not source.startswith("deep"):
            try:
                for link in deep_links(unpack_html(rec["html_gz_b64"]), rec["final_url"], args.deep_links):
                    if link not in seen:
                        with lock:
                            extra.append((link, 0, "deep_" + source))
            except Exception:
                pass

    try:
        with open(args.out, "a", encoding="utf-8") as fh:
            with cf.ThreadPoolExecutor(max_workers=args.workers) as pool:
                try:
                    list(pool.map(lambda j: worker(j, fh), jobs))
                except KeyboardInterrupt:
                    stop.set()   # queued jobs return immediately; running ones finish and are saved
                    raise
            if extra and not stop.is_set():
                rng.shuffle(extra)
                seen_extra = set()
                deep_jobs = []
                for j in extra:
                    if j[0] not in seen_extra:
                        seen_extra.add(j[0])
                        deep_jobs.append(j)
                print(f"[collect] visiting {len(deep_jobs):,d} deep links from benign sites", flush=True)
                with cf.ThreadPoolExecutor(max_workers=args.workers) as pool:
                    try:
                        list(pool.map(lambda j: worker(j, fh), deep_jobs))
                    except KeyboardInterrupt:
                        stop.set()
                        raise
    except KeyboardInterrupt:
        stop.set()
        print("\n[collect] interrupted; progress is saved, run the same command again to resume", flush=True)

    print("[collect] finished:", dict(stats), flush=True)


if __name__ == "__main__":
    main()
