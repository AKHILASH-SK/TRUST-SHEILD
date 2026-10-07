"""
TrustShield ML - model 1 of 2: the link-text (lexical) classifier.

Learns from the URL text alone, using hundreds of thousands of public labelled URLs. It scores links the
sandbox cannot open (dead, blocked, slow) and is also an input to the page model.

    cd backend
    python -m ml.datasets --prepare                     # download feeds once (about 100 MB)
    python -m ml.train_lexical --max-rows 6000          # 1-minute dry run to check everything works
    python -m ml.train_lexical                          # full training (minutes on this CPU)

Output: core_engine/trained_models/lexical_model.joblib (+ .json with metrics and thresholds)
URLs that appear in ml/data/pages.jsonl are held OUT of this model, so the page model later sees honest,
out-of-sample lexical scores.
"""

import argparse
import json
import os
import random
import sys
import time
from typing import List

import numpy as np

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from ml import datasets, trainlib  # noqa: E402
from ml.features import FEATURE_VERSION, LEXICAL_HOST_FEATURES, group_key, lexical_features  # noqa: E402


def _featurize_chunk(urls: List[str]) -> np.ndarray:
    rows = []
    for u in urls:
        f = lexical_features(u)          # compute once per URL, then read the host columns
        rows.append([f[n] for n in LEXICAL_HOST_FEATURES])
    return np.array(rows, dtype=np.float32)


def featurize(urls: List[str], n_jobs: int) -> np.ndarray:
    from joblib import Parallel, delayed
    size = 4000
    chunks = [urls[i:i + size] for i in range(0, len(urls), size)]
    parts = Parallel(n_jobs=n_jobs, verbose=5)(delayed(_featurize_chunk)(c) for c in chunks)
    return np.vstack(parts) if parts else np.zeros((0, len(LEXICAL_HOST_FEATURES)), dtype=np.float32)


def load_pages_urls(path: str) -> set:
    urls = set()
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                try:
                    urls.add(json.loads(line)["url"])
                except Exception:
                    pass
    return urls


def main() -> None:
    ap = argparse.ArgumentParser(description="Train the lexical (URL text) phishing classifier")
    ap.add_argument("--max-per-source", type=int, default=70_000, help="malicious URLs taken per feed")
    ap.add_argument("--max-benign", type=int, default=220_000)
    ap.add_argument("--group-cap", type=int, default=6, help="max URLs per site and class")
    ap.add_argument("--max-rows", type=int, default=0, help="dry run: total rows used (0 = everything)")
    ap.add_argument("--assumed-prevalence", type=float, default=0.05,
                    help="assumed share of malicious links in real traffic, used to pick thresholds")
    ap.add_argument("--pages", default=os.path.join(datasets.DATA_DIR, "pages.jsonl"))
    ap.add_argument("--no-exclude-pages", action="store_true")
    ap.add_argument("--refresh", action="store_true")
    ap.add_argument("--jobs", type=int, default=-1, help="CPU workers for feature extraction")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    rng = random.Random(args.seed)
    t0 = time.time()

    # ---- 1. assemble labelled URLs ------------------------------------------------------------
    print("[1/6] loading datasets ...", flush=True)
    mal_sources = datasets.load_all_malicious(args.refresh, include_phiusiil=True)
    mal: List[str] = []
    for name, urls in mal_sources.items():
        urls = list(dict.fromkeys(urls))
        rng.shuffle(urls)
        mal += urls[:args.max_per_source]
        print(f"   malicious {name:18s} {min(len(urls), args.max_per_source):>8,d} of {len(urls):,d}")
    mal = list(dict.fromkeys(mal))

    legit_phiusiil, _ = datasets.load_phiusiil(args.refresh)
    ben = list(dict.fromkeys(legit_phiusiil))
    tranco = datasets.load_tranco(args.refresh)
    tranco_urls = [f"https://{d}/" for _, d in tranco]
    rng.shuffle(tranco_urls)
    ben += tranco_urls[:90_000]
    # deep links collected from reachable benign pages (benign URLs that have paths)
    if os.path.exists(args.pages):
        with open(args.pages, encoding="utf-8") as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                if rec.get("label") == 0 and str(rec.get("source", "")).startswith("deep"):
                    ben.append(rec["url"])
    ben = list(dict.fromkeys(ben))
    rng.shuffle(ben)
    ben = ben[:args.max_benign]
    print(f"   benign    {len(ben):,d} urls", flush=True)

    held_out = set() if args.no_exclude_pages else load_pages_urls(args.pages)
    held_groups = {group_key(u) for u in held_out}
    if held_out:
        before = len(mal) + len(ben)
        mal = [u for u in mal if u not in held_out and group_key(u) not in held_groups]
        ben = [u for u in ben if u not in held_out and group_key(u) not in held_groups]
        print(f"   held out {before - len(mal) - len(ben):,d} URLs that belong to collected pages", flush=True)

    urls = mal + ben
    labels = np.array([1] * len(mal) + [0] * len(ben), dtype=np.int8)
    groups = [group_key(u) for u in urls]

    # per-site caps, separately for each class
    keep: List[int] = []
    for cls in (1, 0):
        idx = [i for i in range(len(urls)) if labels[i] == cls]
        sub = trainlib.cap_per_group([urls[i] for i in idx], [groups[i] for i in idx], args.group_cap, rng)
        keep += [idx[j] for j in sub]
    keep.sort()
    if args.max_rows and len(keep) > args.max_rows:
        keep = sorted(rng.sample(keep, args.max_rows))
    urls = [urls[i] for i in keep]
    groups = [groups[i] for i in keep]
    labels = labels[keep]
    print(f"[2/6] {len(urls):,d} rows after per-site caps (malicious {int(labels.sum()):,d}, "
          f"benign {int((labels == 0).sum()):,d})", flush=True)

    # ---- 2. features ---------------------------------------------------------------------------
    print("[3/6] extracting features ...", flush=True)
    X = featurize(urls, args.jobs)
    split = np.array([trainlib.split_of(g) for g in groups])
    tr, va, te = split == "train", split == "val", split == "test"
    print(f"   train {tr.sum():,d}  val {va.sum():,d}  test {te.sum():,d}  (split by site, no site on both sides)", flush=True)

    # ---- 3. train ------------------------------------------------------------------------------
    print("[4/6] training LightGBM ...", flush=True)
    cat = [LEXICAL_HOST_FEATURES.index("tld_id")]
    clf = trainlib.fit_lgbm(X[tr], labels[tr], X[va], labels[va], categorical=cat)
    print(f"   best iteration: {clf.best_iteration_}", flush=True)

    # ---- 4. calibrate and choose thresholds ------------------------------------------------------
    print("[5/6] calibrating and choosing thresholds ...", flush=True)
    p_val_raw = clf.predict_proba(X[va])[:, 1]
    calibrator = trainlib.fit_calibrator(p_val_raw, labels[va])
    p_val = calibrator.predict(p_val_raw)
    thresholds = trainlib.choose_thresholds(labels[va], p_val, args.assumed_prevalence)
    print(f"   thresholds: SAFE below {thresholds['t_low']}, DANGEROUS from {thresholds['t_high']}", flush=True)

    # ---- 5. honest test ---------------------------------------------------------------------------
    p_test = calibrator.predict(clf.predict_proba(X[te])[:, 1])
    metrics = trainlib.evaluate(labels[te], p_test, thresholds)
    trainlib.print_report("TEST SET (sites the model never saw)", metrics)
    importances = trainlib.top_importances(clf, LEXICAL_HOST_FEATURES)
    print("\ntop features (share of model gain %):")
    for name, share in importances[:12]:
        print(f"   {name:24s} {share:6.2f}")

    # ---- 6. save -----------------------------------------------------------------------------------
    path = trainlib.save_artifact("lexical_model", {
        "model": clf, "calibrator": calibrator, "features": LEXICAL_HOST_FEATURES, "feature_version": FEATURE_VERSION,
        "thresholds": thresholds, "metrics": {"test": metrics}, "top_features": importances,
        "trained_rows": int(len(urls)), "train_malicious": int(labels[tr].sum()),
        "train_benign": int((labels[tr] == 0).sum()), "excluded_page_urls": len(held_out),
        "categorical": ["tld_id"],
    })
    trainlib.save_url_hashes("lexical", urls)   # lets ml.evaluate_live pick URLs the model never trained on
    print(f"\n[6/6] saved {path}\n   total time {time.time() - t0:.0f}s", flush=True)


if __name__ == "__main__":
    main()
