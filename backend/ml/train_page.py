"""
TrustShield ML - model 2 of 2: the page classifier (the final ML stage of the pipeline).

Input = everything the earlier stages produce for a link:
    link-text features + the lexical model's probability + sandbox/page features
    (login forms, where forms post, scripts, redirects, hidden frames, domain age, brand clues ...)
Output = calibrated probability that the link is malicious, mapped to SAFE / SUSPICIOUS / DANGEROUS.

    cd backend
    python -m ml.train_lexical          # first: the lexical model (it must not have seen the collected pages)
    python -m ml.train_page --dry-run   # quick check
    python -m ml.train_page

Reads ml/data/pages.jsonl written by ml.collect_dataset. Only pages that were actually fetched are used.
"""

import argparse
import json
import os
import random
import sys
import time
from typing import Dict, List

import numpy as np

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from ml import datasets, trainlib  # noqa: E402
from ml.collect_dataset import unpack_html  # noqa: E402
from ml.features import (EVIDENCE_FEATURES, FEATURE_VERSION, PAGE_MODEL_LEXICAL_FEATURES,  # noqa: E402
                         PAGE_MODEL_PAGE_FEATURES, evidence_features, group_key, lexical_features, page_features)

PAGE_MODEL_FEATURES: List[str] = (PAGE_MODEL_LEXICAL_FEATURES + PAGE_MODEL_PAGE_FEATURES + EVIDENCE_FEATURES + ["lexical_prob"])


def main() -> None:
    ap = argparse.ArgumentParser(description="Train the page-level (final) phishing classifier")
    ap.add_argument("--pages", default=os.path.join(datasets.DATA_DIR, "pages.jsonl"))
    ap.add_argument("--group-cap", type=int, default=4)
    ap.add_argument("--assumed-prevalence", type=float, default=0.05)
    ap.add_argument("--min-pages", type=int, default=300, help="refuse to train on fewer fetched pages")
    ap.add_argument("--dry-run", action="store_true", help="train, print the report, do not save the model")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    rng = random.Random(args.seed)
    t0 = time.time()

    lex_path = os.path.join(trainlib.MODEL_DIR, "lexical_model.joblib")
    if not os.path.exists(lex_path):
        raise SystemExit("Train the lexical model first:  python -m ml.train_lexical")
    import joblib
    lex = joblib.load(lex_path)
    if lex.get("feature_version") != FEATURE_VERSION:
        raise SystemExit("lexical_model was built with a different feature version; retrain it.")

    if not lex.get("excluded_page_urls"):
        print("WARNING: the lexical model was trained before any pages were collected, so it may have seen these URLs")
        print("         and its probabilities can look too good. For the cleanest result run python -m ml.train_lexical again now")
        print("         that pages.jsonl exists, then retrain this model.", flush=True)

    # ---- 1. load collected pages -------------------------------------------------------------
    print("[1/5] reading collected pages ...", flush=True)
    rows: List[Dict] = []
    status_count: Dict[str, int] = {}
    with open(args.pages, encoding="utf-8") as fh:
        for line in fh:
            try:
                rec = json.loads(line)
            except Exception:
                continue
            status_count[rec.get("status", "?")] = status_count.get(rec.get("status", "?"), 0) + 1
            if rec.get("status") == "ok" and rec.get("html_gz_b64"):
                rows.append(rec)
    print(f"   statuses: {status_count}", flush=True)
    seen, unique = set(), []
    for rec in rows:
        if rec["url"] not in seen:
            seen.add(rec["url"])
            unique.append(rec)
    rows = unique
    groups = [group_key(r["url"]) for r in rows]
    keep = trainlib.cap_per_group([r["url"] for r in rows], groups, args.group_cap, rng)
    rows = [rows[i] for i in keep]
    groups = [groups[i] for i in keep]
    y = np.array([r["label"] for r in rows], dtype=np.int8)
    print(f"   usable pages: {len(rows):,d} (malicious {int(y.sum()):,d}, benign {int((y == 0).sum()):,d})", flush=True)
    if len(rows) < args.min_pages or y.sum() < 50 or (y == 0).sum() < 50:
        raise SystemExit(f"Not enough fetched pages to train a reliable model ({len(rows)}). "
                         f"Collect more: python -m ml.collect_dataset")

    # ---- 2. features -----------------------------------------------------------------------------
    print("[2/5] building features ...", flush=True)
    lex_feats = [lexical_features(r["url"]) for r in rows]
    lex_in = np.array([[f[n] for n in lex["features"]] for f in lex_feats], dtype=np.float32)
    lex_X = np.array([[f[n] for n in PAGE_MODEL_LEXICAL_FEATURES] for f in lex_feats], dtype=np.float32)
    lex_raw = lex["model"].predict_proba(lex_in)[:, 1]
    lex_prob = lex["calibrator"].predict(lex_raw)

    page_rows = []
    for r in rows:
        pf = page_features(unpack_html(r["html_gz_b64"]), r.get("final_url") or r["url"], r["url"], r.get("sandbox") or {})
        page_rows.append([pf[n] for n in PAGE_MODEL_PAGE_FEATURES])
    page_X = np.array(page_rows, dtype=np.float32)
    ev_rows = []
    for r in rows:
        ef = evidence_features(r.get("evidence"))      # once per page, then read the columns
        ev_rows.append([ef[n] for n in EVIDENCE_FEATURES])
    ev_X = np.array(ev_rows, dtype=np.float32)
    with_ev = int(sum(1 for r in rows if r.get("evidence")))
    print(f"   {with_ev:,d} of {len(rows):,d} pages carry sandbox-v2 evidence", flush=True)
    X = np.hstack([lex_X, page_X, ev_X, lex_prob.reshape(-1, 1).astype(np.float32)])

    split = np.array([trainlib.split_of(g) for g in groups])
    tr, va, te = split == "train", split == "val", split == "test"
    print(f"   train {tr.sum():,d}  val {va.sum():,d}  test {te.sum():,d}", flush=True)
    if min(int(y[va].sum()), int((y[va] == 0).sum()), int(y[te].sum()), int((y[te] == 0).sum())) < 10:
        raise SystemExit("Validation/test split has too few examples of one class; collect more pages.")

    # ---- 3. train ------------------------------------------------------------------------------------
    print("[3/5] training LightGBM ...", flush=True)
    cat = [PAGE_MODEL_FEATURES.index("tld_id")]
    page_urls = [r["url"] for r in rows]
    weights, wstat = trainlib.hosted_balance_weights(page_urls, y)
    print(f"   shared-hosting pages: malicious {wstat['hosted_malicious']:,d} vs benign {wstat['hosted_benign']:,d}; "
          f"benign hosted pages weighted x{wstat['benign_hosted_weight']:.1f}", flush=True)
    clf = trainlib.fit_lgbm(X[tr], y[tr], X[va], y[va], categorical=cat, w_tr=weights[tr], w_val=weights[va])
    print(f"   best iteration: {clf.best_iteration_}", flush=True)

    # ---- 4. calibrate, thresholds, honest test ------------------------------------------------------
    print("[4/5] calibrating and testing ...", flush=True)
    p_val_raw = clf.predict_proba(X[va])[:, 1]
    calibrator = trainlib.fit_calibrator(p_val_raw, y[va])
    thresholds = trainlib.choose_thresholds(y[va], calibrator.predict(p_val_raw), args.assumed_prevalence)
    print(f"   thresholds: SAFE below {thresholds['t_low']}, DANGEROUS from {thresholds['t_high']}", flush=True)

    p_test = calibrator.predict(clf.predict_proba(X[te])[:, 1])
    metrics = trainlib.evaluate(y[te], p_test, thresholds)
    trainlib.print_report("PAGE MODEL - TEST SET (sites never seen in training)", metrics)

    hosted_metrics = trainlib.print_hosted_report([u for u, m in zip(page_urls, te) if m], y[te], p_test, thresholds)
    lex_thr = lex["thresholds"]
    lex_metrics = trainlib.evaluate(y[te], lex_prob[te], lex_thr)
    trainlib.print_report("for comparison: LEXICAL MODEL ALONE on the same pages", lex_metrics)
    print(f"\nwhat the page features add: ROC-AUC {lex_metrics['roc_auc']} -> {metrics['roc_auc']}")

    importances = trainlib.top_importances(clf, PAGE_MODEL_FEATURES)
    print("\ntop features (share of model gain %):")
    for name, share in importances[:15]:
        print(f"   {name:28s} {share:6.2f}")

    # ---- 5. save -----------------------------------------------------------------------------------------
    if args.dry_run:
        print("\n[5/5] dry run: model NOT saved")
        return
    path = trainlib.save_artifact("page_model", {
        "model": clf, "calibrator": calibrator, "features": PAGE_MODEL_FEATURES,
        "feature_version": FEATURE_VERSION, "thresholds": thresholds,
        "metrics": {"test": metrics, "lexical_alone_on_same_pages": lex_metrics, "hosted_test": hosted_metrics},
        "top_features": importances, "trained_rows": int(len(rows)),
        "train_malicious": int(y[tr].sum()), "train_benign": int((y[tr] == 0).sum()),
        "lexical_model_version": lex.get("version"), "categorical": ["tld_id"],
    })
    print(f"\n[5/5] saved {path}\n   total time {time.time() - t0:.0f}s", flush=True)


if __name__ == "__main__":
    main()
