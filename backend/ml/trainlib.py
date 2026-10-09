"""
TrustShield ML - shared training utilities: grouped splits, calibration, thresholds, metrics, saving.
"""

import hashlib
import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "core_engine", "trained_models")


def url_hash(url: str) -> int:
    return int(hashlib.md5(url.encode("utf-8", errors="replace")).hexdigest()[:15], 16)


def save_url_hashes(name: str, urls: List[str]) -> str:
    os.makedirs(MODEL_DIR, exist_ok=True)
    path = os.path.join(MODEL_DIR, f"{name}_train_urls.npy")
    np.save(path, np.array(sorted({url_hash(u) for u in urls}), dtype=np.int64))
    return path


def load_url_hashes(name: str) -> set:
    path = os.path.join(MODEL_DIR, f"{name}_train_urls.npy")
    return set(np.load(path).tolist()) if os.path.exists(path) else set()


def split_of(group: str, val_pct: int = 15, test_pct: int = 15) -> str:
    """Deterministic grouped split: every URL of one site always lands in the same split."""
    bucket = int(hashlib.md5(group.encode("utf-8")).hexdigest(), 16) % 100
    if bucket < test_pct:
        return "test"
    if bucket < test_pct + val_pct:
        return "val"
    return "train"


def cap_per_group(urls: List[str], groups: List[str], cap: int, rng) -> List[int]:
    """Indices to keep so that no single site contributes more than `cap` rows."""
    order = list(range(len(urls)))
    rng.shuffle(order)
    count: Dict[str, int] = {}
    keep = []
    for i in order:
        c = count.get(groups[i], 0)
        if c < cap:
            count[groups[i]] = c + 1
            keep.append(i)
    return sorted(keep)


def choose_thresholds(y: np.ndarray, p: np.ndarray, assumed_prevalence: float = 0.05,
                      target_precision: float = 0.99, max_miss_rate: float = 0.02) -> Dict[str, float]:
    """
    t_high: lowest probability at which a DANGEROUS verdict is >= target_precision correct, judged at the
            assumed real-world share of malicious links (benign rows are re-weighted to that share).
    t_low : highest probability below which at most `max_miss_rate` of malicious links fall (the SAFE band).
    Probabilities between the two become SUSPICIOUS.
    """
    y = np.asarray(y)
    p = np.asarray(p)
    n_pos, n_neg = max(1, int((y == 1).sum())), max(1, int((y == 0).sum()))
    benign_weight = ((1 - assumed_prevalence) / assumed_prevalence) * (n_pos / n_neg)

    candidates = np.unique(np.round(np.concatenate([p, [0.0, 1.0]]), 4))
    t_high = 1.0
    for t in candidates:                      # ascending: the first threshold that is precise enough
        tp = float(((y == 1) & (p >= t)).sum())
        fp = float(((y == 0) & (p >= t)).sum()) * benign_weight
        if tp > 0 and tp / (tp + fp) >= target_precision:
            t_high = float(t)
            break

    t_low = 0.0
    pos_p = np.sort(p[y == 1])
    if len(pos_p):
        idx = int(np.floor(max_miss_rate * len(pos_p)))
        t_low = float(pos_p[idx]) if idx < len(pos_p) else 0.0
    t_low = min(t_low, t_high * 0.9) if t_high > 0 else t_low
    return {"t_low": round(t_low, 4), "t_high": round(t_high, 4),
            "assumed_prevalence": assumed_prevalence, "target_precision": target_precision,
            "max_miss_rate": max_miss_rate}


def band_of(p: float, t_low: float, t_high: float) -> str:
    if p >= t_high:
        return "DANGEROUS"
    if p <= t_low:
        return "SAFE"
    return "SUSPICIOUS"


def evaluate(y: np.ndarray, p: np.ndarray, thresholds: Dict[str, float]) -> Dict[str, Any]:
    from sklearn.metrics import average_precision_score, brier_score_loss, roc_auc_score
    y = np.asarray(y)
    p = np.asarray(p)
    bands = np.array([band_of(v, thresholds["t_low"], thresholds["t_high"]) for v in p])
    mal, ben = y == 1, y == 0
    out: Dict[str, Any] = {
        "n": int(len(y)), "n_malicious": int(mal.sum()), "n_benign": int(ben.sum()),
        "roc_auc": round(float(roc_auc_score(y, p)), 5),
        "pr_auc": round(float(average_precision_score(y, p)), 5),
        "brier": round(float(brier_score_loss(y, p)), 5),
        "malicious_called_safe_pct": round(100 * float((bands[mal] == "SAFE").mean()), 2) if mal.any() else None,
        "malicious_called_suspicious_pct": round(100 * float((bands[mal] == "SUSPICIOUS").mean()), 2) if mal.any() else None,
        "malicious_called_dangerous_pct": round(100 * float((bands[mal] == "DANGEROUS").mean()), 2) if mal.any() else None,
        "benign_called_safe_pct": round(100 * float((bands[ben] == "SAFE").mean()), 2) if ben.any() else None,
        "benign_called_suspicious_pct": round(100 * float((bands[ben] == "SUSPICIOUS").mean()), 2) if ben.any() else None,
        "benign_called_dangerous_pct": round(100 * float((bands[ben] == "DANGEROUS").mean()), 2) if ben.any() else None,
    }
    flagged = bands != "SAFE"
    out["recall_flagged_pct"] = round(100 * float(flagged[mal].mean()), 2) if mal.any() else None
    out["false_alarm_pct"] = round(100 * float(flagged[ben].mean()), 2) if ben.any() else None
    return out


def print_report(title: str, metrics: Dict[str, Any]) -> None:
    print(f"\n=== {title} ===")
    print(f"rows {metrics['n']:,d} (malicious {metrics['n_malicious']:,d}, benign {metrics['n_benign']:,d})")
    print(f"ROC-AUC {metrics['roc_auc']}   PR-AUC {metrics['pr_auc']}   Brier {metrics['brier']}")
    print(f"MALICIOUS links  -> SAFE {metrics['malicious_called_safe_pct']}%   "
          f"SUSPICIOUS {metrics['malicious_called_suspicious_pct']}%   DANGEROUS {metrics['malicious_called_dangerous_pct']}%")
    print(f"BENIGN links     -> SAFE {metrics['benign_called_safe_pct']}%   "
          f"SUSPICIOUS {metrics['benign_called_suspicious_pct']}%   DANGEROUS {metrics['benign_called_dangerous_pct']}%")
    print(f"caught (SUSPICIOUS or DANGEROUS): {metrics['recall_flagged_pct']}%   "
          f"false alarms on benign: {metrics['false_alarm_pct']}%")


def lgbm_params(n_rows: int) -> Dict[str, Any]:
    small = n_rows < 20_000
    return dict(
        n_estimators=3000, learning_rate=0.05 if not small else 0.03,
        num_leaves=63 if not small else 15, min_child_samples=40 if not small else 15,
        subsample=0.8, subsample_freq=1, colsample_bytree=0.8, reg_lambda=1.0,
        n_jobs=-1, random_state=7, verbose=-1,
    )


_DEAD_TITLE = None


def is_dead_page(record: Dict[str, Any]) -> bool:
    """
    A page that is gone or a placeholder: 'Site not found', 404, a platform's takedown notice, 'this app is not live'...
    It tells the model nothing about phishing (the product treats these as 'offline: nothing to open'), and labelling such
    pages benign or malicious only adds noise, so training ignores them.
    """
    import re
    global _DEAD_TITLE
    if _DEAD_TITLE is None:
        _DEAD_TITLE = re.compile(
            r"404|not found|no such (site|app|page)|takedown|take-down|isn'?t live|not live|no longer (available|exists)|"
            r"suspended|has been (removed|deleted|disabled)|deployment (not found|has been)|domain (is )?(for sale|expired|parked)|"
            r"default web ?page|welcome to nginx|apache2? (ubuntu )?default|coming soon|under construction|page cannot be found|"
            r"this (site|page|app|form) (can.t|cannot|could ?n.t) be (reached|found)|couldn.t find this", re.I)
    evidence = record.get("evidence") or {}
    title = str(evidence.get("page_title") or "")
    try:
        status = int(evidence.get("http_status") or 0)
    except (TypeError, ValueError):
        status = 0
    return bool(status >= 400 or _DEAD_TITLE.search(title))


def fmt_secs(seconds: float) -> str:
    seconds = int(max(0, seconds))
    if seconds < 90:
        return f"{seconds}s"
    if seconds < 5400:
        return f"{seconds // 60}m{seconds % 60:02d}s"
    return f"{seconds // 3600}h{(seconds % 3600) // 60:02d}m"


class Stages:
    """Prints '[2/6] text   (step took 12s, total 1m30s)' lines so a long run always shows where it is."""

    def __init__(self, total: int):
        self.total, self.t0, self.last, self.n = total, time.time(), time.time(), 0

    def step(self, text: str) -> None:
        now = time.time()
        if self.n:
            print(f"      done in {fmt_secs(now - self.last)}  (total so far {fmt_secs(now - self.t0)})", flush=True)
        self.n += 1
        self.last = now
        print(f"[{self.n}/{self.total}] {text}", flush=True)

    def finish(self) -> None:
        now = time.time()
        print(f"      done in {fmt_secs(now - self.last)}  (TOTAL {fmt_secs(now - self.t0)})", flush=True)


class _Tee:
    """Copies everything printed to a log file and puts a running clock at the start of every line: [+2m10s] text."""

    def __init__(self, *streams):
        self.streams = streams
        self.t0 = time.time()
        self.at_line_start = True

    def _stamp(self, data: str) -> str:
        out = []
        for chunk in data.splitlines(True):
            if self.at_line_start and chunk.strip():
                out.append(f"[+{fmt_secs(time.time() - self.t0):>6}] ")
            out.append(chunk)
            self.at_line_start = chunk.endswith("\n")
        return "".join(out)

    def write(self, data):
        stamped = self._stamp(data)
        for s in self.streams:
            try:
                s.write(stamped)
                s.flush()
            except Exception:
                pass
        return len(data)

    def flush(self):
        for s in self.streams:
            try:
                s.flush()
            except Exception:
                pass

    def isatty(self):
        return False


def start_log(name: str) -> str:
    """Everything printed from now on is ALSO saved to backend/ml/data/logs/<name>_<time>.log (kept after the run)."""
    import sys
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "logs")
    os.makedirs(log_dir, exist_ok=True)
    path = os.path.join(log_dir, f"{name}_{time.strftime('%Y%m%d-%H%M%S')}.log")
    fh = open(path, "a", encoding="utf-8", buffering=1)
    sys.stdout = _Tee(sys.__stdout__, fh)
    print(f"[log] this run is also saved to {path}", flush=True)
    return path


def progress_callback(every: int = 50, patience: int = 100):
    """LightGBM callback: a readable progress line every `every` trees (validation loss, best so far, speed, time)."""
    t0 = time.time()

    def _callback(env) -> None:
        it = env.iteration + 1
        if it % every and it != 1:
            return
        loss = env.evaluation_result_list[0][2] if env.evaluation_result_list else float("nan")
        best = getattr(env.model, "best_iteration", 0) or 0
        speed = it / max(1e-6, time.time() - t0)
        print(f"      tree {it:>4d}   validation loss {loss:.4f}   {speed:,.0f} trees/s   elapsed {fmt_secs(time.time() - t0)}"
              f"   (stops after {patience} trees without improvement)", flush=True)

    _callback.order = 30
    return _callback


def cached_features(urls: List[str], featurize_fn, tag: str, version: int):
    """Feature matrix for exactly this list of URLs, computed once and then loaded from disk (re-runs are instant)."""
    import hashlib
    cache_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "cache")
    os.makedirs(cache_dir, exist_ok=True)
    key = hashlib.sha256(("\n".join(urls) + f"|v{version}").encode("utf-8", errors="replace")).hexdigest()[:20]
    path = os.path.join(cache_dir, f"{tag}_{key}.npy")
    if os.path.exists(path):
        print(f"      loaded the saved feature matrix ({os.path.basename(path)}): no need to recompute", flush=True)
        return np.load(path)
    matrix = featurize_fn(urls)
    np.save(path, matrix)
    print(f"      saved the feature matrix for next time ({os.path.basename(path)})", flush=True)
    return matrix


def fit_lgbm(X_tr, y_tr, X_val, y_val, categorical: Optional[List[int]] = None, w_tr=None, w_val=None):
    import lightgbm as lgb
    params = lgbm_params(len(y_tr))
    print(f"      training LightGBM on the CPU ({os.cpu_count()} threads): {len(y_tr):,d} rows, up to {params['n_estimators']} trees. "
          f"(Fitting takes seconds to a few minutes; a GPU would not make it meaningfully faster at this size.)", flush=True)
    clf = lgb.LGBMClassifier(class_weight="balanced", **params)
    kwargs = {}
    if w_tr is not None:
        kwargs["sample_weight"] = w_tr
        kwargs["eval_sample_weight"] = [w_val if w_val is not None else np.ones(len(y_val))]
    clf.fit(
        X_tr, y_tr, eval_set=[(X_val, y_val)], eval_metric="binary_logloss",
        categorical_feature=categorical or "auto",
        callbacks=[lgb.early_stopping(100, verbose=False), progress_callback(50, 100)],
        **kwargs,
    )
    return clf


def hosted_balance_weights(urls: List[str], labels, cap: float = 8.0):
    """
    Sample weights that make the two classes count about equally AMONG sites on shared hosting platforms: whichever class is the
    smaller one there is weighted up (at most x`cap`). Without this, hundreds of phishing pages on the same platforms drown the
    few benign ones (the old model learned "hosted = phishing"), or the other way round once many benign hosted pages exist.
    Everything not hosted keeps weight 1.
    """
    from .features import is_hosted
    hosted = np.array([is_hosted(u) for u in urls])
    labels = np.asarray(labels)
    n_mal = int(((labels == 1) & hosted).sum())
    n_ben = int(((labels == 0) & hosted).sum())
    weights = np.ones(len(urls), dtype=np.float32)
    stat = {"hosted_malicious": n_mal, "hosted_benign": n_ben, "benign_hosted_weight": 1.0, "malicious_hosted_weight": 1.0}
    if n_ben > 0 and n_mal > 0:
        if n_mal > n_ben:
            stat["benign_hosted_weight"] = min(cap, n_mal / n_ben)
            weights[(labels == 0) & hosted] = stat["benign_hosted_weight"]
        elif n_ben > n_mal:
            stat["malicious_hosted_weight"] = min(cap, n_ben / n_mal)
            weights[(labels == 1) & hosted] = stat["malicious_hosted_weight"]
    return weights, stat


def print_hosted_report(urls: List[str], y, p, thresholds: Dict[str, Any]) -> Dict[str, Any]:
    """The part of the test set that lives on shared hosting platforms, reported on its own (this is where the old bias was)."""
    from .features import is_hosted
    mask = np.array([is_hosted(u) for u in urls])
    out = {"n": int(mask.sum())}
    if mask.sum() < 5:
        print("\n(hosted sites in the test set: too few to report separately)")
        return out
    yy, pp = np.asarray(y)[mask], np.asarray(p)[mask]
    ben, mal = pp[yy == 0], pp[yy == 1]
    t_lo, t_hi = thresholds["t_low"], thresholds["t_high"]
    out.update({
        "n_benign": int(len(ben)), "n_malicious": int(len(mal)),
        "benign_called_dangerous_pct": round(100 * float((ben >= t_hi).mean()), 1) if len(ben) else None,
        "benign_called_safe_pct": round(100 * float((ben <= t_lo).mean()), 1) if len(ben) else None,
        "malicious_called_dangerous_pct": round(100 * float((mal >= t_hi).mean()), 1) if len(mal) else None,
        "malicious_called_safe_pct": round(100 * float((mal <= t_lo).mean()), 1) if len(mal) else None,
    })
    print(f"\n=== SITES ON SHARED HOSTING (vercel.app, github.io ...) - test set ===")
    print(f"benign {out['n_benign']}: SAFE {out['benign_called_safe_pct']}%   DANGEROUS {out['benign_called_dangerous_pct']}%   "
          f"(the old model called nearly all of these suspicious)")
    print(f"malicious {out['n_malicious']}: SAFE {out['malicious_called_safe_pct']}%   DANGEROUS {out['malicious_called_dangerous_pct']}%")
    return out


def fit_calibrator(p_val: np.ndarray, y_val: np.ndarray):
    from sklearn.isotonic import IsotonicRegression
    iso = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
    iso.fit(p_val, y_val)
    return iso


def top_importances(clf, names: List[str], k: int = 20) -> List[Tuple[str, float]]:
    gains = clf.booster_.feature_importance(importance_type="gain")
    total = float(gains.sum()) or 1.0
    order = np.argsort(-gains)[:k]
    return [(names[i], round(100 * float(gains[i]) / total, 2)) for i in order]


def save_artifact(name: str, payload: Dict[str, Any]) -> str:
    import joblib
    os.makedirs(MODEL_DIR, exist_ok=True)
    payload["version"] = payload.get("version") or time.strftime("%Y%m%d-%H%M")
    path = os.path.join(MODEL_DIR, f"{name}.joblib")
    joblib.dump(payload, path, compress=3)
    summary = {k: v for k, v in payload.items() if k not in ("model", "calibrator")}
    with open(os.path.join(MODEL_DIR, f"{name}.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2, default=str)
    return path
