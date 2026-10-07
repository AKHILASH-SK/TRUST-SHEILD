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


def fit_lgbm(X_tr, y_tr, X_val, y_val, categorical: Optional[List[int]] = None):
    import lightgbm as lgb
    clf = lgb.LGBMClassifier(class_weight="balanced", **lgbm_params(len(y_tr)))
    clf.fit(
        X_tr, y_tr, eval_set=[(X_val, y_val)], eval_metric="binary_logloss",
        categorical_feature=categorical or "auto",
        callbacks=[lgb.early_stopping(100, verbose=False), lgb.log_evaluation(100)],
    )
    return clf


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
