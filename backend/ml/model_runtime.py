"""
TrustShield ML - runtime scoring used by the live link pipeline.

Loads the trained artifacts once and scores a link:
  * if the sandbox fetched the page and a page model exists -> page model (most accurate)
  * otherwise -> lexical model (link text only)
  * no artifacts / ML disabled / any error -> returns None and the pipeline keeps using its rules

Artifacts live in core_engine/trained_models (override with TRUSTSHIELD_ML_DIR).
"""

import logging
import math
import os
import threading
from typing import Any, Dict, List, Optional

import numpy as np

from ml.features import FEATURE_VERSION, evidence_features, lexical_features, page_features

logger = logging.getLogger("trustshield.ml")

DEFAULT_MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                 "core_engine", "trained_models")

SIGNAL_LABELS = {
    "n_password": "login form with password field", "sandbox_has_password": "password field on the page",
    "form_action_external": "form sends data to another domain", "sandbox_external_form": "form posts to another domain",
    "sandbox_exfiltration": "form posts to Telegram/Discord/raw IP", "title_brand_mismatch": "page title claims a brand it does not own",
    "copyright_brand_mismatch": "copyright line names a brand it does not own", "brand_mismatch": "brand name inside an unrelated domain",
    "newly_registered": "newly registered domain", "domain_age_days": "domain age", "free_hosting": "hosted on a free site builder",
    "tld_abused": "top-level domain often used by scammers", "kw_host": "scam keywords in the domain", "kw_path": "scam keywords in the path",
    "entropy_host": "random-looking domain", "entropy_url": "random-looking link", "is_ip_host": "raw IP address as host",
    "n_hyphens_host": "many hyphens in domain", "is_spa_shell": "empty page shell that loads content by script",
    "obfuscation_calls": "obfuscated script code", "right_click_blocked": "right-click blocked", "has_meta_refresh": "automatic redirect",
    "js_redirect": "script redirect", "n_hidden_iframes": "hidden frames", "n_redirects": "redirect chain", "lexical_prob": "link text looks suspicious",
    "has_punycode": "look-alike (punycode) characters", "url_len": "very long link", "n_subdomains": "many subdomains",
    "is_https": "connection security", "n_forms": "number of forms", "body_login_words": "login wording on the page",
}


def ml_to_score(p: float, t_low: float, t_high: float) -> float:
    """Maps a probability to the 0-100 scale so that the 50 / 80 verdict cut-offs match the model bands."""
    p = min(max(float(p), 0.0), 1.0)
    if p <= t_low:
        return round(49.0 * (p / t_low), 2) if t_low > 0 else 0.0
    if p < t_high:
        return round(50.0 + 29.9 * (p - t_low) / max(1e-9, t_high - t_low), 2)
    if t_high >= 1.0:
        return 80.0
    return round(min(100.0, 80.0 + 20.0 * (p - t_high) / (1.0 - t_high)), 2)


def band_of(p: float, t_low: float, t_high: float) -> str:
    if p >= t_high:
        return "DANGEROUS"
    if p <= t_low:
        return "SAFE"
    return "SUSPICIOUS"


class ModelRuntime:
    def __init__(self, model_dir: Optional[str] = None):
        self.model_dir = model_dir or os.getenv("TRUSTSHIELD_ML_DIR") or DEFAULT_MODEL_DIR
        self.enabled = os.getenv("ENABLE_ML", "true").lower() == "true"
        self._lock = threading.Lock()
        self._loaded = False
        self.lexical: Optional[Dict[str, Any]] = None
        self.page: Optional[Dict[str, Any]] = None

    # ---- loading -------------------------------------------------------------------------------
    def _load_one(self, name: str) -> Optional[Dict[str, Any]]:
        path = os.path.join(self.model_dir, f"{name}.joblib")
        if not os.path.exists(path):
            return None
        try:
            import joblib
            art = joblib.load(path)
            if art.get("feature_version") != FEATURE_VERSION:
                logger.warning("%s was trained with feature version %s, runtime has %s: ignoring it",
                               name, art.get("feature_version"), FEATURE_VERSION)
                return None
            return art
        except Exception as exc:
            logger.warning("Could not load %s: %s", name, exc)
            return None

    def load(self) -> None:
        with self._lock:
            if self._loaded:
                return
            self.lexical = self._load_one("lexical_model")
            self.page = self._load_one("page_model")
            self._loaded = True
            logger.info("ML models: lexical=%s page=%s",
                        self.lexical.get("version") if self.lexical else None,
                        self.page.get("version") if self.page else None)

    def available(self) -> bool:
        if not self.enabled:
            return False
        self.load()
        return self.lexical is not None or self.page is not None

    # ---- scoring ----------------------------------------------------------------------------------
    @staticmethod
    def _probability(art: Dict[str, Any], row: np.ndarray) -> float:
        raw = art["model"].predict_proba(row)[:, 1]
        return float(art["calibrator"].predict(raw)[0])

    @staticmethod
    def _signals(art: Dict[str, Any], row: np.ndarray, k: int = 4) -> List[str]:
        try:
            contrib = art["model"].booster_.predict(row, pred_contrib=True)[0][:-1]
            order = np.argsort(-contrib)[:k]
            names = art["features"]
            return [SIGNAL_LABELS.get(names[i], names[i].replace("_", " ")) for i in order if contrib[i] > 0.15]
        except Exception:
            return []

    def score(self, url: str, sandbox: Optional[Dict[str, Any]] = None, use_page: bool = True) -> Optional[Dict[str, Any]]:
        """
        `sandbox` is the dict returned by the sandbox engine (it carries _html and _final_url when the page
        was fetched). Returns None when no model is available.
        """
        if not self.available():
            return None
        try:
            lex_vals = lexical_features(url)

            def build_row(art: Dict[str, Any], extra: Dict[str, float]) -> np.ndarray:
                values = {**lex_vals, **extra}
                return np.array([[values.get(n, float("nan")) for n in art["features"]]], dtype=np.float32)

            lex_row = build_row(self.lexical, {}) if self.lexical else None
            p_lex = self._probability(self.lexical, lex_row) if self.lexical else None

            sandbox = sandbox or {}
            html = sandbox.get("_html") or ""
            fetched = use_page and bool(html) and not sandbox.get("sandbox_unreachable")                 and not sandbox.get("sandbox_blocked_unsafe_url")

            if fetched and self.page is not None and p_lex is not None:
                final_url = sandbox.get("_final_url") or url
                pg = page_features(html, final_url, url, sandbox)
                row = build_row(self.page, {**pg, **evidence_features(sandbox), "lexical_prob": p_lex})
                art, name = self.page, "page"
                p = self._probability(art, row)
            elif self.lexical is not None:
                art, name, row, p = self.lexical, "lexical", lex_row, p_lex
            else:
                return None

            thr = art["thresholds"]
            return {
                "probability": round(p, 4),
                "band": band_of(p, thr["t_low"], thr["t_high"]),
                "score": ml_to_score(p, thr["t_low"], thr["t_high"]),
                "model": name,
                "model_version": art.get("version"),
                "thresholds": {"t_low": thr["t_low"], "t_high": thr["t_high"]},
                "lexical_probability": round(p_lex, 4) if p_lex is not None else None,
                "signals": self._signals(art, row),
            }
        except Exception as exc:
            logger.warning("ML scoring failed for %s: %s", url[:80], exc)
            return None


_runtime: Optional[ModelRuntime] = None
_runtime_lock = threading.Lock()


def get_runtime() -> ModelRuntime:
    global _runtime
    with _runtime_lock:
        if _runtime is None:
            _runtime = ModelRuntime()
        return _runtime


def reset_runtime() -> None:
    """For tests: forget loaded models."""
    global _runtime
    with _runtime_lock:
        _runtime = None
