"""
Exports the link-text (lexical) model so it can run ON THE PHONE with no internet:

    python -m ml.export_for_android

Writes
    app/src/main/assets/ondevice/lexical_model.json     the 350 trees, the calibration table, thresholds and reference lists
    app/src/main/assets/ondevice/public_suffixes.txt    the public-suffix rules (same snapshot the backend uses)
    app/src/test/resources/lexical_parity.json          test vectors computed by the REAL Python code, used by the Android unit test
                                                         to prove the Kotlin features and probabilities are identical

Only the link-text model can run offline: the page model needs the sandbox browser to open the page.
"""
import json
import os
import random
import sys

import joblib

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(BACKEND)
sys.path.insert(0, BACKEND)

from ml import features as F                      # noqa: E402

ASSETS = os.path.join(REPO, "app", "src", "main", "assets", "ondevice")
TEST_RES = os.path.join(REPO, "app", "src", "test", "resources")
MODEL_PATH = os.path.join(BACKEND, "core_engine", "trained_models", "lexical_model.joblib")


def flatten_tree(tree_structure):
    """LightGBM dump -> parallel arrays. A child >= 0 is an internal node index; a child < 0 is the leaf  ~child."""
    sf, th, dl, mt, ct, lc, rc, leaves = [], [], [], [], [], [], [], []

    def walk(node):
        if "leaf_index" in node and "split_index" not in node:
            leaves.append(float(node["leaf_value"]))
            return ~(len(leaves) - 1)
        idx = len(sf)
        sf.append(int(node["split_feature"]))
        dtype = node["decision_type"]
        if dtype == "==":                                         # categorical: threshold is "3||7||9" (value in the set -> left)
            cats = [int(x) for x in str(node["threshold"]).split("||")]
            th.append(0.0)
            ct.append(cats)
        elif dtype == "<=":
            th.append(float(node["threshold"]))
            ct.append(None)
        else:
            raise ValueError(f"unsupported decision type {dtype}")
        dl.append(1 if node.get("default_left") else 0)
        mt.append({"None": 0, "Zero": 1, "NaN": 2}[node.get("missing_type", "None")])
        lc.append(0)
        rc.append(0)
        left = walk(node["left_child"])
        right = walk(node["right_child"])
        lc[idx], rc[idx] = left, right
        return idx

    root = walk(tree_structure)
    return {"sf": sf, "th": th, "dl": dl, "mt": mt, "ct": ct, "lc": lc, "rc": rc, "lv": leaves, "root": root}


def export_model():
    art = joblib.load(MODEL_PATH)
    booster = art["model"].booster_
    dump = booster.dump_model()
    names = list(art["features"])
    assert names == list(F.LEXICAL_HOST_FEATURES), "the model must use exactly the host features"
    trees = [flatten_tree(t["tree_structure"]) for t in dump["tree_info"]]
    cal = art["calibrator"]
    out = {
        "version": art.get("version"),
        "feature_version": art.get("feature_version"),
        "features": names,
        "trees": trees,
        "calibrator": {"x": [float(v) for v in cal.X_thresholds_], "y": [float(v) for v in cal.y_thresholds_]},
        "thresholds": {"t_low": float(art["thresholds"]["t_low"]), "t_high": float(art["thresholds"]["t_high"])},
        "lists": {
            "suspicious_keywords": F.SUSPICIOUS_KEYWORDS,
            "free_hosting_suffixes": sorted(F.FREE_HOSTING_SUFFIXES),
            "shorteners": sorted(F.SHORTENERS),
            "abused_tlds": sorted(F.ABUSED_TLDS),
            "common_tlds": F.COMMON_TLDS,
            "brand_domains": F.BRAND_DOMAINS,
        },
    }
    os.makedirs(ASSETS, exist_ok=True)
    path = os.path.join(ASSETS, "lexical_model.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, separators=(",", ":"))
    print(f"model: {len(trees)} trees, {os.path.getsize(path) // 1024} KB -> {path}")
    return art


def export_suffixes():
    extractor = F._EXTRACT._get_tld_extractor()
    rules = sorted(set(extractor.tlds(include_psl_private_domains=False)))
    path = os.path.join(ASSETS, "public_suffixes.txt")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(rules) + "\n")
    print(f"public suffix rules: {len(rules)} -> {path}")


EDGE_CASES = [
    "http://127.0.0.1/", "http://192.168.1.10:8080/login", "https://[2001:db8::1]/x", "http://[::1]:8000/", "https://user:pass@evil.example.com/",
    "http://user@bank-login.top/verify", "https://xn--e1afmkfd.xn--p1ai/", "https://xn--80ak6aa92e.com/", "HTTPS://WWW.GOOGLE.COM/Search",
    "https://example.com./", "example.com", "www.example.com", "www.com", "localhost", "http://localhost:3000/", "https://a.b.c.d.e.co.uk/",
    "https://foo.bar.ck/", "https://www.ck/", "https://city.kawasaki.jp/", "https://a.kobe.jp/", "http://paypal-secure-login.top/signin",
    "https://paypal.com.evil-site.xyz/", "https://secure-hdfcbank.in/netbanking", "https://login.microsoftonline.com.attacker.net/",
    "http://bit.ly/abc", "https://tinyurl.com/x", "https://mysite.vercel.app/", "https://a.b.github.io/", "https://user.blogspot.com/",
    "https://my-shop.netlify.app/login", "https://0000.1111.2222.3333.xyz/", "http://1.2.3.4.5/", "http://999.999.999.999/",
    "https://very-long-host-name-with-many-hyphens-and-numbers-12345-67890-abcde-fghij.example.org/", "https://a.co/", "https://x.y/",
    "ftp://files.example.com/", "//example.com/path", "https:///", "", "   ", "http://exa mple.com/", "https://example.com:99999/", "https://example.com:abc/",
    "https://EXAMPLE.COM:443/", "https://example.com:8443/x", "https://sub.sub.sub.example.co.in/", "https://my.dyndns.org/", "https://amazon-prize-claim.click/",
    "https://netflix.com/", "https://netflix-login.com/", "https://login-netflix.com.verify-account.shop/", "http://secure.paypal.com.update.ru/",
    "https://apple.com.id-verify.support/", "https://www.hdfcbank.com/", "https://hdfcbank.com.evil.top/", "https://chase.com/", "https://chase-bank-alert.cyou/",
    "https://google.com。evil.com/", "https://münchen.de/", "https://日本語.jp/", "https://a_b.example.com/", "https://-bad-.example.com/",
    "https://httpsgoogle.com/", "https://www.www.example.com/", "https://wwww.example.com/", "https://a.www.example.com/",
    # country-code second-level suffixes and other public-suffix shapes
    "https://www.roblox.com.mu/users/1/profile", "https://roblox.com.mu", "https://www.roblox.com.do/users/1/profile", "https://bank.co.mu/",
    "https://x.com.br/", "https://y.org.uk/", "https://z.gov.in/", "https://w.ac.in/", "https://v.net.au/", "https://u.com.cn/", "https://t.edu.au/",
    "https://a.b.com.mu/", "https://secure.login.paypal.com.mu/", "https://shop.co.za/", "https://shop.com.ng/", "https://paypal.com.ng/",
    "https://mu/", "https://com.mu/", "https://www.com.mu/", "https://sub.mu/", "https://sub.gov.mu/", "https://netflix.com.pk/", "https://amazon.in.net/",
    "https://hdfcbank.co.in/", "https://hdfc.com.in/", "https://store.com.tr/", "https://site.com.ua/", "https://site.com.ve/", "https://app.com.sg/",
    "https://chase.com.vn/", "https://login.apple.com.hk/", "https://a.ltd.uk/", "https://b.plc.uk/", "https://c.me.uk/", "https://d.nhs.uk/",
    "https://s3.amazonaws.com/", "https://x.s3.amazonaws.com/", "https://my.github.io/", "https://a.b.pages.dev/", "https://q.herokuapp.com/",
]


def export_parity(art, n_mal=500, n_ben=400, n_host=150):
    rng = random.Random(11)
    urls = list(EDGE_CASES)
    try:
        from ml import datasets
        mal = []
        for loader in (datasets.load_openphish, datasets.load_phishtank, datasets.load_urlhaus):
            try:
                mal += [u if isinstance(u, str) else u[0] for u in loader(False)]
            except Exception:
                pass
        rng.shuffle(mal)
        urls += mal[:n_mal]
        tranco = datasets.load_tranco(False)
        urls += ["https://" + d + "/" for _, d in rng.sample(tranco[:100000], n_ben)]
        hosted = os.path.join(BACKEND, "ml", "data", "raw", "hosted_benign_large.txt")
        if os.path.exists(hosted):
            with open(hosted, encoding="utf-8") as fh:
                lines = [ln.strip() for ln in fh if ln.strip()]
            urls += rng.sample(lines, min(n_host, len(lines)))
    except Exception as exc:                                       # the edge cases alone still make a useful test
        print("dataset samples skipped:", type(exc).__name__, exc)

    names = list(art["features"])
    cases = []
    for url in urls:
        feats = F.lexical_features(url)
        row = [float(feats[n]) for n in names]
        import numpy as np
        raw = art["model"].predict_proba(np.array([row]))[:, 1]
        prob = round(float(art["calibrator"].predict(raw)[0]), 4)
        cases.append({"url": url, "features": row, "raw": float(raw[0]), "p": prob})
    os.makedirs(TEST_RES, exist_ok=True)
    path = os.path.join(TEST_RES, "lexical_parity.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"features": names, "cases": cases}, fh, ensure_ascii=False, separators=(",", ":"))
    print(f"parity vectors: {len(cases)} urls -> {path}")


if __name__ == "__main__":
    artifact = export_model()
    export_suffixes()
    export_parity(artifact)
