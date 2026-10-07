"""
TrustShield ML - public dataset loading.

Downloads (and caches under ml/data/raw) the public threat feeds and benign lists used to
train the models. Label convention everywhere: 1 = malicious (phishing or malware), 0 = benign.

    python -m ml.datasets --prepare        # download and cache everything, print counts
    python -m ml.datasets --prepare --refresh
"""

import argparse
import csv
import io
import os
import time
import zipfile
from typing import Dict, List, Tuple

import requests

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
RAW_DIR = os.path.join(DATA_DIR, "raw")
HEADERS = {"User-Agent": "trustshield-research/1.0 (phishing-detection training data)"}

SOURCES = {
    "phishtank": "https://data.phishtank.com/data/online-valid.csv",
    "urlhaus": "https://urlhaus.abuse.ch/downloads/csv_online/",
    "phishing_database": "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt",
    "openphish": "https://openphish.com/feed.txt",
    "tranco": "https://tranco-list.eu/top-1m.csv.zip",
    "phiusiil": "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip",
}


def _download(name: str, refresh: bool = False, max_age_hours: float = 24.0) -> str:
    os.makedirs(RAW_DIR, exist_ok=True)
    path = os.path.join(RAW_DIR, name.replace("/", "_") + ".bin")
    if not refresh and os.path.exists(path) and (time.time() - os.path.getmtime(path)) < max_age_hours * 3600:
        return path
    print(f"[datasets] downloading {name} ...", flush=True)
    resp = requests.get(SOURCES[name], headers=HEADERS, timeout=180, stream=True)
    resp.raise_for_status()
    tmp = path + ".part"
    with open(tmp, "wb") as fh:
        for chunk in resp.iter_content(1 << 20):
            fh.write(chunk)
    # Windows antivirus can briefly lock a freshly written file; retry the rename
    for attempt in range(10):
        try:
            os.replace(tmp, path)
            break
        except PermissionError:
            if attempt == 9:
                raise
            time.sleep(1.5)
    return path


def _is_url(text: str) -> bool:
    t = text.strip().lower()
    return t.startswith(("http://", "https://")) and 10 <= len(t) <= 2048 and " " not in t


def load_phishtank(refresh: bool = False) -> List[str]:
    path = _download("phishtank", refresh)
    with open(path, encoding="utf-8", errors="replace", newline="") as fh:
        return [row["url"].strip() for row in csv.DictReader(fh) if row.get("url") and _is_url(row["url"])]


def load_urlhaus(refresh: bool = False) -> List[str]:
    path = _download("urlhaus", refresh)
    urls: List[str] = []
    with open(path, encoding="utf-8", errors="replace", newline="") as fh:
        lines = [ln for ln in fh if ln.strip() and not ln.startswith("#")]
    # columns: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
    for row in csv.reader(lines):
        if len(row) >= 3 and _is_url(row[2]):
            urls.append(row[2].strip())
    return urls


def load_phishing_database(refresh: bool = False) -> List[str]:
    path = _download("phishing_database", refresh)
    with open(path, encoding="utf-8", errors="replace") as fh:
        return [ln.strip() for ln in fh if _is_url(ln)]


def load_openphish(refresh: bool = False) -> List[str]:
    path = _download("openphish", refresh, max_age_hours=1.0)
    with open(path, encoding="utf-8", errors="replace") as fh:
        return [ln.strip() for ln in fh if _is_url(ln)]


def load_tranco(refresh: bool = False) -> List[Tuple[int, str]]:
    """(rank, domain) pairs."""
    path = _download("tranco", refresh, max_age_hours=24 * 7)
    with zipfile.ZipFile(path) as zf:
        name = next(n for n in zf.namelist() if n.endswith(".csv"))
        with zf.open(name) as fh:
            reader = csv.reader(io.TextIOWrapper(fh, encoding="utf-8"))
            return [(int(r[0]), r[1].strip().lower()) for r in reader if len(r) >= 2 and r[0].isdigit()]


def load_phiusiil(refresh: bool = False) -> Tuple[List[str], List[str]]:
    """
    Returns (legitimate_urls, phishing_urls) from the UCI PhiUSIIL dataset.
    In that dataset label 1 means legitimate and 0 means phishing.
    """
    import pandas as pd

    path = _download("phiusiil", refresh, max_age_hours=24 * 30)
    with zipfile.ZipFile(path) as zf:
        name = next(n for n in zf.namelist() if n.lower().endswith(".csv"))
        with zf.open(name) as fh:
            df = pd.read_csv(fh, usecols=["URL", "label"], encoding="utf-8", encoding_errors="replace")
    legit = df.loc[df["label"] == 1, "URL"].astype(str).tolist()
    phish = df.loc[df["label"] == 0, "URL"].astype(str).tolist()
    return [u for u in legit if _is_url(u)], [u for u in phish if _is_url(u)]


def load_all_malicious(refresh: bool = False, include_phiusiil: bool = True) -> Dict[str, List[str]]:
    out = {
        "phishtank": load_phishtank(refresh),
        "urlhaus": load_urlhaus(refresh),
        "phishing_database": load_phishing_database(refresh),
        "openphish": load_openphish(refresh),
    }
    if include_phiusiil:
        out["phiusiil"] = load_phiusiil(refresh)[1]
    return out


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Download and cache the public training datasets")
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--refresh", action="store_true")
    args = parser.parse_args()
    if not args.prepare:
        parser.print_help()
        raise SystemExit(0)
    for name, urls in load_all_malicious(args.refresh).items():
        print(f"malicious  {name:18s} {len(urls):>8,d} urls   e.g. {urls[0][:70] if urls else '-'}")
    legit, _ = load_phiusiil(args.refresh)
    print(f"benign     {'phiusiil':18s} {len(legit):>8,d} urls   e.g. {legit[0][:70] if legit else '-'}")
    tr = load_tranco(args.refresh)
    print(f"benign     {'tranco':18s} {len(tr):>8,d} domains e.g. {tr[0][1] if tr else '-'}")
