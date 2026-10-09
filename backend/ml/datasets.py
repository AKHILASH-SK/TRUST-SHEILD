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


# ---------------------------------------------------------------------------------------------------------------------
# Legitimate sites that live on shared hosting platforms (vercel.app, netlify.app, github.io ...).
# The old training data had almost none (13 benign against 363 malicious), so the models learned "hosted = phishing".
# Source: GitHub repositories with real stars whose "homepage" is a live site on one of those platforms. Real projects with
# stars are overwhelmingly genuine apps, blogs, portfolios and demos. Dead sites are filtered later by the sandbox visit.
# ---------------------------------------------------------------------------------------------------------------------
HOSTED_TOPICS = [
    "vercel", "netlify", "github-pages", "nextjs", "react", "vue", "svelte", "portfolio", "blog", "dashboard",
    "landing-page", "saas", "ecommerce", "tailwindcss", "typescript", "web-app", "admin-dashboard", "chatgpt", "ai",
    "documentation", "resume", "personal-website", "astro", "nuxt", "gatsby", "vite", "pwa", "todo-app", "weather-app",
    "calculator", "game", "quiz-app", "movie-app", "chat-app", "project-management", "analytics", "openai", "firebase",
    "supabase", "mongodb", "nodejs", "express", "api", "frontend", "full-stack", "template", "boilerplate", "demo",
]
HOSTED_STAR_BANDS = [(15, 40), (41, 120), (121, 500), (501, 100000)]


def load_hosted_benign(refresh: bool = False, target: int = 3000, max_age_days: float = 14.0) -> List[str]:
    """URLs of live sites on shared hosting platforms that belong to real, starred GitHub projects (benign label)."""
    from urllib.parse import urlparse
    from .features import FREE_HOSTING_SUFFIXES
    os.makedirs(RAW_DIR, exist_ok=True)
    path = os.path.join(RAW_DIR, "hosted_benign.txt")
    if not refresh and os.path.exists(path) and (time.time() - os.path.getmtime(path)) < max_age_days * 86400:
        with open(path, encoding="utf-8") as fh:
            cached = [ln.strip() for ln in fh if ln.strip()]
        if len(cached) >= min(target, 500):
            return cached
    suffixes = tuple(FREE_HOSTING_SUFFIXES)
    token = os.getenv("GITHUB_TOKEN", "").strip()
    headers = {**HEADERS, "Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    pause = 2.2 if token else 6.6                      # GitHub search: 30/min with a token, 10/min without
    found: Dict[str, str] = {}
    print(f"[datasets] collecting legitimate hosted sites from GitHub (target {target}; "
          f"{'with' if token else 'without'} a GitHub token this takes about {int(len(HOSTED_TOPICS) * len(HOSTED_STAR_BANDS) * pause / 60)} min at most) ...", flush=True)
    stop = False
    for topic in HOSTED_TOPICS:
        for lo, hi in HOSTED_STAR_BANDS:
            if stop or len(found) >= target:
                break
            q = f"topic:{topic} stars:{lo}..{hi}"
            try:
                resp = requests.get("https://api.github.com/search/repositories",
                                    params={"q": q, "sort": "stars", "order": "desc", "per_page": 100}, headers=headers, timeout=40)
            except Exception as exc:
                print(f"   network problem ({type(exc).__name__}); using what was collected", flush=True)
                stop = True
                break
            if resp.status_code in (403, 429):
                print("   GitHub rate limit reached; using what was collected so far", flush=True)
                stop = True
                break
            if resp.status_code != 200:
                time.sleep(pause)
                continue
            for item in resp.json().get("items", []):
                homepage = (item.get("homepage") or "").strip()
                if not homepage.lower().startswith("https://"):
                    continue
                host = (urlparse(homepage).hostname or "").lower()
                if host.endswith(suffixes) and host not in found:
                    found[host] = f"https://{host}/"
            time.sleep(pause)
        print(f"   {topic:18s} -> {len(found):,d} sites", flush=True)
        if stop or len(found) >= target:
            break
    urls = list(found.values())
    if urls:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(urls))
    return urls
