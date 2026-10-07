# TrustShield ML: collect, train, evaluate

Two models, one final verdict.

```
link text ──► [1] lexical model ──┐
                                  ├──► [2] page model ──► probability ──► SAFE / SUSPICIOUS / DANGEROUS
sandbox sees the page ────────────┘
```

* **Lexical model** (`train_lexical.py`) uses the link's host/domain text only. Trained on ~300k public URLs. Used when the
  sandbox cannot open the page, and as one input of the page model.
* **Page model** (`train_page.py`) is the final ML stage. Input: link-text features + the lexical probability + what the
  sandbox saw (login forms, where forms post, scripts, redirects, hidden frames, domain age, brand clues).
* The hard security rules (known threat match, VirusTotal-flagged, password form posting to Telegram, ...) always stay on
  top and can only **raise** the verdict.
* If no model file exists the pipeline silently keeps using its rules.

## Hardware notes (your laptop: 10-core i7, 15.6 GB RAM, RTX 4050)

* Training uses LightGBM on the CPU. It fits in memory easily and the full lexical training takes a few minutes.
  The GPU gives no speed-up for this kind of table data, so it is not used.
* Collecting pages is the slow part: each page is opened in real Chromium. Measured speed with 4 browsers is about
  1,000 pages/hour. Use `--workers 8` with `--memory=7g` for roughly double.

## Step 0 - once

```powershell
cd backend
pip install -r ml/requirements-train.txt
python -m ml.datasets --prepare          # downloads ~100 MB of public feeds
```

Make sure Docker Desktop is running, then from the repository root:

```powershell
docker build -t trustshield-backend .
```

## Step 1 - collect live pages (runs in Docker, resumable)

Opens real phishing pages in an isolated container, never on your machine. Stop with Ctrl+C any time and run the same
command again to continue. Aim for at least 3,000 malicious + 3,000 benign; more is better.

```powershell
docker run --rm --security-opt no-new-privileges --shm-size=1g --memory=7g -w /srv/backend `
  -v "${PWD}/backend/ml/data:/srv/backend/ml/data" trustshield-backend `
  python -m ml.collect_dataset --n-malicious 3500 --n-benign 3500 --workers 8
```

Output: `backend/ml/data/pages.jsonl` (what the sandbox saw, including compressed HTML).
Pages that are already offline are recorded as unreachable and are not used by the page model.

## Step 2 - train the lexical model (minutes)

```powershell
cd backend
python -m ml.train_lexical --max-rows 6000      # optional 1-minute dry run
python -m ml.train_lexical
```

It holds out every URL in `pages.jsonl`, so the page model later receives honest scores.
Read the TEST SET block at the end of the output: that is measured on websites the model never saw.

## Step 3 - train the page model

```powershell
python -m ml.train_page --dry-run               # prints the report, saves nothing
python -m ml.train_page
```

It prints the page model next to the lexical model on the same test pages, so you can see exactly what the sandbox
evidence adds. Artifacts are written to `backend/core_engine/trained_models/` (`*.joblib` + a readable `*.json`).

## Step 4 - measure the whole pipeline on fresh links

```powershell
docker build -t trustshield-backend .     # so the container contains the new models
docker run --rm --shm-size=1g --memory=7g -w /srv/backend `
  -v "${PWD}/backend/ml/data:/srv/backend/ml/data" trustshield-backend `
  python -m ml.evaluate_live --n-malicious 150 --n-benign 150 --workers 6
```

This uses today's newest phishing links and legitimate sites no model trained on, runs the real pipeline, and prints how often
the verdict is right, plus the list of misses and false alarms. By default the threat database and VirusTotal are off, so it
measures the dynamic analysis only. Add `--with-threat-db --with-virustotal` for the full product.

## Honest notes

* Label 1 = malicious means phishing **or** malware (URLhaus), because the app blocks both.
* The public benign sets are mostly bare home pages, so the lexical model uses host-level features only; using path
  features there would teach the model the difference between datasets, not phishing.
* Phishing pages that hide from scanners (cloaking) and brand-new sites will always be the hard cases.
  Retrain regularly: `collect_dataset` then `train_page` is a repeatable loop.
