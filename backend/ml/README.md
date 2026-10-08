# TrustShield ML: three steps (copy and paste)

You need: **Docker Desktop running** (only for steps 1 and 3) and a PowerShell window.
Always start with:

```powershell
cd C:\Users\akhil\AndroidStudioProjects\TrustShield
```

## Step 1 - collect pages with the sandbox (Docker, about 2-4 hours, safe)
```powershell
powershell -ExecutionPolicy Bypass -File backend\ml\scripts\1_collect.ps1
```
* It opens real phishing and real legitimate websites inside an isolated container and saves what the sandbox saw to
  `backend\ml\data\pages.jsonl`.
* Defaults: 3000 bad + 3000 good pages, 8 browsers. Change with `-Malicious 4000 -Benign 4000 -Workers 8`.
* Press **Ctrl+C** whenever you like. Run the same command again later and it **continues** where it stopped.
* Keep the laptop plugged in and awake. You can stop at roughly 1,500 usable pages and still train a first model.
* Progress lines look like `[collect] 250 done (...)`. Many bad links are already offline: that is normal.

## Step 2 - train the models (normal Python, about 5-15 minutes, no Docker)
```powershell
powershell -ExecutionPolicy Bypass -File backend\ml\scripts\2_train.ps1
```
At the end it prints a **TEST SET** report (measured on websites the model never saw). Send me that text.
The trained models are saved in `backend\core_engine\trained_models\` and are used automatically.

## Step 3 - measure on brand-new links (Docker, about 15-30 minutes)
```powershell
powershell -ExecutionPolicy Bypass -File backend\ml\scripts\3_evaluate.ps1
```
It prints how many phishing links are caught, how many real sites are wrongly flagged, and how many verdicts are
decisive (Safe or Dangerous instead of "Unverified - open with care"). These are the numbers for the judges.
Add `-NoLlm` to see the model without the Gemini second opinion.

## What the pieces are
* **Link-text model** (`train_lexical.py`): learns from the link's domain text only, using hundreds of thousands of public URLs.
* **Page model** (`train_page.py`): the final model. Inputs: link-text score + what the sandbox found (login forms, where
  they send data, brand claims, wording, redirects, domain age, certificate...).
* **Gemini reviewer** (`core_engine/llm_reviewer.py`): second opinion only for links the pipeline is unsure about. It can never
  override a hard rule, and it acts only when it agrees with the pipeline's own lean.
* If no model file exists the pipeline still works with its rules.

## Troubleshooting
* "Docker Desktop is not running": open Docker Desktop, wait until it says *Engine running*, run the command again.
* Script blocked by Windows: always use the `powershell -ExecutionPolicy Bypass -File ...` form shown above.
* Out of memory: add `-Workers 4`.
* Start over from nothing: delete `backend\ml\data\pages.jsonl`.

## Honest notes
* Label 1 = malicious means phishing **or** malware (URLhaus), because the app blocks both.
* The public "good" lists are mostly home pages, so the link-text model uses host-level signals only; path signals are used by the
  page model where we collect real deep links from legitimate sites.
* Cloaked phishing pages and brand-new sites will always be the hard cases. Re-run steps 1-2 regularly to keep learning.
