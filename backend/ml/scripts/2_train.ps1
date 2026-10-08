# STEP 2 - train both models (runs on your normal Python, no Docker, takes minutes).
#
#     cd C:\Users\akhil\AndroidStudioProjects\TrustShield
#     powershell -ExecutionPolicy Bypass -File backend\ml\scripts\2_train.ps1
#
# It prints a TEST SET report at the end: that is measured on websites the model never saw. Send me that output.

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
Set-Location (Join-Path $repo "backend")

if (-not (Test-Path "ml\data\pages.jsonl")) {
    Write-Host "No collected pages yet. Run step 1 first (1_collect.ps1)." -ForegroundColor Red
    exit 1
}

Write-Host "Downloading/refreshing the public URL lists (first time about 100 MB)..." -ForegroundColor Cyan
python -m ml.datasets --prepare

Write-Host "`nTraining model 1 of 2: link-text model" -ForegroundColor Cyan
python -m ml.train_lexical
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "`nTraining model 2 of 2: page model (final stage)" -ForegroundColor Cyan
python -m ml.train_page
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "`nDone. The models are saved in backend\core_engine\trained_models\" -ForegroundColor Green
