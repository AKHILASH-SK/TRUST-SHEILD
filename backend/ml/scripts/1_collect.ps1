# STEP 1 - collect training pages with the sandbox (runs inside Docker, safe for your PC).
#
# Run from PowerShell:
#     cd C:\Users\akhil\AndroidStudioProjects\TrustShield
#     powershell -ExecutionPolicy Bypass -File backend\ml\scripts\1_collect.ps1
#
# Options (all optional):   -Malicious 3000  -Benign 3000  -Workers 8
# You can press Ctrl+C at any time and run the same command again: it continues where it stopped.
# Keep the laptop plugged in and stop it from sleeping while this runs.

param(
    [int]$Malicious = 3000,
    [int]$Benign = 3000,
    [int]$Workers = 8
)

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
Set-Location $repo

docker info *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Docker Desktop is not running. Open Docker Desktop, wait until it says 'Engine running', then run this again." -ForegroundColor Red
    exit 1
}

Write-Host "Building the sandbox image (first time takes a few minutes, later runs take seconds)..." -ForegroundColor Cyan
docker build -t trustshield-backend .
if ($LASTEXITCODE -ne 0) { Write-Host "Image build failed." -ForegroundColor Red; exit 1 }

$dataDir = Join-Path $repo "backend\ml\data"
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null

Write-Host "Collecting: $Malicious malicious + $Benign benign pages with $Workers browsers. Output: backend\ml\data\pages.jsonl" -ForegroundColor Cyan
docker run --rm --security-opt no-new-privileges --shm-size=2g --memory=6g -w /srv/backend `
    -v "${dataDir}:/srv/backend/ml/data" trustshield-backend `
    python -m ml.collect_dataset --n-malicious $Malicious --n-benign $Benign --workers $Workers --refresh
