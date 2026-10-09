# STEP 1 - collect training pages with the sandbox (runs inside Docker, safe for your PC).
#
# Run from PowerShell:
#     cd C:\Users\akhil\AndroidStudioProjects\TrustShield
#     powershell -ExecutionPolicy Bypass -File backend\ml\scripts\1_collect.ps1
#
# Options (all optional):
#     -Malicious 3000  -Benign 3000  -Workers 8
#     -HostedBenign 1200   legitimate sites on shared hosting (vercel.app, github.io ...) taken from real GitHub projects.
#                          This is what teaches the model that "hosted on Vercel" alone does not mean phishing.
#     -OnlyHosted          collect ONLY those hosted pages (use this to add them to the pages you already have)
# You can press Ctrl+C at any time and run the same command again: it continues where it stopped.
# Keep the laptop plugged in and stop it from sleeping while this runs.
# Optional: set a GitHub token in PowerShell first ($env:GITHUB_TOKEN = "...") to make the hosted-site search 3x faster.

param(
    [int]$Malicious = 3000,
    [int]$Benign = 3000,
    [int]$Workers = 8,
    [int]$HostedBenign = 0,
    [switch]$OnlyHosted
)

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
Set-Location $repo

if ($OnlyHosted) {
    $Malicious = 0
    $Benign = 0
    if ($HostedBenign -le 0) { $HostedBenign = 1200 }
}

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

$envArgs = @()
if ($env:GITHUB_TOKEN) { $envArgs += @("-e", "GITHUB_TOKEN=$($env:GITHUB_TOKEN)") }
$refresh = @()
if (-not $OnlyHosted) { $refresh += "--refresh" }

Write-Host "Collecting: $Malicious malicious + $Benign benign + $HostedBenign hosted-benign pages with $Workers browsers. Output: backend\ml\data\pages.jsonl" -ForegroundColor Cyan
docker run --rm --security-opt no-new-privileges --shm-size=2g --memory=6g @envArgs -w /srv/backend `
    -v "${dataDir}:/srv/backend/ml/data" trustshield-backend `
    python -m ml.collect_dataset --n-malicious $Malicious --n-benign $Benign --n-hosted-benign $HostedBenign --workers $Workers @refresh
