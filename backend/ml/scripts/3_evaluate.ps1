# STEP 3 - measure the whole pipeline on FRESH links (the numbers to show judges).
#
#     cd C:\Users\akhil\AndroidStudioProjects\TrustShield
#     powershell -ExecutionPolicy Bypass -File backend\ml\scripts\3_evaluate.ps1
#
# Options: -Malicious 150  -Benign 150  -Workers 6  -NoLlm   (-NoLlm switches the Gemini second opinion off)

param(
    [int]$Malicious = 150,
    [int]$Benign = 150,
    [int]$Workers = 6,
    [switch]$NoLlm
)

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
Set-Location $repo

docker info *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Docker Desktop is not running. Open it and run this again." -ForegroundColor Red
    exit 1
}

Write-Host "Rebuilding the image so it contains the newly trained models..." -ForegroundColor Cyan
docker build -t trustshield-backend .
if ($LASTEXITCODE -ne 0) { exit 1 }

# pass the Gemini key from backend\.env into the container (it is never printed)
$envArgs = @()
$envFile = Join-Path $repo "backend\.env"
if ((Test-Path $envFile) -and -not $NoLlm) {
    $line = Get-Content $envFile | Where-Object { $_ -match "^GEMINI_API_KEY=" } | Select-Object -First 1
    if ($line) { $envArgs += @("-e", $line.Trim()) }
}

$extra = @()
if ($NoLlm) { $extra += "--no-llm" }

$dataDir = Join-Path $repo "backend\ml\data"
docker run --rm --shm-size=2g --memory=6g @envArgs -w /srv/backend `
    -v "${dataDir}:/srv/backend/ml/data" trustshield-backend `
    python -m ml.evaluate_live --n-malicious $Malicious --n-benign $Benign --workers $Workers @extra
