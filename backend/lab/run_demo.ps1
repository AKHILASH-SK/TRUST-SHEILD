# The whole impersonation demo in one command (lab mode: simulated bank DNS, rotating DNS, 127.0.0.x senders).
#     cd backend
#     powershell -ExecutionPolicy Bypass -File lab\run_demo.ps1            (add  -Pause  to wait for Enter between scenes)
#
# It opens two windows: the LAB BACKEND (port 8000) and the MAIL GATEWAY (port 2525), then plays the scenes here.
# Use these windows for the demo only: lab mode treats private addresses as real senders. Close them afterwards and start the
# normal backend again (python app.py).
param([switch]$Pause)

$backend = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $backend

# stop any backend already running on 8000 so the lab one can take the port
Get-CimInstance Win32_Process -Filter "Name='python.exe'" | Where-Object { $_.CommandLine -match 'app\.py|gateway\.smtp_gateway' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
Start-Sleep -Seconds 2

python -m lab.make_samples | Out-Null
Start-Process powershell -ArgumentList "-NoExit", "-Command", "`$env:TRUSTSHIELD_LAB_MODE='1'; `$env:TRUSTSHIELD_ENV='development'; cd '$backend'; python app.py"
Write-Host "Starting the lab backend ..." -ForegroundColor Cyan
for ($i = 0; $i -lt 60; $i++) {
    Start-Sleep -Seconds 2
    try { if ((Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8000/api/health -TimeoutSec 3).StatusCode -eq 200) { break } } catch {}
}
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$backend'; python -m gateway.smtp_gateway --port 2525 --api http://127.0.0.1:8000"
Start-Sleep -Seconds 4
Write-Host "Backend and gateway are up. Open the portal at http://localhost:8000/portal/ (Mail Gateway tab) and watch it while the scenes run." -ForegroundColor Cyan

$env:TRUSTSHIELD_LAB_MODE = "1"
$env:TRUSTSHIELD_ENV = "development"
if ($Pause) { python -m lab.scenes --pause } else { python -m lab.scenes }
