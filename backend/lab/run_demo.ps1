# The whole impersonation demo in one command. It NEVER restarts or closes the backend:
#   - if the backend is already running, it is used as it is (so you can show the SOC portal first and run the demo on the same backend);
#   - if it is not running, it is started normally in its own window and left open afterwards;
#   - the mail gateway (port 2525) is started only if it is not already running.
#
#     cd backend
#     powershell -ExecutionPolicy Bypass -File lab\run_demo.ps1            (add  -Pause  to wait for Enter between scenes)
#
# The demo switches the backend into demo mode (simulated bank, rotating DNS, 127.0.0.x senders) for 10 minutes and it switches
# itself off again. To switch it off at once:   python -m lab.scenes --off
# If the backend was started BEFORE the latest update, close its window once and start it again (python app.py).
param([switch]$Pause)

$backend = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $backend

function Test-Backend {
    try { return ((Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8000/api/health -TimeoutSec 3).StatusCode -eq 200) } catch { return $false }
}

python -m lab.make_samples | Out-Null

if (Test-Backend) {
    Write-Host "Backend is already running: using it (nothing is restarted)." -ForegroundColor Green
} else {
    Write-Host "Backend is not running: starting it in its own window (it stays open after the demo) ..." -ForegroundColor Cyan
    Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$backend'; python app.py"
    for ($i = 0; $i -lt 60; $i++) { Start-Sleep -Seconds 2; if (Test-Backend) { break } }
    if (-not (Test-Backend)) { Write-Host "The backend did not start. Look at its window for the error." -ForegroundColor Red; exit 1 }
}

$gatewayUp = $false
try { $gatewayUp = [bool](Get-NetTCPConnection -LocalPort 2525 -State Listen -ErrorAction SilentlyContinue) } catch {}
if ($gatewayUp) {
    Write-Host "Mail gateway is already running: using it." -ForegroundColor Green
} else {
    Write-Host "Starting the mail gateway in its own window ..." -ForegroundColor Cyan
    Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$backend'; python -m gateway.smtp_gateway --port 2525 --api http://127.0.0.1:8000"
    Start-Sleep -Seconds 4
}

Write-Host "Open the portal at http://localhost:8000/portal/ (Ctrl+F5, then the Mail Gateway tab) and watch it while the scenes run." -ForegroundColor Cyan
$env:TRUSTSHIELD_ENV = "development"
if ($Pause) { python -m lab.scenes --pause } else { python -m lab.scenes }
