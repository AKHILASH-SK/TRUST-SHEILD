# One command that checks the whole backend and prints a clear PASS / FAIL.
#
#     cd backend
#     powershell -ExecutionPolicy Bypass -File tools\run_all_checks.ps1            (about 5 minutes: everything)
#     powershell -ExecutionPolicy Bypass -File tools\run_all_checks.ps1 -Quick     (about 1 minute: the new features + trusted links)
#
# It only READS and TESTS. It changes no code, no database, no settings. Do not run it while the lab demo windows are open
# (they slow the machine down and one timing test can then fail by accident).
param([switch]$Quick)

$backend = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $backend
$failed = @()

function Step($title) { Write-Host "`n=== $title ===" -ForegroundColor Cyan }

Step "1/2  Automated tests"
if ($Quick) {
    python -m pytest tests/test_sender_impersonation.py tests/test_fast_flux.py tests/test_tls_inspector.py tests/test_mail_gateway.py tests/test_verdict_memory.py tests/test_link_pipeline_whitelist.py -q -p no:warnings 2>&1 | Select-Object -Last 3
} else {
    python -m pytest -q -p no:warnings 2>&1 | Select-Object -Last 3
}
if ($LASTEXITCODE -ne 0) { $failed += "automated tests" }

Step "2/2  False-positive checklist (legitimate links must never be called Dangerous)"
if ($Quick) { python -m tools.false_positive_check --quick 2>&1 | Select-Object -Last 6 } else { python -m tools.false_positive_check 2>&1 | Select-Object -Last 16 }
if ($LASTEXITCODE -ne 0) { $failed += "false-positive checklist" }

Write-Host ""
if ($failed.Count -eq 0) {
    Write-Host "ALL CHECKS PASSED" -ForegroundColor Green
} else {
    Write-Host ("FAILED: " + ($failed -join ", ")) -ForegroundColor Red
    Write-Host "Scroll up to see which test or link failed, and tell Akhilash (or send the red part to whoever helps you)." -ForegroundColor Yellow
}
