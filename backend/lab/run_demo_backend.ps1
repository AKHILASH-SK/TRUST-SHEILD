# Starts the backend in LAB MODE for the impersonation demo (simulated DNS for bank.test and 127.0.0.x sender addresses).
# Never use this window for normal scanning: lab mode treats private addresses as real senders.
#     cd backend ; powershell -ExecutionPolicy Bypass -File lab\run_demo_backend.ps1
$env:TRUSTSHIELD_LAB_MODE = "1"
python -m lab.make_samples
Write-Host "Upload the .eml files from backend\lab\samples in the portal (Analyze email)." -ForegroundColor Cyan
python app.py
