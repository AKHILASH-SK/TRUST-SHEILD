# Sandbox Analysis Backend Setup (Tier 3)

## 🚀 Quick Start (5 minutes)

### Step 1: Get VirusTotal API Key (Free)
1. Go: https://www.virustotal.com/gui/
2. Sign up (free account)
3. Go to API settings
4. Copy your API key
5. Save it

### Step 2: Install Python Requirements
```bash
cd c:\Users\akhil\AndroidStudioProjects\TrustShield\backend

pip install -r requirements.txt
```

Packages needed:
- Flask (web framework)
- requests (HTTP library)
- flask-cors (cross-origin requests)

### Step 3: Set API Key
**Option A: Windows Command Prompt**
```bash
set VIRUSTOTAL_API_KEY=your_api_key_here
```

**Option B: PowerShell**
```powershell
$env:VIRUSTOTAL_API_KEY = "your_api_key_here"
```

Replace `your_api_key_here` with your actual VirusTotal API key

### Step 4: Start Backend Server
```bash
cd c:\Users\akhil\AndroidStudioProjects\TrustShield\backend

python app.py
```

You should see:
```
🚀 Starting TrustShield Sandbox Backend...
📍 Running on http://0.0.0.0:5000
```

### Step 5: Find Your PC IP Address
Open Command Prompt:
```bash
ipconfig
```

Look for "IPv4 Address" under your WiFi adapter. Example:
```
IPv4 Address . . . . . . . . . . . . : 192.168.1.100
```

Save this IP (example: `192.168.1.100`)

### Step 6: Update Android App
In `NotificationListener.kt`, change:
```kotlin
sandboxChecker = SandboxChecker("http://192.168.1.X:5000")
```

To your actual IP:
```kotlin
sandboxChecker = SandboxChecker("http://192.168.1.100:5000")
```

### Step 7: Rebuild Android App
```bash
cd c:\Users\akhil\AndroidStudioProjects\TrustShield

./gradlew clean
./gradlew assembleDebug -x lintVitalRelease
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

---

## 🧪 Test Backend

### Test 1: Health Check
```bash
curl http://localhost:5000/health
```

Expected response:
```json
{
  "status": "healthy",
  "service": "TrustShield Sandbox Analysis",
  "api_configured": true
}
```

### Test 2: Analyze a Phishing URL
```bash
curl -X POST http://localhost:5000/api/sandbox-check \
  -H "Content-Type: application/json" \
  -d "{\"url\": \"https://paypal-confirm.com\"}"
```

Expected response:
```json
{
  "url": "https://paypal-confirm.com",
  "verdict": "DANGEROUS",
  "confidence": 85,
  "details": "Malicious: 5, Suspicious: 2, Safe: 83",
  "engines_count": 90,
  "malicious_count": 5,
  "suspicious_count": 2
}
```

### Test 3: Analyze a Safe URL
```bash
curl -X POST http://localhost:5000/api/sandbox-check \
  -H "Content-Type: application/json" \
  -d "{\"url\": \"https://google.com\"}"
```

Expected response:
```json
{
  "verdict": "SAFE",
  "confidence": 95
}
```

---

## 🔧 Troubleshooting

### "API key not configured"
- Check: `set VIRUSTOTAL_API_KEY=your_key`
- Verify: Key is correct from VirusTotal
- Restart: Close and reopen terminal

### "Connection refused"
- Check: Backend is running (`python app.py`)
- Check: Port 5000 is not blocked by firewall
- Check: Using correct IP address in Android app

### "Timeout error"
- Check: WiFi connection is working
- Check: PC and phone on same WiFi network
- Check: Backend IP is correct

### "Android can't connect to backend"
- Verify PC IP: `ipconfig` command
- Update Android code with correct IP
- Check firewall: Allow Python on port 5000
- Restart both phone and backend

---

## 📊 Architecture

```
Tier 1: Rule-based (LOCAL - 0ms)
         ↓
Tier 2: Firebase DB (LOCAL - 100ms)
         ↓
Tier 3: Sandbox (BACKEND - 500-2000ms)
        └─ Calls VirusTotal API
           Checks against 90+ security engines
           Returns DANGEROUS/SUSPICIOUS/SAFE
```

---

## 🎯 How It Works

1. **User receives message** with URL
2. **Tier 1**: Rule-based check (instant)
   - If DANGEROUS → Show alert, stop
3. **Tier 2**: Firebase phishing DB (fast)
   - If DANGEROUS → Show alert, stop
4. **Tier 3**: Sandbox analysis (backend)
   - Call Python backend
   - Backend queries VirusTotal
   - Returns verdict
   - Show alert if needed

---

## 💾 File Structure

```
backend/
├── app.py                    ← Main Flask backend
├── sandbox_analyzer.py       ← VirusTotal API integration
├── requirements.txt          ← Python dependencies
└── README.md                 ← This file

Android app:
├── SandboxChecker.kt         ← Android integration
└── NotificationListener.kt   ← Updated with Tier 3
```

---

## 🔐 Security Notes

- ✅ No sensitive data stored
- ✅ Only URL is sent to backend
- ✅ VirusTotal API is secure (HTTPS)
- ✅ No personal data transmitted
- ✅ Free tier limits: 500 requests/day (enough for hackathon)

---

## 🚀 Running in Background

To keep backend running:

**Option 1: Use `nohup` (Linux/Mac)**
```bash
nohup python app.py &
```

**Option 2: Use `pythonw` (Windows)**
```bash
pythonw app.py
```

**Option 3: Leave terminal open** (simplest for hackathon)

---

## 📈 Monitoring

Check logs in console output:
```
[INFO] Sandbox check request for: https://suspicious-link.com
[INFO] URL Features: {'url_length': 28, 'has_https': True, ...}
[INFO] Analyzing URL via VirusTotal: https://suspicious-link.com
[INFO] Verdict: DANGEROUS (Confidence: 85%)
```

---

## 💡 Tips

1. **Backend must run on same WiFi as phone**
2. **Update Android app with correct PC IP**
3. **Keep backend terminal open**
4. **Test with curl before testing on phone**
5. **Check logs for errors**

---

## 🎉 You're Ready!

Your app now has 3-tier analysis:
- ✅ Tier 1: Rule-based (instant)
- ✅ Tier 2: Firebase DB (fast)
- ✅ Tier 3: Sandbox analysis (comprehensive)

Test it with unknown phishing URLs!
