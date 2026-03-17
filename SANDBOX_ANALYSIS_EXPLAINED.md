# TrustShield Sandbox Analysis & Architecture

## What is Sandbox Analysis (Tier 3)?

**Sandbox Analysis** is the third layer of security checking in TrustShield. It analyzes URLs using external security services.

---

## How It Works (Simple Explanation)

```
User receives a message with a link
        ↓
Tier 1: Rule-based checks (instant)
├─ Check for IP addresses
├─ Check for typosquatting
├─ Check for phishing keywords
        ↓
Tier 2: Firebase Phishing Database (fast)
├─ Check against known phishing domains
├─ Check against known malicious links
        ↓
Tier 3: Sandbox Analysis (backend + VirusTotal) ← THIS PART
├─ Send link to backend server
├─ Backend submits to VirusTotal API
├─ VirusTotal scans with 70+ antivirus engines
├─ Returns verdict: SAFE / SUSPICIOUS / DANGEROUS
        ↓
User gets final security verdict
```

---

## Architecture Diagram

```
┌─────────────────────┐
│  Android App        │
│ (TrustShield)       │
│                     │
│ • Extracts links    │
│ • Tier 1 checks     │
│ • Tier 2 Firebase   │
│ • Calls backend API │
└──────────┬──────────┘
           │ HTTP POST (link)
           ↓
┌─────────────────────┐
│  Backend Server     │
│ (Flask Python)      │
│                     │
│ • Receives URL      │
│ • Calls VirusTotal  │
│ • Processes result  │
│ • Sends verdict     │
└──────────┬──────────┘
           │ HTTPS
           ↓
┌─────────────────────┐
│  VirusTotal API     │
│ (Cloud Service)     │
│                     │
│ • Receives URL      │
│ • Scans with:       │
│   - 70+ AV engines  │
│   - Malware DB      │
│   - Phishing DB     │
│   - Behavioral      │
│ • Returns verdict   │
└─────────────────────┘
```

---

## Key Points

### ✅ What We're NOT Doing
- ❌ Opening actual browser (Chromium, Firefox, etc.)
- ❌ Local analysis
- ❌ Manual checking

### ✅ What We ARE Doing
- ✅ Using **VirusTotal** - Industry-standard threat intelligence service
- ✅ Utilizing **70+ antivirus engines** (Avast, Norton, Kaspersky, McAfee, etc.)
- ✅ Cloud-based fast analysis
- ✅ Real-time threat database access
- ✅ Behavioral analysis of URLs
- ✅ Historical tracking of malicious links

---

## VirusTotal Benefits

| Feature | Benefit |
|---------|---------|
| **Multiple AV Engines** | If one misses it, others catch it |
| **Real-time Updates** | New threats detected immediately |
| **Cloud-Based** | No local resources needed |
| **Fast** | Analysis in 1-5 seconds |
| **Comprehensive** | Checks: malware, phishing, suspicious behavior |
| **Free API** | Up to 4 requests/minute |

---

## TrustShield Tier 3 Configuration

**Backend Location:** `http://10.150.255.61:5000`

**VirusTotal API Key:** Configured and active

**Analysis Flow:**
1. App detects link (Tier 1 & 2 passed)
2. App sends to backend: `POST /api/sandbox-check`
3. Backend submits to VirusTotal: `https://www.virustotal.com/api/v3/urls`
4. VirusTotal scans the URL
5. Backend processes results
6. App receives verdict
7. Alert shown to user if dangerous/suspicious

---

## False Positives Fix

We've added a **whitelist of ~1000 legitimate domains** to prevent false positives:

- vivo.com ✓
- oppo.com ✓
- samsung.com ✓
- myntra.com ✓
- paytm.com ✓
- zomato.com ✓
- And 1000+ more official brands

**How it works:**
```
Link Analysis:
1. Check if domain in whitelist → SAFE (skip all checks)
2. If not in whitelist → Run rule-based checks
3. If suspicious → Check Tier 2 Firebase
4. If still suspicious → Check Tier 3 Sandbox
```

---

## Example Analysis

### Scenario 1: Legitimate Link
```
Input: https://www.vivo.com/product
1. Tier 1: Check whitelist → Found in whitelist → SAFE ✓
Result: SAFE - No alert shown
```

### Scenario 2: Suspicious Link
```
Input: https://gooogle-verify.com/login
1. Tier 1: Check whitelist → Not found
2. Tier 1: Check rules → Homograph attack (gooogle) → SUSPICIOUS
3. Continue to Tier 2...
```

### Scenario 3: Known Phishing Link
```
Input: https://paypal-confirm.com
1. Tier 1: Check whitelist → Not found
2. Tier 1: Check rules → Typosquatting → SUSPICIOUS
3. Tier 2: Check Firebase → FOUND AS DANGEROUS → Alert shown ✓
Result: DANGEROUS - Immediate alert, no Tier 3 needed
```

---

## Performance Impact

- **Tier 1:** <100ms (local rule checks)
- **Tier 2:** <200ms (Firebase cache)
- **Tier 3:** 1-5 seconds (VirusTotal API)

Tier 3 only runs for SUSPICIOUS links to save resources.

---

## Security

- ✅ Only HTTPS to VirusTotal
- ✅ Cleartext only to local backend (dev)
- ✅ No link history stored locally
- ✅ No user data sent to VirusTotal
- ✅ Results cached for performance

---

## Summary

**TrustShield uses a 3-tier defense:**

1. **Tier 1 (Fast):** Local rule-based checks + whitelist
2. **Tier 2 (Medium):** Firebase phishing database
3. **Tier 3 (Thorough):** VirusTotal API (70+ antivirus engines)

**Result:** Fast, accurate, multi-layered phishing detection without false positives! 🛡️
