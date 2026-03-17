# TrustShield Phishing Domain Database Implementation

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Android App (TrustShield)                 │
│                                                               │
│  PhishingDomainChecker                                       │
│  ├─ Local Database (embedded in APK)                        │
│  └─ Remote API (calls backend)                              │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       │ HTTP Request
                       │ ?domain=example.com
                       │
┌──────────────────────▼──────────────────────────────────────┐
│              Backend API (Node.js + Express)                 │
│                                                               │
│  Server: https://your-api.com                               │
│  Database: Phishing Domains List (JSON)                     │
│  Endpoints:                                                  │
│  ├─ GET /api/check-domain?domain=X                          │
│  ├─ GET /api/stats                                          │
│  └─ GET /health                                             │
└──────────────────────────────────────────────────────────────┘
```

## Implementation Summary

### 1. Android Side (PhishingDomainChecker.kt)

**Features:**
- ✅ Local embedded phishing database
- ✅ Async remote API calls (doesn't block UI)
- ✅ Fallback to local if API fails
- ✅ Domain extraction from URLs
- ✅ Result callback system

**How it works:**
```
User receives message → Extract URL → Check local DB → 
(if safe) Check remote API → Show result
```

### 2. Backend Side (server.js)

**Features:**
- ✅ Express API server
- ✅ JSON database of phishing domains
- ✅ CORS enabled for all requests
- ✅ Health check endpoint
- ✅ Statistics endpoint
- ✅ Easy to update

**Endpoints:**
```
GET /api/check-domain?domain=paypal-confirm.com
→ { "dangerous": true, "message": "..." }
```

## Deployment Options

### 🚀 RECOMMENDED: Replit (5 minutes, No Credit Card)

1. Go to https://replit.com → Sign up
2. Create Node.js Repl
3. Copy `backend/server.js` and `backend/package.json`
4. Click "Run"
5. Get public URL (automatically provided)
6. Update Android code with URL

**Pros:**
- ✅ Super easy
- ✅ Instant deployment
- ✅ Public URL immediately
- ✅ Free forever (with limits)

**URL Format:** `https://your-repl-name.replit.dev`

### Alternative: Render (10 minutes, More Reliable)

1. Go to https://render.com
2. Connect GitHub repo
3. Select backend folder
4. Deploy
5. Get public URL

**Pros:**
- ✅ More reliable uptime
- ✅ Larger free tier
- ✅ Better performance

**URL Format:** `https://trustshield-api.onrender.com`

### Alternative: Heroku (Deprecated but still works)

```bash
heroku create trustshield-api
git push heroku main
heroku apps:info trustshield-api
```

## Integration Steps

### Step 1: Deploy Backend
1. Choose hosting platform (Replit recommended)
2. Deploy `backend/` folder
3. Get public URL: `https://your-api-url.com`

### Step 2: Update Android Code

In `PhishingDomainChecker.kt`:

```kotlin
private const val PHISHING_API_URL = "https://your-api-url.com/api/check-domain"
```

### Step 3: Update LinkAnalyzer

In `LinkAnalyzer.kt`, add this check:

```kotlin
// Add to runSecurityChecks() method:
private val phishingChecker = PhishingDomainChecker(context)

// Call it:
phishingChecker.checkDomain(url) { result ->
    when (result) {
        PhishingCheckResult.DANGEROUS -> {
            // Mark as dangerous
        }
        PhishingCheckResult.SUSPICIOUS -> {
            // Mark as suspicious
        }
        PhishingCheckResult.SAFE -> {
            // OK
        }
    }
}
```

### Step 4: Build & Test

```bash
./gradlew assembleDebug
adb install app/build/outputs/apk/debug/app-debug.apk
```

## Adding Phishing Domains

### Option A: Edit on Replit/Render
1. Go to your deployed server
2. Edit `server.js`
3. Add domains to `PHISHING_DATABASE`
4. Redeploy (auto-updates)

### Option B: Create Admin Endpoint (Advanced)
Add POST endpoint to `server.js` and call from admin panel

### Option C: Sync with Real Databases
Integrate with PhishTank, URLhaus, or Google Safe Browsing API

## File Structure

```
TrustShield/
├── app/
│   └── src/main/java/com/example/trustshield/
│       ├── PhishingDomainChecker.kt          (NEW)
│       ├── LinkAnalyzer.kt                   (UPDATE)
│       └── ...
└── backend/                                   (NEW)
    ├── server.js                              (API)
    ├── package.json                           (Dependencies)
    ├── DEPLOYMENT.md                          (How to deploy)
    └── README.md                              (Documentation)
```

## Testing

### Test Local Database (Offline)
```kotlin
val checker = PhishingDomainChecker(context)
checker.checkDomain("https://paypal-confirm.com") { result ->
    // Result should be DANGEROUS (from local DB)
}
```

### Test Remote API
```bash
curl "https://your-api.com/api/check-domain?domain=paypal-confirm.com"
```

### Test on Android
1. Open TrustShield app
2. Send message with suspicious link
3. Check if both rule-based AND database checks work

## Cost Analysis

| Platform | Monthly Cost | Requests/Month | Best For |
|----------|-------------|----------------|----------|
| Replit | FREE | 5,000+ | Development |
| Render | FREE | 10,000+ | Small app |
| Heroku | $7+ | Unlimited | Professional |
| Firebase | FREE | 100,000+ | Database only |

**Recommendation:** Start with Replit (free, easy), upgrade to Render if needed (free, more reliable)

## Next Steps

1. ✅ **Deploy backend** (choose platform, deploy server.js)
2. ✅ **Update Android code** (change API URL)
3. ✅ **Test integration** (send messages with suspicious links)
4. ✅ **Add more domains** (expand phishing database)
5. ✅ **Set up monitoring** (track API usage)
6. ✅ **Implement caching** (reduce API calls)
7. ✅ **Add admin panel** (manage domains easily)

## Security Checklist

- [ ] Use HTTPS only (all platforms provide this)
- [ ] Add rate limiting to API
- [ ] Implement authentication for admin endpoints
- [ ] Log all API requests
- [ ] Monitor API uptime
- [ ] Backup database regularly
- [ ] Keep dependencies updated

## Questions?

See:
- `backend/DEPLOYMENT.md` - Detailed deployment steps
- `backend/README.md` - API documentation
- `app/src/main/java/com/example/trustshield/PhishingDomainChecker.kt` - Android implementation
