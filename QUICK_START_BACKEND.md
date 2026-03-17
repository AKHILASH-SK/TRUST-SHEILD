# Quick Start: Deploy Phishing Database Backend

## TL;DR - Deploy in 5 Minutes with Replit

### Step 1: Create Replit Account (2 minutes)
1. Open https://replit.com
2. Click **Sign up** → Use GitHub or email
3. Verify email

### Step 2: Create Backend (1 minute)
1. Click **Create Repl**
2. Choose **Node.js**
3. Name it: `trustshield-api`

### Step 3: Add Code (1 minute)
1. Open the `main.js` file
2. Copy-paste this code:

```javascript
const express = require('express');
const cors = require('cors');
const app = express();

app.use(cors());
app.use(express.json());

// Phishing domains database
const PHISHING_DATABASE = {
  "dangerous": [
    "paypal-confirm.com",
    "verify-account.com",
    "secure-login-amazon.com",
    "gmail-verification.com",
    "apple-verify.com",
    "microsoft-security.com",
  ],
  "suspicious": []
};

// Check domain endpoint
app.get('/api/check-domain', (req, res) => {
  const domain = req.query.domain;
  if (!domain) {
    return res.status(400).json({ error: "Domain required" });
  }
  
  const cleanDomain = domain.toLowerCase().replace("www.", "");
  const isDangerous = PHISHING_DATABASE.dangerous.includes(cleanDomain);
  const isSuspicious = PHISHING_DATABASE.suspicious.includes(cleanDomain);
  
  res.json({
    domain: cleanDomain,
    dangerous: isDangerous,
    suspicious: isSuspicious,
    message: isDangerous ? "Phishing domain detected" : "Domain safe"
  });
});

// Stats endpoint
app.get('/api/stats', (req, res) => {
  res.json({
    dangerousCount: PHISHING_DATABASE.dangerous.length,
    suspiciousCount: PHISHING_DATABASE.suspicious.length
  });
});

app.get('/health', (req, res) => {
  res.json({ status: "OK" });
});

app.listen(3000, () => {
  console.log('🚀 Server running on port 3000');
});
```

### Step 4: Update package.json (30 seconds)
Replace with:
```json
{
  "name": "trustshield-api",
  "version": "1.0.0",
  "main": "main.js",
  "dependencies": {
    "express": "^4.18.2",
    "cors": "^2.8.5"
  }
}
```

### Step 5: Deploy (1 minute)
1. Click **Run** button
2. Wait for "Server running on port 3000"
3. Copy the **public URL** from the top panel
   - Looks like: `https://trustshield-api.replit.dev`

### Step 6: Test (30 seconds)
Open in browser:
```
https://your-api-url.com/api/check-domain?domain=paypal-confirm.com
```

Should return:
```json
{
  "domain": "paypal-confirm.com",
  "dangerous": true,
  "suspicious": false,
  "message": "Phishing domain detected"
}
```

### Step 7: Update Android App
In `PhishingDomainChecker.kt`, change:

```kotlin
private const val PHISHING_API_URL = "https://your-api-url.com/api/check-domain"
```

Replace `your-api-url.com` with your actual Replit URL!

### Step 8: Build & Install
```bash
cd c:\Users\akhil\AndroidStudioProjects\TrustShield
.\gradlew assembleDebug -x lintVitalRelease
adb install -r app\build\outputs\apk\debug\app-debug.apk
```

### Step 9: Test on Phone
1. Open TrustShield app
2. Send WhatsApp message: `Check this: paypal-confirm.com`
3. You should see alert!

---

## ✅ Done! 

Your phishing database is now:
- ✅ Deployed online
- ✅ Running 24/7
- ✅ Connected to Android app
- ✅ Checking domains in real-time

---

## Adding More Domains

To add more phishing domains:

1. Go to your Replit project
2. Edit `main.js`
3. Add domains to the list:

```javascript
"dangerous": [
  "paypal-confirm.com",
  "verify-account.com",
  "secure-login-amazon.com",
  "new-phishing-domain.com",  // ← Add here
],
```

4. Click **Run** again
5. Done! (Changes take effect immediately)

---

## Troubleshooting

### API not responding
- Check if Replit server is running (click Run)
- Check if URL is correct

### Android app not connecting
- Update URL in `PhishingDomainChecker.kt`
- Make sure phone has internet connection
- Check app has INTERNET permission

### Want to make changes?
- Go to Replit editor
- Edit `main.js`
- Click Run
- Changes live immediately!

---

## Next Steps

- 📱 Add more phishing domains to database
- 🔒 Add admin authentication
- 📊 Add analytics/logging
- 🔄 Auto-sync with PhishTank database
- 🚀 Upgrade to production server if needed

---

**Congratulations! Your phishing database is live! 🎉**
