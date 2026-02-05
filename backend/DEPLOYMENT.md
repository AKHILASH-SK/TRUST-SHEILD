# TrustShield Backend Deployment Guide

## Overview
This is a simple Node.js/Express API that serves a phishing domain database. It can be deployed for FREE on multiple platforms.

---

## Option 1: Deploy to Replit (EASIEST - 5 Minutes)

### Step 1: Create Replit Account
1. Go to https://replit.com
2. Sign up with GitHub or email
3. Click "Create Repl"

### Step 2: Upload Backend Files
1. Create new Repl → Node.js
2. Copy contents of `server.js` into main file
3. Copy contents of `package.json` into package.json

### Step 3: Install & Run
```bash
npm install
npm start
```

### Step 4: Get Public URL
- Replit automatically gives you a public URL
- Example: `https://trustshield-api.replit.dev`

---

## Option 2: Deploy to Heroku (FREE Tier - 10 Minutes)

### Step 1: Create Heroku Account
1. Go to https://heroku.com
2. Sign up (verify email)

### Step 2: Install Heroku CLI
```bash
# Windows
choco install heroku-cli

# Or download from https://devcenter.heroku.com/articles/heroku-cli
```

### Step 3: Deploy
```bash
cd backend
heroku login
heroku create trustshield-api
git push heroku main
```

### Step 4: Get Public URL
```bash
heroku apps:info trustshield-api
```

---

## Option 3: Deploy to Render (FREE - 8 Minutes)

### Step 1: Create Render Account
1. Go to https://render.com
2. Sign up with GitHub

### Step 2: Connect Repository
1. Click "New +"
2. Select "Web Service"
3. Connect your GitHub repo
4. Select branch: `main`

### Step 3: Configure
- **Build command:** `npm install`
- **Start command:** `npm start`
- **Environment:** Node

### Step 4: Deploy
Click "Create Web Service"

Your URL: `https://trustshield-api.onrender.com`

---

## Option 4: Firebase Realtime Database (No Coding)

If you prefer database without coding:

### Step 1: Create Firebase Project
1. Go to https://firebase.google.com
2. Click "Go to console"
3. Create new project

### Step 2: Create Realtime Database
1. Go to Realtime Database
2. Create database in "locked mode"
3. Import JSON:

```json
{
  "phishing": {
    "dangerous": {
      "paypal-confirm.com": true,
      "verify-account.com": true,
      "secure-login-amazon.com": true
    },
    "suspicious": {}
  }
}
```

### Step 3: Update Android Code
Change the API URL to your Firebase endpoint

---

## Testing Your API

After deployment, test these endpoints:

```bash
# Check a domain
curl "https://your-api-url.com/api/check-domain?domain=paypal-confirm.com"

# Get statistics
curl "https://your-api-url.com/api/stats"

# Health check
curl "https://your-api-url.com/health"
```

### Expected Response:
```json
{
  "domain": "paypal-confirm.com",
  "dangerous": true,
  "suspicious": false,
  "message": "This domain is in the phishing database"
}
```

---

## Update Android App with Your API URL

In `PhishingDomainChecker.kt`, update:

```kotlin
private const val PHISHING_API_URL = "https://your-deployed-api-url.com/api/check-domain"
```

---

## Adding New Phishing Domains

### Option A: Edit JSON File
1. Go to your deployed server
2. Edit `server.js` → Update `PHISHING_DATABASE`
3. Redeploy

### Option B: Create Admin Endpoint (Advanced)
Add this to `server.js`:

```javascript
app.post('/api/admin/add-domain', (req, res) => {
  const { domain, type, password } = req.body;
  
  if (password !== process.env.ADMIN_PASSWORD) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  
  if (type === "dangerous") {
    PHISHING_DATABASE.dangerous.push(domain);
  } else {
    PHISHING_DATABASE.suspicious.push(domain);
  }
  
  res.json({ success: true, message: `Added ${domain}` });
});
```

---

## Cost Breakdown

| Platform | Cost | Limits | Best For |
|----------|------|--------|----------|
| **Replit** | FREE | 500MB storage, 1 GB bandwidth/month | Quick testing |
| **Heroku** | FREE | 550 hours/month (shared dyno) | Small projects |
| **Render** | FREE | 750 hours/month | Medium projects |
| **Firebase** | FREE | 100 concurrent connections | Database only |

---

## Recommended Setup

**For Production:**
1. Use **Render** (most reliable free tier)
2. Use **Firebase** for database storage
3. Update database weekly with new phishing domains

**For Development:**
1. Use **Replit** (easy to edit)
2. Test locally with `npm start`

---

## Integration with Android App

The `PhishingDomainChecker` class will:

1. **Check local database first** (instant, offline)
2. **Query remote API in background** (doesn't block UI)
3. **Update LinkAnalyzer** with database results
4. **Show alert if domain is found**

---

## Future Enhancements

- [ ] Sync database daily from PhishTank API
- [ ] Use machine learning to detect new phishing patterns
- [ ] Add user reporting system
- [ ] Create admin dashboard to manage domains
- [ ] Implement caching to reduce API calls

