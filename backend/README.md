# TrustShield Backend - Phishing Domain Database API

## What is This?

This is a simple backend API that stores known phishing domains and allows the TrustShield Android app to check if a domain is malicious.

## Features

✅ Fast domain lookups  
✅ Local embedded database (for offline use)  
✅ Remote API (for real-time updates)  
✅ Zero deployment cost (free hosting options)  
✅ Easy to update database  
✅ Health monitoring  

## Quick Start

### Local Development

```bash
# Install dependencies
npm install

# Start server
npm start

# Server runs on http://localhost:3000
```

### Test the API

```bash
# Check a safe domain
curl "http://localhost:3000/api/check-domain?domain=google.com"

# Check a phishing domain
curl "http://localhost:3000/api/check-domain?domain=paypal-confirm.com"

# Get statistics
curl "http://localhost:3000/api/stats"
```

## API Endpoints

### 1. Check Domain
```
GET /api/check-domain?domain=example.com
```

**Response:**
```json
{
  "domain": "example.com",
  "dangerous": false,
  "suspicious": false,
  "message": "Domain appears safe"
}
```

### 2. Get Statistics
```
GET /api/stats
```

**Response:**
```json
{
  "dangerousCount": 12,
  "suspiciousCount": 3,
  "totalDomains": 15,
  "lastUpdated": "2026-01-30T20:30:00.000Z"
}
```

### 3. Health Check
```
GET /health
```

**Response:**
```json
{
  "status": "Server is running"
}
```

## Database Structure

The phishing database is organized in `server.js`:

```javascript
const PHISHING_DATABASE = {
  "dangerous": [
    "paypal-confirm.com",
    "verify-account.com",
    // ... more domains
  ],
  "suspicious": [
    "unusual-domain.com",
    // ... more domains
  ]
};
```

## Update the Database

### Method 1: Edit File
1. Edit `server.js`
2. Add domains to `PHISHING_DATABASE.dangerous` or `PHISHING_DATABASE.suspicious`
3. Redeploy to your hosting platform

### Method 2: Integrate with External Sources
You can sync with public phishing databases:
- **PhishTank:** https://phishtank.com/api_documentation.php
- **URLhaus:** https://urlhaus.abuse.ch/
- **Google Safe Browsing:** https://safebrowsing.googleapis.com/

## Deployment

See `DEPLOYMENT.md` for step-by-step instructions to deploy to:
- ✅ Replit (easiest, 5 minutes)
- ✅ Heroku (reliable, free tier)
- ✅ Render (modern, free tier)
- ✅ Firebase (database only)

## Integration with Android App

The Android app (`PhishingDomainChecker.kt`) will:

1. Check local database first (instant)
2. Query this API in background (async)
3. Show alert if domain is found
4. Fall back to local data if API is unavailable

## Environment Variables

Optional (for production):

```bash
PORT=3000
ADMIN_PASSWORD=your-secret-password
```

## Security Notes

⚠️ **For Production:**
- Add authentication for admin endpoints
- Use HTTPS only
- Implement rate limiting
- Add CORS restrictions
- Log all requests
- Use environment variables for secrets

## Contributing

To add phishing domains:
1. Create a pull request
2. Add domain to `server.js`
3. Include source/reason in comment
4. Deploy and test

## Support

For issues or questions:
- Create GitHub issue
- Check deployment guide

## License

MIT

---

**Made for TrustShield Android Security App**
