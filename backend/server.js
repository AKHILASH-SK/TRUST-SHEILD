// TrustShield Phishing Domain Database API
// Node.js + Express backend
// Deploy to: Heroku, Replit, or Render (all free)

const express = require('express');
const cors = require('cors');
const app = express();

app.use(cors());
app.use(express.json());

// Phishing domains database (update this regularly)
const PHISHING_DATABASE = {
  "dangerous": [
    // Bank phishing
    "paypal-confirm.com",
    "verify-account.com",
    "secure-login-amazon.com",
    "gmail-verification.com",
    "apple-verify.com",
    "microsoft-security.com",
    "verify-payment.com",
    "account-update.com",
    "confirm-identity.com",
    "security-alert.com",
    "urgent-verification.com",
    "click-here-verify.com",
    "verify-identity.net",
    "secure-verify.com",
    "account-confirm.org",
    // Add more as needed
  ],
  "suspicious": [
    "unusual-domain-pattern.com",
    "verify-click.com",
    // Add suspicious domains here
  ]
};

/**
 * GET /api/check-domain
 * Check if a domain is in the phishing database
 * 
 * Query params:
 * - domain: The domain to check (e.g., "paypal-confirm.com")
 * 
 * Response:
 * {
 *   "domain": "paypal-confirm.com",
 *   "dangerous": true,
 *   "suspicious": false,
 *   "message": "This domain is in the phishing database"
 * }
 */
app.get('/api/check-domain', (req, res) => {
  const domain = req.query.domain;
  
  if (!domain) {
    return res.status(400).json({
      error: "Domain parameter required",
      example: "/api/check-domain?domain=example.com"
    });
  }
  
  const cleanDomain = domain.toLowerCase().replace("www.", "");
  
  const isDangerous = PHISHING_DATABASE.dangerous.includes(cleanDomain);
  const isSuspicious = PHISHING_DATABASE.suspicious.includes(cleanDomain);
  
  res.json({
    domain: cleanDomain,
    dangerous: isDangerous,
    suspicious: isSuspicious,
    message: isDangerous 
      ? "This domain is in the phishing database" 
      : isSuspicious
      ? "This domain is marked as suspicious"
      : "Domain appears safe"
  });
});

/**
 * GET /api/stats
 * Get database statistics
 */
app.get('/api/stats', (req, res) => {
  res.json({
    dangerousCount: PHISHING_DATABASE.dangerous.length,
    suspiciousCount: PHISHING_DATABASE.suspicious.length,
    totalDomains: PHISHING_DATABASE.dangerous.length + PHISHING_DATABASE.suspicious.length,
    lastUpdated: new Date().toISOString()
  });
});

/**
 * Health check endpoint
 */
app.get('/health', (req, res) => {
  res.json({ status: "Server is running" });
});

/**
 * Root endpoint
 */
app.get('/', (req, res) => {
  res.json({
    name: "TrustShield Phishing Domain Database API",
    version: "1.0.0",
    endpoints: {
      checkDomain: "/api/check-domain?domain=example.com",
      stats: "/api/stats",
      health: "/health"
    }
  });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 TrustShield API running on port ${PORT}`);
  console.log(`📊 Phishing domains in database: ${PHISHING_DATABASE.dangerous.length}`);
  console.log(`⚠️  Suspicious domains: ${PHISHING_DATABASE.suspicious.length}`);
});

// Export for serverless deployments (Vercel, Netlify)
module.exports = app;
