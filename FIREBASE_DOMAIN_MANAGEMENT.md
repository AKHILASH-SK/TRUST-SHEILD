# Firebase Phishing Domains - Management Guide

## 📝 How to Add/Update Phishing Domains in Firebase

### Quick Reference

**To add a new phishing domain:**
1. Go to Firebase Console → Realtime Database
2. Navigate to: `phishing_domains` → `dangerous`
3. Click **+** button
4. Enter domain name and save
5. Done! App updates within 1 hour (or on restart)

---

## 📊 Database Structure

Your Firebase database should look like:

```
trustshield-project-abc123 (root)
└── phishing_domains
    ├── dangerous
    │   ├── 0: "paypal-confirm.com"
    │   ├── 1: "verify-account.com"
    │   ├── 2: "secure-login-amazon.com"
    │   └── ... more domains
    └── suspicious
        └── (empty for now)
```

---

## ✅ Step-by-Step: Add New Domain

### Method 1: Firebase Console (Easiest)

**Step 1:** Open Firebase Console
- Go: https://console.firebase.google.com
- Select your **TrustShield** project

**Step 2:** Navigate to Database
- Click **Build** → **Realtime Database**
- Click your database name

**Step 3:** Add Domain
- Click the **dangerous** node
- Click the **+** (plus icon)
- A new child appears with a number
- **Key:** Will be auto-generated (0, 1, 2, etc.)
- **Value:** Enter domain name like `malicious-bank.com`
- Press **Enter** or click outside to save

**Step 4:** Done!
- Domain is added to Firebase
- Your app checks every hour for updates
- Next time user gets that domain in a message → Alert! 🚨

---

## 📌 Domain Naming Format

**Always use:**
- ✅ `paypal-confirm.com` (lowercase)
- ✅ `amazon-verify-login.com`
- ✅ `fake-google-account.com`

**Don't use:**
- ❌ `https://paypal-confirm.com` (no protocol)
- ❌ `www.paypal-confirm.com` (no www)
- ❌ `paypal-confirm.com/path` (no path)
- ❌ `PayPal-Confirm.com` (use lowercase)

---

## 🚀 Quick Add: Common Phishing Domains

Here are popular phishing domains to add. Go through them one by one:

### Banking & Payment
```
paypal-security-update.com
verify-amazon-account.com
bank-login-confirm.com
credit-card-verify.com
secure-payment-gateway.com
```

### Email & Social
```
gmail-security-alert.com
facebook-login-verify.com
instagram-verify-account.com
twitter-account-confirm.com
whatsapp-verify-number.com
```

### Tech Companies
```
apple-id-verify.com
microsoft-account-recover.com
google-security-alert.com
adobe-account-confirm.com
netflix-verify-payment.com
```

### General Phishing
```
account-verify-urgent.com
security-alert-required.com
confirm-identity-now.com
update-payment-method.com
verify-account-access.com
```

---

## 🔄 Update Existing Domain

**To change or fix a domain:**

1. In Firebase Console → Realtime Database
2. Find the domain under `phishing_domains` → `dangerous`
3. Click on it
4. Click **✏️ Edit** (appears on hover)
5. Change the value
6. Click **Save**

---

## 🗑️ Delete a Domain

**To remove a domain from the list:**

1. In Firebase Console → Realtime Database
2. Find the domain
3. Hover over it
4. Click **🗑️ Delete** icon
5. Confirm delete

---

## 📥 Add "Suspicious" Domains

Some domains aren't definitely phishing, just suspicious. Add them to a separate list:

**Step 1:** Create suspicious node (if doesn't exist)
- Click **phishing_domains**
- Click **+** button
- Key: `suspicious`
- Value: (leave empty, will add children)
- Click **Add**

**Step 2:** Add suspicious domains
- Click **suspicious**
- Click **+** button
- Add domains like: `shortened-url-service.com`
- These will show orange alert instead of red

---

## 📊 Current Domain List

**Default domains (in code):**
```
1. paypal-confirm.com
2. verify-account.com
3. secure-login-amazon.com
4. gmail-verification.com
5. apple-verify.com
6. microsoft-security.com
7. adobe-security-alert.com
8. bank-login-verify.com
9. paypal-security.com
10. amazon-verify-account.com
11. google-account-verify.com
12. facebook-login-check.com
```

**To add these to Firebase:**
1. Add each one following "Step-by-Step: Add New Domain" above
2. Or copy-paste all 12 one by one

---

## 🔄 How App Updates Work

### Timeline:
1. **User gets message** with link
2. **App extracts domain** (e.g., `paypal-confirm.com`)
3. **App checks local cache** instantly
4. **Alert shows immediately** if found
5. **Background:** App refreshes from Firebase every 1 hour
6. **Next check:** Uses updated list from Firebase

### Cache Details:
- **Caches for:** 1 hour
- **Fallback:** Uses embedded domains if Firebase unavailable
- **Offline:** Works completely offline with cached data
- **Auto-update:** Checks Firebase in background on app startup

---

## 🚀 Bulk Import (Advanced)

If you have 100+ domains, manually adding is slow. Instead:

### Option 1: Use Realtime Database REST API
```bash
curl -X POST https://YOUR_DATABASE.firebaseio.com/phishing_domains/dangerous.json \
  -H "Content-Type: application/json" \
  -d '{
    "0": "domain1.com",
    "1": "domain2.com",
    "2": "domain3.com"
  }'
```

### Option 2: Use Firebase CLI
```bash
firebase database:set phishing_domains/dangerous domains.json
```

See `FIREBASE_ADVANCED.md` for details.

---

## 📈 Monitoring

### Check How Many Domains You Have:
1. Go to Firebase Realtime Database
2. Click **phishing_domains**
3. Count the entries under **dangerous** and **suspicious**

### Monitor App Usage:
- Go to Firebase Console → Analytics
- See how many users have app installed
- Check which notifications were shown

---

## 🔐 Security Checklist

- ✅ Database is in **test mode** (for development)
- ⚠️ **Before releasing:** Change security rules to read-only
- ✅ Only domains are stored (no personal data)
- ✅ Data is encrypted in transit (HTTPS)
- ✅ Firebase handles backups automatically

---

## ❓ FAQ

### Q: How long does it take for new domains to appear?
**A:** Within 1 hour. Faster if user restarts app.

### Q: Can I add domains with spaces or special characters?
**A:** No, only valid domain names work (a-z, 0-9, hyphens).

### Q: What if someone adds a fake domain?
**A:** Firebase security rules prevent this. Only you can write (in console), anyone can read.

### Q: How many domains can I add?
**A:** Realtime Database allows unlimited. App handles thousands easily.

### Q: Can users submit new phishing domains?
**A:** Not in basic setup. Advanced: See `FIREBASE_ADVANCED.md` for user reporting system.

---

## 🎯 Next Steps

1. ✅ Complete Firebase setup (FIREBASE_SETUP.md)
2. ✅ Add 20+ phishing domains to `dangerous` list
3. ✅ Build and test Android app
4. ✅ Send test messages with phishing domains
5. ✅ Verify alerts show correctly
6. 📈 Monitor and expand domain list regularly

---

## 📚 Related Docs

- `FIREBASE_SETUP.md` - Initial setup guide
- `IMPLEMENTATION_COMPLETE.md` - Full project overview
- `PhishingDomainCheckerFirebase.kt` - Android code reference
