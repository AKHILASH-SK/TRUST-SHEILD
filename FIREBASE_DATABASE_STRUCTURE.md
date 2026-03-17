# Firebase Database Structure - Visual Guide

## 🗂️ Expected Database Structure

After setup, your Firebase Realtime Database should look like:

```
trustshield-project-xyz (root)
│
└── phishing_domains/
    │
    ├── dangerous/
    │   ├── 0: "paypal-confirm.com"
    │   ├── 1: "verify-account.com"
    │   ├── 2: "secure-login-amazon.com"
    │   ├── 3: "gmail-verification.com"
    │   ├── 4: "apple-verify.com"
    │   ├── 5: "microsoft-security.com"
    │   ├── 6: "adobe-security-alert.com"
    │   ├── 7: "bank-login-verify.com"
    │   ├── 8: "paypal-security.com"
    │   ├── 9: "amazon-verify-account.com"
    │   ├── 10: "google-account-verify.com"
    │   └── 11: "facebook-login-check.com"
    │
    └── suspicious/
        └── (empty - or add suspicious domains here)
```

---

## ✅ Step-by-Step: Create This Structure

### Step 1: Create `phishing_domains` Node

1. Open Firebase Console
2. Go to **Realtime Database**
3. Look at the root (should be empty or have existing data)
4. Click the **+** icon next to your project name at the root level
5. A popup appears:
   - **Key:** `phishing_domains`
   - **Value:** (leave empty - we'll add children)
6. Press **Enter** or click outside
7. New node `phishing_domains` appears

### Step 2: Create `dangerous` Node

1. Click on `phishing_domains` to expand it
2. Click the **+** icon next to `phishing_domains`
3. A popup appears:
   - **Key:** `dangerous`
   - **Value:** (leave empty)
4. Press **Enter**
5. You now have: `phishing_domains` → `dangerous`

### Step 3: Add First Domain

1. Click the **+** icon next to `dangerous`
2. A popup appears:
   - **Key:** `0`
   - **Value:** `paypal-confirm.com`
3. Press **Enter**
4. First domain added!

### Step 4: Add More Domains (Repeat)

1. Click **+** next to `dangerous` again
2. For next domain:
   - **Key:** `1`
   - **Value:** `verify-account.com`
3. Repeat for each domain (keys: 0, 1, 2, 3, ... 11)

---

## 🎯 Quick Copy-Paste Domains

Add these 12 domains to `phishing_domains` → `dangerous`:

```
0: paypal-confirm.com
1: verify-account.com
2: secure-login-amazon.com
3: gmail-verification.com
4: apple-verify.com
5: microsoft-security.com
6: adobe-security-alert.com
7: bank-login-verify.com
8: paypal-security.com
9: amazon-verify-account.com
10: google-account-verify.com
11: facebook-login-check.com
```

---

## 📊 Visual: How It Looks in Firebase Console

### Tree View:
```
💾 trustshield-xyz
  ├ phishing_domains
  │ ├ dangerous
  │ │ ├ 0  paypal-confirm.com
  │ │ ├ 1  verify-account.com
  │ │ ├ 2  secure-login-amazon.com
  │ │ └ ... more domains
  │ └ suspicious
  └ (other nodes, if any)
```

### JSON View:
```json
{
  "phishing_domains": {
    "dangerous": {
      "0": "paypal-confirm.com",
      "1": "verify-account.com",
      "2": "secure-login-amazon.com",
      "3": "gmail-verification.com",
      "4": "apple-verify.com",
      "5": "microsoft-security.com",
      "6": "adobe-security-alert.com",
      "7": "bank-login-verify.com",
      "8": "paypal-security.com",
      "9": "amazon-verify-account.com",
      "10": "google-account-verify.com",
      "11": "facebook-login-check.com"
    },
    "suspicious": {}
  }
}
```

---

## 🔍 How Android App Reads This

The `PhishingDomainCheckerFirebase.kt` reads this structure:

```kotlin
// Reads from: phishing_domains → dangerous
val dangerous = snapshot.child("dangerous")

// Gets all values (0, 1, 2, 3, ... 11)
for (domainSnapshot in dangerous.children) {
    val domain = domainSnapshot.value as String
    // Results in: "paypal-confirm.com", "verify-account.com", etc.
}
```

---

## ➕ Adding More Domains Later

To add domain #12:

1. Click **phishing_domains** → **dangerous**
2. Click **+** icon
3. **Key:** `12`
4. **Value:** `new-phishing-domain.com`
5. Click **Add**

App will sync within 1 hour!

---

## 📝 Domain Format Rules

### ✅ Correct Format:
- `paypal-confirm.com` (lowercase)
- `amazon-verify.com` (lowercase)
- `secure-login-bank.com` (hyphens ok)

### ❌ Wrong Format:
- `https://paypal-confirm.com` (no protocol)
- `www.paypal-confirm.com` (no www)
- `paypal-confirm.com/verify` (no path)
- `PayPal-Confirm.com` (must be lowercase)

---

## 🧪 Test Your Setup

### Test 1: Check Structure Exists
1. Firebase Console → Realtime Database
2. You should see:
   - `phishing_domains`
   - `dangerous` under it
   - Domain entries under `dangerous`

### Test 2: Check Data Loads
1. Install and open app
2. Check Android logs:
   ```
   adb logcat | findstr "PhishingChecker"
   ```
3. Look for:
   ```
   Loaded 12 dangerous domains from cache
   ```

### Test 3: Send Test Message
1. Send WhatsApp message: `Check: paypal-confirm.com`
2. Expected: 🔴 Red alert notification
3. Logs show: `DANGEROUS domain detected`

---

## 🚨 Troubleshooting Structure

### Problem: Database is empty
**Solution:** Follow Step 1-4 above to create nodes

### Problem: `phishing_domains` exists but no `dangerous` node
**Solution:** Click `phishing_domains` → Click **+** → Add `dangerous` node

### Problem: `dangerous` exists but no domains
**Solution:** Click `dangerous` → Click **+** → Add domains with keys 0, 1, 2, etc.

### Problem: Domains added but app doesn't detect them
**Solutions:**
1. Check spelling of domain names (must match exactly)
2. Verify domains are lowercase
3. Restart app
4. Check internet connection
5. Check Firebase security rules allow reading

---

## 🔐 Optional: Add Suspicious Domains

To add potentially phishing domains (orange alert instead of red):

1. Click **phishing_domains**
2. Click **+**
3. **Key:** `suspicious`
4. **Value:** (leave empty)
5. Click **+** next to `suspicious`
6. Add domains:
   - **Key:** `0`
   - **Value:** `bit.ly` (URL shortener example)
7. Repeat for more suspicious domains

Result: Suspicious domains show orange alert instead of red

---

## 📚 What's Next?

1. ✅ Create this database structure
2. ✅ Add 12 phishing domains
3. ✅ Build and test Android app
4. ✅ Send test message with phishing domain
5. ✅ Verify red alert appears
6. 📈 Monitor and expand domain list

---

**Database ready? Now build the app with:** `./gradlew assembleDebug -x lintVitalRelease` 🚀
