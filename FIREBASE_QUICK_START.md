# Firebase Setup - Quick Start (10 Minutes)

## ⚡ Super Quick Steps

### Step 1: Create Firebase Project
1. Go: https://console.firebase.google.com
2. Click **"Create a project"**
3. Name: `TrustShield`
4. Continue → Continue → Create project
5. Wait for setup (2 minutes)

### Step 2: Create Realtime Database
1. Left sidebar: **Build** → **Realtime Database**
2. Click **Create Database**
3. Location: **us-central1**
4. Security: **Test mode**
5. Click **Enable**

✅ You now have a database URL like:
```
https://trustshield-abc123.firebaseio.com
```

### Step 3: Add Sample Data
1. In database, click **+** next to root
2. **Key:** `phishing_domains` → **Add**
3. Click **+** next to `phishing_domains`
4. **Key:** `dangerous` → **Add**
5. Click **+** next to `dangerous`
6. **Key:** `0` → **Value:** `paypal-confirm.com` → **Add**
7. Repeat 5-6 for:
   - `1: verify-account.com`
   - `2: secure-login-amazon.com`
   - (add 10+ more domains)

### Step 4: Download google-services.json
1. Firebase Console → **⚙️ Project Settings** (top left)
2. Go to **General** tab
3. Scroll: **Your apps** section
4. Click **Android** (or add new Android app)
5. Package name: `com.example.trustshield`
6. Click **Register app**
7. Click **Download google-services.json**
8. Save to: `app/google-services.json` in your project

### Step 5: Update Android Code
Already done! I created:
- ✅ `PhishingDomainCheckerFirebase.kt` (uses Firebase)
- ✅ Updated `app/build.gradle.kts` (Firebase dependencies)
- ✅ Updated `build.gradle.kts` (Google Services plugin)

### Step 6: Build & Test
```bash
cd c:\Users\akhil\AndroidStudioProjects\TrustShield

# Sync gradle
./gradlew --sync

# Build
./gradlew assembleDebug -x lintVitalRelease

# Install
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

### Step 7: Test
Send WhatsApp message:
```
Check this: paypal-confirm.com
```

Expected: 🔴 Red alert notification appears

---

## ✅ That's It!

Your app now:
- ✅ Uses Firebase database
- ✅ Reads phishing domains
- ✅ Shows alerts
- ✅ Works offline (caches data)
- ✅ Updates hourly

---

## 📝 Need More Info?

- **Setup details:** See `FIREBASE_SETUP.md`
- **Add/update domains:** See `FIREBASE_DOMAIN_MANAGEMENT.md`
- **Project overview:** See `IMPLEMENTATION_COMPLETE.md`

---

## 🆘 Stuck?

### Common Issues:

**"google-services.json not found"**
- Place it in `app/` folder (not root)

**"Firebase module not found"**
- Run: `./gradlew --sync`
- Click **Sync Now** in Android Studio

**"Build fails with Firebase errors"**
- Delete: `app/build/` folder
- Run: `./gradlew clean assembleDebug -x lintVitalRelease`

**"App doesn't show alerts"**
- Make sure domains are in Firebase database under:
  `phishing_domains` → `dangerous`
- Restart app
- Send test message with exact domain

---

**Next:** See `FIREBASE_DOMAIN_MANAGEMENT.md` to add more phishing domains! 📚
