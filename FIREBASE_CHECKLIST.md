# Firebase Setup Checklist

## 📋 Complete Step-by-Step Checklist

### ✅ PHASE 1: Firebase Project Setup (5 minutes)

- [ ] Go to https://console.firebase.google.com
- [ ] Click "Create a project"
- [ ] Project name: `TrustShield`
- [ ] Enable Google Analytics (select or continue without)
- [ ] Create project
- [ ] Wait for project to initialize (1-2 minutes)

**Status:** Firebase project created ✓

---

### ✅ PHASE 2: Create Realtime Database (3 minutes)

- [ ] In Firebase Console, click **Build** → **Realtime Database**
- [ ] Click **Create Database**
- [ ] Select location: **us-central1** (default)
- [ ] Security rules: **Start in test mode**
- [ ] Click **Enable**
- [ ] Wait for database to initialize
- [ ] **SAVE THIS URL:** https://your-project.firebaseio.com

**Status:** Database created ✓

---

### ✅ PHASE 3: Download google-services.json (3 minutes)

- [ ] Click **⚙️ Project Settings** (top left of Firebase Console)
- [ ] Go to **General** tab
- [ ] Scroll down to **Your apps** section
- [ ] Click **Android** (or add Android app if not shown)
- [ ] Fill in:
  - [ ] **Package name:** `com.example.trustshield`
  - [ ] **App nickname:** `TrustShield` (optional)
- [ ] Click **Register app**
- [ ] Click **Download google-services.json**
- [ ] **IMPORTANT:** Move file to `app/google-services.json` in your project

**Status:** google-services.json downloaded and placed ✓

---

### ✅ PHASE 4: Create Database Structure (5 minutes)

**Create `phishing_domains` node:**
- [ ] Go to Realtime Database
- [ ] Click **+** at root
- [ ] Key: `phishing_domains`
- [ ] Click **Add**

**Create `dangerous` node:**
- [ ] Click **+** next to `phishing_domains`
- [ ] Key: `dangerous`
- [ ] Click **Add**

**Add domains (repeat for each):**
- [ ] Click **+** next to `dangerous`
  - [ ] Key: `0` → Value: `paypal-confirm.com`
  - [ ] Key: `1` → Value: `verify-account.com`
  - [ ] Key: `2` → Value: `secure-login-amazon.com`
  - [ ] Key: `3` → Value: `gmail-verification.com`
  - [ ] Key: `4` → Value: `apple-verify.com`
  - [ ] Key: `5` → Value: `microsoft-security.com`
  - [ ] Key: `6` → Value: `adobe-security-alert.com`
  - [ ] Key: `7` → Value: `bank-login-verify.com`
  - [ ] Key: `8` → Value: `paypal-security.com`
  - [ ] Key: `9` → Value: `amazon-verify-account.com`
  - [ ] Key: `10` → Value: `google-account-verify.com`
  - [ ] Key: `11` → Value: `facebook-login-check.com`

**Status:** Database structure created with 12 phishing domains ✓

---

### ✅ PHASE 5: Android Code Setup (Already Done!)

- [x] Updated `app/build.gradle.kts` with Firebase dependencies
- [x] Updated `build.gradle.kts` with Google Services plugin
- [x] Created `PhishingDomainCheckerFirebase.kt`
- [x] Created `NotificationListenerFirebase.kt`

**Status:** Android code ready ✓

---

### ✅ PHASE 6: Build & Install APK (5 minutes)

**Open PowerShell and navigate to project:**
```bash
cd c:\Users\akhil\AndroidStudioProjects\TrustShield
```

**Sync Gradle:**
- [ ] Run: `./gradlew --sync`
- [ ] Wait for completion (2-3 minutes)

**Clean Build:**
- [ ] Run: `./gradlew clean`
- [ ] Wait for completion

**Build APK:**
- [ ] Run: `./gradlew assembleDebug -x lintVitalRelease`
- [ ] Watch for: `BUILD SUCCESSFUL`

**Install on Device:**
- [ ] Run: `adb install -r app/build/outputs/apk/debug/app-debug.apk`
- [ ] Watch for: `Success`

**Status:** APK built and installed ✓

---

### ✅ PHASE 7: Test on Device (5 minutes)

**Verify Permissions:**
- [ ] Open Settings → Apps & notifications → Special app access → Notification access
- [ ] Enable **TrustShield** in the list

**Send Test Message:**
- [ ] Open WhatsApp
- [ ] Send message: `Check this: paypal-confirm.com`

**Check Results:**
- [ ] 🔴 Red alert notification appears
- [ ] Message shows "Dangerous phishing domain detected"
- [ ] Check logs: `adb logcat | findstr "PhishingChecker"`

**Test More Domains:**
- [ ] Send: `google.com` (should NOT alert - safe)
- [ ] Send: `verify-account.com` (should alert - red)
- [ ] Send: `secure-login-amazon.com` (should alert - red)

**Status:** App tested and working ✓

---

## 📋 Quick Verification

**Before Testing, Verify:**
- [ ] `app/google-services.json` exists and is in correct location
- [ ] Firebase database has structure: `phishing_domains` → `dangerous` → domains
- [ ] 12 domains added to Firebase
- [ ] Build has no errors (check terminal output)
- [ ] APK installed successfully on device
- [ ] TrustShield notification access is enabled in Settings

---

## 🆘 Troubleshooting Checklist

**If Build Fails:**
- [ ] Check `google-services.json` is in `app/` folder (not root)
- [ ] Delete `app/build/` folder
- [ ] Run: `./gradlew clean`
- [ ] Run: `./gradlew --sync`
- [ ] Try building again

**If APK Won't Install:**
- [ ] Uninstall old version: `adb uninstall com.example.trustshield`
- [ ] Try install again: `adb install -r app/build/outputs/apk/debug/app-debug.apk`
- [ ] Check device has space and USB debugging enabled

**If No Alerts Show:**
- [ ] Check domains are in Firebase (go to console and verify)
- [ ] Verify domain names are exact (e.g., `paypal-confirm.com` not `paypal-confirm.com/`)
- [ ] Check device notification access is enabled for TrustShield
- [ ] Restart app
- [ ] Check logs: `adb logcat | findstr "NOTIFY"`

**If Domains Not Loading:**
- [ ] Check internet connection on device
- [ ] Check Firebase database URL is correct
- [ ] Wait 1 hour for cache refresh
- [ ] Restart app to force sync
- [ ] Check Firebase security rules are not too restrictive

---

## ✅ Final Checklist Before Going Live

- [ ] Firebase project created and tested
- [ ] Database has 12+ phishing domains
- [ ] App installed on device
- [ ] Alerts working for dangerous domains
- [ ] Alerts not showing for safe domains
- [ ] Offline mode works (disable internet and test)
- [ ] Notification access enabled in Settings
- [ ] Logs show successful Firebase syncs

---

## 🎉 Success Indicators

**You're done when:**
✅ App is installed and running  
✅ Notification access is enabled  
✅ Firebase database has phishing domains  
✅ Sending test message with phishing domain shows red alert  
✅ Sending test message with safe domain shows no alert  
✅ Logs show "DANGEROUS domain detected"  

---

## 📚 Documentation Files

If you get stuck, check:
- `FIREBASE_QUICK_START.md` - 10-minute overview
- `FIREBASE_SETUP.md` - Detailed step-by-step
- `FIREBASE_DATABASE_STRUCTURE.md` - Visual database guide
- `FIREBASE_DOMAIN_MANAGEMENT.md` - Add/update domains
- `FIREBASE_INTEGRATION_SUMMARY.md` - Complete overview

---

## 🚀 Next Steps After Testing

1. Add more phishing domains (100+)
2. Test with real-world scenarios
3. Update security rules before Play Store
4. Monitor Firebase Console
5. Expand database with public API data
6. Deploy to Play Store

---

**Ready? Start with PHASE 1 above! 🚀**

**Questions? Check `FIREBASE_QUICK_START.md` for quick answers!**
