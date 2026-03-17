# Firebase Phishing Database Setup - Complete Guide

## ✅ Step 1: Create Firebase Project (5 minutes)

### 1.1 Go to Firebase Console
- Open: https://console.firebase.google.com
- Click "Create a new project"

### 1.2 Create Project
- **Project name:** `TrustShield`
- Click **Continue**

### 1.3 Enable Google Analytics
- Select: **"Enable Google Analytics for this project"**
- Click **Continue**

### 1.4 Configure Analytics
- Choose: **Default Account for Firebase**
- Click **Create project**

Wait for it to finish (1-2 minutes)...

---

## ✅ Step 2: Create Database (3 minutes)

### 2.1 Go to Realtime Database
In Firebase console, left sidebar:
- Click **Build** → **Realtime Database**

### 2.2 Create Database
- Click **Create Database**
- Location: **us-central1** (default)
- Security Rules: **Start in test mode**
- Click **Enable**

✅ Database created! You'll see a URL like:
```
https://trustshield-abc123.firebaseio.com
```

**Copy this URL and save it** (you'll need it later)

---

## ✅ Step 3: Add Phishing Domains Data (2 minutes)

### 3.1 Add Structure in Database
In Realtime Database, you'll see:
```
trustshield-abc123 (root)
```

### 3.2 Click the Root Node
- Click the **+** icon next to the project name
- **Key:** `phishing_domains`
- Click **Add**

### 3.3 Add Dangerous Domains
- Click the **+** icon next to `phishing_domains`
- **Key:** `dangerous`
- Click **Add**

Now you have:
```
phishing_domains
└── dangerous
```

### 3.4 Add Domain List
- Click the **+** icon next to `dangerous`
- **Key:** `0` (for first domain)
- **Value:** `paypal-confirm.com`
- Click **Add**

- Click the **+** icon next to `dangerous` again
- **Key:** `1`
- **Value:** `verify-account.com`
- Click **Add**

**Add these domains:**
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

### Result:
```
phishing_domains
└── dangerous
    ├── 0: paypal-confirm.com
    ├── 1: verify-account.com
    ├── 2: secure-login-amazon.com
    └── ... more domains
```

---

## ✅ Step 4: Update Android Project (5 minutes)

### 4.1 Add Firebase Dependencies
Open `app/build.gradle.kts` and add after the existing dependencies:

```kotlin
// Firebase
implementation(platform("com.google.firebase:firebase-bom:33.0.0"))
implementation("com.google.firebase:firebase-database-ktx")
```

### 4.2 Add Google Services Plugin
At the top of `app/build.gradle.kts`, add:

```kotlin
plugins {
    // ... existing plugins
    id("com.google.gms.google-services")
}
```

### 4.3 Update Root build.gradle.kts
Open `build.gradle.kts` (root level) and add to plugins section:

```kotlin
plugins {
    // ... existing plugins
    id("com.google.gms.google-services") version "4.4.0" apply false
}
```

---

## ✅ Step 5: Download Google Services File (3 minutes)

### 5.1 Get Firebase Config
In Firebase console:
1. Click **⚙️ Project Settings** (top left)
2. Go to **General** tab
3. Scroll down to **Your apps** section
4. Click **Android app** (or add if not there)

### 5.2 Get Configuration File
1. Fill in app details:
   - **Package name:** `com.example.trustshield`
   - **App nickname:** `TrustShield`
2. Click **Register app**
3. Click **Download google-services.json**
4. Click **Next** (skip other steps)

### 5.3 Add to Android Project
Move the downloaded `google-services.json` to:
```
app/google-services.json
```

**Important:** Make sure it's in the `app/` folder, not the root

---

## ✅ Step 6: Update PhishingDomainChecker.kt

Replace your current `PhishingDomainChecker.kt` with Firebase version (I'll create this).

The code will:
- ✅ Read domains from Firebase
- ✅ Cache data locally (works offline)
- ✅ Check domains in real-time
- ✅ Show alerts instantly

---

## ✅ Step 7: Sync & Build

```bash
cd c:\Users\akhil\AndroidStudioProjects\TrustShield

# Sync gradle
./gradlew --sync

# Build
./gradlew assembleDebug -x lintVitalRelease

# Install on device
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

---

## ✅ Step 8: Test

Send a WhatsApp message with:
```
Check this: paypal-confirm.com
```

Expected result:
- 🔴 Red alert notification appears
- Message: "Dangerous phishing domain detected"

---

## 🔐 Security Rules (Important!)

### Current (Test Mode)
When you created the database, it's in **test mode** which means:
- Anyone can read/write
- Only for development

### Before Publishing to Play Store
Change security rules to:

Go to **Realtime Database** → **Rules** tab and paste:

```json
{
  "rules": {
    "phishing_domains": {
      ".read": true,
      ".write": false
    }
  }
}
```

This means:
- ✅ Anyone can READ domains (app checks them)
- ❌ Nobody can WRITE (only you in Firebase console)
- Keeps data safe

---

## 📝 Summary of Files

```
TrustShield/
├── app/
│   ├── build.gradle.kts (UPDATED - added Firebase)
│   ├── google-services.json (NEW - download from Firebase)
│   └── src/main/java/com/example/trustshield/
│       ├── PhishingDomainChecker.kt (UPDATED - uses Firebase)
│       └── ...
│
├── build.gradle.kts (UPDATED - added Google Services)
└── FIREBASE_SETUP.md (this file)
```

---

## ✅ Setup Complete!

Once you complete these 8 steps:
1. ✅ Your app reads phishing domains from Firebase
2. ✅ Works offline (caches locally)
3. ✅ Shows alerts for dangerous domains
4. ✅ Easy to add/update domains anytime

**Next:** See `FIREBASE_DOMAIN_MANAGEMENT.md` to learn how to add/update domains
