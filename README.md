# TrustShield 🛡️

TrustShield is a real-time intelligent security application designed exclusively to protect users from malicious phishing links before any damage occurs.

## 🎣 The Threat
Cybercriminals use sophisticated phishing links sent via SMS, WhatsApp, and other messaging apps to steal sensitive data (passwords, banking details, personal information). Often, users don't realize it's a scam until they've already clicked the link and the damage is done.

## 🛡️ Our Solution: Zero-Click Prevention
TrustShield protects users by intercepting and analyzing links directly from device notifications **before** the user even clicks them. When a message containing a link is received, TrustShield silently extracts it, runs a comprehensive security check, and alerts the user immediately if it is a threat.

## ⚙️ How It Works (The Architecture)

Our threat-detection pipeline consists of 4 main stages:

1. **Notification Interception**: The app securely extracts URLs from incoming notifications (WhatsApp, SMS, etc.).
2. **Rule-Based Fast Check**: The link is instantly analyzed on-device for obvious red flags like typosquatting or homograph attacks.
3. **Phishing Domain DB Check**: The URL is cross-referenced against our **Firebase Realtime Database** (`phishing_db`), which contains a hardcoded list of known scam and phishing links.
4. **Sandbox Analysis & VirusTotal API**: If a link is unknown, it requires deeper analysis. While our custom ML classification model and automated DB updaters are currently in development, we have integrated the **VirusTotal API** as our final classification layer. This ensures that the app can still catch sophisticated, zero-day attacks in real-time and deliver an accurate final verdict to the user.

```mermaid
graph TD
    A[User Receives Message] -->|Notification Listener| B(Link Extractor)
    B --> C{1. Rule-Based Check}
    C --> D{2. Firebase DB Check}
    D -->|Found in DB| E[Block & Alert User]
    D -->|Not in DB| F{3. Sandbox / VirusTotal API}
    
    F -->|Malicious| E
    F -->|Safe| G[Allow Link / Safe Verdict]
```

## 🧪 Testing Guide for Hackathon Judges

To easily test TrustShield's capabilities, we have seeded our Firebase database with known scam links. 

**How to test the Phishing DB:**
1. Install the app and grant the necessary Notification access permissions.
2. Send the following message to the device (via SMS, WhatsApp, or any messenger):
   👉 `https://paypal-security-verify.com/confirm-account`
3. TrustShield will instantly intercept the notification and flag it as a severe phishing attempt because it matches a known threat in our database.

**How to test the API fallback:**
1. Send a real, legitimate link (e.g., `https://google.com` or `https://github.com`) to the device.
2. TrustShield will analyze it, realize it is not in the malicious database, check it against the external APIs, and return a "Safe" verdict.

---

## 📥 Download the App

You can download the latest pre-compiled APK file directly to try out TrustShield on your Android device:

**[Download TrustShield APK](https://github.com/AKHILASH-SK/TRUST-SHEILD/raw/master/apk/TrustShield-debug.apk)**

*(Note: You may need to enable "Install from unknown sources" on your Android device to install the APK.)*

---

## 💻 How to Run the Frontend Locally

If you want to clone the repository and run the Android app yourself, follow these steps:

### 1. Clone the Repository
```bash
git clone https://github.com/AKHILASH-SK/TRUST-SHEILD.git
cd TRUST-SHEILD
```

### 2. Open in Android Studio
1. Launch **Android Studio**.
2. Select **Open** and choose the `TRUST-SHEILD` folder you just cloned.
3. Wait for the initial Gradle sync to complete.

### 3. Build and Run
1. Connect your Android device via USB (ensure USB Debugging is enabled) or start an Android Emulator.
2. In Android Studio, click the green **Play** button (Run 'app') in the top toolbar.
3. Alternatively, you can install it via the terminal:
```bash
.\gradlew installDebug
```
