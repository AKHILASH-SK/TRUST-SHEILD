# 🚀 TrustShield Frontend Integration Guide

## Overview

The Android app is now integrated with the Flask backend running on port 8000. This guide explains how to test the authentication flow on a real phone.

---

## ✅ What's Been Implemented

### 1. **Retrofit API Client**
- Location: `app/src/main/java/com/example/trustshield/network/`
- `TrustShieldApiService.kt` - API endpoint definitions
- `RetrofitClient.kt` - Retrofit singleton manager

### 2. **Data Models**
- Location: `app/src/main/java/com/example/trustshield/network/models/`
- `ApiModels.kt` - Request/Response data classes for all endpoints

### 3. **Updated LoginActivity**
- Uses backend API: `POST /api/auth/login`
- Replaces hardcoded Firebase with real database authentication
- Requires: **Phone number** + **PIN** (4-6 digits)
- Saves user data to SharedPreferences

### 4. **New RegistrationActivity**
- Uses backend API: `POST /api/auth/register`
- Registers new users with fields:
  - First Name
  - Last Name
  - Email
  - Phone Number
  - PIN (4-6 digits)
  - PIN Confirmation
- Email validation included
- Navigates back to login after successful registration

### 5. **Backend Config Manager**
- Location: `app/src/main/java/com/example/trustshield/config/BackendConfig.kt`
- Stores backend URL in SharedPreferences
- Can be updated runtime without recompile

---

## 🔧 Setup and Testing

### Step 1: Find Your Computer's IP Address

**On Windows PowerShell:**
```powershell
ipconfig
```

Look for "IPv4 Address" under your WiFi adapter.  
Example: `192.168.0.100`

### Step 2: Update Backend URL in App

Edit `RetrofitClient.kt` and change the default:

```kotlin
// Line ~74 in RetrofitClient.kt
fun getInstance(baseUrl: String = "http://192.168.0.100:8000"): RetrofitClient {
```

Replace `192.168.0.100` with your actual IP address.

**OR** (Better Way - No Recompile):
1. Run app on phone
2. LoginActivity appears
3. Backend URL stored in SharedPreferences: `http://192.168.0.100:8000`

### Step 3: Verify Backend is Running

Before testing, ensure Flask backend is running:

```bash
cd c:\Users\akhil\AndroidStudioProjects\TrustShield\backend
python app.py
```

You should see:
```
🔌 Connecting to database: localhost:5432/trustshield_db
 * Running on http://0.0.0.0:8000
```

### Step 4: Connect Phone to Same WiFi

- Phone and computer must be on the **same WiFi network**
- Verify phone can ping your computer's IP (use ping app on Android)

### Step 5: Build and Deploy to Phone

```bash
# In project root
./gradlew installDebug
# Or in Android Studio: Run > Run 'app'
```

---

## 📱 Test Registration Flow

### Step 1: Register New User

1. App shows **LoginActivity**
2. Click **"Register"** button
3. Enter:
   - First Name: `Akhil`
   - Last Name: `Sharma`
   - Email: `akhil@gmail.com`
   - Phone: `9876543210`
   - PIN: `1234`
   - Confirm PIN: `1234`
4. Click **"Register"**

### Expected Result:
```
✅ Toast: "Registration successful! Please login with your phone and PIN"
✅ Navigate back to LoginActivity
✅ Data saved in PostgreSQL:
   SELECT * FROM users;
   | id | name | email | phone_number |
   | 1  |Akhil |akhil@|9876543210   |
```

---

## 📱 Test Login Flow

### Step 1: Login with Registered Credentials

1. **LoginActivity** shows
2. Enter:
   - Phone: `9876543210`
   - PIN: `1234`
3. Click **"Login"**

### Expected Result:
```
✅ Toast: "Login successful! Welcome Akhil"
✅ Navigate to HomeActivity
✅ User data saved to SharedPreferences
✅ Backend logs: "GET / HTTP/1.1" 200 OK
```

---

## 🔗 API Endpoints Called

### Registration
```http
POST http://192.168.0.100:8000/api/auth/register
Content-Type: application/json

{
  "name": "Akhil",
  "last_name": "Sharma",
  "email": "akhil@gmail.com",
  "phone_number": "9876543210",
  "pin": "1234"
}
```

**Response (201 Created):**
```json
{
  "id": 1,
  "name": "Akhil",
  "email": "akhil@gmail.com",
  "phone_number": "9876543210",
  "created_at": "2026-03-22T12:40:19"
}
```

### Login
```http
POST http://192.168.0.100:8000/api/auth/login
Content-Type: application/json

{
  "phone_number": "9876543210",
  "pin": "1234"
}
```

**Response (200 OK):**
```json
{
  "id": 1,
  "name": "Akhil",
  "email": "akhil@gmail.com",
  "phone_number": "9876543210",
  "message": "Login successful"
}
```

---

## ❌ Error Messages

| Scenario | Error | Solution |
|----------|-------|----------|
| Can't reach backend | `Network error: Connection refused` | Verify backend is running, IP is correct, phone on same WiFi |
| Wrong PIN | `Invalid phone number or PIN` | Check PIN is exactly 4-6 digits |
| Email exists | `Email or phone number already registered` | Use different email/phone |
| No network | `Network error: Address unreachable` | Connect to WiFi |
| Layout issues | `Views not found in layout` | Check activity_login.xml exists with correct IDs |

---

## 🧪 Verify Backend Database

### Check if User Registered:

```bash
psql -U postgres -d trustshield_db -c "SELECT id, name, email, phone_number FROM users;"
```

Expected output:
```
 id | name  | email           | phone_number
----+-------+-----------------+--------------
  1 | Akhil | akhil@gmail.com | 9876543210
```

### Check Link Scans (Later):

```bash
psql -U postgres -d trustshield_db -c "SELECT * FROM link_scans WHERE user_id = 1;"
```

---

## 📝 Backend Configuration

### View Backend IP Settings:

```kotlin
// In RetrofitClient.kt (Line ~74)
fun getInstance(baseUrl: String = "http://192.168.0.100:8000"): RetrofitClient
```

### Change Backend URL at Runtime:

```kotlin
// In any Activity
BackendConfig.setBackendUrl(this, "http://192.168.0.123:8000")
RetrofitClient.reset()
val apiService = RetrofitClient.getInstance().getApiService()
```

---

## 🐛 Debug Logging

### Enable HTTP Logging:

All HTTP requests/responses are logged via OkHttp:

```
adb logcat | grep -i "HTTP"
```

You'll see:
```
D/OkHttp: --> POST /api/auth/login
D/OkHttp: {"phone_number":"9876543210","pin":"1234"}
D/OkHttp: <-- 200 OK (123ms)
D/OkHttp: {"id":1,"name":"Akhil",...}
```

### Enable App Logging:

```bash
adb logcat | grep "LoginActivity\|Registration"
```

---

## 📋 Checklist for Testing

- [ ] Backend running on port 8000
- [ ] Computer IP address identified (ipconfig)
- [ ] Phone connected to same WiFi
- [ ] App APK built and installed
- [ ] RetrofitClient.kt updated with correct IP
- [ ] Register new user with unique email
- [ ] Verify user data in PostgreSQL
- [ ] Login with registered credentials
- [ ] User navigates to HomeActivity
- [ ] No network errors in logcat

---

## 🚀 Next Steps (After Testing)

1. **Link Scanning Integration**
   - When NotificationListener detects a link
   - Call `POST /api/links/scan` to save to database

2. **Scan History Screen**
   - Create new Activity to display scan history
   - Call `GET /api/links/history/{user_id}`

3. **Tier 3 Integration**
   - Integrate VirusTotal or similar for unknown links
   - Update backend `/api/links/scan` endpoint

---

## 💡 Tips

- **Test Registration First**: Creates database record you can verify
- **Check SharedPreferences**: User ID and phone number saved for later use
- **Monitor Backend Logs**: Flask prints all requests: `127.0.0.1 - - [date] "POST /api/auth/login"...`
- **Use Postman/cURL**: Test API directly before using in app

---

**Status**: ✅ Frontend integration complete, ready for real phone testing!
