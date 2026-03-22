# BACKEND SETUP GUIDE

## ✅ What I've Created

```
backend/
├── main.py           ← FastAPI application with endpoints
├── database.py       ← PostgreSQL connection
├── models.py         ← SQLAlchemy models (User, LinkScan)
├── schemas.py        ← Pydantic validation models
├── requirements.txt  ← Python dependencies
├── .env             ← Configuration file
└── README.md        ← Documentation
```

---

## 📋 STEP-BY-STEP SETUP

### **Step 1: Update `.env` File**

Edit `backend\.env` and replace `your_password`:

```
DB_USER=postgres
DB_PASSWORD=YOUR_POSTGRES_PASSWORD  ← Change this!
DB_HOST=localhost
DB_PORT=5432
DB_NAME=trustshield_db
SERVER_HOST=0.0.0.0
SERVER_PORT=8000
```

---

### **Step 2: Install Python Dependencies**

Open PowerShell in the `backend` folder:

```powershell
cd c:\Users\akhil\AndroidStudioProjects\TrustShield\backend
pip install -r requirements.txt
```

**Expected output:**
```
Successfully installed fastapi uvicorn sqlalchemy psycopg2-binary pydantic python-dotenv bcrypt
```

---

### **Step 3: Run the Backend Server**

```powershell
python main.py
```

**Expected output:**
```
🔌 Connecting to database: localhost:5432/trustshield_db
INFO:     Uvicorn running on http://0.0.0.0:8000
INFO:     Application startup complete
```

---

### **Step 4: Test the API**

Visit: **http://localhost:8000/docs**

You should see the **Swagger UI** with all endpoints listed.

**Try registering a test user:**
1. Click on **POST /api/auth/register**
2. Click **"Try it out"**
3. Enter this JSON:
```json
{
  "name": "Test",
  "last_name": "User",
  "email": "test@example.com",
  "phone_number": "+919876543210",
  "pin": "1234"
}
```
4. Click **Execute**
5. You should get response: `"id": 1, "name": "Test"`

---

### **Step 5: Test Login**

1. Click **POST /api/auth/login**
2. Enter:
```json
{
  "phone_number": "+919876543210",
  "pin": "1234"
}
```
3. Should return: `"message": "Login successful"`

---

## 🚀 BACKEND IS NOW RUNNING!

**Server URL:** `http://localhost:8000`

---

## 📱 NEXT: Update Android App

I'll create Kotlin code to:
1. ✅ Add Registration Screen
2. ✅ Update Login Screen (phone + PIN)
3. ✅ Connect to FastAPI backend
4. ✅ Save/retrieve user data

Ready? Let me know when backend is running! 👍
