# URL Security - Cheat Sheet

## Regex Patterns - Copy & Paste Ready

### Basic URL Extraction (Recommended)
```regex
(?:(?:https?|ftp)://)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+(?::\d{1,5})?(?:/[^\s]*)?
```

### HTTPS Only
```regex
https://[^\s]+
```

### With Context
```regex
\b(?:(?:https?|ftp)://)?(?:www\.)?[a-zA-Z0-9][-a-zA-Z0-9]*[a-zA-Z0-9]\.(?:[a-zA-Z0-9][-a-zA-Z0-9]*[a-zA-Z0-9]\.)*[a-zA-Z]{2,}(?:[/?#][^\s]*)?\b
```

---

## Gradle Dependencies - Copy & Paste Ready

```gradle
dependencies {
    // HTTP & Network
    implementation("com.squareup.okhttp3:okhttp:5.3.0")
    implementation("com.squareup.okhttp3:logging-interceptor:5.3.0")
    
    // APIs & REST
    implementation("com.squareup.retrofit2:retrofit:2.10.0")
    implementation("com.squareup.retrofit2:converter-gson:2.10.0")
    
    // Google Services
    implementation("com.google.android.gms:play-services-safetynet:18.1.0")
    
    // Async & Coroutines
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")
    
    // Local Storage & Caching
    implementation("androidx.room:room-runtime:2.6.1")
    implementation("androidx.room:room-ktx:2.6.1")
    kapt("androidx.room:room-compiler:2.6.1")
    
    // Background Tasks
    implementation("androidx.work:work-runtime-ktx:2.8.1")
    
    // JSON
    implementation("com.google.code.gson:gson:2.10.1")
    
    // Enhanced TLS (Optional)
    implementation("org.conscrypt:conscrypt-android:2.5.2")
}
```

---

## Key Classes & Enums

```kotlin
enum class Severity { INFO, MEDIUM, HIGH, CRITICAL }

data class SecurityCheckResult(
    val passed: Boolean?,
    val severity: Severity,
    val message: String,
    val checkType: String = "Unknown"
)

data class URLSecurityReport(
    val url: String,
    val overallRisk: Severity,
    val checks: List<SecurityCheckResult>,
    val isBlocked: Boolean = false,
    val timestamp: Long = System.currentTimeMillis()
)
```

---

## Fast Checks - 4 Lines Each

### 1. IP Address Detection
```kotlin
val ipv4Pattern = """^(\d{1,3}\.){3}\d{1,3}$""".toRegex()
val host = Uri.parse(url).host ?: ""
val isIP = ipv4Pattern.matches(host) && host.split(".").all { (it.toIntOrNull() ?: -1) in 0..255 }
// If isIP: Severity.HIGH, else: Severity.INFO
```

### 2. Homograph Detection
```kotlin
val patterns = listOf(Regex("[0O]{2,}"), Regex("[1lI]{2,}"), Regex("[5S]{2,}"))
val domain = Uri.parse(url).host?.lowercase() ?: ""
val hasHomograph = patterns.any { it.containsMatchIn(domain) }
// If hasHomograph: Severity.MEDIUM, else: Severity.INFO
```

### 3. URL Structure
```kotlin
val uri = Uri.parse(url)
val hasIssues = uri.scheme == null || uri.host == null || url.length > 2048
val hasEmbeddedCreds = uri.userInfo != null
// If issues: Severity.MEDIUM, else: Severity.INFO
```

### 4. Typosquatting
```kotlin
val commonDomains = listOf("google.com", "facebook.com", "amazon.com")
val domain = Uri.parse(url).host?.lowercase() ?: ""
val isSuspicious = domain.matches(Regex("^g00gle\\..*|^amaz0n\\..*"))
// If suspicious: Severity.HIGH, else: Severity.INFO
```

---

## Android Manifest Additions

```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
```

---

## ProGuard Rules

```proguard
-dontwarn okhttp3.**
-dontwarn okio.**
-keep class okhttp3.** { *; }
-keep class com.google.android.gms.** { *; }
-keep class retrofit2.** { *; }
-keep class com.google.gson.** { *; }
```

---

## Quick Integration Steps

### Step 1: Initialize in Activity
```kotlin
override fun onResume() {
    super.onResume()
    SafetyNet.getClient(this).initSafeBrowsing().await()
}

override fun onPause() {
    SafetyNet.getClient(this).shutdownSafeBrowsing()
    super.onPause()
}
```

### Step 2: Check URL
```kotlin
lifecycleScope.launch {
    val results = FastURLChecks.runAllFastChecks(url)
    displayResults(results)
    
    // Optional: Run slow checks
    if (results.any { it.severity >= Severity.HIGH }) {
        val slowResults = SlowURLChecks(this@Activity).runSlowChecks(url)
        displayResults(slowResults)
    }
}
```

### Step 3: Display Results
```kotlin
val overallRisk = results.maxByOrNull { it.severity }?.severity ?: Severity.INFO
when (overallRisk) {
    Severity.CRITICAL -> showBlockWarning()
    Severity.HIGH -> showRedWarning()
    Severity.MEDIUM -> showYellowWarning()
    Severity.INFO -> showGreenCheckmark()
}
```

---

## API Key Setup (5 Minutes Each)

### Google Safe Browsing
1. https://console.cloud.google.com
2. Create project
3. Enable "Safe Browsing API"
4. Create Android API key
5. Restrict to Android app

### PhishTank (Optional)
1. https://www.phishtank.com/developer_info.php
2. Register email
3. Verify email
4. Copy API key from profile

### URLhaus (No Key Needed)
- Use directly: https://urlhaus-api.abuse.ch/v1/url/
- POST request with `url=` parameter
- Response is JSON

---

## Performance Targets

```
Fast Checks:
├─ IP Detection: < 1ms
├─ URL Structure: < 5ms
├─ Homograph: < 3ms
├─ Typosquatting: < 20ms
└─ TOTAL: < 50ms ✓

Online Checks:
├─ Safe Browsing: 300-500ms ✓
├─ SSL/TLS: 400-800ms
└─ URLhaus: 800-1200ms

Cache Hit: < 10ms ✓
Memory Impact: 7-8 MB ✓
Battery Impact: Negligible ✓
```

---

## Test URLs

### Safe URLs
```
https://www.google.com
https://www.github.com
https://www.amazon.com
https://www.wikipedia.org
https://www.stackoverflow.com
```

### Suspicious (Local Detection)
```
http://192.168.1.1/admin
http://g00gle.com
http://amaz0n.com
http://1234567890.12345 (IP-like)
```

### Known Threats (Requires API)
```
(Cannot share real phishing URLs for safety)
Test with Safe Browsing test URLs:
https://testsafebrowsing.appspot.com/s/phishing.html
```

---

## Common Issues & Fixes

| Issue | Solution |
|-------|----------|
| SafetyNet crashes | Initialize in onResume(), shutdown in onPause() |
| API always times out | Check network, increase timeout to 10s |
| High memory usage | Check for OkHttpClient duplicate instances |
| API rate limit hit | Implement exponential backoff + caching |
| False positives | Adjust pattern thresholds, add whitelist |
| Slow startup | Move slow checks to background thread |
| Database locked | Use Room with proper async operations |
| Crashes on older API | Check minSdkVersion compatibility |

---

## Decision Tree (60 Seconds)

```
Is URL CRITICAL to check immediately?
  ├─ YES → Run Fast Checks only (< 50ms)
  └─ NO  → Queue background slow checks

Do you have network?
  ├─ YES → Run online checks (Google Safe Browsing)
  └─ NO  → Use cache or fast checks only

Is threat level HIGH?
  ├─ YES → Check URLhaus too (malware)
  └─ NO  → Single check sufficient

Is this a known URL in cache?
  ├─ YES → Return cached result (< 10ms)
  └─ NO  → Run full check suite

Final Decision:
  ├─ CRITICAL (flagged by API) → BLOCK
  ├─ HIGH (IP + structure issues) → WARN + ALLOW
  ├─ MEDIUM (homograph detected) → WARN + ALLOW
  └─ INFO (all clear) → ALLOW
```

---

## Memory-Efficient Caching

```kotlin
// Cache only URL hash, not full URL
val urlHash = url.sha256() // From androidx.security
cache[urlHash] = SecurityCheckResult

// Set TTL to 24 hours
val expiresAt = System.currentTimeMillis() + 24 * 60 * 60 * 1000

// Limit cache size
val maxCacheSize = 500 // URLs
if (cache.size > maxCacheSize) {
    cache.remove(cache.keys.first())
}
```

---

## Async Pattern (Coroutines)

```kotlin
lifecycleScope.launch {
    // Run on main thread
    showLoading(true)
    
    // Switch to IO thread
    withContext(Dispatchers.IO) {
        val result = SlowURLChecks(context).checkURL(url)
        
        // Back to main thread
        withContext(Dispatchers.Main) {
            showLoading(false)
            displayResult(result)
        }
    }
}
```

---

## Key Configuration Values

```kotlin
// Timeouts
const val FAST_CHECK_TIMEOUT_MS = 100
const val SLOW_CHECK_TIMEOUT_MS = 5000
const val API_TIMEOUT_SECONDS = 5

// Cache
const val CACHE_TTL_HOURS = 24
const val MAX_CACHE_ENTRIES = 500

// Thresholds
const val LEVENSHTEIN_DISTANCE_THRESHOLD = 2
const val DOMAIN_AGE_THRESHOLD_DAYS = 30
const val MAX_URL_LENGTH = 2048

// Concurrency
const val MAX_CONCURRENT_CHECKS = 3
const val THREAD_POOL_SIZE = 4
```

---

## Logging Setup

```kotlin
// Add to OkHttp for debugging
val loggingInterceptor = HttpLoggingInterceptor()
    .setLevel(if (BuildConfig.DEBUG) HttpLoggingInterceptor.Level.BODY else HttpLoggingInterceptor.Level.NONE)

val client = OkHttpClient.Builder()
    .addInterceptor(loggingInterceptor)
    .build()

// Log security checks
Log.d("SecurityCheck", "Check: $checkType, Result: $passed, Severity: $severity")

// Structured logging
data class SecurityCheckLog(
    val checkType: String,
    val url: String, // HASH ONLY in production
    val passed: Boolean,
    val severity: String,
    val durationMs: Long,
    val timestamp: Long = System.currentTimeMillis()
)
```

---

## Production Checklist

```
BEFORE RELEASE:
□ All 4 fast checks implemented
□ Google Safe Browsing integrated
□ Caching working (24h TTL)
□ Database schema tested
□ Network errors handled gracefully
□ Timeouts set (5s max)
□ ProGuard rules configured
□ API keys secured (not in source)
□ Permissions in manifest
□ Tested without network
□ Performance profiled (< 100ms UI)
□ Memory leak check with LeakCanary
□ Crash reporting enabled
□ Analytics/logging configured
□ User messaging clear
□ Dark mode tested
□ Accessibility reviewed
```

---

## Quick Command Reference

```bash
# Test current network latency
adb shell ping -c 3 8.8.8.8

# View app logs
adb logcat | grep "SecurityCheck"

# Profile memory
adb shell dumpsys meminfo | grep TOTAL

# Check network state
adb shell settings get global airplane_mode_on

# Clear app cache
adb shell pm clear com.your.app

# View database
adb shell sqlite3 /data/data/com.your.app/databases/url_security_db
```

---

## Reference Links (Bookmark These)

- Google Safe Browsing Docs: https://developers.google.com/safe-browsing/v4
- OkHttp: https://square.github.io/okhttp/
- Android Uri: https://developer.android.com/reference/android/net/Uri
- Room Database: https://developer.android.com/training/data-storage/room
- Kotlin Coroutines: https://kotlinlang.org/docs/coroutines-overview.html
- URLhaus API: https://urlhaus.abuse.ch/api/
- PhishTank API: https://www.phishtank.com/developer_info.php

---

## Size Summary

```
Implementation Effort:
├─ Fast checks only: 2-3 hours
├─ + Google Safe Browsing: 4-5 hours
├─ + Caching & DB: 6-7 hours
└─ Complete solution: 8-12 hours

Code Size:
├─ Fast checks: ~300 lines
├─ Slow checks: ~400 lines
├─ UI integration: ~200 lines
└─ Database: ~150 lines
└─ TOTAL: ~1000 lines Kotlin

Binary Impact:
├─ OkHttp: ~800 KB
├─ Retrofit: ~200 KB
├─ SafetyNet: ~300 KB
├─ Room: ~200 KB
└─ TOTAL: ~1.5 MB (after ProGuard)
```

---

**Last Updated: January 28, 2026**
**Quick Reference Version: v1.0**
