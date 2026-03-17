# URL Security Implementation - Quick Reference Guide

## Quick Integration Checklist

### Step 1: Add Dependencies to build.gradle.kts

```kotlin
dependencies {
    // HTTP Client
    implementation("com.squareup.okhttp3:okhttp:5.3.0")
    
    // Google Play Services
    implementation("com.google.android.gms:play-services-safetynet:18.1.0")
    
    // Retrofit for API calls
    implementation("com.squareup.retrofit2:retrofit:2.10.0")
    implementation("com.squareup.retrofit2:converter-gson:2.10.0")
    
    // Coroutines
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")
    
    // WorkManager for background tasks
    implementation("androidx.work:work-runtime-ktx:2.8.1")
    
    // Room for caching
    implementation("androidx.room:room-runtime:2.6.1")
    kapt("androidx.room:room-compiler:2.6.1")
    
    // Gson for JSON parsing
    implementation("com.google.code.gson:gson:2.10.1")
}
```

---

## Check Execution Times & Network Requirements

```
┌─────────────────────────────┬────────┬─────────┬──────────────┐
│ Check Type                  │ Time   │ Network │ Failure Safe │
├─────────────────────────────┼────────┼─────────┼──────────────┤
│ 1. IP Detection             │ <1ms   │ No      │ Yes (local)  │
│ 2. URL Structure            │ 1-5ms  │ No      │ Yes (local)  │
│ 3. Homograph Detection      │ 1-3ms  │ No      │ Yes (local)  │
│ 4. Typosquatting           │ 5-20ms │ No      │ Yes (local)  │
├─────────────────────────────┼────────┼─────────┼──────────────┤
│ 5. SSL/TLS Cert Check      │ 500ms+ │ Yes     │ No (skip)    │
│ 6. Safe Browsing           │ 500ms+ │ Yes     │ No (skip)    │
├─────────────────────────────┼────────┼─────────┼──────────────┤
│ 7. Domain Age Check        │ 1-3s   │ Yes     │ No (skip)    │
│ 8. URLhaus Lookup          │ 1-3s   │ Yes     │ No (skip)    │
│ 9. PhishTank Lookup        │ 1-3s   │ Yes     │ No (skip)    │
└─────────────────────────────┴────────┴─────────┴──────────────┘

RECOMMENDED STRATEGY:
- Real-time UI: Only checks 1-4 (< 50ms total)
- Background: All checks when needed
- User Click: First run 1-4, then background run 5-9
```

---

## Database Schema for Caching

### Room Database Entity

```kotlin
import androidx.room.*

@Entity(tableName = "url_security_cache")
data class URLSecurityCacheEntity(
    @PrimaryKey(autoGenerate = true)
    val id: Int = 0,
    
    val urlHash: String,  // SHA-256 hash of URL
    val originalUrl: String,  // Only if safe to store
    val overallRisk: String,  // INFO, MEDIUM, HIGH, CRITICAL
    val isBlocked: Boolean,
    val checkResults: String,  // JSON serialized
    val timestamp: Long,
    val expiresAt: Long  // For TTL
)

@Dao
interface URLSecurityDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertCache(entity: URLSecurityCacheEntity)
    
    @Query("SELECT * FROM url_security_cache WHERE urlHash = :hash AND expiresAt > :now")
    suspend fun getCachedResult(hash: String, now: Long = System.currentTimeMillis()): URLSecurityCacheEntity?
    
    @Query("DELETE FROM url_security_cache WHERE expiresAt < :now")
    suspend fun deleteExpiredCache(now: Long = System.currentTimeMillis())
}

@Database(entities = [URLSecurityCacheEntity::class], version = 1)
abstract class URLSecurityDatabase : RoomDatabase() {
    abstract fun urlSecurityDao(): URLSecurityDao
    
    companion object {
        @Volatile
        private var INSTANCE: URLSecurityDatabase? = null
        
        fun getInstance(context: Context): URLSecurityDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    URLSecurityDatabase::class.java,
                    "url_security_db"
                ).build()
                INSTANCE = instance
                instance
            }
        }
    }
}
```

---

## Fast Checks Implementation (< 50ms)

```kotlin
object FastURLChecks {
    
    /**
     * Run all fast checks - should complete in < 50ms
     */
    fun runAllFastChecks(url: String): List<SecurityCheckResult> {
        val results = mutableListOf<SecurityCheckResult>()
        
        // 1. Check IP Address (< 1ms)
        results.add(checkIPAddress(url))
        
        // 2. Check URL Structure (< 5ms)
        results.add(analyzeURLStructure(url))
        
        // Extract host once for remaining checks
        val host = try {
            android.net.Uri.parse(url).host ?: ""
        } catch (e: Exception) {
            ""
        }
        
        if (host.isNotEmpty()) {
            // 3. Check Homograph Attack (< 3ms)
            results.add(detectHomographAttack(host))
            
            // 4. Check Typosquatting (< 20ms with local list)
            results.add(checkTyposquattingFast(host))
        }
        
        return results
    }
    
    private fun checkIPAddress(url: String): SecurityCheckResult {
        return try {
            val uri = android.net.Uri.parse(url)
            val host = uri.host ?: ""
            
            // IPv4 pattern
            val ipv4Pattern = """^(\d{1,3}\.){3}\d{1,3}$""".toRegex()
            if (ipv4Pattern.matches(host)) {
                val isValid = host.split(".").all { octet ->
                    (octet.toIntOrNull() ?: -1) in 0..255
                }
                if (isValid) {
                    return SecurityCheckResult(
                        passed = false,
                        severity = Severity.HIGH,
                        message = "URL uses IP address: $host",
                        checkType = "IP_ADDRESS_DETECTION"
                    )
                }
            }
            
            // IPv6 pattern
            if (host.contains(":") && host.count { it == ':' } >= 2) {
                return SecurityCheckResult(
                    passed = false,
                    severity = Severity.HIGH,
                    message = "URL uses IPv6 address",
                    checkType = "IP_ADDRESS_DETECTION"
                )
            }
            
            SecurityCheckResult(
                passed = true,
                severity = Severity.INFO,
                message = "URL uses domain name",
                checkType = "IP_ADDRESS_DETECTION"
            )
        } catch (e: Exception) {
            SecurityCheckResult(
                passed = false,
                severity = Severity.MEDIUM,
                message = "Error checking IP address: ${e.localizedMessage}",
                checkType = "IP_ADDRESS_DETECTION"
            )
        }
    }
    
    private fun analyzeURLStructure(url: String): SecurityCheckResult {
        return try {
            val uri = android.net.Uri.parse(url)
            val issues = mutableListOf<String>()
            
            if (uri.scheme == null) {
                issues.add("Missing scheme")
            } else if (uri.scheme !in listOf("http", "https", "ftp")) {
                issues.add("Unusual scheme: ${uri.scheme}")
            }
            
            if (uri.host == null || uri.host?.isEmpty() == true) {
                issues.add("Missing hostname")
            }
            
            if (url.contains("%") && uri.host?.contains("%") == true) {
                issues.add("URL encoding in hostname")
            }
            
            if (uri.userInfo != null) {
                issues.add("Credentials in URL")
            }
            
            if (url.length > 2048) {
                issues.add("URL too long (${url.length} chars)")
            }
            
            return if (issues.isEmpty()) {
                SecurityCheckResult(
                    passed = true,
                    severity = Severity.INFO,
                    message = "URL structure valid",
                    checkType = "URL_STRUCTURE_ANALYSIS"
                )
            } else {
                SecurityCheckResult(
                    passed = false,
                    severity = Severity.MEDIUM,
                    message = issues.joinToString("; "),
                    checkType = "URL_STRUCTURE_ANALYSIS"
                )
            }
        } catch (e: Exception) {
            SecurityCheckResult(
                passed = false,
                severity = Severity.MEDIUM,
                message = "Error analyzing structure: ${e.localizedMessage}",
                checkType = "URL_STRUCTURE_ANALYSIS"
            )
        }
    }
    
    private fun detectHomographAttack(domain: String): SecurityCheckResult {
        val domainLower = domain.lowercase()
        
        // Pattern for visually similar characters
        val patterns = mapOf(
            Regex("[0O]{2,}") to "Mixing 0 and O",
            Regex("[1lI]{2,}") to "Mixing 1, l, and I",
            Regex("[5S]{2,}") to "Mixing 5 and S",
            Regex("[8B]{2,}") to "Mixing 8 and B"
        )
        
        val found = patterns.entries.find { (pattern, _) ->
            pattern.containsMatchIn(domainLower)
        }
        
        return if (found != null) {
            SecurityCheckResult(
                passed = false,
                severity = Severity.MEDIUM,
                message = "Possible homograph attack: ${found.value}",
                checkType = "HOMOGRAPH_DETECTION"
            )
        } else {
            SecurityCheckResult(
                passed = true,
                severity = Severity.INFO,
                message = "No homograph patterns detected",
                checkType = "HOMOGRAPH_DETECTION"
            )
        }
    }
    
    private fun checkTyposquattingFast(domain: String): SecurityCheckResult {
        // Pre-built list of common legitimate domains
        val commonDomains = listOf(
            "google.com", "facebook.com", "instagram.com", "twitter.com", "youtube.com",
            "amazon.com", "ebay.com", "walmart.com", "apple.com", "microsoft.com",
            "github.com", "gitlab.com", "stackoverflow.com", "reddit.com", "wikipedia.org",
            "linkedin.com", "telegram.org", "whatsapp.com", "gmail.com", "outlook.com",
            "paypal.com", "stripe.com", "square.com", "coinbase.com", "kraken.com"
        )
        
        val domainLower = domain.lowercase()
        
        // Check for exact match first
        if (commonDomains.contains(domainLower)) {
            return SecurityCheckResult(
                passed = true,
                severity = Severity.INFO,
                message = "Known legitimate domain",
                checkType = "TYPOSQUATTING_DETECTION"
            )
        }
        
        // Check for suspicious variations
        val suspiciousPatterns = listOf(
            Regex("^g00gle\\..*") to "google typo",
            Regex("^fac3book\\..*") to "facebook typo",
            Regex("^amaz0n\\..*") to "amazon typo",
            Regex("^microsoift\\..*") to "microsoft typo",
            Regex(".*google-.*\\..*") to "google subdomain trick",
            Regex(".*paypal-.*\\..*") to "paypal subdomain trick"
        )
        
        val matched = suspiciousPatterns.find { (pattern, _) ->
            pattern.matches(domainLower)
        }
        
        return if (matched != null) {
            SecurityCheckResult(
                passed = false,
                severity = Severity.HIGH,
                message = "Likely typosquatting: ${matched.second}",
                checkType = "TYPOSQUATTING_DETECTION"
            )
        } else {
            SecurityCheckResult(
                passed = true,
                severity = Severity.INFO,
                message = "Domain doesn't match known typosquatting patterns",
                checkType = "TYPOSQUATTING_DETECTION"
            )
        }
    }
}
```

---

## Slow Checks Implementation (Network-Based)

```kotlin
class SlowURLChecks(private val context: Context) {
    
    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(Duration.ofSeconds(5))
        .readTimeout(Duration.ofSeconds(5))
        .connectionSpecs(listOf(ConnectionSpec.MODERN_TLS))
        .build()
    
    suspend fun checkSSLCertificate(url: String): SecurityCheckResult {
        return withContext(Dispatchers.IO) {
            try {
                val request = Request.Builder().url(url).head().build()
                val response = httpClient.newCall(request).execute()
                
                SecurityCheckResult(
                    passed = true,
                    severity = Severity.INFO,
                    message = "HTTPS connection successful",
                    checkType = "SSL_TLS_VALIDATION"
                )
            } catch (e: Exception) {
                SecurityCheckResult(
                    passed = false,
                    severity = Severity.HIGH,
                    message = "SSL/TLS error: ${e.localizedMessage}",
                    checkType = "SSL_TLS_VALIDATION"
                )
            }
        }
    }
    
    suspend fun checkGoogleSafeBrowsing(
        url: String,
        apiKey: String
    ): SecurityCheckResult {
        return withContext(Dispatchers.IO) {
            try {
                // Initialize if needed
                SafetyNet.getClient(context).initSafeBrowsing().await()
                
                val response = SafetyNet.getClient(context).lookupUri(
                    url,
                    apiKey,
                    SafeBrowsingThreat.TYPE_POTENTIALLY_HARMFUL_APPLICATION,
                    SafeBrowsingThreat.TYPE_SOCIAL_ENGINEERING
                ).await()
                
                if (response.detectedThreats.isEmpty()) {
                    SecurityCheckResult(
                        passed = true,
                        severity = Severity.INFO,
                        message = "Not found in Google Safe Browsing database",
                        checkType = "SAFE_BROWSING"
                    )
                } else {
                    val threats = response.detectedThreats.map { it.threatType }.joinToString(", ")
                    SecurityCheckResult(
                        passed = false,
                        severity = Severity.CRITICAL,
                        message = "Google Safe Browsing threat detected: $threats",
                        checkType = "SAFE_BROWSING"
                    )
                }
            } catch (e: Exception) {
                SecurityCheckResult(
                    passed = null,
                    severity = Severity.MEDIUM,
                    message = "Safe Browsing check unavailable: ${e.localizedMessage}",
                    checkType = "SAFE_BROWSING"
                )
            }
        }
    }
    
    suspend fun checkURLhaus(url: String): SecurityCheckResult {
        return withContext(Dispatchers.IO) {
            try {
                val requestBody = RequestBody.create(
                    "url=${URLEncoder.encode(url, "UTF-8")}&format=json",
                    "application/x-www-form-urlencoded".toMediaType()
                )
                
                val request = Request.Builder()
                    .url("https://urlhaus-api.abuse.ch/v1/url/")
                    .post(requestBody)
                    .build()
                
                val response = httpClient.newCall(request).execute()
                val body = response.body?.string() ?: return@withContext SecurityCheckResult(
                    passed = null,
                    severity = Severity.MEDIUM,
                    message = "Empty response from URLhaus",
                    checkType = "URLHAUS_CHECK"
                )
                
                val json = JSONObject(body)
                if (json.optString("query_status") == "ok") {
                    val results = json.optJSONArray("results")
                    if (results != null && results.length() > 0) {
                        val threat = results.getJSONObject(0).optString("threat", "unknown")
                        return@withContext SecurityCheckResult(
                            passed = false,
                            severity = Severity.CRITICAL,
                            message = "URLhaus malware: $threat",
                            checkType = "URLHAUS_CHECK"
                        )
                    }
                }
                
                SecurityCheckResult(
                    passed = true,
                    severity = Severity.INFO,
                    message = "Not found in URLhaus database",
                    checkType = "URLHAUS_CHECK"
                )
            } catch (e: Exception) {
                SecurityCheckResult(
                    passed = null,
                    severity = Severity.MEDIUM,
                    message = "URLhaus check failed: ${e.localizedMessage}",
                    checkType = "URLHAUS_CHECK"
                )
            }
        }
    }
}
```

---

## Activity Integration Example

```kotlin
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch

class URLSecurityCheckActivity : AppCompatActivity() {
    private lateinit var analyzer: URLSecurityAnalyzer
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        analyzer = URLSecurityAnalyzer(
            context = this,
            safeBrowsingApiKey = "YOUR_API_KEY",  // From Google Cloud Console
            phishTankApiKey = "YOUR_API_KEY"      // From PhishTank
        )
    }
    
    override fun onResume() {
        super.onResume()
        try {
            SafetyNet.getClient(this).initSafeBrowsing().await()
        } catch (e: Exception) {
            Log.e("SafeBrowsing", "Init failed", e)
        }
    }
    
    override fun onPause() {
        SafetyNet.getClient(this).shutdownSafeBrowsing()
        super.onPause()
    }
    
    fun onCheckURLClicked(url: String) {
        lifecycleScope.launch {
            // Step 1: Show loading indicator
            showLoadingIndicator(true)
            
            // Step 2: Run fast checks immediately (< 50ms)
            val fastChecks = FastURLChecks.runAllFastChecks(url)
            updateUIWithFastResults(fastChecks, url)
            
            // Determine if we should run slow checks
            val hasHighRisk = fastChecks.any { 
                it.severity in listOf(Severity.HIGH, Severity.CRITICAL) 
            }
            
            // Step 3: Run slow checks in background if high risk or user requested
            if (hasHighRisk) {
                val slowChecks = SlowURLChecks(this@URLSecurityCheckActivity)
                val slowResults = listOf(
                    slowChecks.checkGoogleSafeBrowsing(url, "YOUR_API_KEY"),
                    slowChecks.checkURLhaus(url)
                )
                
                val allResults = fastChecks + slowResults
                updateUIWithAllResults(allResults, url)
            }
            
            showLoadingIndicator(false)
        }
    }
    
    private fun updateUIWithFastResults(results: List<SecurityCheckResult>, url: String) {
        val overallRisk = determineOverallRisk(results)
        
        // Update UI
        when (overallRisk) {
            Severity.INFO -> showGreenWarning("URL appears safe", url)
            Severity.MEDIUM -> showYellowWarning("Caution: Check details", url)
            Severity.HIGH -> showRedWarning("Dangerous URL", url)
            Severity.CRITICAL -> showBlockedWarning("URL Blocked", url)
        }
    }
    
    private fun updateUIWithAllResults(results: List<SecurityCheckResult>, url: String) {
        val groupedResults = results.groupBy { it.severity }
        
        // Display detailed report
        // Implementation depends on UI design
    }
    
    private fun determineOverallRisk(results: List<SecurityCheckResult>): Severity {
        return when {
            results.any { it.severity == Severity.CRITICAL } -> Severity.CRITICAL
            results.any { it.severity == Severity.HIGH } -> Severity.HIGH
            results.any { it.severity == Severity.MEDIUM } -> Severity.MEDIUM
            else -> Severity.INFO
        }
    }
}
```

---

## Key Configuration Points

### 1. Environment File
```properties
# Create app/src/main/assets/security.properties
google.safe.browsing.api.key=YOUR_API_KEY_HERE
phishtank.api.key=YOUR_API_KEY_HERE
cache.ttl.hours=24
max.concurrent.checks=3
timeout.seconds=10
```

### 2. AndroidManifest.xml Permissions
```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
```

### 3. ProGuard/R8 Rules
```proguard
# OkHttp
-dontwarn okhttp3.**
-dontwarn okio.**
-keep class okhttp3.** { *; }

# Retrofit
-dontwarn retrofit2.**
-keep class retrofit2.** { *; }

# Google Play Services
-dontwarn com.google.android.gms.**
-keep class com.google.android.gms.** { *; }

# Gson
-keep class com.google.gson.** { *; }
```

---

## Testing Checklist

```
✓ Test with safe URLs (google.com, github.com)
✓ Test with IP addresses (192.168.1.1)
✓ Test with obviously malicious patterns
✓ Test with network disabled (should handle gracefully)
✓ Test caching behavior
✓ Test timeout scenarios
✓ Test with very long URLs
✓ Performance test: measure real-time UI response
✓ Test background checks with WorkManager
✓ Test database operations
✓ Test concurrent requests
✓ Test memory leaks with LeakCanary
```

---

## Debugging Commands

```bash
# View app security checks in logcat
adb logcat | grep "SecurityCheck"

# View network traffic
adb logcat | grep "OkHttp"

# Test specific URL locally
# Create a simple test app snippet
```

---

## Resources

- Google Safe Browsing: https://developers.google.com/safe-browsing/v4
- URLhaus API: https://urlhaus.abuse.ch/api/
- PhishTank API: https://www.phishtank.com/developer_info.php
- OkHttp: https://square.github.io/okhttp/
- Kotlin Coroutines: https://kotlinlang.org/docs/coroutines-overview.html
