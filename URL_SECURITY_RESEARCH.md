# URL Security Analysis Research & Implementation Guide

## Table of Contents
1. [Link Extraction from Text](#link-extraction-from-text)
2. [Rule-Based Security Checks](#rule-based-security-checks)
3. [Android Implementation](#android-implementation)
4. [Performance Considerations](#performance-considerations)
5. [Popular Android Libraries](#popular-android-libraries)
6. [Code Examples](#code-examples)

---

## Link Extraction from Text

### Regex Patterns for URL Detection

#### Basic URL Pattern (Most Common)
```regex
https?://[^\s]+
```
- Matches HTTP/HTTPS URLs
- Stops at whitespace
- Simple but may include trailing punctuation

#### RFC 3986 Compliant Pattern
```regex
(?:https?|ftp)://(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?::\d+)?(?:/[^\s]*)?
```
- Follows RFC 3986 standard
- More robust domain validation
- Handles ports and paths

#### Android-Specific Pattern (Recommended)
```regex
(?:(?:https?|ftp)://)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+(?::\d{1,5})?(?:/[^\s]*)?
```
- Detects URLs with or without scheme
- Validates TLD (top-level domain)
- More portable across Android versions

#### URL in Text with Context Awareness
```regex
\b(?:(?:https?|ftp)://)?(?:www\.)?(?:[a-zA-Z0-9][-a-zA-Z0-9]*[a-zA-Z0-9]\.)+[a-zA-Z]{2,}(?:\.[a-zA-Z]{2})?(?:[/?#][^\s]*)?\b
```
- Includes www prefix detection
- Word boundary awareness
- Better context matching

### Kotlin Implementation for Link Extraction
```kotlin
fun extractUrls(text: String): List<String> {
    val urlPattern = """(?:(?:https?|ftp)://)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+(?::\d{1,5})?(?:/[^\s]*)?\b""".toRegex()
    return urlPattern.findAll(text).map { it.value }.toList()
}

fun extractUrlsWithScheme(text: String): List<String> {
    val schemePattern = """(?:https?|ftp)://[^\s]+(?=\s|$)""".toRegex()
    return schemePattern.findAll(text).map { it.value }.toList()
}

// Normalize URLs for processing
fun normalizeUrl(url: String): String {
    return try {
        var normalized = url.trim()
        if (!normalized.startsWith("http://") && !normalized.startsWith("https://") && 
            !normalized.startsWith("ftp://")) {
            normalized = "https://$normalized"
        }
        normalized
    } catch (e: Exception) {
        url
    }
}
```

---

## Rule-Based Security Checks

### 1. IP Address Detection (FAST CHECK)
**Why Important**: Phishing sites often use IP addresses instead of domains to avoid SSL certificate requirements.

**Red Flags**:
- IPv4 address as host (e.g., `http://192.168.1.1`)
- IPv6 address format
- Numeric-only hostname

```kotlin
fun isIPAddress(host: String?): Boolean {
    if (host == null) return false
    
    // IPv4 check
    val ipv4Pattern = """^(\d{1,3}\.){3}\d{1,3}$""".toRegex()
    if (ipv4Pattern.matches(host)) {
        return host.split(".").all { octet ->
            val num = octet.toIntOrNull() ?: return false
            num in 0..255
        }
    }
    
    // IPv6 check (simplified)
    if (host.contains(":") && host.count { it == ':' } >= 2) {
        return true // Likely IPv6
    }
    
    return false
}

fun checkIPAddress(url: String): SecurityCheckResult {
    return try {
        val uri = android.net.Uri.parse(url)
        val host = uri.host ?: return SecurityCheckResult(
            passed = false,
            severity = Severity.HIGH,
            message = "Unable to extract hostname from URL"
        )
        
        if (isIPAddress(host)) {
            SecurityCheckResult(
                passed = false,
                severity = Severity.HIGH,
                message = "URL uses IP address instead of domain name: $host"
            )
        } else {
            SecurityCheckResult(
                passed = true,
                severity = Severity.INFO,
                message = "URL uses domain name"
            )
        }
    } catch (e: Exception) {
        SecurityCheckResult(
            passed = false,
            severity = Severity.MEDIUM,
            message = "Error parsing URL: ${e.message}"
        )
    }
}
```

### 2. SSL/TLS Certificate Validation (MODERATE CHECK)
**Why Important**: Ensures encrypted communication and domain ownership verification.

**What to Check**:
- Certificate validity period
- Certificate chain completeness
- Self-signed certificates
- Certificate hostname match

```kotlin
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import java.security.cert.X509Certificate
import javax.net.ssl.X509TrustManager
import java.util.Date

fun validateSSLCertificate(url: String): SecurityCheckResult {
    return try {
        val httpUrl = java.net.URL(url)
        val connection = httpUrl.openConnection() as HttpsURLConnection
        connection.connectTimeout = 5000
        
        val certificate = connection.serverCertificates.firstOrNull() as? X509Certificate
            ?: return SecurityCheckResult(
                passed = false,
                severity = Severity.HIGH,
                message = "No SSL certificate found"
            )
        
        val now = Date()
        val notBefore = certificate.notBefore
        val notAfter = certificate.notAfter
        
        return when {
            now.before(notBefore) -> SecurityCheckResult(
                passed = false,
                severity = Severity.HIGH,
                message = "Certificate not yet valid (starts: $notBefore)"
            )
            now.after(notAfter) -> SecurityCheckResult(
                passed = false,
                severity = Severity.HIGH,
                message = "Certificate has expired (expired: $notAfter)"
            )
            // Check if expiring soon (within 30 days)
            notAfter.time - now.time < 30 * 24 * 60 * 60 * 1000 -> SecurityCheckResult(
                passed = true,
                severity = Severity.MEDIUM,
                message = "Certificate expires soon: $notAfter"
            )
            else -> SecurityCheckResult(
                passed = true,
                severity = Severity.INFO,
                message = "Certificate valid until $notAfter"
            )
        }
    } catch (e: Exception) {
        SecurityCheckResult(
            passed = false,
            severity = Severity.HIGH,
            message = "SSL/TLS validation failed: ${e.message}"
        )
    }
}
```

### 3. Domain Age Checking (MODERATE-SLOW CHECK)
**Why Important**: New domains (< 1 year old) are more likely to be malicious.

**Limitations on Android**: 
- Requires external API or WHOIS lookup
- Cannot be done efficiently on device without network
- Recommend querying only for suspicious URLs

```kotlin
// Requires external API - example using WHOIS/DomainTools
suspend fun checkDomainAge(domain: String): SecurityCheckResult {
    // NOTE: This would require API call to service like DomainTools, abuse.ch, etc.
    // Example pseudo-code:
    return try {
        val response = whoisApiService.getDomainInfo(domain)
        val createdDate = response.creationDate
        val ageInDays = (System.currentTimeMillis() - createdDate.time) / (1000 * 60 * 60 * 24)
        
        return when {
            ageInDays < 30 -> SecurityCheckResult(
                passed = false,
                severity = Severity.HIGH,
                message = "Domain is very new: $ageInDays days old"
            )
            ageInDays < 90 -> SecurityCheckResult(
                passed = false,
                severity = Severity.MEDIUM,
                message = "Domain is relatively new: $ageInDays days old"
            )
            else -> SecurityCheckResult(
                passed = true,
                severity = Severity.INFO,
                message = "Domain age: $ageInDays days"
            )
        }
    } catch (e: Exception) {
        SecurityCheckResult(
            passed = false,
            severity = Severity.MEDIUM,
            message = "Could not verify domain age: ${e.message}"
        )
    }
}
```

### 4. Phishing/Malware Database Checks (SLOW CHECK)
**Why Important**: Known malicious URLs are already catalogued in threat databases.

#### Google Safe Browsing API (RECOMMENDED - Official)
```kotlin
import com.google.android.gms.safetynet.SafetyNet
import com.google.android.gms.safetynet.SafeBrowsingThreat

// Initialize in Activity.onResume()
suspend fun initSafeBrowsing(context: Context) {
    try {
        SafetyNet.getClient(context).initSafeBrowsing().await()
    } catch (e: Exception) {
        Log.e("SafeBrowsing", "Failed to init: ${e.message}")
    }
}

// Check URL against Google's Safe Browsing database
suspend fun checkSafeBrowsingGoogle(context: Context, url: String, apiKey: String): SecurityCheckResult {
    return try {
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
                message = "URL not found in Safe Browsing database"
            )
        } else {
            val threats = response.detectedThreats.map { it.threatType }.joinToString(", ")
            SecurityCheckResult(
                passed = false,
                severity = Severity.CRITICAL,
                message = "URL flagged by Google Safe Browsing: $threats"
            )
        }
    } catch (e: Exception) {
        SecurityCheckResult(
            passed = null,
            severity = Severity.MEDIUM,
            message = "Safe Browsing check unavailable: ${e.message}"
        )
    }
}

// Shutdown in Activity.onPause()
fun shutdownSafeBrowsing(context: Context) {
    SafetyNet.getClient(context).shutdownSafeBrowsing()
}
```

#### URLhaus API (FREE, No Authentication)
**Pros**: No API key required, free malware URL database
**Cons**: Limited to malware, not phishing; rate-limited; slower

```kotlin
suspend fun checkURLhaus(url: String): SecurityCheckResult {
    return try {
        val client = OkHttpClient()
        val request = Request.Builder()
            .url("https://urlhaus-api.abuse.ch/v1/url/")
            .post(RequestBody.create(
                "url=$url",
                "application/x-www-form-urlencoded".toMediaType()
            ))
            .build()
        
        val response = client.newCall(request).execute()
        val jsonBody = JSONObject(response.body?.string() ?: "{}")
        val query_status = jsonBody.optString("query_status")
        
        if (query_status == "ok") {
            val urls = jsonBody.optJSONArray("results")
            if (urls != null && urls.length() > 0) {
                val threat = urls.optJSONObject(0)?.optString("threat")
                return SecurityCheckResult(
                    passed = false,
                    severity = Severity.CRITICAL,
                    message = "URL found in URLhaus malware database: $threat"
                )
            }
        }
        
        SecurityCheckResult(
            passed = true,
            severity = Severity.INFO,
            message = "URL not found in URLhaus database"
        )
    } catch (e: Exception) {
        SecurityCheckResult(
            passed = null,
            severity = Severity.MEDIUM,
            message = "URLhaus check failed: ${e.message}"
        )
    }
}
```

#### PhishTank API (FREE, But Needs Registration)
**Pros**: Specifically for phishing URLs; comprehensive database
**Cons**: Requires API key; slower; needs network

```kotlin
suspend fun checkPhishTank(url: String, apiKey: String): SecurityCheckResult {
    return try {
        val client = OkHttpClient()
        val requestBody = RequestBody.create(
            "url=$url&format=json&app_token=$apiKey",
            "application/x-www-form-urlencoded".toMediaType()
        )
        
        val request = Request.Builder()
            .url("https://checkurl.phishtank.com/checkurl/")
            .post(requestBody)
            .build()
        
        val response = client.newCall(request).execute()
        val jsonBody = JSONObject(response.body?.string() ?: "{}")
        val results = jsonBody.optJSONObject("results")
        
        val inDatabase = results?.optInt("in_database") == 1
        val phishLikelihood = results?.optInt("phish_likelihood")
        
        return when {
            inDatabase && phishLikelihood ?: 0 > 75 -> SecurityCheckResult(
                passed = false,
                severity = Severity.CRITICAL,
                message = "URL flagged as phishing (likelihood: $phishLikelihood%)"
            )
            inDatabase -> SecurityCheckResult(
                passed = false,
                severity = Severity.HIGH,
                message = "URL in PhishTank database (likelihood: $phishLikelihood%)"
            )
            else -> SecurityCheckResult(
                passed = true,
                severity = Severity.INFO,
                message = "URL not identified as phishing"
            )
        }
    } catch (e: Exception) {
        SecurityCheckResult(
            passed = null,
            severity = Severity.MEDIUM,
            message = "PhishTank check failed: ${e.message}"
        )
    }
}
```

### 5. Suspicious Pattern Detection (FAST CHECK)

#### Typosquatting Detection
```kotlin
fun detectTyposquatting(domain: String, knownDomains: List<String>): SecurityCheckResult {
    // Levenshtein distance for fuzzy matching
    val distances = knownDomains.map { known ->
        known to levenshteinDistance(domain.lowercase(), known.lowercase())
    }
    
    val closestMatch = distances.minByOrNull { it.second }
    
    return if (closestMatch != null && closestMatch.second <= 2 && closestMatch.second > 0) {
        SecurityCheckResult(
            passed = false,
            severity = Severity.HIGH,
            message = "Potential typosquatting: similar to ${closestMatch.first}"
        )
    } else {
        SecurityCheckResult(
            passed = true,
            severity = Severity.INFO,
            message = "Domain doesn't appear to be typosquatting"
        )
    }
}

fun levenshteinDistance(s1: String, s2: String): Int {
    val dp = Array(s1.length + 1) { IntArray(s2.length + 1) }
    
    for (i in 0..s1.length) dp[i][0] = i
    for (j in 0..s2.length) dp[0][j] = j
    
    for (i in 1..s1.length) {
        for (j in 1..s2.length) {
            dp[i][j] = when {
                s1[i - 1] == s2[j - 1] -> dp[i - 1][j - 1]
                else -> 1 + minOf(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1])
            }
        }
    }
    
    return dp[s1.length][s2.length]
}
```

#### Homograph Attack Detection
```kotlin
fun detectHomographAttack(domain: String): SecurityCheckResult {
    // Common homograph characters: 0 vs O, 1 vs l vs I, etc.
    val suspiciousCombinations = listOf(
        Regex("[0O]+") to "numbers and O",
        Regex("[1lI]+") to "1, l, and I",
        Regex("[5S]+") to "5 and S",
        Regex("[8B]+") to "8 and B",
        Regex("[2Z]+") to "2 and Z"
    )
    
    val domainLower = domain.lowercase()
    val foundCombinations = suspiciousCombinations.filter { (pattern, _) ->
        pattern.containsMatchIn(domainLower)
    }
    
    return if (foundCombinations.isNotEmpty()) {
        val details = foundCombinations.joinToString { it.second }
        SecurityCheckResult(
            passed = false,
            severity = Severity.MEDIUM,
            message = "Possible homograph attack: contains visually similar characters ($details)"
        )
    } else {
        SecurityCheckResult(
            passed = true,
            severity = Severity.INFO,
            message = "No obvious homograph patterns detected"
        )
    }
}
```

### 6. URL Structure Analysis (FAST CHECK)

```kotlin
fun analyzeURLStructure(url: String): SecurityCheckResult {
    return try {
        val uri = android.net.Uri.parse(url)
        val issues = mutableListOf<String>()
        
        // Check for missing scheme
        if (uri.scheme == null) {
            issues.add("Missing scheme (http/https)")
        }
        
        // Check for unusual schemes
        if (uri.scheme != null && uri.scheme !in listOf("http", "https", "ftp")) {
            issues.add("Unusual scheme: ${uri.scheme}")
        }
        
        // Check for missing hostname
        if (uri.host == null || uri.host?.isEmpty() == true) {
            issues.add("Missing or empty hostname")
        }
        
        // Check for suspicious port
        val port = uri.port
        if (port > 0 && port !in listOf(80, 443, 8080, 8443, 21)) {
            if (port < 1024) {
                issues.add("Unusual privileged port: $port")
            }
        }
        
        // Check for excessive query parameters
        val queryParams = uri.queryParameterNames.size
        if (queryParams > 10) {
            issues.add("Excessive query parameters: $queryParams")
        }
        
        // Check for very long URL
        if (url.length > 2048) {
            issues.add("URL exceeds safe length (${url.length} chars)")
        }
        
        // Check for encoded characters in domain
        val host = uri.host ?: ""
        if (host.contains("%")) {
            issues.add("URL-encoded characters in hostname (potential obfuscation)")
        }
        
        // Check for authentication in URL
        if (uri.userInfo != null) {
            issues.add("Credentials embedded in URL")
        }
        
        return if (issues.isEmpty()) {
            SecurityCheckResult(
                passed = true,
                severity = Severity.INFO,
                message = "URL structure appears normal"
            )
        } else {
            SecurityCheckResult(
                passed = false,
                severity = Severity.MEDIUM,
                message = "URL structure issues: ${issues.joinToString(", ")}"
            )
        }
    } catch (e: Exception) {
        SecurityCheckResult(
            passed = false,
            severity = Severity.MEDIUM,
            message = "Error analyzing URL structure: ${e.message}"
        )
    }
}
```

---

## Android Implementation

### Data Classes and Enums

```kotlin
enum class Severity {
    INFO,      // Information only
    MEDIUM,    // Warning - handle with caution
    HIGH,      // Danger - likely malicious
    CRITICAL   // Block immediately
}

data class SecurityCheckResult(
    val passed: Boolean?,  // null = couldn't determine
    val severity: Severity,
    val message: String,
    val checkType: String = "Unknown"
)

data class URLSecurityReport(
    val url: String,
    val timestamp: Long = System.currentTimeMillis(),
    val overallRisk: Severity,
    val checks: List<SecurityCheckResult>,
    val isBlocked: Boolean = false
)
```

### Main URL Security Analyzer

```kotlin
class URLSecurityAnalyzer(
    private val context: Context,
    private val safeBrowsingApiKey: String = "",
    private val phishTankApiKey: String = ""
) {
    
    private val knownLegitDomains = listOf(
        "google.com", "facebook.com", "twitter.com", "amazon.com", "github.com"
    )
    
    suspend fun analyzeURL(url: String, runSlowChecks: Boolean = false): URLSecurityReport {
        val normalizedUrl = normalizeUrl(url)
        val results = mutableListOf<SecurityCheckResult>()
        
        // FAST CHECKS (run immediately)
        results.add(checkURLStructure(normalizedUrl))
        results.add(checkIPAddress(normalizedUrl))
        results.add(checkHomographAttack(normalizedUrl))
        results.add(checkTyposquatting(normalizedUrl))
        
        // MODERATE CHECKS (if needed)
        if (runSlowChecks) {
            results.add(validateSSLCertificate(normalizedUrl))
        }
        
        // SLOW CHECKS (only for high-risk URLs or if explicitly requested)
        if (runSlowChecks && results.any { it.severity == Severity.HIGH || it.severity == Severity.CRITICAL }) {
            results.add(checkSafeBrowsingGoogle(normalizedUrl))
            results.add(checkURLhaus(normalizedUrl))
            results.add(checkPhishTank(normalizedUrl))
        }
        
        // Determine overall risk
        val overallRisk = when {
            results.any { it.severity == Severity.CRITICAL } -> Severity.CRITICAL
            results.any { it.severity == Severity.HIGH } -> Severity.HIGH
            results.any { it.severity == Severity.MEDIUM } -> Severity.MEDIUM
            else -> Severity.INFO
        }
        
        return URLSecurityReport(
            url = url,
            overallRisk = overallRisk,
            checks = results,
            isBlocked = overallRisk == Severity.CRITICAL
        )
    }
    
    private fun checkURLStructure(url: String): SecurityCheckResult {
        // Implementation from above
        return analyzeURLStructure(url)
    }
    
    private fun checkIPAddress(url: String): SecurityCheckResult {
        return checkIPAddress(url)
    }
    
    private fun checkHomographAttack(url: String): SecurityCheckResult {
        val uri = android.net.Uri.parse(url)
        val host = uri.host ?: return SecurityCheckResult(
            passed = false, Severity.HIGH, "Cannot extract hostname"
        )
        return detectHomographAttack(host)
    }
    
    private fun checkTyposquatting(url: String): SecurityCheckResult {
        val uri = android.net.Uri.parse(url)
        val host = uri.host ?: return SecurityCheckResult(
            passed = true, Severity.INFO, "Cannot extract hostname"
        )
        return detectTyposquatting(host, knownLegitDomains)
    }
    
    private suspend fun checkSafeBrowsingGoogle(url: String): SecurityCheckResult {
        return if (safeBrowsingApiKey.isNotEmpty()) {
            checkSafeBrowsingGoogle(context, url, safeBrowsingApiKey)
        } else {
            SecurityCheckResult(
                passed = null, Severity.MEDIUM, "Safe Browsing API key not configured"
            )
        }
    }
    
    private suspend fun checkURLhaus(url: String): SecurityCheckResult {
        return checkURLhaus(url)
    }
    
    private suspend fun checkPhishTank(url: String): SecurityCheckResult {
        return if (phishTankApiKey.isNotEmpty()) {
            checkPhishTank(url, phishTankApiKey)
        } else {
            SecurityCheckResult(
                passed = null, Severity.MEDIUM, "PhishTank API key not configured"
            )
        }
    }
}
```

---

## Performance Considerations

### Check Classification

| Check | Execution Time | Network | Data Needed | Priority |
|-------|---|---|---|---|
| IP Address Detection | < 1ms | No | Built-in | FAST |
| URL Structure Analysis | 1-5ms | No | Built-in | FAST |
| Homograph Detection | 1-3ms | No | Built-in | FAST |
| Typosquatting Detection | 5-20ms | No | Local list (< 1MB) | FAST |
| SSL/TLS Validation | 500ms-2s | Yes | Device cert store | MODERATE |
| Domain Age Checking | 1-3s | Yes | WHOIS API | SLOW |
| Google Safe Browsing | 500ms-1s | Yes | Requires API key | SLOW |
| URLhaus Lookup | 1-3s | Yes | Free API | SLOW |
| PhishTank Lookup | 1-3s | Yes | Requires API key | SLOW |

### Implementation Strategy

**For Real-Time UI Display**:
```kotlin
// Run only fast checks (< 50ms total)
val report = analyzer.analyzeURL(url, runSlowChecks = false)
displayBasicWarning(report)

// Perform slower checks in background
GlobalScope.launch {
    val detailedReport = analyzer.analyzeURL(url, runSlowChecks = true)
    updateDetailedWarning(detailedReport)
}
```

**For Background Processing**:
```kotlin
// Use WorkManager for periodic checks
val checkWork = PeriodicWorkRequestBuilder<URLSecurityWorker>(
    15, TimeUnit.MINUTES
).build()

WorkManager.getInstance(context).enqueueUniquePeriodicWork(
    "url_security_checks",
    ExistingPeriodicWorkPolicy.KEEP,
    checkWork
)
```

**Caching Results**:
```kotlin
class URLSecurityCache(private val context: Context) {
    private val cache = mutableMapOf<String, Pair<URLSecurityReport, Long>>()
    private val CACHE_VALIDITY_MS = 24 * 60 * 60 * 1000 // 24 hours
    
    fun getCachedResult(url: String): URLSecurityReport? {
        val (report, timestamp) = cache[url] ?: return null
        return if (System.currentTimeMillis() - timestamp < CACHE_VALIDITY_MS) {
            report
        } else {
            cache.remove(url)
            null
        }
    }
    
    fun cacheResult(url: String, report: URLSecurityReport) {
        cache[url] = report to System.currentTimeMillis()
    }
}
```

---

## Popular Android Libraries

### 1. OkHttp (HTTP Client)
**Purpose**: Making secure HTTPS requests, SSL/TLS validation
**Installation**:
```gradle
implementation("com.squareup.okhttp3:okhttp:5.3.0")
implementation("com.squareup.okhttp3:logging-interceptor:5.3.0")
```
**Features**:
- Automatic TLS 1.3/1.2 negotiation
- Certificate pinning support
- Connection pooling
- Built-in GZIP compression

**Usage for Security**:
```kotlin
val client = OkHttpClient.Builder()
    .connectionSpecs(listOf(
        ConnectionSpec.RESTRICTED_TLS,
        ConnectionSpec.MODERN_TLS
    ))
    .certificatePinner(
        CertificatePinner.Builder()
            .add("example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            .build()
    )
    .build()
```

### 2. Google Play Services - SafetyNet/Safe Browsing
**Purpose**: Check URLs against Google's malware/phishing database
**Installation**:
```gradle
implementation("com.google.android.gms:play-services-safetynet:18.1.0")
```
**Features**:
- Google's real-time threat detection
- Battery and bandwidth optimized
- Privacy preserving (hash prefixes)
- Covers multiple threat types

### 3. Retrofit (REST Client)
**Purpose**: Making API calls to threat intelligence services
**Installation**:
```gradle
implementation("com.squareup.retrofit2:retrofit:2.10.0")
implementation("com.squareup.retrofit2:converter-gson:2.10.0")
```
**Usage**:
```kotlin
interface ThreatIntelService {
    @POST("v1/url/")
    suspend fun checkURLhaus(@Body request: URLhausRequest): URLhausResponse
    
    @POST("checkurl/")
    suspend fun checkPhishTank(@Body request: PhishTankRequest): PhishTankResponse
}
```

### 4. WorkManager (Background Tasks)
**Purpose**: Schedule periodic security checks without heavy battery drain
**Installation**:
```gradle
implementation("androidx.work:work-runtime-ktx:2.8.1")
```

### 5. Room Database (Local Caching)
**Purpose**: Cache security check results locally
**Installation**:
```gradle
implementation("androidx.room:room-runtime:2.6.1")
kapt("androidx.room:room-compiler:2.6.1")
```

### 6. Kotlin Coroutines (Async Operations)
**Purpose**: Non-blocking security checks
**Installation**:
```gradle
implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")
```

### 7. Conscrypt (Enhanced SSL/TLS)
**Purpose**: Modern TLS features (optional enhancement)
**Installation**:
```gradle
implementation("org.conscrypt:conscrypt-android:2.5.2")
```
**Usage**:
```kotlin
import org.conscrypt.Conscrypt
import java.security.Security

Security.insertProviderAt(Conscrypt.newProvider(), 1)
```

---

## Code Examples

### Complete URL Security Activity

```kotlin
class URLSecurityActivity : AppCompatActivity() {
    private lateinit var analyzer: URLSecurityAnalyzer
    private lateinit var cache: URLSecurityCache
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_url_security)
        
        analyzer = URLSecurityAnalyzer(
            this,
            safeBrowsingApiKey = "YOUR_API_KEY",
            phishTankApiKey = "YOUR_API_KEY"
        )
        cache = URLSecurityCache(this)
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
    
    fun checkURL(url: String) {
        lifecycleScope.launch {
            // Check cache first
            val cached = cache.getCachedResult(url)
            if (cached != null) {
                displayReport(cached)
                return@launch
            }
            
            // Show fast checks immediately
            val fastReport = analyzer.analyzeURL(url, runSlowChecks = false)
            displayReport(fastReport)
            
            // Get detailed report in background
            val detailedReport = analyzer.analyzeURL(url, runSlowChecks = true)
            cache.cacheResult(url, detailedReport)
            displayReport(detailedReport)
        }
    }
    
    private fun displayReport(report: URLSecurityReport) {
        // Update UI based on report
        val riskColor = when (report.overallRisk) {
            Severity.INFO -> android.graphics.Color.GREEN
            Severity.MEDIUM -> android.graphics.Color.YELLOW
            Severity.HIGH -> android.graphics.Color.RED
            Severity.CRITICAL -> android.graphics.Color.RED
        }
        
        val riskText = when (report.overallRisk) {
            Severity.INFO -> "Safe"
            Severity.MEDIUM -> "Caution"
            Severity.HIGH -> "Dangerous"
            Severity.CRITICAL -> "Blocked"
        }
        
        // Display detailed checks
        report.checks.forEach { check ->
            Log.d("SecurityCheck", "${check.checkType}: ${check.message} (${check.severity})")
        }
    }
}
```

---

## Summary & Recommendations

### For TrustShield Implementation

**Phase 1 (MVP - Fast Checks Only)**:
1. Implement URL extraction with regex
2. Add IP address detection
3. Add URL structure analysis
4. Add homograph attack detection
5. Maintain local domain list for typosquatting

**Phase 2 (Enhanced Protection)**:
6. Integrate Google Safe Browsing API
7. Add SSL/TLS certificate validation
8. Implement result caching
9. Add background security checks

**Phase 3 (Advanced)**:
10. URLhaus integration
11. PhishTank integration
12. Domain age checking
13. Machine learning classification

### Critical API Keys Needed
- **Google Safe Browsing API**: https://console.cloud.google.com
- **PhishTank API**: https://www.phishtank.com/developer_info.php (free registration)
- URLhaus has no API key requirement

### Performance Budget
- Fast checks: < 50ms
- Moderate checks: 500ms - 2s
- Slow checks: 1-3s each
- Total with all checks: < 10s maximum

### Security Best Practices
1. Never log full URLs with sensitive data
2. Cache only URL hashes, not full URLs
3. Use HTTPS for all external API calls
4. Implement rate limiting for external APIs
5. Store API keys securely (preferably in secure SharedPreferences)
6. Validate all inputs before processing
7. Handle exceptions gracefully without exposing stack traces
