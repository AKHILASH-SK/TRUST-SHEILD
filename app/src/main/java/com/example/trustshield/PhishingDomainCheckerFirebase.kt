package com.example.trustshield

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import com.google.firebase.database.DataSnapshot
import com.google.firebase.database.DatabaseError
import com.google.firebase.database.FirebaseDatabase
import com.google.firebase.database.ValueEventListener
import org.json.JSONArray
import org.json.JSONObject

enum class PhishingCheckResult {
    SAFE,
    SUSPICIOUS,
    DANGEROUS
}

data class PhishingCheckData(
    val domain: String,
    val result: PhishingCheckResult,
    val message: String
)

class PhishingDomainCheckerFirebase(private val context: Context) {
    
    companion object {
        private const val TAG = "PhishingChecker"
        private const val CACHE_KEY = "phishing_domains_cache"
        private const val CACHE_TIMESTAMP = "phishing_cache_timestamp"
        private const val CACHE_VALIDITY_MS = 3600000L // 1 hour
        
        // Local fallback database (embedded in APK)
        private val LOCAL_DANGEROUS_DOMAINS = setOf(
            // PayPal phishing
            "paypal-confirm.com",
            "verify-account.com",
            "paypal-security.com",
            "paypal-verification.net",
            "paypalupdate.com",
            "paypal-limited.com",
            
            // Amazon phishing
            "secure-login-amazon.com",
            "amazon-verify-account.com",
            "amazon-security-alert.com",
            "amaz0n-account.com",
            "amazon-verify.net",
            "amazon-confirm.com",
            "amazon-login-verify.com",
            
            // Google phishing
            "google-account-verify.com",
            "google-verify-account.net",
            "googleaccountverify.com",
            "google-security-alert.com",
            "accounts-google.com",
            "google-security-check.net",
            "g00gle-account.com",
            
            // Gmail phishing
            "gmail-verification.com",
            "gmail-verify.net",
            "gmail-security.com",
            "gmail-account-verify.com",
            
            // Apple phishing
            "apple-verify.com",
            "apple-id-verify.com",
            "icloud-verify.com",
            "apple-security-alert.com",
            "applesecurity.net",
            "appleid-verify.com",
            
            // Microsoft phishing
            "microsoft-security.com",
            "microsoft-verify.net",
            "outlook-verify.com",
            "microsoft-account-security.net",
            "ms-office-verify.com",
            "windows-security-update.com",
            
            // Adobe phishing
            "adobe-security-alert.com",
            "adobe-verify.net",
            "adobe-account-verify.com",
            
            // Banking phishing
            "bank-login-verify.com",
            "banking-secure-login.com",
            "secure-bank-login.net",
            "bank-verification.com",
            "online-banking-verify.net",
            "banking-security-alert.com",
            
            // Facebook phishing
            "facebook-login-check.com",
            "facebook-verify.net",
            "facebook-security-alert.com",
            "facebook-account-verify.com",
            "fb-verify.net",
            
            // Instagram phishing
            "instagram-verify.net",
            "instagram-security.com",
            "instagram-account-verify.com",
            
            // LinkedIn phishing
            "linkedin-verify.net",
            "linkedin-security.com",
            "linkedin-account-verify.com",
            
            // Twitter/X phishing
            "twitter-verify.net",
            "twitter-security.com",
            "x-verify.com",
            
            // WhatsApp phishing
            "whatsapp-verify.net",
            "whatsapp-security.com",
            
            // Cryptocurrency phishing
            "crypto-wallet-verify.com",
            "blockchain-login-verify.net",
            "bitcoin-wallet-secure.com",
            "ethereum-verify.net",
            "coinbase-verify.net",
            "metamask-security.com",
            "bitcoin-security-alert.com",
            
            // Malicious tech support
            "windows-tech-support.com",
            "mac-support-alert.net",
            "iphone-security-warning.com",
            "antivirus-security-alert.com",
            "computer-virus-detected.net",
            
            // Generic malicious domains
            "secure-verify.net",
            "account-verification.net",
            "confirm-identity.com",
            "verify-payment.net",
            "payment-confirm.com",
            "suspicious-domain-alert.com",
            "malware-test-site.com",
            "phishing-test.net",
            "click-me-now.com",
            "limited-offer-expires.com",
            "urgent-action-required.net",
            "verify-now-secure.com"
        )
    }
    
    private val sharedPreferences: SharedPreferences =
        context.getSharedPreferences("phishing_checker", Context.MODE_PRIVATE)
    
    private val database = FirebaseDatabase.getInstance()
    private var cachedDangerousDomains = mutableSetOf<String>()
    private var cachedSuspiciousDomains = mutableSetOf<String>()
    private var isInitialized = false
    
    init {
        loadCachedDomains()
        if (cachedDangerousDomains.isEmpty()) {
            // If no cache, use local fallback
            cachedDangerousDomains.addAll(LOCAL_DANGEROUS_DOMAINS)
        }
        // Fetch fresh data from Firebase in background
        fetchFromFirebaseIfNeeded()
    }
    
    /**
     * Load cached domains from SharedPreferences
     */
    private fun loadCachedDomains() {
        try {
            val cachedJSON = sharedPreferences.getString(CACHE_KEY, null)
            if (cachedJSON != null) {
                val obj = JSONObject(cachedJSON)
                
                val dangerousArray = obj.optJSONArray("dangerous") ?: JSONArray()
                cachedDangerousDomains.clear()
                for (i in 0 until dangerousArray.length()) {
                    cachedDangerousDomains.add(dangerousArray.getString(i))
                }
                
                val suspiciousArray = obj.optJSONArray("suspicious") ?: JSONArray()
                cachedSuspiciousDomains.clear()
                for (i in 0 until suspiciousArray.length()) {
                    cachedSuspiciousDomains.add(suspiciousArray.getString(i))
                }
                
                Log.d(TAG, "Loaded ${cachedDangerousDomains.size} dangerous domains from cache")
                isInitialized = true
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error loading cached domains: ${e.message}")
        }
    }
    
    /**
     * Save domains to cache
     */
    private fun saveCacheToPreferences() {
        try {
            val obj = JSONObject()
            val dangerousArray = JSONArray(cachedDangerousDomains.toList())
            val suspiciousArray = JSONArray(cachedSuspiciousDomains.toList())
            
            obj.put("dangerous", dangerousArray)
            obj.put("suspicious", suspiciousArray)
            
            sharedPreferences.edit().apply {
                putString(CACHE_KEY, obj.toString())
                putLong(CACHE_TIMESTAMP, System.currentTimeMillis())
                apply()
            }
            
            Log.d(TAG, "Cached ${cachedDangerousDomains.size} dangerous domains")
        } catch (e: Exception) {
            Log.e(TAG, "Error saving cache: ${e.message}")
        }
    }
    
    /**
     * Fetch domains from Firebase if cache is expired
     */
    private fun fetchFromFirebaseIfNeeded() {
        val lastFetch = sharedPreferences.getLong(CACHE_TIMESTAMP, 0)
        val timeSinceLastFetch = System.currentTimeMillis() - lastFetch
        
        // Fetch if cache is older than 1 hour or never fetched
        if (timeSinceLastFetch > CACHE_VALIDITY_MS) {
            fetchFromFirebase()
        }
    }
    
    /**
     * Fetch phishing domains from Firebase Realtime Database
     */
    private fun fetchFromFirebase() {
        try {
            val dbRef = database.getReference("phishing_domains")
            
            dbRef.addListenerForSingleValueEvent(object : ValueEventListener {
                override fun onDataChange(snapshot: DataSnapshot) {
                    try {
                        if (snapshot.exists()) {
                            val dangerous = snapshot.child("dangerous")
                            
                            if (dangerous.exists()) {
                                val newDangerousSet = mutableSetOf<String>()
                                for (domainSnapshot in dangerous.children) {
                                    val domain = domainSnapshot.value as? String
                                    if (domain != null) {
                                        newDangerousSet.add(domain.toLowerCase())
                                    }
                                }
                                
                                cachedDangerousDomains = newDangerousSet
                                saveCacheToPreferences()
                                Log.d(TAG, "Updated phishing database from Firebase: ${cachedDangerousDomains.size} domains")
                            }
                            
                            val suspicious = snapshot.child("suspicious")
                            if (suspicious.exists()) {
                                val newSuspiciousSet = mutableSetOf<String>()
                                for (domainSnapshot in suspicious.children) {
                                    val domain = domainSnapshot.value as? String
                                    if (domain != null) {
                                        newSuspiciousSet.add(domain.toLowerCase())
                                    }
                                }
                                cachedSuspiciousDomains = newSuspiciousSet
                            }
                            
                            isInitialized = true
                        } else {
                            Log.w(TAG, "No phishing_domains node found in Firebase")
                            // Use local fallback
                            cachedDangerousDomains.addAll(LOCAL_DANGEROUS_DOMAINS)
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "Error processing Firebase data: ${e.message}")
                    }
                }
                
                override fun onCancelled(error: DatabaseError) {
                    Log.e(TAG, "Firebase fetch cancelled: ${error.message}")
                    // Fall back to cached data or local database
                    if (cachedDangerousDomains.isEmpty()) {
                        cachedDangerousDomains.addAll(LOCAL_DANGEROUS_DOMAINS)
                    }
                }
            })
        } catch (e: Exception) {
            Log.e(TAG, "Error fetching from Firebase: ${e.message}")
            // Use local fallback
            if (cachedDangerousDomains.isEmpty()) {
                cachedDangerousDomains.addAll(LOCAL_DANGEROUS_DOMAINS)
            }
        }
    }
    
    /**
     * Check if a domain is in the phishing database
     * Returns result immediately from cache, updates in background if needed
     */
    fun checkDomain(domain: String, callback: (PhishingCheckData) -> Unit) {
        val normalizedDomain = domain.toLowerCase().trim()
        val extractedDomain = extractDomainFromUrl(normalizedDomain)
        
        // Check local cache immediately
        val result = checkLocalDatabase(extractedDomain)
        
        // Return cached result
        callback(result)
        
        // Refresh from Firebase in background if needed
        fetchFromFirebaseIfNeeded()
    }
    
    /**
     * Check local cached database
     */
    private fun checkLocalDatabase(domain: String): PhishingCheckData {
        val normalizedDomain = domain.toLowerCase().trim()
        
        return when {
            cachedDangerousDomains.contains(normalizedDomain) -> {
                PhishingCheckData(
                    domain = normalizedDomain,
                    result = PhishingCheckResult.DANGEROUS,
                    message = "⚠️ DANGEROUS: Known phishing domain detected in database"
                )
            }
            cachedSuspiciousDomains.contains(normalizedDomain) -> {
                PhishingCheckData(
                    domain = normalizedDomain,
                    result = PhishingCheckResult.SUSPICIOUS,
                    message = "⚠️ SUSPICIOUS: Domain flagged as potentially dangerous"
                )
            }
            else -> {
                PhishingCheckData(
                    domain = normalizedDomain,
                    result = PhishingCheckResult.SAFE,
                    message = "✅ Domain appears safe"
                )
            }
        }
    }
    
    /**
     * Extract domain from URL string
     * Examples:
     * "http://paypal-confirm.com/verify" → "paypal-confirm.com"
     * "paypal-confirm.com" → "paypal-confirm.com"
     * "www.paypal-confirm.com" → "paypal-confirm.com"
     */
    private fun extractDomainFromUrl(urlString: String): String {
        return try {
            // Remove protocol if present
            var domain = urlString
                .replace(Regex("^https?://"), "")
                .replace(Regex("^www\\."), "")
            
            // Remove path, query, fragment
            domain = domain.split("/")[0]
                .split("?")[0]
                .split("#")[0]
                .split(":")[0]
            
            domain.toLowerCase()
        } catch (e: Exception) {
            Log.e(TAG, "Error extracting domain: ${e.message}")
            urlString.toLowerCase()
        }
    }
    
    /**
     * Get current database statistics
     */
    fun getDatabaseStats(): Map<String, Int> {
        return mapOf(
            "dangerous" to cachedDangerousDomains.size,
            "suspicious" to cachedSuspiciousDomains.size,
            "total" to (cachedDangerousDomains.size + cachedSuspiciousDomains.size)
        )
    }
    
    /**
     * Refresh data from Firebase (manual refresh)
     */
    fun refreshFromFirebase() {
        Log.d(TAG, "Manual refresh requested")
        fetchFromFirebase()
    }
}
