package com.example.trustshield

import android.net.Uri
import android.util.Log
import com.example.trustshield.network.RetrofitClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Data class representing an official brand and its trusted domains.
 */
data class OfficialBrand(
    val name: String,
    val primaryDomain: String,
    val aliases: List<String> = emptyList(),
    val trustedSubdomains: List<String> = emptyList(),
    val trustedCdns: List<String> = emptyList()
)

enum class VerificationStatus {
    VERIFIED_OFFICIAL,
    BRAND_ABUSE,
    UNKNOWN
}

data class DomainVerificationResult(
    val status: VerificationStatus,
    val brandName: String? = null,
    val reason: String
)

/**
 * Centralized registry of verified official brands and their domains.
 * Fetches data dynamically from the backend database.
 */
object OfficialDomainRegistry {
    private const val TAG = "OFFICIAL_REGISTRY"
    
    // Dynamic registry of verified official brands fetched from backend
    private var OFFICIAL_BRANDS: List<OfficialBrand> = emptyList()
    
    /**
     * Fetches the latest brand registry from the backend database.
     */
    suspend fun fetchRegistryFromBackend() {
        withContext(Dispatchers.IO) {
            try {
                Log.d(TAG, "🔄 Fetching official domains from backend...")
                val apiService = RetrofitClient.getInstance().getApiService()
                val response = apiService.getOfficialBrands()
                
                if (response.isSuccessful && response.body() != null) {
                    val newBrands = response.body()!!.brands
                    if (newBrands.isNotEmpty()) {
                        OFFICIAL_BRANDS = newBrands
                        Log.d(TAG, "✅ Successfully loaded ${OFFICIAL_BRANDS.size} brands from database!")
                    }
                } else {
                    Log.e(TAG, "❌ Failed to fetch brands: ${response.code()}")
                }
            } catch (e: Exception) {
                Log.e(TAG, "❌ Error fetching brand registry: ${e.message}")
            }
        }
    }
    
    /**
     * Verifies if a given domain is an official domain for a known brand,
     * or if it's attempting to spoof a known brand.
     */
    fun verifyDomain(domain: String): DomainVerificationResult {
        val cleanDomain = domain.lowercase().removePrefix("www.")
        
        for (brand in OFFICIAL_BRANDS) {
            // 1. Check exact match with primary domain or aliases
            val allValidDomains = mutableListOf(brand.primaryDomain)
            allValidDomains.addAll(brand.aliases)
            
            if (allValidDomains.contains(cleanDomain)) {
                return DomainVerificationResult(
                    VerificationStatus.VERIFIED_OFFICIAL,
                    brand.name,
                    "Verified official domain for ${brand.name}"
                )
            }
            
            // 2. Check if it's a valid subdomain of the primary domain
            if (cleanDomain.endsWith(".${brand.primaryDomain}")) {
                val subdomainPart = cleanDomain.removeSuffix(".${brand.primaryDomain}")
                // If there are specific trusted subdomains, check them
                if (brand.trustedSubdomains.isNotEmpty()) {
                    if (brand.trustedSubdomains.contains(subdomainPart) || 
                        brand.trustedSubdomains.any { subdomainPart.endsWith(".$it") }) {
                        return DomainVerificationResult(
                            VerificationStatus.VERIFIED_OFFICIAL,
                            brand.name,
                            "Verified official subdomain for ${brand.name}"
                        )
                    }
                } else {
                    // If no specific subdomains are listed but it ends with the primary domain,
                    // we cautiously trust it but could flag for review
                    return DomainVerificationResult(
                        VerificationStatus.VERIFIED_OFFICIAL,
                        brand.name,
                        "Verified official subdomain for ${brand.name}"
                    )
                }
            }
            
            // 3. Check aliases subdomains
            for (alias in brand.aliases) {
                if (cleanDomain.endsWith(".$alias")) {
                    return DomainVerificationResult(
                        VerificationStatus.VERIFIED_OFFICIAL,
                        brand.name,
                        "Verified official alias subdomain for ${brand.name}"
                    )
                }
            }
            
            // 4. Check CDNs
            if (brand.trustedCdns.contains(cleanDomain) || 
                brand.trustedCdns.any { cleanDomain.endsWith(".$it") }) {
                return DomainVerificationResult(
                    VerificationStatus.VERIFIED_OFFICIAL,
                    brand.name,
                    "Verified official CDN for ${brand.name}"
                )
            }
            
            // 5. Spoofing Check (BRAND ABUSE)
            // If the domain contains the brand name but wasn't verified above
            val brandNameLower = brand.name.lowercase().replace(" ", "")
            if (cleanDomain.contains(brandNameLower)) {
                // Ignore if it's just a generic word match (e.g. "apple" in "applepie.com")
                // but flag it if it looks like a deliberate spoofing attempt
                val suspiciousPatterns = listOf(
                    "$brandNameLower-", 
                    "-$brandNameLower",
                    brandNameLower + "login",
                    brandNameLower + "support",
                    brandNameLower + "security",
                    brandNameLower + "verify",
                    brandNameLower + "account"
                )
                
                if (suspiciousPatterns.any { cleanDomain.contains(it) } || 
                    cleanDomain == "${brandNameLower}.net" || 
                    cleanDomain == "${brandNameLower}.org" ||
                    cleanDomain == "${brandNameLower}.co" ||
                    cleanDomain == "${brandNameLower}.info") {
                    
                    return DomainVerificationResult(
                        VerificationStatus.BRAND_ABUSE,
                        brand.name,
                        "🔴 DANGEROUS: Abuses ${brand.name} brand - This is fake"
                    )
                }
                
                // Even without specific patterns, containing the exact brand name 
                // in the domain when it's NOT an official domain is highly suspicious
                // for major brands
                if (cleanDomain.contains(brandNameLower) && brandNameLower.length >= 4) {
                    return DomainVerificationResult(
                        VerificationStatus.BRAND_ABUSE,
                        brand.name,
                        "🔴 DANGEROUS: Abuses ${brand.name} brand - This is fake"
                    )
                }
            }
        }
        
        // Not associated with any known brand in our registry
        return DomainVerificationResult(
            VerificationStatus.UNKNOWN,
            null,
            "Domain not found in official registry"
        )
    }
}
