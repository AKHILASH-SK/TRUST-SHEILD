package com.example.trustshield

import android.util.Log

/**
 * Verification Result
 * Represents the status of domain verification against official registry
 */
enum class VerificationStatus {
    VERIFIED_OFFICIAL,  // Domain matches official brand registry
    BRAND_ABUSE,        // Domain contains brand name but is not official
    UNKNOWN             // Domain not in registry and no abuse detected
}

/**
 * Verification Result Data
 * Contains verification status and details about the verification
 */
data class VerificationResult(
    val status: VerificationStatus,
    val brandName: String? = null,      // e.g., "YouTube"
    val reason: String = ""              // Explanation for user
)

/**
 * Official Brand Definition
 * Stores all known official domains, aliases, and trusted subdomains for a brand
 */
data class OfficialBrand(
    val name: String,                       // e.g., "YouTube"
    val primaryDomain: String,              // e.g., "youtube.com"
    val aliases: List<String> = emptyList(),        // e.g., ["youtu.be"]
    val trustedSubdomains: List<String> = emptyList(), // e.g., ["m", "support", "studio"]
    val trustedCdns: List<String> = emptyList()    // e.g., ["youtube-nocookie.com"]
)

/**
 * Official Domain Registry
 * 
 * Centralized registry of verified official brands and their domains.
 * Used as the FIRST verification layer before rule-based checks.
 * 
 * Strategy:
 *   1. Store primary domains, aliases, trusted subdomains
 *   2. Exact matches → VERIFIED OFFICIAL
 *   3. Valid subdomains → VERIFIED OFFICIAL
 *   4. Brand name in unrelated domain → BRAND ABUSE
 *   5. Unknown → defer to other checks
 */
object OfficialDomainRegistry {
    private const val TAG = "OFFICIAL_REGISTRY"
    
    // Complete registry of verified official brands
    private val OFFICIAL_BRANDS = listOf(
        // ==== STREAMING & VIDEO ====
        OfficialBrand(
            name = "YouTube",
            primaryDomain = "youtube.com",
            aliases = listOf("youtu.be"),
            trustedSubdomains = listOf("m", "www", "support", "studio", "music", "shorts"),
            trustedCdns = listOf("youtube-nocookie.com", "googlevideo.com", "googleusercontent.com")
        ),
        OfficialBrand(
            name = "Vimeo",
            primaryDomain = "vimeo.com",
            aliases = emptyList(),
            trustedSubdomains = listOf("www", "help", "blog"),
            trustedCdns = emptyList()
        ),
        OfficialBrand(
            name = "DailyMotion",
            primaryDomain = "dailymotion.com",
            aliases = emptyList(),
            trustedSubdomains = listOf("www"),
            trustedCdns = emptyList()
        ),
        
        // ==== SOCIAL MEDIA ====
        OfficialBrand(
            name = "Facebook",
            primaryDomain = "facebook.com",
            aliases = listOf("fb.com"),
            trustedSubdomains = listOf("m", "www", "developers", "business", "help"),
            trustedCdns = listOf("fbcdn.net", "facebook-urls.com")
        ),
        OfficialBrand(
            name = "Instagram",
            primaryDomain = "instagram.com",
            aliases = listOf("instagramm.com"), // Note: intentional typo for mobile redirects
            trustedSubdomains = listOf("www", "m", "help"),
            trustedCdns = listOf("instagr.am", "cdninstagram.com")
        ),
        OfficialBrand(
            name = "Twitter",
            primaryDomain = "twitter.com",
            aliases = listOf("x.com", "t.co"),
            trustedSubdomains = listOf("www", "m", "mobile", "help", "developer"),
            trustedCdns = listOf("twimg.com", "twitter-urls.com")
        ),
        OfficialBrand(
            name = "LinkedIn",
            primaryDomain = "linkedin.com",
            aliases = emptyList(),
            trustedSubdomains = listOf("www", "m", "help", "business"),
            trustedCdns = listOf("lnkd.in")
        ),
        OfficialBrand(
            name = "Reddit",
            primaryDomain = "reddit.com",
            aliases = emptyList(),
            trustedSubdomains = listOf("www", "m", "old", "new", "help"),
            trustedCdns = emptyList()
        ),
        OfficialBrand(
            name = "TikTok",
            primaryDomain = "tiktok.com",
            aliases = listOf("tiktok.com", "vm.tiktok.com"),
            trustedSubdomains = listOf("www", "m", "vt"),
            trustedCdns = listOf("tiktokcdn.com", "tiktokv.com")
        ),
        OfficialBrand(
            name = "Telegram",
            primaryDomain = "telegram.org",
            aliases = listOf("t.me", "telegram.me"),
            trustedSubdomains = listOf("www", "desktop"),
            trustedCdns = emptyList()
        ),
        OfficialBrand(
            name = "WhatsApp",
            primaryDomain = "whatsapp.com",
            aliases = emptyList(),
            trustedSubdomains = listOf("www", "web", "faq"),
            trustedCdns = emptyList()
        ),
        OfficialBrand(
            name = "Discord",
            primaryDomain = "discord.com",
            aliases = listOf("discord.gg", "discordapp.com"),
            trustedSubdomains = listOf("www", "status", "blog", "support"),
            trustedCdns = listOf("cdn.discordapp.com", "discordstatus.com")
        ),
        OfficialBrand(
            name = "Twitch",
            primaryDomain = "twitch.tv",
            aliases = emptyList(),
            trustedSubdomains = listOf("www", "m", "help"),
            trustedCdns = listOf("twitchcdn.net", "twtc.me")
        ),
        
        // ==== AI ASSISTANTS & CHATBOTS ====
        OfficialBrand(
            name = "ChatGPT",
            primaryDomain = "openai.com",
            aliases = listOf("chat.openai.com"),
            trustedSubdomains = listOf("www", "platform", "community", "help"),
            trustedCdns = listOf("cdn.openai.com")
        ),
        OfficialBrand(
            name = "Google",
            primaryDomain = "google.com",
            aliases = listOf("g.co"),
            trustedSubdomains = listOf("www", "mail", "drive", "docs", "sheets", "accounts", "support", 
                                       "play", "photos", "calendar", "meet", "scholar", "trends"),
            trustedCdns = listOf("googleapis.com", "gstatic.com", "googleadservices.com", "googleanalyticsv3.com")
        ),
        OfficialBrand(
            name = "Bard",
            primaryDomain = "bard.google.com",
            aliases = listOf("makersuite.google.com"),
            trustedSubdomains = emptyList(),
            trustedCdns = emptyList()
        ),
        
        // ==== E-COMMERCE & SHOPPING ====
        OfficialBrand(
            name = "Amazon",
            primaryDomain = "amazon.com",
            aliases = emptyList(),
            trustedSubdomains = listOf("www", "m", "smile", "prime", "music", "kindle", "drive"),
            trustedCdns = listOf("cloudfront.net", "amzn.com", "a.co")
        ),
        OfficialBrand(
            name = "eBay",
            primaryDomain = "ebay.com",
            aliases = emptyList(),
            trustedSubdomains = listOf("www", "m", "my", "help"),
            trustedCdns = listOf("ebayimg.com", "ebay-urls.com")
        ),
        OfficialBrand(
            name = "Flipkart",
            primaryDomain = "flipkart.com",
            aliases = listOf("fk.io"),
            trustedSubdomains = listOf("www", "m", "help"),
            trustedCdns = listOf("flixcdn.net", "flipkartcdn.com")
        ),
        OfficialBrand(
            name = "Myntra",
            primaryDomain = "myntra.com",
            aliases = emptyList(),
            trustedSubdomains = listOf("www", "m", "help"),
            trustedCdns = listOf("myntrascdn.com")
        ),
        OfficialBrand(
            name = "Snapdeal",
            primaryDomain = "snapdeal.com",
            aliases = emptyList(),
            trustedSubdomains = listOf("www", "m", "help"),
            trustedCdns = listOf("snapdealcdn.com")
        ),
        OfficialBrand(
            name = "AliExpress",
            primaryDomain = "aliexpress.com",
            aliases = emptyList(),
            trustedSubdomains = listOf("www", "m"),
            trustedCdns = listOf("akamaized.net")
        ),
        OfficialBrand(
            name = "Shopify",
            primaryDomain = "shopify.com",
            aliases = emptyList(),
            trustedSubdomains = listOf("www", "help", "community", "apps"),
            trustedCdns = listOf("shopifycdn.com", "shopify.com.cdn.cloudflare.net")
        ),
        
        // ==== FOOD & DELIVERY ====
        OfficialBrand(
            name = "Swiggy",
            primaryDomain = "swiggy.com",
            aliases = emptyList(),
            trustedSubdomains = listOf("www", "m", "help"),
            trustedCdns = listOf("swiggyscdn.com")
        ),
        OfficialBrand(
            name = "Zomato",
            primaryDomain = "zomato.com",
            aliases = emptyList(),
            trustedSubdomains = listOf("www", "m", "help"),
            trustedCdns = listOf("zomatocdn.com")
        ),
        OfficialBrand(
            name = "Uber Eats",
            primaryDomain = "ubereats.com",
            aliases = emptyList(),
            trustedSubdomains = listOf("www", "m", "help"),
            trustedCdns = emptyList()
        ),
        OfficialBrand(
            name = "DoorDash",
            primaryDomain = "doordash.com",
            aliases = emptyList(),
            trustedSubdomains = listOf("www", "help"),
            trustedCdns = emptyList()
        ),
        
        // ==== TECH & SOFTWARE ====
        OfficialBrand(
            name = "GitHub",
            primaryDomain = "github.com",
            aliases = emptyList(),
            trustedSubdomains = listOf("www", "status", "help", "raw.githubusercontent.com"),
            trustedCdns = listOf("githubusercontent.com", "ghcr.io")
        ),
        OfficialBrand(
            name = "Microsoft",
            primaryDomain = "microsoft.com",
            aliases = emptyList(),
            trustedSubdomains = listOf("www", "account", "support", "learn", "docs"),
            trustedCdns = listOf("msn.com", "microsoft-tst.com")
        ),
        OfficialBrand(
            name = "Apple",
            primaryDomain = "apple.com",
            aliases = listOf("icloud.com"),
            trustedSubdomains = listOf("www", "support", "developer", "www1", "www2"),
            trustedCdns = listOf("iCloud.com", "mzstatic.com")
        ),
        OfficialBrand(
            name = "Slack",
            primaryDomain = "slack.com",
            aliases = emptyList(),
            trustedSubdomains = listOf("www", "app", "help"),
            trustedCdns = listOf("slack-edge.com")
        ),
        OfficialBrand(
            name = "Zoom",
            primaryDomain = "zoom.us",
            aliases = emptyList(),
            trustedSubdomains = listOf("www", "app", "support", "help"),
            trustedCdns = emptyList()
        ),
        OfficialBrand(
            name = "Dropbox",
            primaryDomain = "dropbox.com",
            aliases = listOf("db.tt"),
            trustedSubdomains = listOf("www", "help", "support"),
            trustedCdns = listOf("dropboxstatic.com", "dropboxusercontent.com")
        ),
        OfficialBrand(
            name = "Netflix",
            primaryDomain = "netflix.com",
            aliases = emptyList(),
            trustedSubdomains = listOf("www", "help", "www1", "www2"),
            trustedCdns = listOf("nflxext.com", "nflximg.net")
        ),
        OfficialBrand(
            name = "Spotify",
            primaryDomain = "spotify.com",
            aliases = emptyList(),
            trustedSubdomains = listOf("www", "open", "support", "developer"),
            trustedCdns = listOf("spotify.com", "spotifycdn.com")
        ),
        
        // ==== PAYMENT & FINANCIAL ====
        OfficialBrand(
            name = "PayPal",
            primaryDomain = "paypal.com",
            aliases = emptyList(),
            trustedSubdomains = listOf("www", "help", "developer"),
            trustedCdns = listOf("paypalobjects.com")
        ),
        OfficialBrand(
            name = "Stripe",
            primaryDomain = "stripe.com",
            aliases = emptyList(),
            trustedSubdomains = listOf("www", "support", "developer"),
            trustedCdns = listOf("stripe.com.cdn")
        ),
        OfficialBrand(
            name = "Paytm",
            primaryDomain = "paytm.com",
            aliases = emptyList(),
            trustedSubdomains = listOf("www", "help", "blog"),
            trustedCdns = listOf("paytmcdn.com")
        ),
        
        // ==== BOOKING & TRAVEL ====
        OfficialBrand(
            name = "Booking.com",
            primaryDomain = "booking.com",
            aliases = emptyList(),
            trustedSubdomains = listOf("www", "m", "help"),
            trustedCdns = listOf("bstatic.com")
        ),
        OfficialBrand(
            name = "Airbnb",
            primaryDomain = "airbnb.com",
            aliases = listOf("airbnb.co", "airbnb.ie"),
            trustedSubdomains = listOf("www", "m", "help"),
            trustedCdns = listOf("airbnbcdn.com")
        ),
        OfficialBrand(
            name = "Expedia",
            primaryDomain = "expedia.com",
            aliases = emptyList(),
            trustedSubdomains = listOf("www", "m", "help"),
            trustedCdns = listOf("expediacdn.com")
        ),
        
        // ==== STREAMING & ENTERTAINMENT ====
        OfficialBrand(
            name = "HBO Max",
            primaryDomain = "hbomax.com",
            aliases = listOf("max.com"),
            trustedSubdomains = listOf("www", "help"),
            trustedCdns = emptyList()
        ),
        OfficialBrand(
            name = "Disney+",
            primaryDomain = "disneyplus.com",
            aliases = emptyList(),
            trustedSubdomains = listOf("www", "help"),
            trustedCdns = emptyList()
        ),
        
        // ==== INDIAN BANKS ====
        OfficialBrand(
            name = "ICICI Bank",
            primaryDomain = "icicibank.com",
            aliases = listOf("icici.com"),
            trustedSubdomains = listOf("www", "m", "help", "corporate"),
            trustedCdns = emptyList()
        ),
        OfficialBrand(
            name = "Axis Bank",
            primaryDomain = "axisbank.com",
            aliases = listOf("axis.com", "axisbank.co.in"),
            trustedSubdomains = listOf("www", "m", "help", "corporate"),
            trustedCdns = emptyList()
        ),
        OfficialBrand(
            name = "HDFC Bank",
            primaryDomain = "hdfcbank.com",
            aliases = listOf("hdfc.com"),
            trustedSubdomains = listOf("www", "m", "help", "corporate", "online"),
            trustedCdns = emptyList()
        ),
        OfficialBrand(
            name = "State Bank of India",
            primaryDomain = "sbi.co.in",
            aliases = listOf("sbionline.sbi.co.in"),
            trustedSubdomains = listOf("www", "m", "help"),
            trustedCdns = emptyList()
        ),
        OfficialBrand(
            name = "Bank of Baroda",
            primaryDomain = "bankofbaroda.in",
            aliases = listOf("bob.co.in", "bob.in"),
            trustedSubdomains = listOf("www", "m", "help"),
            trustedCdns = emptyList()
        ),
        OfficialBrand(
            name = "Canara Bank",
            primaryDomain = "canara.co.in",
            aliases = listOf("canarabank.com"),
            trustedSubdomains = listOf("www", "m", "help"),
            trustedCdns = emptyList()
        ),
        OfficialBrand(
            name = "Kotak Bank",
            primaryDomain = "kotak.com",
            aliases = listOf("kotakbank.com"),
            trustedSubdomains = listOf("www", "m", "help", "corporate"),
            trustedCdns = emptyList()
        ),
        OfficialBrand(
            name = "IndusInd Bank",
            primaryDomain = "indusind.com",
            aliases = listOf("indusindbank.com"),
            trustedSubdomains = listOf("www", "m", "help"),
            trustedCdns = emptyList()
        ),
        OfficialBrand(
            name = "YES Bank",
            primaryDomain = "yesbank.in",
            aliases = listOf("yesbankltd.com"),
            trustedSubdomains = listOf("www", "m", "help"),
            trustedCdns = emptyList()
        ),
        OfficialBrand(
            name = "IDBI Bank",
            primaryDomain = "idbi.com",
            aliases = listOf("idbionline.com"),
            trustedSubdomains = listOf("www", "m", "help"),
            trustedCdns = emptyList()
        ),
        OfficialBrand(
            name = "Standard Chartered",
            primaryDomain = "standardchartered.co.in",
            aliases = listOf("sc.com"),
            trustedSubdomains = listOf("www", "m", "help"),
            trustedCdns = emptyList()
        ),
        OfficialBrand(
            name = "HSBC India",
            primaryDomain = "hsbc.co.in",
            aliases = listOf("hsbc.com"),
            trustedSubdomains = listOf("www", "m", "help"),
            trustedCdns = emptyList()
        ),
        OfficialBrand(
            name = "Citi Bank India",
            primaryDomain = "citibank.co.in",
            aliases = listOf("citibank.com"),
            trustedSubdomains = listOf("www", "m", "help"),
            trustedCdns = emptyList()
        ),
        OfficialBrand(
            name = "Federal Bank",
            primaryDomain = "federalbank.co.in",
            aliases = emptyList(),
            trustedSubdomains = listOf("www", "m", "help"),
            trustedCdns = emptyList()
        ),
        OfficialBrand(
            name = "South Indian Bank",
            primaryDomain = "southindianbank.in",
            aliases = emptyList(),
            trustedSubdomains = listOf("www", "m", "help"),
            trustedCdns = emptyList()
        ),
        OfficialBrand(
            name = "AU Bank",
            primaryDomain = "aubank.in",
            aliases = listOf("aubankonline.com"),
            trustedSubdomains = listOf("www", "m", "help"),
            trustedCdns = emptyList()
        )
    )
    
    /**
     * Verify a domain against the official registry
     * Returns VERIFIED_OFFICIAL if recognized, BRAND_ABUSE if suspect, UNKNOWN otherwise
     * 
     * @param checkHost The domain host to verify
     * @return VerificationResult with status and reason
     */
    fun verifyDomain(checkHost: String): VerificationResult {
        return try {
            // Normalize input
            val normalizedHost = checkHost.lowercase().trim()
            
            OFFICIAL_BRANDS.forEach { brand ->
                // Check 1: Exact match with primary domain
                if (normalizedHost == brand.primaryDomain) {
                    Log.d(TAG, "✅ Verified Official: ${brand.name} (exact match: $normalizedHost)")
                    return VerificationResult(
                        VerificationStatus.VERIFIED_OFFICIAL,
                        brand.name,
                        "✅ Verified official ${brand.name} domain"
                    )
                }
                
                // Check 2: Alias match
                if (normalizedHost in brand.aliases) {
                    Log.d(TAG, "✅ Verified Official: ${brand.name} (alias: $normalizedHost)")
                    return VerificationResult(
                        VerificationStatus.VERIFIED_OFFICIAL,
                        brand.name,
                        "✅ Verified official ${brand.name} shortener"
                    )
                }
                
                // Check 3: Trusted CDN
                if (normalizedHost in brand.trustedCdns) {
                    Log.d(TAG, "✅ Verified Official: ${brand.name} (CDN: $normalizedHost)")
                    return VerificationResult(
                        VerificationStatus.VERIFIED_OFFICIAL,
                        brand.name,
                        "✅ Verified official ${brand.name} CDN"
                    )
                }
                
                // Check 4: Valid subdomain check
                if (isTrustedSubdomain(normalizedHost, brand)) {
                    Log.d(TAG, "✅ Verified Official: ${brand.name} (subdomain: $normalizedHost)")
                    return VerificationResult(
                        VerificationStatus.VERIFIED_OFFICIAL,
                        brand.name,
                        "✅ Verified official ${brand.name} subdomain"
                    )
                }
                
                // Check 5: Brand abuse detection (contains brand keyword but not official)
                if (containsBrandKeyword(normalizedHost, brand.name, brand.primaryDomain)) {
                    Log.d(TAG, "🔴 Brand Abuse Detected: ${brand.name} in $normalizedHost")
                    return VerificationResult(
                        VerificationStatus.BRAND_ABUSE,
                        brand.name,
                        "🔴 DANGEROUS: Abuses ${brand.name} brand - This is fake"
                    )
                }
            }
            
            // Not in registry and no brand abuse detected
            Log.d(TAG, "❓ Unknown domain: $normalizedHost")
            VerificationResult(
                VerificationStatus.UNKNOWN,
                null,
                "Not in official registry - defer to phishing checks"
            )
            
        } catch (e: Exception) {
            Log.e(TAG, "Error verifying domain: ${e.message}", e)
            VerificationResult(
                VerificationStatus.UNKNOWN,
                null,
                "Verification error: ${e.message}"
            )
        }
    }
    
    /**
     * Check if domain is a trusted subdomain of a brand
     * Example: m.youtube.com, support.youtube.com
     */
    private fun isTrustedSubdomain(host: String, brand: OfficialBrand): Boolean {
        // Try to match trusted subdomains
        for (trustedSub in brand.trustedSubdomains) {
            val subdomainHost = "$trustedSub.${brand.primaryDomain}"
            if (host == subdomainHost) {
                return true
            }
        }
        
        // Also check aliases
        for (alias in brand.aliases) {
            if (host == alias) {
                return true
            }
        }
        
        return false
    }
    
    /**
     * Detect if domain contains brand keyword but is NOT official
     * Prevents trademark abuse like "youtube-clone.com" or "youtube.evil.com"
     */
    private fun containsBrandKeyword(host: String, brandName: String, primaryDomain: String): Boolean {
        val brandKeywordLower = brandName.lowercase()
        val hostLower = host.lowercase()
        
        // Check if brand keyword exists in domain
        if (!hostLower.contains(brandKeywordLower)) {
            return false  // Brand keyword not present
        }
        
        // If it contains brand keyword, it should be the primary domain or valid subdomain
        // If it's not, it's brand abuse
        
        // Exception: if it's the primary domain itself, it's not abuse
        if (hostLower == primaryDomain) {
            return false
        }
        
        // Exception: if it's an obvious subdomain like www.youtube.com, it's fine
        if (hostLower.endsWith(".$primaryDomain")) {
            return false  // Valid subdomain
        }
        
        // Brand keyword is in domain but not as official → ABUSE
        // Examples: "youtube-clone.com", "youtubbe.com", "youtube.evil.com"
        return true
    }
    
    /**
     * Get all verified brands (for debugging/logging)
     */
    fun getAllBrands(): List<OfficialBrand> = OFFICIAL_BRANDS
}
