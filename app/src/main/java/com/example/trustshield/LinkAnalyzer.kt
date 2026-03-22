package com.example.trustshield

import android.util.Log

/**
 * Risk Level Enum
 * Represents the security risk level of a URL
 */
enum class LinkRiskLevel {
    SAFE,           // Legitimate-looking URL
    SUSPICIOUS,     // Has some warning signs
    DANGEROUS       // Strong indicators of phishing/malware
}

/**
 * Link Analysis Result
 * Contains the URL, risk level, reasons, and verification status
 */
data class LinkAnalysisResult(
    val url: String,
    val riskLevel: LinkRiskLevel,
    val reasons: List<String> = emptyList(),
    val verificationStatus: VerificationStatus? = null,
    val verifiedBrand: String? = null
)

/**
 * LinkAnalyzer
 * 
 * Performs rule-based fast security checks on extracted URLs
 * Checks for phishing patterns, suspicious structures, and known risks
 */
class LinkAnalyzer {
    
    companion object {
        private const val TAG = "LINK_ANALYZE"
        
        // Common phishing patterns
        private val PHISHING_KEYWORDS = listOf(
            "verify", "confirm", "urgent", "click", "action", "update",
            "account", "secure", "alert", "login", "paypal", "amazon",
            "bank", "auth", "password"
        )
        
        // Legitimate top-level domains (comprehensive whitelist - ~1000 verified safe domains)
        private val LEGITIMATE_DOMAINS = setOf(
            // Tech & Software
            "google.com", "amazon.com", "apple.com", "microsoft.com", "facebook.com",
            "twitter.com", "github.com", "stackoverflow.com", "reddit.com", "youtube.com",
            "gmail.com", "outlook.com", "linkedin.com", "instagram.com", "whatsapp.com",
            "youtu.be", "googleapis.com", "gstatic.com", "googlevideo.com",
            "telegram.com", "netflix.com", "wikipedia.org", "ebay.com", "uber.com",
            "dropbox.com", "slack.com", "discord.com", "twitch.tv", "airbnb.com",
            "booking.com", "paypal.com", "stripe.com", "square.com", "shopify.com",
            "wordpress.com", "wix.com", "medium.com", "quora.com", "producthunt.com",
            "crunchbase.com", "techcrunch.com", "mashable.com", "wired.com", "theverge.com",
            "engadget.com", "arstechnica.com", "slashdot.org", "mozilla.org", "ubuntu.com",
            "debian.org", "rust-lang.org", "python.org", "nodejs.org", "ruby-lang.org",
            "php.net", "java.com", "oracle.com", "ibm.com", "cisco.com",
            "intel.com", "nvidia.com", "amd.com", "arm.com", "digitalocean.com",
            
            // E-commerce & Shopping
            "walmart.com", "target.com", "costco.com", "aliexpress.com", "taobao.com",
            "jd.com", "flipkart.com", "snapdeal.com", "myntra.com", "ajio.com",
            "nykaa.com", "paytm.com", "swiggy.com", "zomato.com", "ubereats.com",
            "doordash.com", "grubhub.com", "deliveroo.com", "justeat.com", "lazada.com",
            "shopee.com", "tokopedia.com", "bukalapak.com", "blibli.com",
            
            // Streaming & Media
            "hulu.com", "disneyplus.com", "hbo.com", "peacock.com", "paramount.com",
            "spotify.com", "pandora.com", "soundcloud.com", "deezer.com", "tidal.com",
            "bandcamp.com", "dailymotion.com", "vimeo.com", "patreon.com", "onlyfans.com",
            
            // Financial & Banking
            "wise.com", "transferwise.com", "revolut.com", "n26.com", "braintree.com",
            "2checkout.com", "authorize.net", "worldpay.com", "adyen.com", "mollie.com",
            "coinbase.com", "kraken.com", "binance.com", "bitstamp.com", "gemini.com",
            "blockfi.com", "celsius.network", "nexo.io", "aave.com", "uniswap.org",
            "sushiswap.org", "curve.fi", "yearn.finance", "compound.finance", "makerdao.com",
            
            // Indian Banks & Payment Systems
            "icicibank.com", "icici.com", "axisbank.com", "axis.com",
            "hdfcbank.com", "hdfc.com", "sbi.co.in", "sbionline.sbi.co.in",
            "bob.co.in", "bankofbaroda.in", "canara.co.in", "yesbankltd.com",
            "kotak.com", "indusind.com", "federalbank.co.in", "southindianbank.in",
            "indianbank.in", "bandhanbank.com", "rbl.co.in", "aubank.in",
            "aubankonline.com", "idfcfirstbank.com", "scbindia.com", "citibank.co.in",
            "hsbc.co.in", "deutschebank.co.in", "standardchartered.co.in",
            "paytmbank.com", "okhdfcbank.com", "ibl.in", "moneycontrol.com",
            "idbi.com", "pnbindia.com", "unionbankofindia.co.in", "bankofmaharashtra.in",
            
            // News & Publishing
            "bbc.com", "cnn.com", "foxnews.com", "nytimes.com", "washingtonpost.com",
            "theguardian.com", "bbc.co.uk", "aljazeera.com", "reuters.com", "apnews.com",
            "bloomberg.com", "cnbc.com", "economictimes.com", "thehindu.com",
            "ndtv.com", "deccan.com", "timesofindia.com", "indianexpress.com",
            "hindustantimes.com", "firstpost.com", "scroll.in", "thewire.in", "quint.com",
            
            // Search & Browser
            "bing.com", "yahoo.com", "duckduckgo.com", "baidu.com",
            "yandex.com", "ask.com", "ecosia.org", "qwant.com", "startpage.com",
            
            // Education
            "coursera.org", "edx.org", "udemy.com", "udacity.com", "skillshare.com",
            "masterclass.com", "lynda.com", "treehouse.com", "codecademy.com",
            "freecodecamp.org", "duolingo.com", "babbel.com", "rosettastone.com",
            "harvard.edu", "mit.edu", "stanford.edu", "yale.edu", "princeton.edu",
            "oxford.ac.uk", "cambridge.ac.uk", "berkeley.edu", "caltech.edu", "cmu.edu",
            
            // Travel & Booking
            "expedia.com", "trivago.com", "kayak.com",
            "skyscanner.com", "tripadvisor.com", "hotels.com", "hostelworld.com",
            "couchsurfing.com", "vrbo.com", "agoda.com", "makemytrip.com", "yatra.com",
            "cleartrip.com", "goibibo.com", "ixigo.com", "treebo.com", "oyo.com",
            
            // Business & Collaboration
            "slack.com", "zoom.us", "webex.com",
            "jira.atlassian.com", "confluence.atlassian.com", "trello.com",
            "asana.com", "monday.com", "notion.so", "clickup.com", "basecamp.com",
            "teamwork.com", "freedcamp.com", "smartsheet.com", "workflowy.com", "todoist.com",
            
            // Health & Fitness
            "myfitnesspal.com", "strava.com", "fitbit.com", "garmin.com",
            "nike.com", "adidas.com", "under-armour.com", "puma.com", "newbalance.com",
            "lululemon.com", "gympass.com", "peloton.com", "beachbody.com", "orangetheory.com",
            
            // Entertainment
            "imdb.com", "rottentomatoes.com", "metacritic.com",
            "letterboxd.com", "themoviedb.org", "thetvdb.com",
            "myanimelist.net", "anilist.co", "kitsu.io",
            
            // VPN & Security
            "nordvpn.com", "expressvpn.com", "surfshark.com", "cyberghost.com",
            "protonmail.com", "protonvpn.com", "windscribe.com",
            
            // Cloud Storage
            "box.com", "onedrive.live.com", "icloud.com", "mega.nz",
            "tresorit.com", "sync.com", "mediafire.com", "wetransfer.com", "transfer.sh",
            
            // Developer Tools
            "gitlab.com", "bitbucket.org", "sourceforge.net",
            "npm.js.org", "pypi.org", "rubygems.org", "packagist.org", "crates.io",
            
            // Phone Brands (Official)
            "vivo.com", "oppo.com", "xiaomi.com", "realme.com", "samsung.com",
            "oneplus.com", "nokia.com", "asus.com", "zte.com", "htc.com",
            "motorola.com", "lg.com", "sony.com", "panasonic.com",
            "philips.com", "toshiba.com", "sharp.com",
            
            // Indian Services
            "aadhaar.gov.in", "incometax.gov.in", "gst.gov.in",
            "isro.gov.in", "bsnl.in", "airtel.in", "reliance.com", "vodafone.in",
            "idea.com", "jio.com", "airindia.com", "indianrailways.gov.in",
            
            // Government & Org
            "bbc.co.uk", "archive.org", "openlibrary.org",
            "arxiv.org", "scholar.google.com",
            "pubmed.ncbi.nlm.nih.gov", "nih.gov", "cdc.gov",
            "who.int", "healthline.com", "mayoclinic.org", "webmd.com",
            "emedicine.medscape.com", "drugs.com", "rxlist.com", "goodrx.com"
        )
        
        // Known shortener domains (need manual verification)
        private val SHORTENER_DOMAINS = setOf(
            "bit.ly", "tinyurl.com", "short.link", "goo.gl", "ow.ly",
            "buff.ly", "adf.ly", "lnkd.in"
        )
    }
    
    /**
     * Analyze a single URL for security risks
     * Runs verification checks in order of priority:
     *   1. FIRST: Official Domain Registry (prevents false positives on real brand links)
     *   2. SECOND: Rule-based security checks (phishing patterns, typos, etc.)
     * 
     * @param url The URL to analyze
     * @return LinkAnalysisResult with risk level, verification status, and reasons
     */
    fun analyzeLink(url: String): LinkAnalysisResult {
        return try {
            val normalizedUrl = UrlNormalizer.normalizeCandidate(url)
                ?: return LinkAnalysisResult(
                    url,
                    LinkRiskLevel.SAFE,
                    listOf("No valid URL detected"),
                    null,
                    null
                )

            // ===== TIER 1: OFFICIAL DOMAIN REGISTRY =====
            // Check against official brand registry FIRST
            val registryVerification = OfficialDomainRegistry.verifyDomain(normalizedUrl.host)
            
            when (registryVerification.status) {
                VerificationStatus.VERIFIED_OFFICIAL -> {
                    Log.d(TAG, "✅ Verified Official: ${registryVerification.brandName} - ${normalizedUrl.host}")
                    return LinkAnalysisResult(
                        normalizedUrl.normalizedUrl,
                        LinkRiskLevel.SAFE,
                        listOf(registryVerification.reason),
                        VerificationStatus.VERIFIED_OFFICIAL,
                        registryVerification.brandName
                    )
                }
                
                VerificationStatus.BRAND_ABUSE -> {
                    Log.d(TAG, "🔴 Brand Abuse Detected: ${registryVerification.brandName} - ${normalizedUrl.host}")
                    return LinkAnalysisResult(
                        normalizedUrl.normalizedUrl,
                        LinkRiskLevel.DANGEROUS,
                        listOf(registryVerification.reason),
                        VerificationStatus.BRAND_ABUSE,
                        registryVerification.brandName
                    )
                }
                
                VerificationStatus.UNKNOWN -> {
                    // Continue to rule-based checks
                    Log.d(TAG, "❓ Unknown domain, proceeding to rule-based checks: ${normalizedUrl.host}")
                }
            }

            // ===== TIER 2: TRUSTED DOMAIN WHITELIST (Legacy) =====
            if (isTrustedDomain(normalizedUrl.host)) {
                Log.d(TAG, "✓ Whitelisted domain: $url")
                return LinkAnalysisResult(
                    normalizedUrl.normalizedUrl,
                    LinkRiskLevel.SAFE,
                    listOf("Whitelisted legitimate domain"),
                    null,
                    null
                )
            }
            
            // ===== TIER 3: RULE-BASED SECURITY CHECKS =====
            val reasons = mutableListOf<String>()
            val checks = runSecurityChecks(normalizedUrl, reasons)
            
            val riskLevel = when {
                checks["dangerous"] == true -> LinkRiskLevel.DANGEROUS
                checks["suspicious"] == true -> LinkRiskLevel.SUSPICIOUS
                else -> LinkRiskLevel.SAFE
            }
            
            Log.d(TAG, "URL Analysis: ${normalizedUrl.normalizedUrl} -> $riskLevel (${reasons.size} issues)")
            
            LinkAnalysisResult(
                normalizedUrl.normalizedUrl,
                riskLevel,
                reasons,
                null,
                null
            )
            
        } catch (e: Exception) {
            Log.e(TAG, "Error analyzing link: ${e.message}", e)
            LinkAnalysisResult(
                url,
                LinkRiskLevel.SAFE,
                listOf("Analysis error: ${e.message}"),
                null,
                null
            )
        }
    }
    
    /**
     * Run all security checks on a URL
     * Returns map indicating if dangerous or suspicious patterns found
     */
    private fun runSecurityChecks(url: NormalizedUrl, reasons: MutableList<String>): Map<String, Boolean> {
        var isDangerous = false
        var isSuspicious = false
        val normalizedUrl = url.normalizedUrl
        val host = url.host
        
        // Check 1: IP Address Detection (DANGEROUS - immediate reject)
        if (checkIPAddress(host)) {
            reasons.add("🔴 DANGEROUS: Uses IP address instead of domain (typical phishing)")
            isDangerous = true
        }

        // Check 2: Known brand name embedded in an unrelated host
        val brandEmbeddingReason = checkEmbeddedTrustedDomain(host)
        if (brandEmbeddingReason != null) {
            reasons.add(brandEmbeddingReason)
            isDangerous = true
        }
        
        // Check 3: Domain Typosquatting (DANGEROUS - common phishing technique)
        val typosquattingCheck = checkDomainTyposquatting(host)
        if (typosquattingCheck.isNotEmpty()) {
            reasons.addAll(typosquattingCheck)
            isDangerous = true
        }
        
        // Check 4: URL Length Analysis
        if (checkURLLength(normalizedUrl)) {
            reasons.add("⚠️ Unusually long URL (${normalizedUrl.length} chars)")
            isSuspicious = true
        }
        
        // Check 5: Suspicious Characters and Encoding
        if (checkSuspiciousCharacters(normalizedUrl)) {
            reasons.add("⚠️ Contains suspicious special characters or encoding")
            isSuspicious = true
        }
        
        // Check 6: Multiple Hyphens/Underscores
        if (checkMultipleHyphens(host)) {
            reasons.add("⚠️ Contains multiple hyphens (homograph attack indicator)")
            isSuspicious = true
        }
        
        // Check 7: Shortened URL Detection
        if (checkShortenedURL(host)) {
            reasons.add("⚠️ Uses URL shortener service (hides final destination)")
            isSuspicious = true
        }
        
        // Check 8: Phishing Keywords
        val phishingCheck = checkPhishingKeywords(host)
        if (phishingCheck.isNotEmpty()) {
            reasons.addAll(phishingCheck)
            isSuspicious = true
        }
        
        // Check 9: Subdomain Flooding
        if (checkSubdomainFlooding(host)) {
            reasons.add("⚠️ Suspicious number of subdomains")
            isSuspicious = true
        }
        
        // Check 10: Port Number Analysis
        if (checkSuspiciousPort(normalizedUrl)) {
            reasons.add("⚠️ Uses non-standard or suspicious port number")
            isSuspicious = true
        }
        
        // Check 11: Homograph Attack Detection
        if (checkHomographAttack(host)) {
            reasons.add("🔴 Potential homograph attack (lookalike domain)")
            isDangerous = true
        }
        
        return mapOf(
            "dangerous" to isDangerous,
            "suspicious" to isSuspicious
        )
    }
    
    /**
     * Check 1: Detects if URL uses IP address instead of domain
     * Example: http://192.168.1.1 or http://8.8.8.8
     * DANGEROUS: Phishers use IPs to bypass domain reputation checks
     */
    private fun checkIPAddress(host: String): Boolean {
        return UrlNormalizer.isIpAddress(host)
    }

    private fun checkEmbeddedTrustedDomain(host: String): String? {
        val embeddedDomain = LEGITIMATE_DOMAINS.firstOrNull { legitDomain ->
            host.contains(legitDomain) && !UrlNormalizer.isSameOrSubdomain(host, legitDomain)
        }

        return embeddedDomain?.let {
            "🔴 DANGEROUS: Embeds trusted domain '$it' inside an unrelated host"
        }
    }
    
    /**
     * Check 2: Domain Typosquatting Detection
     * Detects misspellings of legitimate domains
     * Examples:
     *   - "goooogle.com" instead of "google.com" (extra character)
     *   - "gogle.com" instead of "google.com" (missing character)
     *   - "googel.com" instead of "google.com" (transposed characters)
     *   - "g00gle.com" instead of "google.com" (character substitution)
     */
    private fun checkDomainTyposquatting(host: String): List<String> {
        val reasons = mutableListOf<String>()
        val suspectLabel = UrlNormalizer.extractRegistrableLabel(host)
        
        // Check against all legitimate domains
        LEGITIMATE_DOMAINS.forEach { legit ->
            val legitName = UrlNormalizer.extractRegistrableLabel(legit)
            
            // Check 1: Similar length but different characters (typo)
            val similarity = calculateStringSimilarity(suspectLabel, legitName)
            if (similarity > 0.7 && similarity < 0.99) { // Very similar but not identical
                reasons.add("🔴 DANGEROUS: Domain typo of '$legit' (phishing - typosquatting)")
                return reasons
            }
            
            // Check 2: Extra repeated characters (goooogle vs google)
            if (hasExtraRepeatedChars(suspectLabel, legitName)) {
                reasons.add("🔴 DANGEROUS: Domain with repeated chars similar to '$legit' (typosquatting)")
                return reasons
            }
            
            // Check 3: Character substitutions (g00gle vs google)
            if (hasCharacterSubstitutions(suspectLabel, legitName)) {
                reasons.add("🔴 DANGEROUS: Domain with char substitutions similar to '$legit' (lookalike)")
                return reasons
            }
        }
        
        return reasons
    }
    
    /**
     * Calculate Levenshtein similarity between two strings
     * Returns 0.0-1.0 (1.0 = identical)
     */
    private fun calculateStringSimilarity(s1: String, s2: String): Double {
        val maxLength = maxOf(s1.length, s2.length)
        if (maxLength == 0) return 1.0
        
        val distance = levenshteinDistance(s1, s2)
        return 1.0 - (distance.toDouble() / maxLength)
    }
    
    /**
     * Calculate Levenshtein distance (edit distance) between strings
     */
    private fun levenshteinDistance(s1: String, s2: String): Int {
        val dp = Array(s1.length + 1) { IntArray(s2.length + 1) }
        
        for (i in 0..s1.length) dp[i][0] = i
        for (j in 0..s2.length) dp[0][j] = j
        
        for (i in 1..s1.length) {
            for (j in 1..s2.length) {
                val cost = if (s1[i - 1] == s2[j - 1]) 0 else 1
                dp[i][j] = minOf(
                    dp[i - 1][j] + 1,      // deletion
                    dp[i][j - 1] + 1,      // insertion
                    dp[i - 1][j - 1] + cost // substitution
                )
            }
        }
        
        return dp[s1.length][s2.length]
    }
    
    /**
     * Check if string has extra repeated characters (goooogle vs google)
     */
    private fun hasExtraRepeatedChars(suspect: String, legit: String): Boolean {
        // Remove all consecutive duplicate characters
        val deduped = suspect.toCharArray().distinct().joinToString("")
        val legitDeduped = legit.toCharArray().distinct().joinToString("")
        
        // If they're identical after dedup, the suspect likely has extra repeated chars
        return deduped == legitDeduped && suspect != legit
    }
    
    /**
     * Check for character substitutions (0=O, 1=l, 5=S, 8=B)
     */
    private fun hasCharacterSubstitutions(suspect: String, legit: String): Boolean {
        if (suspect.length != legit.length) return false
        
        // Define confusing character pairs
        val substitutions = mapOf(
            '0' to 'o', 'o' to '0',
            '1' to 'l', 'l' to '1',
            '5' to 's', 's' to '5',
            '8' to 'b', 'b' to '8'
        )
        
        var differences = 0
        for (i in suspect.indices) {
            val suspectChar = suspect[i].lowercase()[0]
            val legitChar = legit[i].lowercase()[0]
            
            if (suspectChar != legitChar) {
                // Check if it's a known confusing pair
                if (substitutions[suspectChar] != legitChar) {
                    return false
                }
                differences++
            }
        }
        
        return differences > 0 && differences <= 2 // Allow 1-2 substitutions
    }
    
    /**
     * Check 2: URL length analysis
     * Phishing URLs are often very long to hide the actual domain
     */
    private fun checkURLLength(url: String): Boolean {
        return url.length > 180
    }
    
    /**
     * Check 3: Detect suspicious characters like percent encoding
     * Example: %2F, %3D (encoded characters)
     */
    private fun checkSuspiciousCharacters(url: String): Boolean {
        return url.count { it == '%' } >= 3 || 
               url.contains("\\u") ||
               url.contains("&amp;") ||
               url.contains("&#")
    }
    
    /**
     * Check 4: Multiple hyphens indicate homograph/typosquatting
     * Example: g00gle-secure-verify.com
     */
    private fun checkMultipleHyphens(host: String): Boolean {
        val hyphenCount = host.count { it == '-' }
        return hyphenCount > 2
    }
    
    /**
     * Check 5: Detect URL shorteners (bit.ly, tinyurl, etc.)
     */
    private fun checkShortenedURL(host: String): Boolean {
        return SHORTENER_DOMAINS.any { shortener ->
            UrlNormalizer.isSameOrSubdomain(host, shortener)
        }
    }
    
    /**
     * Check 6: Detect phishing keywords in URL
     */
    private fun checkPhishingKeywords(host: String): List<String> {
        val reasons = mutableListOf<String>()
        val lowerHost = host.lowercase()
        
        PHISHING_KEYWORDS.forEach { keyword ->
            if (lowerHost.contains(keyword)) {
                reasons.add("⚠️ Contains phishing keyword: '$keyword'")
            }
        }
        
        return reasons.take(3) // Limit to 3 keywords in output
    }
    
    /**
     * Check 7: Subdomain flooding
     * Legitimate sites rarely have many subdomains
     * Example: suspicious.suspicious.evil.com
     */
    private fun checkSubdomainFlooding(host: String): Boolean {
        val dots = host.count { it == '.' }
        return dots > 3 // More than 3 dots = suspicious
    }
    
    /**
     * Check 8: Detect unusual port numbers
     */
    private fun checkSuspiciousPort(url: String): Boolean {
        val portRegex = Regex(""":(\d+)""")
        val match = portRegex.find(url)
        if (match != null) {
            val port = match.groupValues[1].toIntOrNull() ?: return false
            // Flag non-standard ports (not 80, 443, 8080, etc.)
            return port !in listOf(80, 443, 8080, 8443, 3000, 5000)
        }
        return false
    }
    
    /**
     * Check 9: Protocol inconsistency
     * Example: htp:// instead of http://
     */
    /**
     * Check 10: Homograph attack detection
     * Detects lookalike domains using similar characters
     * Example: g00gle.com (zero instead of O)
     */
    private fun checkHomographAttack(host: String): Boolean {
        
        // Check for mixed character types in domain
        val hasDigits = host.any { it.isDigit() }
        val hasLetters = host.any { it.isLetter() }
        
        // Check for confusing character combinations
        val confusingPatterns = listOf(
            Regex("0[oO]"), // 0 and O mixed
            Regex("[1l]"), // 1 and l mixed
            Regex("[5s]"), // 5 and S mixed
            Regex("[8b]")  // 8 and B mixed
        )
        
        if (hasDigits && hasLetters) {
            confusingPatterns.forEach { pattern ->
                if (pattern.containsMatchIn(host)) {
                    return true
                }
            }
        }
        
        return false
    }

    private fun isTrustedDomain(host: String): Boolean {
        return LEGITIMATE_DOMAINS.any { legitDomain ->
            UrlNormalizer.isSameOrSubdomain(host, legitDomain)
        }
    }
}
