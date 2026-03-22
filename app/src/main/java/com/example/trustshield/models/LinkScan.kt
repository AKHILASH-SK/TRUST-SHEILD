package com.example.trustshield.models

/**
 * LinkScan data class
 * Represents a scanned link and its analysis result
 */
data class LinkScan(
    val scanId: String = "",
    val url: String = "",
    val host: String = "",
    val verdict: String = "SAFE",  // SAFE, SUSPICIOUS, DANGEROUS
    val riskLevel: String = "SAFE",
    val verificationStatus: String? = null,  // VERIFIED_OFFICIAL, BRAND_ABUSE, UNKNOWN
    val verifiedBrand: String? = null,  // e.g., "YouTube", "Facebook"
    val reasons: List<String> = emptyList(),
    val sourceApp: String = "Unknown",  // Which app the notification came from
    val timestamp: Long = 0L,
    val userAction: String = "ignored",  // accepted, rejected, ignored
    val reviewedAt: Long = 0L,
    val isUserTrusted: Boolean = false,  // Did user mark this as safe?
    val isUserBlocked: Boolean = false   // Did user block this?
) {
    // No-arg constructor for Firebase
    constructor() : this("", "", "", "SAFE", "SAFE", null, null, emptyList(), "Unknown", 0L, "ignored", 0L, false, false)
}

/**
 * User statistics
 */
data class UserStats(
    val totalScans: Int = 0,
    val safeLinks: Int = 0,
    val suspiciousLinks: Int = 0,
    val dangerousLinks: Int = 0,
    val verifiedOfficialCount: Int = 0,
    val lastUpdated: Long = 0L
) {
    constructor() : this(0, 0, 0, 0, 0, 0L)
    
    fun getSafePercentage(): Double {
        return if (totalScans > 0) (safeLinks.toDouble() / totalScans) * 100 else 0.0
    }
    
    fun getSuspiciousPercentage(): Double {
        return if (totalScans > 0) (suspiciousLinks.toDouble() / totalScans) * 100 else 0.0
    }
    
    fun getDangerousPercentage(): Double {
        return if (totalScans > 0) (dangerousLinks.toDouble() / totalScans) * 100 else 0.0
    }
}
