package com.example.trustshield.models

/**
 * User data class
 * Represents a TrustShield user account
 */
data class User(
    val userId: String = "",
    val phoneNumber: String = "",
    val name: String = "",
    val email: String = "",
    val createdAt: Long = 0L,
    val lastLogin: Long = 0L,
    val deviceId: String = "",
    val totalScans: Int = 0,
    val preferences: UserPreferences = UserPreferences()
) {
    // No-arg constructor for Firebase
    constructor() : this("", "", "", "", 0L, 0L, "", 0)
}

/**
 * User preferences/settings
 */
data class UserPreferences(
    val notificationsEnabled: Boolean = true,
    val autoBlock: Boolean = false,
    val theme: String = "light"
) {
    constructor() : this(true, false, "light")
}
