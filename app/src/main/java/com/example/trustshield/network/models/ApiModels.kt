package com.example.trustshield.network.models

import com.google.gson.annotations.SerializedName

/**
 * API Request/Response Models
 * Data classes for communication with TrustShield Backend
 */

// ===== Authentication Models =====

/**
 * Registration Request
 */
data class RegisterRequest(
    val name: String,
    val last_name: String,
    val email: String,
    val phone_number: String,
    val pin: String
)

/**
 * Registration Response
 */
data class RegisterResponse(
    val id: Int,
    val name: String,
    val email: String,
    val phone_number: String,
    val created_at: String
)

/**
 * Login Request
 */
data class LoginRequest(
    val phone_number: String,
    val pin: String
)

/**
 * Login Response
 */
data class LoginResponse(
    val id: Int,
    val name: String,
    val email: String,
    val phone_number: String,
    val message: String
)

// ===== Link Scan Models =====

/**
 * Save Link Scan Request
 */
data class LinkScanRequest(
    val user_id: Int,
    val url: String,
    val risk_level: String,
    val reasons: String,
    val verdict: String
)

/**
 * Save Link Scan Response
 */
data class LinkScanResponse(
    val id: Int,
    val user_id: Int,
    val url: String,
    val risk_level: String,
    val reasons: String,
    val verdict: String,
    val analyzed_at: String
)

/**
 * Link Scan History Item
 */
data class LinkScanHistoryItem(
    val id: Int,
    val user_id: Int,
    val url: String,
    val risk_level: String,
    val reasons: String,
    val verdict: String,
    val analyzed_at: String
)

/**
 * Link Scan History Response
 */
data class LinkHistoryResponse(
    val user_id: Int,
    val total_scans: Int,
    val scans: List<LinkScanHistoryItem>
)

// ===== Health Check Models =====

/**
 * Health Check Response
 */
data class HealthCheckResponse(
    val status: String,
    val message: String
)

/**
 * Error Response
 */
data class ErrorResponse(
    val error: String
)
