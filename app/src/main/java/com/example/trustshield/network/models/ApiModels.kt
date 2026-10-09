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
    val created_at: String,
    val token: String? = null
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
    val message: String,
    val token: String? = null
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
    val verdict: String,
    val source_app: String? = null
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
    val analyzed_at: String,
    val source_app: String? = null,
    val threat_score: Float? = null
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

/**
 * Link Explain (Gemini Forensics) Request & Response
 */
data class LinkExplainRequest(
    val url: String,
    val scan_id: Int? = null
)

data class LinkExplainResponse(
    val status: String,
    val url: String?,
    val scan_id: Int?,
    val verdict: String?,
    val threat_score: Float?,
    val summary: String?,
    val source: String? = null,       // "gemini" when Gemini wrote the text, "rules" otherwise
    val model: String? = null         // the label to show, e.g. "Written by Google Gemini"
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
