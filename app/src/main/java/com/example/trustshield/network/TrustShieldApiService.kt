package com.example.trustshield.network

import com.example.trustshield.network.models.*
import retrofit2.Response
import retrofit2.http.*

/**
 * TrustShield API Service
 * Retrofit interface for backend communication
 * 
 * Base URL: http://192.168.x.x:8000
 */
interface TrustShieldApiService {
    
    // ===== Health Check =====
    
    /**
     * Health check endpoint
     * GET /
     */
    @GET("/")
    suspend fun healthCheck(): Response<HealthCheckResponse>
    
    /**
     * Health check endpoint
     * GET /api/health
     */
    @GET("/api/health")
    suspend fun apiHealth(): Response<HealthCheckResponse>
    
    // ===== Authentication =====
    
    /**
     * Register a new user
     * POST /api/auth/register
     * 
     * Request: {name, last_name, email, phone_number, pin}
     * Response: {id, name, email, phone_number, created_at}
     */
    @POST("/api/auth/register")
    suspend fun register(@Body request: RegisterRequest): Response<RegisterResponse>
    
    /**
     * Login user with phone number and PIN
     * POST /api/auth/login
     * 
     * Request: {phone_number, pin}
     * Response: {id, name, email, phone_number, message}
     */
    @POST("/api/auth/login")
    suspend fun login(@Body request: LoginRequest): Response<LoginResponse>
    
    // ===== Link Scanning =====
    
    /**
     * Save a scanned link to database
     * POST /api/links/scan
     * 
     * Request: {user_id, url}
     * Response: {id, user_id, url, risk_level, reasons, verdict, analyzed_at}
     */
    @POST("/api/links/scan")
    suspend fun saveLinkScan(@Body request: LinkScanRequest): Response<LinkScanResponse>
    
    /**
     * Get all scanned links for a user
     * GET /api/links/history/{user_id}
     * 
     * Response: {user_id, total_scans, scans[]}
     */
    @GET("/api/links/history/{user_id}")
    suspend fun getLinkHistory(@Path("user_id") userId: Int): Response<LinkHistoryResponse>
}
