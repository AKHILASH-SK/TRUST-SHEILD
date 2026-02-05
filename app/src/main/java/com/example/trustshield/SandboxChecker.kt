package com.example.trustshield

import android.util.Log
import java.net.URL
import java.io.OutputStreamWriter
import java.io.BufferedReader
import java.io.InputStreamReader
import org.json.JSONObject

/**
 * Tier 3 Analysis: Sandbox Check via Backend
 * 
 * For URLs that bypass:
 * - Tier 1: Rule-based checks
 * - Tier 2: Firebase phishing database
 * 
 * This checks against external APIs (VirusTotal)
 */
class SandboxChecker(
    private val backendUrl: String = "http://192.168.1.X:5000"  // UPDATE THIS
) {
    
    companion object {
        private const val TAG = "SandboxChecker"
        private const val TIMEOUT_MS = 5000  // 5 second timeout
    }
    
    /**
     * Check URL via backend sandbox analysis
     * Called for unknown links that passed Tier 1 & 2
     */
    fun checkURL(url: String, callback: (SandboxResult) -> Unit) {
        Thread {
            try {
                Log.d(TAG, "Checking URL via sandbox: $url")
                
                val result = performSandboxCheck(url)
                
                Log.d(TAG, "Sandbox result: ${result.verdict} (${result.confidence}%)")
                
                callback(result)
                
            } catch (e: Exception) {
                Log.e(TAG, "Sandbox check error: ${e.message}")
                callback(SandboxResult(
                    url = url,
                    verdict = "UNKNOWN",
                    confidence = 0,
                    details = "Sandbox check failed: ${e.message}"
                ))
            }
        }.start()
    }
    
    /**
     * Perform actual HTTP call to backend
     */
    private fun performSandboxCheck(url: String): SandboxResult {
        return try {
            // Create request
            val endpoint = "$backendUrl/api/sandbox-check"
            val httpUrl = URL(endpoint)
            val conn = httpUrl.openConnection() as java.net.HttpURLConnection
            
            // Configure connection
            conn.requestMethod = "POST"
            conn.setRequestProperty("Content-Type", "application/json")
            conn.connectTimeout = TIMEOUT_MS
            conn.readTimeout = TIMEOUT_MS
            
            // Send request body
            val requestBody = JSONObject().apply {
                put("url", url)
            }.toString()
            
            conn.outputStream.use { output ->
                OutputStreamWriter(output).use { writer ->
                    writer.write(requestBody)
                    writer.flush()
                }
            }
            
            // Read response
            val responseCode = conn.responseCode
            val responseText = if (responseCode == 200) {
                conn.inputStream.bufferedReader().readText()
            } else {
                conn.errorStream?.bufferedReader()?.readText() ?: ""
            }
            
            Log.d(TAG, "Backend response code: $responseCode")
            Log.d(TAG, "Backend response: ${responseText.take(200)}")
            
            // Parse response
            parseBackendResponse(url, responseText)
            
        } catch (e: Exception) {
            Log.e(TAG, "HTTP error: ${e.message}")
            SandboxResult(
                url = url,
                verdict = "UNKNOWN",
                confidence = 0,
                details = "Connection error: ${e.message}"
            )
        }
    }
    
    /**
     * Parse backend JSON response
     */
    private fun parseBackendResponse(url: String, responseText: String): SandboxResult {
        return try {
            val json = JSONObject(responseText)
            
            SandboxResult(
                url = url,
                verdict = json.optString("verdict", "UNKNOWN"),
                confidence = json.optInt("confidence", 0),
                details = json.optString("details", ""),
                enginesCount = json.optInt("engines_count", 0),
                maliciousCount = json.optInt("malicious_count", 0),
                suspiciousCount = json.optInt("suspicious_count", 0)
            )
        } catch (e: Exception) {
            Log.e(TAG, "Parse error: ${e.message}")
            SandboxResult(
                url = url,
                verdict = "UNKNOWN",
                confidence = 0,
                details = "Parse error: ${e.message}"
            )
        }
    }
}

/**
 * Result from sandbox analysis
 */
data class SandboxResult(
    val url: String,
    val verdict: String,  // "DANGEROUS", "SUSPICIOUS", "SAFE", "UNKNOWN"
    val confidence: Int,  // 0-100
    val details: String = "",
    val enginesCount: Int = 0,
    val maliciousCount: Int = 0,
    val suspiciousCount: Int = 0
)
