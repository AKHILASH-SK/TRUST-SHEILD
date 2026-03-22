package com.example.trustshield

import android.content.Context
import android.util.Log
import com.example.trustshield.network.RetrofitClient
import com.example.trustshield.network.models.LinkScanRequest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch

/**
 * LinkScanRecorder
 * Handles saving link analysis results to backend database
 * Runs asynchronously via Retrofit API
 */
class LinkScanRecorder(private val context: Context) {
    
    companion object {
        private const val TAG = "LINK_RECORDER"
    }
    
    /**
     * Callback when link scan is saved to backend
     */
    interface OnLinkScanCallback {
        fun onSuccess(scanId: Int, verdict: String)
        fun onFailure(error: String)
    }
    
    /**
     * Record a link scan result to backend
     * Runs asynchronously in the background
     */
    fun recordLinkScan(
        url: String,
        host: String,
        riskLevel: LinkRiskLevel,
        verificationStatus: String?,
        verifiedBrand: String?,
        reasons: List<String>,
        sourceApp: String,
        callback: OnLinkScanCallback? = null
    ) {
        // Log immediately (before async call)
        Log.d(TAG, "=== 📤 RECORDING LINK SCAN ===")
        Log.d(TAG, "URL: $url")
        Log.d(TAG, "Risk Level: $riskLevel")
        Log.d(TAG, "⭐ About to call backend API...")
        
        GlobalScope.launch(Dispatchers.IO) {
            try {
                Log.d(TAG, "🔄 Coroutine started on IO dispatcher")
                
                // Get user ID from SharedPreferences
                val sharedPref = context.getSharedPreferences("trustshield_prefs", Context.MODE_PRIVATE)
                val userId = sharedPref.getInt("user_id", -1)
                
                if (userId == -1) {
                    Log.d(TAG, "❌ No user logged in - skipping record")
                    callback?.onFailure("No user logged in")
                    return@launch
                }
                
                Log.d(TAG, "📤 [API] Saving link scan: $url (User: $userId, Risk: $riskLevel)")
                
                // Convert LinkRiskLevel enum to verdict string
                val verdict = when (riskLevel) {
                    LinkRiskLevel.DANGEROUS -> "DANGEROUS"
                    LinkRiskLevel.SUSPICIOUS -> "SUSPICIOUS"
                    LinkRiskLevel.SAFE -> "SAFE"
                }
                
                // Create request with full analysis data
                val linkScanRequest = LinkScanRequest(
                    user_id = userId,
                    url = url,
                    risk_level = riskLevel.name,
                    reasons = reasons.joinToString(", "),
                    verdict = verdict
                )
                
                // Call backend API
                Log.d(TAG, "🔌 [API] Connecting to backend...")
                val apiService = RetrofitClient.getInstance("http://10.177.26.61:8000").getApiService()
                
                Log.d(TAG, "🔌 [API] Sending request: POST http://10.177.26.61:8000/api/links/scan")
                val response = apiService.saveLinkScan(linkScanRequest)
                
                if (response.isSuccessful && response.body() != null) {
                    val scanResponse = response.body()!!
                    Log.d(TAG, "✅ [API SUCCESS] Link scan saved!")
                    Log.d(TAG, "   Scan ID: ${scanResponse.id}")
                    Log.d(TAG, "   Verdict: ${scanResponse.verdict}")
                    Log.d(TAG, "   Risk Level: ${scanResponse.risk_level}")
                    Log.d(TAG, "   Response Code: ${response.code()}")
                    
                    // Execute callback on main thread
                    GlobalScope.launch {
                        callback?.onSuccess(scanResponse.id, scanResponse.verdict)
                    }
                } else {
                    val errorMsg = "API Error: ${response.code()} ${response.message()}"
                    Log.e(TAG, "❌ [API FAILED] $errorMsg")
                    
                    // Execute callback on main thread
                    GlobalScope.launch {
                        callback?.onFailure(errorMsg)
                    }
                }
                
            } catch (e: Exception) {
                val errorMsg = "Exception: ${e.message}\n${android.util.Log.getStackTraceString(e)}"
                Log.e(TAG, "❌ [API ERROR] $errorMsg", e)
                
                // Execute callback on main thread
                GlobalScope.launch {
                    callback?.onFailure(errorMsg)
                }
            }
        }
    }
}

