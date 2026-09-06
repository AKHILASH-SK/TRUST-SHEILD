package com.example.trustshield.config

import android.content.Context
import android.util.Log
import com.example.trustshield.network.RetrofitClient

import com.example.trustshield.BuildConfig

/**
 * BackendConfig
 * Configuration helper for backend URL setup
 */
object BackendConfig {
    
    private const val TAG = "BackendConfig"
    private const val PREFS_NAME = "backend_prefs"
    private const val KEY_BACKEND_URL = "backend_url"
    
    private val DEFAULT_BACKEND_URL = BuildConfig.BASE_URL
    
    /**
     * Get the backend URL from SharedPreferences
     * Returns default if not set
     */
    fun getBackendUrl(context: Context): String {
        val sharedPref = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val url = sharedPref.getString(KEY_BACKEND_URL, "")
        if (url.isNullOrEmpty()) {
            return DEFAULT_BACKEND_URL
        }
        return url
    }
    
    /**
     * Set the backend URL and update Retrofit client
     */
    fun setBackendUrl(context: Context, url: String) {
        try {
            val sharedPref = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            with(sharedPref.edit()) {
                putString(KEY_BACKEND_URL, url)
                apply()
            }
            
            // Update Retrofit client
            RetrofitClient.updateBaseUrl(url)
            
            Log.d(TAG, "Backend URL updated to: $url")
        } catch (e: Exception) {
            Log.e(TAG, "Error setting backend URL: ${e.message}", e)
        }
    }
    
    /**
     * Build complete URL (No longer used for production)
     */
    fun buildBackendUrl(ipAddress: String): String {
        return DEFAULT_BACKEND_URL
    }
    
    /**
     * Check if backend URL is configured
     * Always return true now that we are in production
     */
    fun isConfigured(context: Context): Boolean {
        return true
    }
}
