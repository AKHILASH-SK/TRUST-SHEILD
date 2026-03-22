package com.example.trustshield.config

import android.content.Context
import android.util.Log
import com.example.trustshield.network.RetrofitClient

/**
 * BackendConfig
 * Configuration helper for backend URL setup
 * 
 * How to use:
 * 1. Call BackendConfig.initializeBackendUrl(context) in MainActivity.onCreate()
 * 2. App will look for backend_url in SharedPreferences
 * 3. If not found, displays a setup dialog
 * 4. User enters their computer's IP address (from ipconfig)
 * 5. URL is automatically set to http://<IP>:8000
 */
object BackendConfig {
    
    private const val TAG = "BackendConfig"
    private const val PREFS_NAME = "backend_prefs"
    private const val KEY_BACKEND_URL = "backend_url"
    private const val DEFAULT_BACKEND_URL = "http://192.168.x.x:8000"
    
    /**
     * Get the backend URL from SharedPreferences
     * Returns default if not set
     */
    fun getBackendUrl(context: Context): String {
        val sharedPref = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val url = sharedPref.getString(KEY_BACKEND_URL, "")
        return if (url.isNullOrEmpty()) DEFAULT_BACKEND_URL else url
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
     * Build complete URL with port
     */
    fun buildBackendUrl(ipAddress: String): String {
        return "http://$ipAddress:8000"
    }
    
    /**
     * Check if backend URL is configured
     */
    fun isConfigured(context: Context): Boolean {
        val url = getBackendUrl(context)
        return url != DEFAULT_BACKEND_URL && url.contains(":8000")
    }
}
