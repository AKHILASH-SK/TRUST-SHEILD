package com.example.trustshield

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import android.util.Log

/**
 * PermissionManager
 * 
 * Handles runtime permission requests for Android 13+
 * Specifically manages POST_NOTIFICATIONS permission
 */
class PermissionManager(private val context: Context) {
    
    companion object {
        private const val TAG = "PERM_MANAGER"
        const val NOTIFICATION_PERMISSION_CODE = 1001
    }
    
    /**
     * Check if POST_NOTIFICATIONS permission is granted (Android 13+)
     */
    fun hasNotificationPermission(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val hasPermission = ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
            
            Log.d(TAG, "Notification permission granted: $hasPermission")
            hasPermission
        } else {
            // Permissions auto-granted on Android 12 and below
            Log.d(TAG, "Android version < 13, notifications auto-enabled")
            true
        }
    }
    
    /**
     * Request notification permission if needed
     * Should be called from MainActivity
     */
    fun requestNotificationPermission(activity: android.app.Activity) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (!hasNotificationPermission()) {
                Log.d(TAG, "Requesting notification permission...")
                ActivityCompat.requestPermissions(
                    activity,
                    arrayOf(Manifest.permission.POST_NOTIFICATIONS),
                    NOTIFICATION_PERMISSION_CODE
                )
            }
        }
    }
}
