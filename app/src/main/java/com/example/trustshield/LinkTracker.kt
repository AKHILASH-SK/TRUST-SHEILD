package com.example.trustshield

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import java.util.concurrent.ConcurrentHashMap

/**
 * LinkTracker
 * 
 * Tracks:
 * 1. Notification keys that have been processed (prevents duplicate processing)
 * 2. Notifications already alerted within current cycle
 */
class LinkTracker(context: Context) {
    
    companion object {
        private const val TAG = "LINK_TRACKER"
        private const val PREFS_NAME = "trustshield_link_tracker"
    }
    
    private val sharedPrefs: SharedPreferences = 
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    
    // In-memory: Track notification keys we've already processed THIS SESSION
    // This prevents the same notification from being processed multiple times
    private val processedNotificationKeys = ConcurrentHashMap<String, Long>()
    
    // In-memory: Track which links we've alerted for THIS SESSION
    // Different from processedNotificationKeys - this is for deduplication across messages
    private val alertedLinksThisSession = ConcurrentHashMap<String, Long>()
    
    init {
        Log.d(TAG, "LinkTracker initialized")
    }
    
    /**
     * Check if we've already processed this notification key
     * Prevents processing the same notification multiple times
     * 
     * @param notificationKey Unique key for the notification (from StatusBarNotification.getKey())
     * @return true if we've already processed it, false if this is new
     */
    fun hasProcessedNotification(notificationKey: String): Boolean {
        val hasProcessed = processedNotificationKeys.containsKey(notificationKey)
        
        if (hasProcessed) {
            Log.d(TAG, "⏭️  Notification already processed: $notificationKey")
        }
        
        return hasProcessed
    }
    
    /**
     * Mark a notification as processed
     * Call this after you've processed all links in a notification
     * 
     * @param notificationKey Unique key for the notification
     */
    fun markNotificationProcessed(notificationKey: String) {
        val currentTime = System.currentTimeMillis()
        processedNotificationKeys[notificationKey] = currentTime
        Log.d(TAG, "✓ Notification marked as processed: $notificationKey")
    }
    
    /**
     * Clear old processed notifications (older than 5 minutes)
     * Prevents memory from growing infinitely
     */
    fun cleanupOldProcessedNotifications() {
        val currentTime = System.currentTimeMillis()
        val fiveMinutesAgo = currentTime - (5 * 60 * 1000) // 5 minutes
        
        val toRemove = processedNotificationKeys.filter { (_, time) ->
            time < fiveMinutesAgo
        }
        
        toRemove.forEach { (key, _) ->
            processedNotificationKeys.remove(key)
        }
        
        if (toRemove.isNotEmpty()) {
            Log.d(TAG, "Cleaned up ${toRemove.size} old processed notifications")
        }
    }
    
    /**
     * Clear all tracked notifications and links
     * Use for testing or manual reset
     */
    fun clearAll() {
        processedNotificationKeys.clear()
        alertedLinksThisSession.clear()
        Log.d(TAG, "✓ All tracking cleared")
    }
    
    /**
     * Get count of currently tracked notifications
     */
    fun getProcessedNotificationCount(): Int {
        return processedNotificationKeys.size
    }
}
