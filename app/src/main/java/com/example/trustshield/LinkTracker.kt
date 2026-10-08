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
    private val MAX_TRACKED = 3000
    
    // In-memory: Track which links we've alerted for THIS SESSION
    // Different from processedNotificationKeys - this is for deduplication across messages
    private val alertedLinksThisSession = ConcurrentHashMap<String, Long>()
    
    init {
        Log.d(TAG, "LinkTracker initialized")
    }
    
    /**
     * Check if we've already processed this exact notification content
     * Prevents processing the same notification multiple times
     * 
     * @param notificationKey Unique key for the notification
     * @param messageText The full text content of the notification
     * @return true if we've already processed it, false if this is new
     */
    fun hasProcessedNotification(notificationKey: String, messageText: String): Boolean {
        val uniqueId = "$notificationKey:${messageText.hashCode()}"
        val hasProcessed = processedNotificationKeys.containsKey(uniqueId)
        
        if (hasProcessed) {
            Log.d(TAG, "⏭️  Notification already processed: $uniqueId")
        }
        
        return hasProcessed
    }
    
    /**
     * Mark a notification as processed
     * Call this after you've processed all links in a notification
     * 
     * @param notificationKey Unique key for the notification
     * @param messageText The full text content of the notification
     */
    fun markNotificationProcessed(notificationKey: String, messageText: String) {
        val uniqueId = "$notificationKey:${messageText.hashCode()}"
        val currentTime = System.currentTimeMillis()
        processedNotificationKeys[uniqueId] = currentTime
        Log.d(TAG, "✓ Notification marked as processed: $uniqueId")
    }
    
    /**
     * Keeps memory bounded. Entries are NOT expired by age: an old message that an app re-posts hours later
     * (WhatsApp re-posts the whole chat when a new message arrives) must still be recognised as already handled.
     */
    fun cleanupOldProcessedNotifications() {
        val overflow = processedNotificationKeys.size - MAX_TRACKED
        if (overflow <= 0) return
        processedNotificationKeys.entries
            .sortedBy { it.value }
            .take(overflow)
            .forEach { processedNotificationKeys.remove(it.key) }
        Log.d(TAG, "Trimmed $overflow oldest tracked entries")
    }

    /**
     * One chat message = one unit, recognised by its own timestamp, sender and text.
     * Returns true the first time a unit is seen; false when an app re-posts a message we already handled.
     * The same link sent again as a NEW message has a new timestamp, so it is scanned again.
     */
    fun markMessageUnitIfNew(notificationKey: String, unitId: String): Boolean {
        val id = "u:$notificationKey:$unitId"
        return processedNotificationKeys.putIfAbsent(id, System.currentTimeMillis()) == null
    }

    /**
     * Collapse the different spellings of one link inside a single notification
     * ("www.x.org", "https://www.x.org/", "https://x.org") into one entry; the version with a scheme wins.
     */
    fun dedupeLinks(links: Collection<String>): List<String> {
        val byKey = linkedMapOf<String, String>()
        for (raw in links) {
            val link = raw.trim()
            if (link.isEmpty()) continue
            val key = canonicalKey(link)
            val current = byKey[key]
            if (current == null || (!current.contains("://") && link.contains("://"))) byKey[key] = link
        }
        return byKey.values.toList()
    }

    private fun canonicalKey(link: String): String {
        var k = link.lowercase().substringBefore('#')
        k = k.removePrefix("https://").removePrefix("http://").removePrefix("www.")
        return k.trimEnd('/')
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
