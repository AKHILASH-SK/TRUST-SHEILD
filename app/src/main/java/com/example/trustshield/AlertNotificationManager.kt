package com.example.trustshield

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import android.util.Log

/**
 * AlertNotificationManager
 * 
 * Manages user-visible notifications for security alerts
 * Shows warnings when suspicious or dangerous links are detected
 */
class AlertNotificationManager(private val context: Context) {
    
    companion object {
        private const val TAG = "ALERT_NOTIFY"
        private const val CHANNEL_ID = "trustshield_security_alerts"
        private const val CHANNEL_NAME = "Security Alerts"
        private const val ALERT_COOLDOWN_MS = 30000  // 30 seconds - don't show same link alert twice within this period
    }
    
    private val notificationManager: NotificationManager = 
        context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
    
    private val permissionManager = PermissionManager(context)
    
    // Track recently alerted links to prevent duplicate alerts
    private val recentlyAletedLinks = mutableMapOf<String, Long>()
    
    init {
        createNotificationChannel()
        Log.d(TAG, "AlertNotificationManager initialized")
    }
    
    /**
     * Create notification channel for Android 8+ with proper settings
     */
    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            // Delete and recreate channel to ensure fresh settings
            try {
                notificationManager.deleteNotificationChannel(CHANNEL_ID)
                Log.d(TAG, "Deleted existing notification channel")
            } catch (e: Exception) {
                Log.d(TAG, "No existing channel to delete")
            }
            
            val importance = NotificationManager.IMPORTANCE_MAX
            val channel = NotificationChannel(CHANNEL_ID, CHANNEL_NAME, importance).apply {
                description = "Alerts for suspicious links and phishing attempts"
                enableVibration(true)
                enableLights(true)
                setShowBadge(true)
                // Allow sounds and vibrations
                setSound(android.provider.Settings.System.DEFAULT_NOTIFICATION_URI, 
                    android.media.AudioAttributes.Builder()
                        .setUsage(android.media.AudioAttributes.USAGE_NOTIFICATION)
                        .build())
            }
            notificationManager.createNotificationChannel(channel)
            Log.d(TAG, "Notification channel created with IMPORTANCE_MAX")
        }
    }
    
    /**
     * Show alert for dangerous link
     * @param isFromPhishingDB If true, alert every time (no cooldown) - link is in phishing database
     */
    fun showDangerousLinkAlert(url: String, fromApp: String, reasons: List<String>, isFromPhishingDB: Boolean = false) {
        val now = System.currentTimeMillis()
        
        // For phishing database hits, ALWAYS alert (no cooldown)
        // For rule-based detections, apply cooldown to prevent spam
        if (!isFromPhishingDB) {
            // Check if we recently alerted for this link (rule-based only)
            val lastAlertTime = recentlyAletedLinks[url] ?: 0L
            if (now - lastAlertTime < ALERT_COOLDOWN_MS) {
                Log.w(TAG, "⚠️ SKIP: Duplicate alert for same link (shown ${now - lastAlertTime}ms ago): $url")
                return  // Skip duplicate alert
            }
        }
        
        // Mark this link as recently alerted
        recentlyAletedLinks[url] = now
        
        // Clean up old entries to prevent memory leak
        recentlyAletedLinks.entries.removeIf { (_, time) -> now - time > ALERT_COOLDOWN_MS * 2 }
        
        // Check if notification permission is granted
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (!permissionManager.hasNotificationPermission()) {
                Log.e(TAG, "POST_NOTIFICATIONS permission NOT granted - cannot show notification")
                return
            }
        }
        
        val title = "🔴 DANGEROUS LINK"
        val message = "From: $fromApp"
        val bigText = "DANGEROUS LINK DETECTED!\n\nApp: $fromApp\n\nURL: $url\n\nRisks:\n• ${reasons.take(3).joinToString("\n• ")}\n\nDo not click this link!"
        
        // Use URL hash as unique ID
        val notificationId = Math.abs(url.hashCode() % 100000)
        
        Log.e(TAG, "Showing DANGEROUS link alert with ID: $notificationId")
        showNotification(title, message, bigText, NotificationCompat.PRIORITY_MAX, isError = true, notificationId)
    }
    
    /**
     * Show alert for suspicious link
     * @param isFromPhishingDB If true, alert every time (no cooldown) - link is in phishing database
     */
    fun showSuspiciousLinkAlert(url: String, fromApp: String, reasons: List<String>, isFromPhishingDB: Boolean = false) {
        val now = System.currentTimeMillis()
        
        // For phishing database hits, ALWAYS alert (no cooldown)
        // For rule-based detections, apply cooldown to prevent spam
        if (!isFromPhishingDB) {
            // Check if we recently alerted for this link (rule-based only)
            val lastAlertTime = recentlyAletedLinks[url] ?: 0L
            if (now - lastAlertTime < ALERT_COOLDOWN_MS) {
                Log.w(TAG, "⚠️ SKIP: Duplicate alert for same link (shown ${now - lastAlertTime}ms ago): $url")
                return  // Skip duplicate alert
            }
        }
        
        // Mark this link as recently alerted
        recentlyAletedLinks[url] = now
        
        // Clean up old entries to prevent memory leak
        recentlyAletedLinks.entries.removeIf { (_, time) -> now - time > ALERT_COOLDOWN_MS * 2 }
        
        // Check if notification permission is granted
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (!permissionManager.hasNotificationPermission()) {
                Log.e(TAG, "POST_NOTIFICATIONS permission NOT granted - cannot show notification")
                return
            }
        }
        
        val title = "⚠️  SUSPICIOUS LINK"
        val message = "From: $fromApp"
        val bigText = "SUSPICIOUS LINK DETECTED!\n\nApp: $fromApp\n\nURL: $url\n\nWarnings:\n• ${reasons.take(3).joinToString("\n• ")}\n\nBe cautious!"
        
        // Use URL hash as unique ID
        val notificationId = Math.abs(url.hashCode() % 100000)
        
        Log.w(TAG, "Showing SUSPICIOUS link alert with ID: $notificationId")
        showNotification(title, message, bigText, NotificationCompat.PRIORITY_HIGH, isError = false, notificationId)
    }
    
    /**
     * Show general notification with proper configuration
     */
    private fun showNotification(
        title: String,
        message: String,
        bigText: String,
        priority: Int,
        isError: Boolean,
        notificationId: Int
    ) {
        try {
            Log.d(TAG, "=== Creating notification ===")
            Log.d(TAG, "Title: $title")
            Log.d(TAG, "ID: $notificationId")
            
            // Create intent to open MainActivity when notification is tapped
            val intent = Intent(context, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
            }
            
            val pendingIntent: PendingIntent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                PendingIntent.getActivity(context, notificationId, intent, 
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
            } else {
                PendingIntent.getActivity(context, notificationId, intent, 
                    PendingIntent.FLAG_UPDATE_CURRENT)
            }
            
            val notification = NotificationCompat.Builder(context, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setContentTitle(title)
                .setContentText(message)
                .setStyle(NotificationCompat.BigTextStyle().bigText(bigText))
                .setContentIntent(pendingIntent)
                .setPriority(priority)
                .setCategory(NotificationCompat.CATEGORY_ALARM)
                .setAutoCancel(true)
                // Vibration pattern
                .setVibrate(longArrayOf(0, 500, 250, 500, 250, 500))
                // LED lights
                .setLights(if (isError) 0xFFFF0000.toInt() else 0xFFFFAA00.toInt(), 500, 500)
                .setShowWhen(true)
                .setOngoing(false)
                // Add visual weight
                .setDefaults(NotificationCompat.DEFAULT_ALL)
                // Make sure it's prominent
                .setFullScreenIntent(pendingIntent, true)
                .build()
            
            Log.d(TAG, "Posting notification to system...")
            notificationManager.notify(notificationId, notification)
            Log.d(TAG, "✓ Notification posted successfully! ID: $notificationId")
            
        } catch (e: SecurityException) {
            Log.e(TAG, "SecurityException - Permission might not be granted: ${e.message}")
            e.printStackTrace()
        } catch (e: Exception) {
            Log.e(TAG, "Exception showing notification: ${e.message}", e)
            e.printStackTrace()
        }
    }
}
