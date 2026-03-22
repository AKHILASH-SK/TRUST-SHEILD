package com.example.trustshield

import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.os.Bundle
import android.net.Uri
import android.util.Log

/**
 * NotificationListener Service
 * 
 * Purpose: Listens to notifications from external applications and:
 * 1. Extracts the title and text content
 * 2. Finds all links in the notification
 * 3. Analyzes links for phishing/security risks
 * 4. Shows alerts ONLY for new suspicious/dangerous links (not duplicates)
 * 5. Logs results for security monitoring
 * 
 * Requirements:
 * - Android API 24+
 * - User must grant "Notification access" permission in Settings
 * - Service must be registered in AndroidManifest.xml
 */
class NotificationListener : NotificationListenerService() {

    companion object {
        // Tag for logging notifications
        private const val TAG = "NOTIFY"
    }
    
    // Initialize link extractor and analyzer
    private val linkExtractor = LinkExtractor()
    private val linkAnalyzer = LinkAnalyzer()
    private lateinit var alertManager: AlertNotificationManager
    private lateinit var linkTracker: LinkTracker
    private lateinit var linkScanRecorder: LinkScanRecorder
    private lateinit var phishingChecker: PhishingDomainCheckerFirebase
    private lateinit var sandboxChecker: SandboxChecker

    override fun onCreate() {
        super.onCreate()
        alertManager = AlertNotificationManager(this)
        linkTracker = LinkTracker(this)
        linkScanRecorder = LinkScanRecorder(this)

        phishingChecker = PhishingDomainCheckerFirebase(this)
        sandboxChecker = SandboxChecker("http://10.101.140.61:5000")
        Log.d(TAG, "NotificationListener service created with 3-tier analysis + backend recording")
    }

    /**
     * Called when a notification is posted by any application.
     * Extracts content and analyzes for security threats.
     * 
     * @param sbn StatusBarNotification object containing notification data
     */
    override fun onNotificationPosted(sbn: StatusBarNotification) {
        try {
            // Get unique notification key
            val notificationKey = sbn.key
            
            // Extract the package name of the app that posted the notification
            val packageName = sbn.packageName

            // Ignore our own app notifications to prevent recursive alert loops
            if (packageName == applicationContext.packageName) {
                Log.d(TAG, "Skipping self notification from: $packageName")
                return
            }

            // Skip notifications we've already processed
            if (linkTracker.hasProcessedNotification(notificationKey)) {
                return
            }
            
            // Get the notification extras bundle containing notification data
            val extras: Bundle = sbn.notification.extras

            // Safely extract the notification title
            val title = extras.getString("android.title")
            
            // Safely extract the notification text content
            val text = extras.getCharSequence("android.text")?.toString()
            
            // Safely extract the expanded/big text content (if available)
            val bigText = extras.getCharSequence("android.bigText")?.toString()
            
            // Extract additional message fields from WhatsApp and other apps
            val subText = extras.getCharSequence("android.subText")?.toString()
            val summaryText = extras.getCharSequence("android.summaryText")?.toString()
            
            // For conversation-style notifications (Android 11+)
            val lines = extractNotificationLines(extras)

            // Combine all available message content into a single readable string
            val allMessages = listOfNotNull(
                title, 
                text, 
                bigText, 
                subText, 
                summaryText
            ) + lines
            
            val fullMessage = allMessages
                .filter { it.isNotBlank() }
                .joinToString(" | ")

            // Log the app and message
            Log.d(TAG, "App: $packageName")
            Log.d(TAG, "Message: $fullMessage")
            
            // ========== PHASE 1: LINK EXTRACTION & ANALYSIS ==========
            performLinkSecurityAnalysis(fullMessage, packageName)

            // Mark processed to avoid duplicate handling of the same notification
            linkTracker.markNotificationProcessed(notificationKey)
            linkTracker.cleanupOldProcessedNotifications()
            
        } catch (e: Exception) {
            // Log any errors that occur during notification processing
            Log.e(TAG, "Error processing notification: ${e.message}", e)
        }
    }

    /**
     * Analyze notification for links and perform security checks
     * Shows user-visible alerts for suspicious/dangerous links
     * Each notification is processed only once (no duplicates)
     * 
     * 3-Tier Analysis:
     * Tier 1: Rule-based checks (instant)
     * Tier 2: Firebase phishing database (fast)
     * Tier 3: Sandbox analysis via backend (for unknown links)
     */
    private fun performLinkSecurityAnalysis(message: String, packageName: String) {
        try {
            // Step 1: Extract all links from the message
            val links = linkExtractor.extractLinks(message)
            
            if (links.isEmpty()) {
                Log.d(TAG, "No links detected in notification")
                return
            }
            
            Log.d(TAG, "Found ${links.size} link(s) in notification from $packageName")
            
            // Step 2: Analyze each link (3-tier analysis)
            links.forEach { url ->
                Log.d(TAG, "")
                Log.d(TAG, "🔍 ============ ANALYZING LINK ============")
                Log.d(TAG, "URL: $url")
                
                // TIER 1: Rule-based analysis (instant)
                val analysis = linkAnalyzer.analyzeLink(url)
                Log.d(TAG, "Tier 1 Verdict: ${analysis.riskLevel} - Reasons: ${analysis.reasons}")
                var isSuspiciousFromTier1 = false
                
                // Record link scan to backend (Tier 1 verdict)
                // Also handles callback to show alert if backend verdict is DANGEROUS (Tier 0 override)
                Log.d(TAG, "📤 Calling LinkScanRecorder.recordLinkScan()...")
                linkScanRecorder.recordLinkScan(
                    url = url,
                    host = Uri.parse(url).host ?: "",
                    riskLevel = analysis.riskLevel,
                    verificationStatus = null,
                    verifiedBrand = null,
                    reasons = analysis.reasons,
                    sourceApp = packageName,
                    callback = object : LinkScanRecorder.OnLinkScanCallback {
                        override fun onSuccess(scanId: Int, verdict: String) {
                            Log.d(TAG, "✅ Backend response: Scan #$scanId - Verdict: $verdict")
                            // If backend says DANGEROUS (Tier 0 override), show alert
                            if (verdict == "DANGEROUS") {
                                Log.e(TAG, "🔴 BACKEND TIER 0 MATCH: $url is DANGEROUS (database phishing)")
                                alertManager.showDangerousLinkAlert(
                                    url,
                                    packageName,
                                    listOf("Known phishing URL from database")
                                )
                            }
                        }
                        
                        override fun onFailure(error: String) {
                            Log.e(TAG, "❌ Backend API error: $error")
                        }
                    }
                )
                
                when (analysis.riskLevel) {
                    LinkRiskLevel.DANGEROUS -> {
                        Log.e(TAG, "🔴 DANGEROUS LINK (Tier 1 - Rule-based)!")
                        alertManager.showDangerousLinkAlert(
                            url, 
                            packageName, 
                            analysis.reasons
                        )
                        return@forEach  // Skip further analysis for this link
                    }
                    LinkRiskLevel.SUSPICIOUS -> {
                        Log.w(TAG, "⚠️ SUSPICIOUS LINK (Tier 1 - Rule-based) - Continuing to Tier 2...")
                        isSuspiciousFromTier1 = true
                        // Don't return! Continue to Tier 2 & 3 for further analysis
                    }
                    LinkRiskLevel.SAFE -> {
                        Log.d(TAG, "✓ Tier 1 passed: $url")
                    }
                }
                
                // TIER 2: Firebase phishing database (background)
                phishingChecker.checkDomain(url) { firebaseResult ->
                    when (firebaseResult.result) {
                        PhishingCheckResult.DANGEROUS -> {
                            Log.e(TAG, "🔴 DANGEROUS DOMAIN (Tier 2 - Firebase DB)!")
                            // ALWAYS alert for phishing DB hits, even if repeated
                            alertManager.showDangerousLinkAlert(
                                url, 
                                packageName, 
                                listOf("Firebase: ${firebaseResult.message}"),
                                isFromPhishingDB = true  // Alert every time, no cooldown
                            )
                        }
                        PhishingCheckResult.SUSPICIOUS -> {
                            Log.w(TAG, "⚠️ SUSPICIOUS DOMAIN (Tier 2 - Firebase DB)!")
                            // ALWAYS alert for phishing DB hits, even if repeated
                            alertManager.showSuspiciousLinkAlert(
                                url,
                                packageName,
                                listOf("Firebase: ${firebaseResult.message}"),
                                isFromPhishingDB = true  // Alert every time, no cooldown
                            )
                            // Continue to Tier 3 for SUSPICIOUS
                            performSandboxAnalysis(url, packageName, isSuspiciousFromTier1)
                        }
                        PhishingCheckResult.SAFE -> {
                            Log.d(TAG, "✓ Tier 2 passed: $url")
                            
                            // TIER 3: Sandbox analysis (backend API)
                            // ONLY if link was SUSPICIOUS in Tier 1 (unknown but risky)
                            if (isSuspiciousFromTier1) {
                                Log.d(TAG, "⚠️ Tier 1 found SUSPICIOUS - continuing to Tier 3...")
                                performSandboxAnalysis(url, packageName, true)
                            } else {
                                Log.d(TAG, "✓ All tiers passed for: $url - Link is safe")
                            }
                        }
                    }
                }
            }
            
        } catch (e: Exception) {
            Log.e(TAG, "Error in link security analysis: ${e.message}", e)
        }
    }
    
    /**
     * Tier 3: Sandbox analysis via backend for SUSPICIOUS links only
     * @param isSuspicious Only runs if link was SUSPICIOUS in Tier 1
     */
    private fun performSandboxAnalysis(url: String, packageName: String, isSuspicious: Boolean) {
        // Only run Tier 3 for links that were SUSPICIOUS in Tier 1
        if (!isSuspicious) {
            Log.d(TAG, "⏭️ Skipping Tier 3 for SAFE link: $url")
            return
        }
        
        Log.d(TAG, "🔬 Starting Tier 3 Sandbox Analysis for: $url")
        
        sandboxChecker.checkURL(url) { result ->
            when (result.verdict) {
                "DANGEROUS" -> {
                    Log.e(TAG, "🔴 DANGEROUS (Tier 3 - Sandbox)! Confidence: ${result.confidence}%")
                    alertManager.showDangerousLinkAlert(
                        url,
                        packageName,
                        listOf(
                            "Sandbox: ${result.details}",
                            "Malicious engines: ${result.maliciousCount}/${result.enginesCount}"
                        )
                    )
                }
                
                "SUSPICIOUS" -> {
                    Log.w(TAG, "⚠️ SUSPICIOUS (Tier 3 - Sandbox)! Confidence: ${result.confidence}%")
                    alertManager.showSuspiciousLinkAlert(
                        url,
                        packageName,
                        listOf(
                            "Sandbox: ${result.details}",
                            "Suspicious engines: ${result.suspiciousCount}/${result.enginesCount}"
                        )
                    )
                }
                
                "SAFE" -> {
                    Log.i(TAG, "✓ Link appears safe (Tier 3 - Sandbox): $url")
                    // No alert needed - all tiers passed
                }
                
                else -> {
                    Log.d(TAG, "⚠️ Sandbox analysis inconclusive: ${result.details}")
                    // Don't alert if sandbox is unavailable
                }
            }
        }
    }

    /**
     * Extract text lines from notification extras (for messaging apps)
     */
    private fun extractNotificationLines(extras: Bundle): List<String> {
        val lines = mutableListOf<String>()
        
        // Try to extract message lines from ParcelableArray (common in messaging apps)
        try {
            val parcelableArray = extras.getParcelableArray("android.messages")
            if (parcelableArray != null) {
                for (item in parcelableArray) {
                    if (item is Bundle) {
                        val text = item.getCharSequence("text")?.toString()
                        val sender = item.getCharSequence("sender")?.toString()
                        if (!text.isNullOrBlank()) {
                            if (!sender.isNullOrBlank()) {
                                lines.add("$sender: $text")
                            } else {
                                lines.add(text)
                            }
                        }
                    }
                }
            }
        } catch (e: Exception) {
            Log.d(TAG, "Could not extract message lines: ${e.message}")
        }
        
        // Try to extract text lines from getCharSequenceArray
        try {
            val textLines = extras.getCharSequenceArray("android.textLines")
            if (textLines != null) {
                for (line in textLines) {
                    if (line != null && line.toString().isNotBlank()) {
                        lines.add(line.toString())
                    }
                }
            }
        } catch (e: Exception) {
            Log.d(TAG, "Could not extract text lines: ${e.message}")
        }
        
        return lines
    }

    /**
     * Called when a notification is removed (dismissed) by the user or application.
     * 
     * @param sbn StatusBarNotification object of the removed notification
     */
    override fun onNotificationRemoved(sbn: StatusBarNotification) {
        try {
            Log.d(TAG, "Notification removed from: ${sbn.packageName}")
        } catch (e: Exception) {
            Log.e(TAG, "Error processing notification removal: ${e.message}", e)
        }
    }
}
