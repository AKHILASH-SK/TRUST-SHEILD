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
        sandboxChecker = SandboxChecker()
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
            // Skip early if it's our own notification
            if (packageName == applicationContext.packageName) {
                Log.d(TAG, "Skipping self notification from: $packageName")
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

            // Deep extraction of links across notification Bundle (URLSpans, rich text, nested fields)
            val discoveredLinks = linkedSetOf<String>()
            discoveredLinks.addAll(linkExtractor.extractLinksFromBundle(extras))
            
            // Inspect notification action buttons (e.g. "Visit Link" quick action)
            sbn.notification.actions?.forEach { action ->
                action.title?.let { discoveredLinks.addAll(linkExtractor.extractLinks(it)) }
                action.extras?.let { discoveredLinks.addAll(linkExtractor.extractLinksFromBundle(it)) }
            }
            
            // Also inspect ticker text and plain text string
            sbn.notification.tickerText?.let { discoveredLinks.addAll(linkExtractor.extractLinks(it)) }
            discoveredLinks.addAll(linkExtractor.extractLinks(fullMessage))

            val isEmailApp = packageName.contains("gm", ignoreCase = true) || packageName.contains("mail", ignoreCase = true)
            if (isEmailApp) {
                Log.i(TAG, "📧 [Email Notification] From: $packageName | Title: '$title' | Message: '$fullMessage'")
                if (discoveredLinks.isEmpty()) {
                    Log.w(TAG, "⚠️ [Email Notification] No URLs or URLSpans found in the notification preview snippet.")
                } else {
                    Log.i(TAG, "🔗 [Email Notification] Extracted ${discoveredLinks.size} link(s): $discoveredLinks")
                }
            }

            // Decide which links are NEW. Chat apps re-post the whole conversation (old messages included) whenever a
            // new message arrives, so each message is tracked by its own timestamp; links from messages we already
            // handled are skipped, while a link sent again as a new message is scanned again.
            val messageUnits = extractMessageUnits(extras)
            val linksToScan: List<String>
            if (messageUnits.isNotEmpty()) {
                val fresh = linkedSetOf<String>()
                for ((unitId, unitText) in messageUnits) {
                    if (linkTracker.markMessageUnitIfNew(notificationKey, unitId)) {
                        fresh.addAll(linkExtractor.extractLinks(unitText))
                    }
                }
                linksToScan = linkTracker.dedupeLinks(fresh)
                if (linksToScan.isEmpty()) {
                    linkTracker.cleanupOldProcessedNotifications()
                    return
                }
            } else {
                // Mail apps update the same notification (new text, same links): only links not yet handled for this
                // notification are scanned.
                linksToScan = linkTracker.newLinksForNotification(notificationKey, linkTracker.dedupeLinks(discoveredLinks))
                if (linksToScan.isEmpty()) {
                    return
                }
            }

            // Log the app and message
            Log.d(TAG, "App: $packageName")
            Log.d(TAG, "Message: $fullMessage")
            
            // ========== PHASE 1: LINK EXTRACTION & ANALYSIS ==========
            performLinkSecurityAnalysis(linksToScan, packageName)

            // Mark processed to avoid duplicate handling of the same notification
            linkTracker.markNotificationProcessed(notificationKey, fullMessage)
            linkTracker.cleanupOldProcessedNotifications()
            
        } catch (e: Exception) {
            // Log any errors that occur during notification processing
            Log.e(TAG, "Error processing notification: ${e.message}", e)
        }
    }

    /**
     * Analyze notification for links and alert the user.
     *
     * The BACKEND verdict is the one the user is shown: it runs the whole pipeline (threat lists, VirusTotal, a real
     * sandbox browser, the ML models). The rules on this phone are only a hint: they used to raise a final "dangerous"
     * alert on their own, and they disagreed with the backend (a real recruitment page was announced as a "homograph
     * attack" while the history said Safe). Now:
     *   - a hit in the phishing-domain database alerts at once (hard evidence);
     *   - otherwise the link is sent to the backend and the alert follows ITS verdict;
     *   - only when the backend cannot be reached do this phone's rules decide, and the alert says so.
     */
    private fun performLinkSecurityAnalysis(links: List<String>, packageName: String) {
        try {
            if (links.isEmpty()) {
                Log.d(TAG, "No links detected in notification")
                return
            }
            Log.d(TAG, "Found ${links.size} link(s) in notification from $packageName")

            links.forEach { url ->
                val hint = linkAnalyzer.analyzeLink(url)
                Log.d(TAG, "Local hint for $url: ${hint.riskLevel} ${hint.reasons}")

                phishingChecker.checkDomain(url) { firebaseResult ->
                    var recordedLevel = hint.riskLevel
                    val reasons = hint.reasons.toMutableList()
                    var alertedFromDatabase = false

                    if (firebaseResult.result == PhishingCheckResult.DANGEROUS) {
                        Log.e(TAG, "DANGEROUS DOMAIN (phishing database): $url")
                        recordedLevel = LinkRiskLevel.DANGEROUS
                        reasons.add("Firebase: ${firebaseResult.message}")
                        alertManager.showDangerousLinkAlert(
                            url, packageName, listOf("Known phishing domain: ${firebaseResult.message}"), isFromPhishingDB = true
                        )
                        alertedFromDatabase = true
                    }

                    linkScanRecorder.recordLinkScan(
                        url = url,
                        host = Uri.parse(url).host ?: "",
                        riskLevel = recordedLevel,
                        verificationStatus = null,
                        verifiedBrand = null,
                        reasons = reasons,
                        sourceApp = packageName,
                        callback = object : LinkScanRecorder.OnLinkScanCallback {
                            override fun onResult(scanId: Int, verdict: String, reasons: String, aiPending: Boolean) {
                                Log.d(TAG, "Backend verdict for $url: $verdict (AI check pending: $aiPending)")
                                if (alertedFromDatabase) return
                                val points = com.example.trustshield.gate.GateText.bullets(reasons)
                                // The alert goes out AT ONCE with the first verdict; the AI summary/second opinion never delays it.
                                when (verdict) {
                                    "DANGEROUS" -> alertManager.showDangerousLinkAlert(url, packageName, points.ifEmpty { listOf("TrustShield analysis found this link dangerous") })
                                    "SUSPICIOUS" -> alertManager.showSuspiciousLinkAlert(url, packageName, points.ifEmpty { listOf("TrustShield could not confirm this link is safe") })
                                    else -> Log.d(TAG, "Backend says safe: no alert for $url")
                                }
                                if (aiPending && verdict == "SUSPICIOUS") followUpAiCheck(scanId, url, packageName)
                            }

                            override fun onSuccess(scanId: Int, verdict: String) {}

                            override fun onFailure(error: String) {
                                Log.e(TAG, "Backend not reachable for $url: $error")
                                if (alertedFromDatabase) return
                                val note = "Checked on this phone only (the TrustShield server could not be reached)"
                                when (hint.riskLevel) {
                                    LinkRiskLevel.DANGEROUS -> alertManager.showDangerousLinkAlert(url, packageName, hint.reasons.take(3) + note)
                                    LinkRiskLevel.SUSPICIOUS -> alertManager.showSuspiciousLinkAlert(url, packageName, hint.reasons.take(3) + note)
                                    LinkRiskLevel.SAFE -> {}
                                }
                            }
                        }
                    )
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error in link security analysis: ${e.message}", e)
        }
    }

    /**
     * The first verdict was "Unverified" and an AI second opinion was still running on the server. Check back a few times: if it
     * turns out dangerous, alert again (loudly); if it clears the link, remove the earlier warning.
     */
    private fun followUpAiCheck(scanId: Int, url: String, packageName: String) {
        Thread {
            repeat(10) {
                try { Thread.sleep(6000) } catch (e: InterruptedException) { return@Thread }
                val state = com.example.trustshield.gate.GateClient.fetchScanState(scanId) ?: return@repeat
                if (state.aiPending) return@repeat
                val points = com.example.trustshield.gate.GateText.bullets(state.reasons)
                when (state.verdict) {
                    "DANGEROUS" -> alertManager.showDangerousLinkAlert(url, packageName, points.ifEmpty { listOf("An AI check confirmed this link is dangerous") })
                    "SAFE" -> alertManager.cancelAlert(url)
                    else -> Log.d(TAG, "AI check left $url as unverified")
                }
                return@Thread
            }
        }.start()
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
    /**
     * Messages of a conversation-style notification as (id, text); the id is built from the message's own
     * timestamp, sender and text. Empty when the app does not provide individual messages.
     */
    private fun extractMessageUnits(extras: Bundle): List<Pair<String, String>> {
        val units = mutableListOf<Pair<String, String>>()
        try {
            val array = extras.getParcelableArray("android.messages") ?: return units
            for (item in array) {
                if (item is Bundle) {
                    val text = item.getCharSequence("text")?.toString() ?: continue
                    if (text.isBlank()) continue
                    val sender = item.getCharSequence("sender")?.toString() ?: ""
                    val time = item.getLong("time", 0L)
                    units.add("$time|$sender|${text.hashCode()}" to text)
                }
            }
        } catch (e: Exception) {
            Log.d(TAG, "Could not read message units: ${e.message}")
        }
        return units
    }

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
