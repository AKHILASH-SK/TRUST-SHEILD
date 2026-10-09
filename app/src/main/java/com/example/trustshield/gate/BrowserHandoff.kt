package com.example.trustshield.gate

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri

/**
 * Opens a link in a REAL browser app. While TrustShield is the default browser, a plain "open this link" would come
 * straight back to us, so the intent is always addressed to one specific other browser (never to ourselves).
 */
object BrowserHandoff {
    private const val PREFS = "trustshield_prefs"
    private const val KEY_BROWSER = "gate_browser_pkg"
    private val PREFERRED = listOf(
        "com.android.chrome", "org.mozilla.firefox", "com.sec.android.app.sbrowser", "com.microsoft.emmx",
        "com.brave.browser", "com.opera.browser", "com.duckduckgo.mobile.android"
    )

    private fun probe() =
        Intent(Intent.ACTION_VIEW, Uri.parse("https://example.com")).addCategory(Intent.CATEGORY_BROWSABLE)

    /** Installed browsers other than TrustShield itself. */
    fun otherBrowsers(context: Context): List<String> =
        context.packageManager.queryIntentActivities(probe(), PackageManager.MATCH_ALL)
            .map { it.activityInfo.packageName }
            .filter { it != context.packageName }
            .distinct()

    /** Remember the user's current default browser (call before TrustShield becomes the default). */
    fun rememberCurrentDefault(context: Context) {
        val current = context.packageManager.resolveActivity(probe(), PackageManager.MATCH_DEFAULT_ONLY)
            ?.activityInfo?.packageName
        if (current != null && current != context.packageName && current != "android") {
            context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString(KEY_BROWSER, current).apply()
        }
    }

    private fun chooseBrowser(context: Context): String? {
        val installed = otherBrowsers(context)
        val remembered = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY_BROWSER, null)
        return when {
            remembered != null && remembered in installed -> remembered
            else -> PREFERRED.firstOrNull { it in installed } ?: installed.firstOrNull()
        }
    }

    /** Returns false when there is no other browser on the phone to hand the link to. */
    fun open(context: Context, url: String): Boolean {
        val target = chooseBrowser(context) ?: return false
        val intent = Intent(Intent.ACTION_VIEW, Uri.parse(url))
            .addCategory(Intent.CATEGORY_BROWSABLE)
            .setPackage(target)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        return try {
            context.startActivity(intent)
            true
        } catch (e: Exception) {
            false
        }
    }
}
