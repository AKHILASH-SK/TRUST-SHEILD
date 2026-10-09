package com.example.trustshield.gate

import android.app.role.RoleManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.Settings

/** Link Gate only sees taps in other apps while TrustShield is the phone's default browser. */
object GateSetup {
    fun isEnabled(context: Context): Boolean {
        val probe = Intent(Intent.ACTION_VIEW, Uri.parse("https://example.com")).addCategory(Intent.CATEGORY_BROWSABLE)
        val current = context.packageManager.resolveActivity(probe, PackageManager.MATCH_DEFAULT_ONLY)
            ?.activityInfo?.packageName
        return current == context.packageName
    }

    /** The system dialog "Set TrustShield as your default browser?", or the default-apps settings page as a fallback. */
    fun enableIntent(context: Context): Intent {
        BrowserHandoff.rememberCurrentDefault(context)
        val roles = context.getSystemService(RoleManager::class.java)
        return if (roles != null && roles.isRoleAvailable(RoleManager.ROLE_BROWSER) && !roles.isRoleHeld(RoleManager.ROLE_BROWSER)) {
            roles.createRequestRoleIntent(RoleManager.ROLE_BROWSER)
        } else {
            Intent(Settings.ACTION_MANAGE_DEFAULT_APPS_SETTINGS)
        }
    }
}
