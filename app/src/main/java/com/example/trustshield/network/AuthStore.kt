package com.example.trustshield.network

import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * AuthStore
 * Holds the bearer token issued by the backend at login.
 * The token lives in app-private storage and is loaded once per process by TrustShieldApp,
 * so activities and the notification listener service all see the same session.
 */
object AuthStore {
    private const val TAG = "AuthStore"
    private const val PREFS = "trustshield_prefs"
    private const val KEY_TOKEN = "auth_token"

    @Volatile
    var token: String? = null
        private set

    private var appContext: Context? = null

    fun init(context: Context) {
        appContext = context.applicationContext
        token = context.applicationContext
            .getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(KEY_TOKEN, null)
    }

    fun saveToken(context: Context, newToken: String?) {
        token = newToken
        context.applicationContext
            .getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .apply { if (newToken.isNullOrBlank()) remove(KEY_TOKEN) else putString(KEY_TOKEN, newToken) }
            .apply()
    }

    /**
     * Called when the server rejects the token (expired or invalid).
     * Clears the session so the next screen sends the user back to login.
     */
    fun expireSession() {
        val context = appContext ?: return
        Log.w(TAG, "Session expired, clearing stored credentials")
        token = null
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .remove(KEY_TOKEN)
            .putBoolean("is_logged_in", false)
            .apply()
    }

    fun clear(context: Context) = saveToken(context, null)
}
