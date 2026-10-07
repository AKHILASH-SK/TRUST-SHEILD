package com.example.trustshield

import android.app.Application
import com.example.trustshield.network.AuthStore

/**
 * Application entry point. Loads the saved session before any activity or the
 * notification listener service makes a network call.
 */
class TrustShieldApp : Application() {
    override fun onCreate() {
        super.onCreate()
        AuthStore.init(this)
    }
}
