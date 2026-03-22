package com.example.trustshield.activities

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.example.trustshield.R
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * MainActivity
 * Splash/Router Activity - Checks login state and routes to appropriate screen
 * This is the launcher activity
 */
class MainActivity : AppCompatActivity() {
    
    companion object {
        private const val TAG = "MainActivity"
    }
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        
        // Router logic: check if user is logged in
        lifecycleScope.launch {
            try {
                Log.d(TAG, "Checking login status...")
                
                val sharedPref = getSharedPreferences("trustshield_prefs", Context.MODE_PRIVATE)
                val userId = sharedPref.getInt("user_id", -1)
                val isLoggedIn = sharedPref.getBoolean("is_logged_in", false)
                
                Log.d(TAG, "userId: $userId, isLoggedIn: $isLoggedIn")
                
                // Small delay for splash effect (optional)
                delay(500)
                
                if (userId != -1 && isLoggedIn) {
                    // User is logged in - go to HomeActivity
                    Log.d(TAG, "User logged in, navigating to HomeActivity")
                    navigateToHome()
                } else {
                    // User not logged in - go to LoginActivity
                    Log.d(TAG, "User not logged in, navigating to LoginActivity")
                    navigateToLogin()
                }
                
            } catch (e: Exception) {
                Log.e(TAG, "Error checking login status: ${e.message}", e)
                navigateToLogin()
            }
        }
    }
    
    private fun navigateToHome() {
        startActivity(Intent(this, HomeActivity::class.java))
        finish()
    }
    
    private fun navigateToLogin() {
        startActivity(Intent(this, LoginActivity::class.java))
        finish()
    }
}
