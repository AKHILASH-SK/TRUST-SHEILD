package com.example.trustshield.activities

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.FrameLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.lifecycle.lifecycleScope
import com.example.trustshield.R
import com.example.trustshield.firebase.FirebaseService
import com.google.android.material.button.MaterialButton
import com.google.android.material.bottomnavigation.BottomNavigationView
import kotlinx.coroutines.launch

/**
 * ProfileActivity
 * User profile and statistics
 */
class ProfileActivity : AppCompatActivity() {
    
    private lateinit var firebaseService: FirebaseService
    private lateinit var toolbar: Toolbar
    private lateinit var nameText: TextView
    private lateinit var phoneText: TextView
    private lateinit var walletBalanceText: TextView
    private lateinit var logoutButton: MaterialButton
    private lateinit var bottomNav: BottomNavigationView
    private lateinit var progressOverlay: FrameLayout
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_profile)
        
        firebaseService = FirebaseService()
        
        // Check if user is logged in via SharedPreferences
        val sharedPref = getSharedPreferences("trustshield_prefs", Context.MODE_PRIVATE)
        val userId = sharedPref.getInt("user_id", -1)
        
        if (userId == -1 && !firebaseService.isUserLoggedIn()) {
            navigateToLogin()
            return
        }
        
        initializeViews()
        setupToolbar()
        setupListeners()
        loadUserProfile()
    }
    
    private fun initializeViews() {
        toolbar = findViewById(R.id.toolbar)
        nameText = findViewById(R.id.tv_name)
        phoneText = findViewById(R.id.tv_phone)
        walletBalanceText = findViewById(R.id.tv_wallet_balance)
        logoutButton = findViewById(R.id.btn_logout)
        bottomNav = findViewById(R.id.bottom_navigation)
        progressOverlay = findViewById(R.id.progress_overlay)
    }
    
    private fun setupToolbar() {
        setSupportActionBar(toolbar)
        supportActionBar?.setDisplayShowTitleEnabled(false)
    }
    
    private fun setupListeners() {
        bottomNav.selectedItemId = R.id.nav_profile
        
        bottomNav.setOnItemSelectedListener { item ->
            when (item.itemId) {
                R.id.nav_home -> {
                    val intent = Intent(this, HomeActivity::class.java)
                    intent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP
                    startActivity(intent)
                    overridePendingTransition(0, 0)
                    true
                }
                R.id.nav_dashboard -> {
                    val intent = Intent(this, DashboardActivity::class.java)
                    startActivity(intent)
                    overridePendingTransition(0, 0)
                    true
                }
                R.id.nav_profile -> true
                else -> false
            }
        }
        
        logoutButton.setOnClickListener {
            progressOverlay.visibility = View.VISIBLE
            
            // Clear Firebase
            firebaseService.logout()
            
            // Clear SharedPreferences
            val sharedPref = getSharedPreferences("trustshield_prefs", Context.MODE_PRIVATE)
            sharedPref.edit().clear().apply()
            
            Toast.makeText(this, "Logged out successfully", Toast.LENGTH_SHORT).show()
            progressOverlay.visibility = View.GONE
            navigateToLogin()
        }
    }
    
    private fun loadUserProfile() {
        lifecycleScope.launch {
            try {
                progressOverlay.visibility = View.VISIBLE
                
                val user = firebaseService.getCurrentUser()
                
                if (user != null) {
                    nameText.text = user.name
                    phoneText.text = user.phoneNumber
                } else {
                    // Fallback to shared preferences if firebase user object is missing
                    val sharedPref = getSharedPreferences("trustshield_prefs", Context.MODE_PRIVATE)
                    val userName = sharedPref.getString("user_name", "User") ?: "User"
                    nameText.text = userName
                }
                
                // Display wallet balance
                val sharedPref = getSharedPreferences("trustshield_prefs", Context.MODE_PRIVATE)
                val balance = sharedPref.getInt("wallet_balance", 1000)
                walletBalanceText.text = "$balance Scans Left"
                
                progressOverlay.visibility = View.GONE
                
            } catch (e: Exception) {
                progressOverlay.visibility = View.GONE
                Toast.makeText(this@ProfileActivity, "Error loading profile", Toast.LENGTH_SHORT).show()
            }
        }
    }
    
    private fun navigateToLogin() {
        val intent = Intent(this, LoginActivity::class.java)
        intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        startActivity(intent)
        finish()
    }
}
