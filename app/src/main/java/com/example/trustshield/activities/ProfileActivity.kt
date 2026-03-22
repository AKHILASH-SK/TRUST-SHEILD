package com.example.trustshield.activities

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.lifecycle.lifecycleScope
import com.example.trustshield.R
import com.example.trustshield.firebase.FirebaseService
import com.google.android.material.button.MaterialButton
import com.google.android.material.textfield.TextInputEditText
import kotlinx.coroutines.launch

/**
 * ProfileActivity
 * User profile and statistics
 */
class ProfileActivity : AppCompatActivity() {
    
    private lateinit var firebaseService: FirebaseService
    private lateinit var toolbar: Toolbar
    private lateinit var nameInput: TextInputEditText
    private lateinit var emailInput: TextInputEditText
    private lateinit var phoneText: TextView
    private lateinit var totalScansText: TextView
    private lateinit var safeLinksText: TextView
    private lateinit var suspiciousLinksText: TextView
    private lateinit var dangerousLinksText: TextView
    private lateinit var saveButton: MaterialButton
    private lateinit var logoutButton: MaterialButton
    private lateinit var progressBar: ProgressBar
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_profile)
        
        firebaseService = FirebaseService()
        
        // Check if user is logged in
        if (!firebaseService.isUserLoggedIn()) {
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
        nameInput = findViewById(R.id.et_name)
        emailInput = findViewById(R.id.et_email)
        phoneText = findViewById(R.id.tv_phone)
        totalScansText = findViewById(R.id.tv_total_scans)
        safeLinksText = findViewById(R.id.tv_safe_links)
        suspiciousLinksText = findViewById(R.id.tv_suspicious_links)
        dangerousLinksText = findViewById(R.id.tv_dangerous_links)
        saveButton = findViewById(R.id.btn_save_profile)
        logoutButton = findViewById(R.id.btn_logout)
        progressBar = findViewById(R.id.progress_bar)
    }
    
    private fun setupToolbar() {
        setSupportActionBar(toolbar)
        supportActionBar?.title = "Profile & Settings"
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        toolbar.setNavigationOnClickListener {
            onBackPressed()
        }
    }
    
    private fun setupListeners() {
        saveButton.setOnClickListener {
            val name = nameInput.text?.toString()?.trim() ?: ""
            val email = emailInput.text?.toString()?.trim() ?: ""
            
            if (name.isEmpty()) {
                Toast.makeText(this, "Please enter your name", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            
            updateProfile(name, email)
        }
        
        logoutButton.setOnClickListener {
            firebaseService.logout()
            Toast.makeText(this, "Logged out successfully", Toast.LENGTH_SHORT).show()
            navigateToLogin()
        }
    }
    
    private fun loadUserProfile() {
        lifecycleScope.launch {
            try {
                progressBar.visibility = View.VISIBLE
                
                val user = firebaseService.getCurrentUser()
                val stats = firebaseService.getUserStats()
                
                progressBar.visibility = View.GONE
                
                if (user != null) {
                    nameInput.setText(user.name)
                    emailInput.setText(user.email)
                    phoneText.text = "Phone: ${user.phoneNumber}"
                }
                
                // Display statistics
                totalScansText.text = stats.totalScans.toString()
                safeLinksText.text = "${stats.safeLinks} (${String.format("%.1f", stats.getSafePercentage())}%)"
                suspiciousLinksText.text = "${stats.suspiciousLinks} (${String.format("%.1f", stats.getSuspiciousPercentage())}%)"
                dangerousLinksText.text = "${stats.dangerousLinks} (${String.format("%.1f", stats.getDangerousPercentage())}%)"
                
            } catch (e: Exception) {
                progressBar.visibility = View.GONE
                Toast.makeText(this@ProfileActivity, "Error loading profile: ${e.message}", Toast.LENGTH_SHORT).show()
            }
        }
    }
    
    private fun updateProfile(name: String, email: String) {
        lifecycleScope.launch {
            try {
                val userId = firebaseService.getCurrentUserId() ?: return@launch
                val success = firebaseService.updateUserProfile(userId, name, email)
                
                if (success) {
                    Toast.makeText(this@ProfileActivity, "Profile updated successfully", Toast.LENGTH_SHORT).show()
                } else {
                    Toast.makeText(this@ProfileActivity, "Failed to update profile", Toast.LENGTH_SHORT).show()
                }
            } catch (e: Exception) {
                Toast.makeText(this@ProfileActivity, "Error: ${e.message}", Toast.LENGTH_SHORT).show()
            }
        }
    }
    
    private fun navigateToLogin() {
        startActivity(Intent(this, LoginActivity::class.java))
        finish()
    }
}
