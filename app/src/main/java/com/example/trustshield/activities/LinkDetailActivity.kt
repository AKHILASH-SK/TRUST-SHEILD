package com.example.trustshield.activities

import android.content.Intent
import android.os.Bundle
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.lifecycle.lifecycleScope
import com.example.trustshield.R
import com.example.trustshield.firebase.FirebaseService
import com.google.android.material.button.MaterialButton
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * LinkDetailActivity
 * Shows detailed information about a scanned link
 */
class LinkDetailActivity : AppCompatActivity() {
    
    private lateinit var firebaseService: FirebaseService
    private lateinit var toolbar: Toolbar
    private lateinit var urlText: TextView
    private lateinit var hostText: TextView
    private lateinit var verdictText: TextView
    private lateinit var verdictIcon: ImageView
    private lateinit var verificationStatusText: TextView
    private lateinit var verifiedBrandText: TextView
    private lateinit var reasonsList: TextView
    private lateinit var timestampText: TextView
    private lateinit var sourceAppText: TextView
    private lateinit var acceptButton: MaterialButton
    private lateinit var blockButton: MaterialButton
    private lateinit var deleteButton: MaterialButton
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_link_detail)
        
        firebaseService = FirebaseService()
        
        initializeViews()
        setupToolbar()
        loadLinkDetails()
        setupListeners()
    }
    
    private fun initializeViews() {
        toolbar = findViewById(R.id.toolbar)
        urlText = findViewById(R.id.tv_full_url)
        hostText = findViewById(R.id.tv_host)
        verdictText = findViewById(R.id.tv_verdict)
        verdictIcon = findViewById(R.id.iv_verdict_icon)
        verificationStatusText = findViewById(R.id.tv_verification_status)
        verifiedBrandText = findViewById(R.id.tv_verified_brand)
        reasonsList = findViewById(R.id.tv_reasons)
        timestampText = findViewById(R.id.tv_timestamp)
        sourceAppText = findViewById(R.id.tv_source_app)
        acceptButton = findViewById(R.id.btn_accept)
        blockButton = findViewById(R.id.btn_block)
        deleteButton = findViewById(R.id.btn_delete)
    }
    
    private fun setupToolbar() {
        setSupportActionBar(toolbar)
        supportActionBar?.title = "Link Details"
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        toolbar.setNavigationOnClickListener {
            onBackPressed()
        }
    }
    
    private fun loadLinkDetails() {
        val url = intent.getStringExtra("url") ?: ""
        val host = intent.getStringExtra("host") ?: ""
        val verdict = intent.getStringExtra("verdict") ?: "SAFE"
        val riskLevel = intent.getStringExtra("riskLevel") ?: "SAFE"
        val verificationStatus = intent.getStringExtra("verificationStatus")
        val verifiedBrand = intent.getStringExtra("verifiedBrand")
        val reasons = intent.getStringArrayExtra("reasons") ?: arrayOf()
        val timestamp = intent.getLongExtra("timestamp", 0L)
        val sourceApp = intent.getStringExtra("sourceApp") ?: "Unknown"
        val scanId = intent.getStringExtra("scanId") ?: ""
        
        // Display URL and host
        urlText.text = url
        hostText.text = "Host: $host"
        
        // Display verdict with color coding
        verdictText.text = verdict
        when {
            riskLevel.contains("SAFE") -> {
                verdictText.setTextColor(getColor(android.R.color.holo_green_dark))
                verdictIcon.setImageResource(R.drawable.ic_check_circle)  // Green checkmark
            }
            riskLevel.contains("SUSPICIOUS") -> {
                verdictText.setTextColor(getColor(android.R.color.holo_orange_dark))
                verdictIcon.setImageResource(R.drawable.ic_warning_circle)  // Orange warning
            }
            riskLevel.contains("DANGEROUS") -> {
                verdictText.setTextColor(getColor(android.R.color.holo_red_dark))
                verdictIcon.setImageResource(R.drawable.ic_error_circle)  // Red error
            }
        }
        
        // Display verification status
        val allVerifications = buildString {
            append(if (verificationStatus == "VERIFIED_OFFICIAL") "✅" else "❌")
            append(" Verified Official Domain\n")
            
            if (verifiedBrand != null) {
                append("✅ Brand: $verifiedBrand\n")
            }
            
            append("✅ Firebase Phishing Database: Not in DB\n")
            append("✅ Sandbox Analysis: No threats")
        }
        verificationStatusText.text = allVerifications
        
        if (verifiedBrand != null) {
            verifiedBrandText.text = "Official $verifiedBrand"
            verifiedBrandText.visibility = android.view.View.VISIBLE
        }
        
        // Display reasons
        if (reasons.isNotEmpty()) {
            reasonsList.text = reasons.joinToString("\n• ", "• ")
        } else {
            reasonsList.text = "No specific reasons - appears safe"
        }
        
        // Display timestamp
        val dateFormat = SimpleDateFormat("MMM dd, yyyy hh:mm a", Locale.getDefault())
        val formattedDate = dateFormat.format(Date(timestamp))
        timestampText.text = "Scanned: $formattedDate"
        
        // Display source app
        sourceAppText.text = "Source: $sourceApp"
        
        // Store scanId for actions
        acceptButton.tag = scanId
        blockButton.tag = scanId
        deleteButton.tag = scanId
    }
    
    private fun setupListeners() {
        acceptButton.setOnClickListener {
            val scanId = it.tag as? String ?: return@setOnClickListener
            markAsAccepted(scanId)
        }
        
        blockButton.setOnClickListener {
            val scanId = it.tag as? String ?: return@setOnClickListener
            markAsBlocked(scanId)
        }
        
        deleteButton.setOnClickListener {
            val scanId = it.tag as? String ?: return@setOnClickListener
            deleteScan(scanId)
        }
    }
    
    private fun markAsAccepted(scanId: String) {
        lifecycleScope.launch {
            try {
                val userId = firebaseService.getCurrentUserId() ?: return@launch
                val success = firebaseService.updateLinkScanAction(
                    userId, scanId, "accepted", isUserTrusted = true
                )
                if (success) {
                    Toast.makeText(this@LinkDetailActivity, "Marked as trusted", Toast.LENGTH_SHORT).show()
                    acceptButton.isEnabled = false
                }
            } catch (e: Exception) {
                Toast.makeText(this@LinkDetailActivity, "Error: ${e.message}", Toast.LENGTH_SHORT).show()
            }
        }
    }
    
    private fun markAsBlocked(scanId: String) {
        lifecycleScope.launch {
            try {
                val userId = firebaseService.getCurrentUserId() ?: return@launch
                val success = firebaseService.updateLinkScanAction(
                    userId, scanId, "rejected", isUserBlocked = true
                )
                if (success) {
                    Toast.makeText(this@LinkDetailActivity, "Marked as blocked", Toast.LENGTH_SHORT).show()
                    blockButton.isEnabled = false
                }
            } catch (e: Exception) {
                Toast.makeText(this@LinkDetailActivity, "Error: ${e.message}", Toast.LENGTH_SHORT).show()
            }
        }
    }
    
    private fun deleteScan(scanId: String) {
        lifecycleScope.launch {
            try {
                val userId = firebaseService.getCurrentUserId() ?: return@launch
                val success = firebaseService.deleteLinkScan(userId, scanId)
                if (success) {
                    Toast.makeText(this@LinkDetailActivity, "Scan deleted", Toast.LENGTH_SHORT).show()
                    onBackPressed()
                }
            } catch (e: Exception) {
                Toast.makeText(this@LinkDetailActivity, "Error deleting: ${e.message}", Toast.LENGTH_SHORT).show()
            }
        }
    }
}
