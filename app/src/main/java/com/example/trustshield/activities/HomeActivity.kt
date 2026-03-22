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
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.example.trustshield.R
import com.example.trustshield.adapters.LinkScanAdapter
import com.example.trustshield.firebase.FirebaseService
import com.example.trustshield.models.LinkScan
import com.google.android.material.button.MaterialButton
import com.google.android.material.floatingactionbutton.FloatingActionButton
import kotlinx.coroutines.launch

/**
 * HomeActivity
 * Displays user's link scan history and statistics
 */
class HomeActivity : AppCompatActivity() {
    
    private lateinit var firebaseService: FirebaseService
    private lateinit var toolbar: Toolbar
    private lateinit var linkHistoryRecycler: RecyclerView
    private lateinit var emptyStateView: View
    private lateinit var emptyStateText: TextView
    private lateinit var progressBar: ProgressBar
    private lateinit var profileButton: MaterialButton
    private lateinit var scanFab: FloatingActionButton
    
    private val linkScanAdapter = LinkScanAdapter { linkScan ->
        onLinkScanClicked(linkScan)
    }
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        try {
            setContentView(R.layout.activity_home)
            
            firebaseService = FirebaseService()
            
            // Check if user is logged in
            if (!firebaseService.isUserLoggedIn()) {
                navigateToLogin()
                return
            }
            
            initializeViews()
            setupToolbar()
            setupRecyclerView()
            setupListeners()
            loadLinkHistory()
        } catch (e: Exception) {
            android.util.Log.e("HomeActivity", "Initialization error: ${e.message}", e)
            Toast.makeText(this, "Error loading home: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }
    
    private fun initializeViews() {
        toolbar = findViewById(R.id.toolbar)
        linkHistoryRecycler = findViewById(R.id.recycler_link_history)
        emptyStateView = findViewById(R.id.empty_state_container)
        emptyStateText = findViewById(R.id.tv_empty_state)
        progressBar = findViewById(R.id.progress_bar)
        profileButton = findViewById(R.id.btn_profile)
        scanFab = findViewById(R.id.fab_scan)
    }
    
    private fun setupToolbar() {
        setSupportActionBar(toolbar)
        supportActionBar?.title = "TrustShield"
        supportActionBar?.subtitle = "Your Link Security Dashboard"
    }
    
    private fun setupRecyclerView() {
        linkHistoryRecycler.apply {
            layoutManager = LinearLayoutManager(this@HomeActivity, LinearLayoutManager.VERTICAL, false)
            adapter = linkScanAdapter
        }
    }
    
    private fun setupListeners() {
        profileButton.setOnClickListener {
            navigateToProfile()
        }
        
        scanFab.setOnClickListener {
            // TODO: Open manual link scanner/input dialog
            // For now, just refresh
            loadLinkHistory()
        }
    }
    
    private fun loadLinkHistory() {
        lifecycleScope.launch {
            try {
                progressBar.visibility = View.VISIBLE
                
                val userId = firebaseService.getCurrentUserId() ?: return@launch
                val linkScans = firebaseService.getUserLinkScans(userId)
                
                progressBar.visibility = View.GONE
                
                if (linkScans.isEmpty()) {
                    emptyStateView.visibility = View.VISIBLE
                    linkHistoryRecycler.visibility = View.GONE
                    emptyStateText.text = "No links scanned yet.\nStart using TrustShield to check link safety!"
                } else {
                    emptyStateView.visibility = View.GONE
                    linkHistoryRecycler.visibility = View.VISIBLE
                    linkScanAdapter.submitList(linkScans)
                }
            } catch (e: Exception) {
                progressBar.visibility = View.GONE
                emptyStateView.visibility = View.VISIBLE
                emptyStateText.text = "Error loading link history: ${e.message}"
            }
        }
    }
    
    private fun onLinkScanClicked(linkScan: LinkScan) {
        val intent = Intent(this, LinkDetailActivity::class.java)
        intent.putExtra("scanId", linkScan.scanId)
        intent.putExtra("url", linkScan.url)
        intent.putExtra("host", linkScan.host)
        intent.putExtra("verdict", linkScan.verdict)
        intent.putExtra("riskLevel", linkScan.riskLevel)
        intent.putExtra("verificationStatus", linkScan.verificationStatus)
        intent.putExtra("verifiedBrand", linkScan.verifiedBrand)
        intent.putExtra("reasons", linkScan.reasons.toTypedArray())
        intent.putExtra("timestamp", linkScan.timestamp)
        intent.putExtra("sourceApp", linkScan.sourceApp)
        startActivity(intent)
    }
    
    private fun navigateToProfile() {
        startActivity(Intent(this, ProfileActivity::class.java))
    }
    
    private fun navigateToLogin() {
        startActivity(Intent(this, LoginActivity::class.java))
        finish()
    }
    
    override fun onResume() {
        super.onResume()
        loadLinkHistory()  // Refresh on resume
    }
}
