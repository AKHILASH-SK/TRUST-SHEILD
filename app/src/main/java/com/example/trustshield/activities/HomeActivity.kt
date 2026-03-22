package com.example.trustshield.activities

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.util.Log
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
import com.example.trustshield.adapters.LinkHistoryAdapter
import com.example.trustshield.network.RetrofitClient
import com.google.android.material.button.MaterialButton
import com.google.android.material.floatingactionbutton.FloatingActionButton
import kotlinx.coroutines.launch

/**
 * HomeActivity
 * Displays user's link scan history from backend
 */
class HomeActivity : AppCompatActivity() {
    
    companion object {
        private const val TAG = "HomeActivity"
    }
    
    private lateinit var toolbar: Toolbar
    private lateinit var linkHistoryRecycler: RecyclerView
    private lateinit var emptyStateView: View
    private lateinit var emptyStateText: TextView
    private lateinit var progressBar: ProgressBar
    private lateinit var profileButton: MaterialButton
    private lateinit var logoutButton: MaterialButton
    private lateinit var scanFab: FloatingActionButton
    private lateinit var userGreeting: TextView
    
    private val linkHistoryAdapter = LinkHistoryAdapter()
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        try {
            setContentView(R.layout.activity_home)
            
            // Check if user is logged in
            val sharedPref = getSharedPreferences("trustshield_prefs", Context.MODE_PRIVATE)
            val userId = sharedPref.getInt("user_id", -1)
            val userName = sharedPref.getString("user_name", "User") ?: "User"
            
            if (userId == -1) {
                Log.w(TAG, "No logged in user found")
                navigateToLogin()
                return
            }
            
            initializeViews()
            setupToolbar(userName)
            setupRecyclerView()
            setupListeners()
            loadLinkHistory(userId)
            
        } catch (e: Exception) {
            Log.e(TAG, "Initialization error: ${e.message}", e)
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
        logoutButton = findViewById(R.id.btn_logout)
        scanFab = findViewById(R.id.fab_scan)
        userGreeting = findViewById(R.id.tv_user_greeting)
    }
    
    private fun setupToolbar(userName: String) {
        setSupportActionBar(toolbar)
        supportActionBar?.title = "TrustShield"
        supportActionBar?.subtitle = "Link Security Dashboard"
        userGreeting.text = "Welcome back, $userName!"
    }
    
    private fun setupRecyclerView() {
        linkHistoryRecycler.apply {
            layoutManager = LinearLayoutManager(this@HomeActivity)
            adapter = linkHistoryAdapter
        }
    }
    
    private fun setupListeners() {
        profileButton.setOnClickListener {
            Toast.makeText(this, "Profile page coming soon", Toast.LENGTH_SHORT).show()
        }
        
        logoutButton.setOnClickListener {
            logout()
        }
        
        scanFab.setOnClickListener {
            val sharedPref = getSharedPreferences("trustshield_prefs", Context.MODE_PRIVATE)
            val userId = sharedPref.getInt("user_id", -1)
            if (userId != -1) {
                loadLinkHistory(userId)
            }
        }
    }
    
    private fun loadLinkHistory(userId: Int) {
        lifecycleScope.launch {
            try {
                progressBar.visibility = View.VISIBLE
                Log.d(TAG, "Loading link history for user: $userId")
                
                val apiService = RetrofitClient.getInstance().getApiService()
                val response = apiService.getLinkHistory(userId)
                
                if (response.isSuccessful && response.body() != null) {
                    val historyResponse = response.body()!!
                    val links = historyResponse.scans
                    
                    Log.d(TAG, "Loaded ${links.size} links from backend")
                    
                    progressBar.visibility = View.GONE
                    
                    if (links.isEmpty()) {
                        emptyStateView.visibility = View.VISIBLE
                        linkHistoryRecycler.visibility = View.GONE
                        emptyStateText.text = "No links scanned yet.\nStart using TrustShield to check link safety!"
                    } else {
                        emptyStateView.visibility = View.GONE
                        linkHistoryRecycler.visibility = View.VISIBLE
                        linkHistoryAdapter.submitList(links)
                    }
                } else {
                    progressBar.visibility = View.GONE
                    emptyStateView.visibility = View.VISIBLE
                    emptyStateText.text = "Error loading link history: ${response.code()} ${response.message()}"
                    Log.e(TAG, "Error loading history: ${response.code()} ${response.message()}")
                }
                
            } catch (e: Exception) {
                progressBar.visibility = View.GONE
                emptyStateView.visibility = View.VISIBLE
                emptyStateText.text = "Error: ${e.message}"
                Log.e(TAG, "Exception loading history: ${e.message}", e)
            }
        }
    }
    
    private fun logout() {
        try {
            val sharedPref = getSharedPreferences("trustshield_prefs", Context.MODE_PRIVATE)
            sharedPref.edit().clear().apply()
            
            Toast.makeText(this, "Logged out successfully", Toast.LENGTH_SHORT).show()
            navigateToLogin()
        } catch (e: Exception) {
            Log.e(TAG, "Logout error: ${e.message}", e)
        }
    }
    
    private fun navigateToLogin() {
        startActivity(Intent(this, LoginActivity::class.java))
        finish()
    }
}
