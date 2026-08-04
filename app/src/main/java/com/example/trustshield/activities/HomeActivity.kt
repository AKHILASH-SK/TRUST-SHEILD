package com.example.trustshield.activities

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout
import com.example.trustshield.R
import com.example.trustshield.adapters.LinkHistoryAdapter
import com.example.trustshield.network.RetrofitClient
import com.google.android.material.floatingactionbutton.FloatingActionButton
import com.google.android.material.bottomnavigation.BottomNavigationView
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
    private lateinit var swipeRefresh: SwipeRefreshLayout
    private lateinit var scanFab: FloatingActionButton
    private lateinit var bottomNav: BottomNavigationView
    
    private val linkHistoryAdapter = LinkHistoryAdapter()
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        try {
            setContentView(R.layout.activity_home)
            
            // Check if user is logged in
            val sharedPref = getSharedPreferences("trustshield_prefs", Context.MODE_PRIVATE)
            val userId = sharedPref.getInt("user_id", -1)
            
            if (userId == -1) {
                Log.w(TAG, "No logged in user found")
                navigateToLogin()
                return
            }
            
            initializeViews()
            setupToolbar()
            setupRecyclerView()
            setupListeners()
            loadLinkHistory(userId)
            
        } catch (e: Exception) {
            Log.e(TAG, "Error in onCreate: ${e.message}", e)
        }
    }
    
    private fun initializeViews() {
        toolbar = findViewById(R.id.toolbar)
        linkHistoryRecycler = findViewById(R.id.recycler_link_history)
        emptyStateView = findViewById(R.id.empty_state_container)
        emptyStateText = findViewById(R.id.tv_empty_state)
        swipeRefresh = findViewById(R.id.swipe_refresh_layout)
        scanFab = findViewById(R.id.fab_scan)
        bottomNav = findViewById(R.id.bottom_navigation)
    }
    
    private fun setupToolbar() {
        setSupportActionBar(toolbar)
    }
    
    private fun setupRecyclerView() {
        linkHistoryRecycler.apply {
            layoutManager = LinearLayoutManager(this@HomeActivity)
            adapter = linkHistoryAdapter
        }
    }
    
    private fun setupListeners() {
        bottomNav.selectedItemId = R.id.nav_home
        
        bottomNav.setOnItemSelectedListener { item ->
            when (item.itemId) {
                R.id.nav_home -> true
                R.id.nav_dashboard -> {
                    val intent = Intent(this, DashboardActivity::class.java)
                    startActivity(intent)
                    overridePendingTransition(0, 0)
                    true
                }
                R.id.nav_profile -> {
                    val intent = Intent(this, ProfileActivity::class.java)
                    startActivity(intent)
                    overridePendingTransition(0, 0)
                    true
                }
                else -> false
            }
        }
        
        swipeRefresh.setOnRefreshListener {
            val sharedPref = getSharedPreferences("trustshield_prefs", Context.MODE_PRIVATE)
            val userId = sharedPref.getInt("user_id", -1)
            if (userId != -1) {
                loadLinkHistory(userId)
            } else {
                swipeRefresh.isRefreshing = false
            }
        }
        
        scanFab.setOnClickListener {
            val sharedPref = getSharedPreferences("trustshield_prefs", Context.MODE_PRIVATE)
            val userId = sharedPref.getInt("user_id", -1)
            if (userId != -1) {
                swipeRefresh.isRefreshing = true
                loadLinkHistory(userId)
            }
        }
    }
    
    private fun loadLinkHistory(userId: Int) {
        lifecycleScope.launch {
            try {
                emptyStateView.visibility = View.GONE
                swipeRefresh.isRefreshing = true
                
                val apiService = RetrofitClient.getInstance().getApiService()
                val response = apiService.getLinkHistory(userId)
                
                if (response.isSuccessful && response.body() != null) {
                    val historyResponse = response.body()!!
                    Log.d(TAG, "Loaded ${historyResponse.scans.size} scans")
                    
                    if (historyResponse.scans.isEmpty()) {
                        showEmptyState("No scan history found")
                    } else {
                        linkHistoryAdapter.submitList(historyResponse.scans)
                        linkHistoryRecycler.visibility = View.VISIBLE
                    }
                } else {
                    Log.e(TAG, "Failed to load history: ${response.code()}")
                    showEmptyState("Failed to load history")
                    Toast.makeText(this@HomeActivity, "Could not load history", Toast.LENGTH_SHORT).show()
                }
                
                swipeRefresh.isRefreshing = false
                
            } catch (e: Exception) {
                swipeRefresh.isRefreshing = false
                Log.e(TAG, "Network error: ${e.message}", e)
                showEmptyState("Network error")
                Toast.makeText(this@HomeActivity, "Network error", Toast.LENGTH_SHORT).show()
            }
        }
    }
    
    private fun showEmptyState(message: String) {
        emptyStateView.visibility = View.VISIBLE
        linkHistoryRecycler.visibility = View.GONE
        emptyStateText.text = message
    }
    
    private fun navigateToLogin() {
        startActivity(Intent(this, LoginActivity::class.java))
        finish()
    }
}
