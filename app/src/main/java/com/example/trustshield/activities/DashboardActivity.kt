package com.example.trustshield.activities

import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.lifecycle.lifecycleScope
import com.example.trustshield.R
import com.example.trustshield.network.RetrofitClient
import com.github.mikephil.charting.charts.PieChart
import com.github.mikephil.charting.data.PieData
import com.github.mikephil.charting.data.PieDataSet
import com.github.mikephil.charting.data.PieEntry
import com.github.mikephil.charting.formatter.PercentFormatter
import com.google.android.material.bottomnavigation.BottomNavigationView
import kotlinx.coroutines.launch

class DashboardActivity : AppCompatActivity() {
    
    companion object {
        private const val TAG = "DashboardActivity"
    }
    
    private lateinit var toolbar: Toolbar
    private lateinit var bottomNav: BottomNavigationView
    private lateinit var totalScansText: TextView
    private lateinit var pieChart: PieChart
    private lateinit var chartProgressBar: ProgressBar
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_dashboard)
        
        initializeViews()
        setupToolbar()
        setupChart()
        setupListeners()
        
        loadStatistics()
    }
    
    private fun initializeViews() {
        toolbar = findViewById(R.id.toolbar)
        bottomNav = findViewById(R.id.bottom_navigation)
        totalScansText = findViewById(R.id.tv_total_scans)
        pieChart = findViewById(R.id.pie_chart)
        chartProgressBar = findViewById(R.id.chart_progress_bar)
    }
    
    private fun setupToolbar() {
        setSupportActionBar(toolbar)
        supportActionBar?.title = "Security Dashboard"
        supportActionBar?.subtitle = "Your Scanning Statistics"
    }
    
    private fun setupChart() {
        pieChart.apply {
            setUsePercentValues(true)
            description.isEnabled = false
            setExtraOffsets(5f, 10f, 5f, 5f)
            dragDecelerationFrictionCoef = 0.95f
            isDrawHoleEnabled = true
            setHoleColor(Color.WHITE)
            setTransparentCircleColor(Color.WHITE)
            setTransparentCircleAlpha(110)
            holeRadius = 58f
            transparentCircleRadius = 61f
            setDrawCenterText(true)
            centerText = "Security\nAnalysis"
            rotationAngle = 0f
            isRotationEnabled = true
            isHighlightPerTapEnabled = true
            legend.isEnabled = true
        }
    }
    
    private fun setupListeners() {
        bottomNav.selectedItemId = R.id.nav_dashboard
        
        bottomNav.setOnItemSelectedListener { item ->
            when (item.itemId) {
                R.id.nav_home -> {
                    val intent = Intent(this, HomeActivity::class.java)
                    intent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP
                    startActivity(intent)
                    overridePendingTransition(0, 0)
                    true
                }
                R.id.nav_dashboard -> true
                R.id.nav_profile -> {
                    val intent = Intent(this, ProfileActivity::class.java)
                    startActivity(intent)
                    overridePendingTransition(0, 0)
                    true
                }
                else -> false
            }
        }
    }
    
    private fun loadStatistics() {
        val sharedPref = getSharedPreferences("trustshield_prefs", Context.MODE_PRIVATE)
        val userId = sharedPref.getInt("user_id", -1)
        
        if (userId == -1) {
            Toast.makeText(this, "Please log in first", Toast.LENGTH_SHORT).show()
            return
        }
        
        lifecycleScope.launch {
            try {
                chartProgressBar.visibility = View.VISIBLE
                pieChart.visibility = View.INVISIBLE
                
                val apiService = RetrofitClient.getInstance().getApiService()
                val response = apiService.getLinkHistory(userId)
                
                if (response.isSuccessful && response.body() != null) {
                    val scans = response.body()!!.scans
                    
                    var safeCount = 0
                    var suspiciousCount = 0
                    var dangerousCount = 0
                    
                    for (scan in scans) {
                        when (scan.verdict) {
                            "SAFE" -> safeCount++
                            "SUSPICIOUS" -> suspiciousCount++
                            "DANGEROUS" -> dangerousCount++
                        }
                    }
                    
                    totalScansText.text = scans.size.toString()
                    
                    updateChart(safeCount, suspiciousCount, dangerousCount)
                } else {
                    Toast.makeText(this@DashboardActivity, "Error loading stats", Toast.LENGTH_SHORT).show()
                }
                
                chartProgressBar.visibility = View.GONE
                pieChart.visibility = View.VISIBLE
                
            } catch (e: Exception) {
                chartProgressBar.visibility = View.GONE
                Log.e(TAG, "Error loading statistics: ${e.message}", e)
                Toast.makeText(this@DashboardActivity, "Network error", Toast.LENGTH_SHORT).show()
            }
        }
    }
    
    private fun updateChart(safe: Int, suspicious: Int, dangerous: Int) {
        val entries = ArrayList<PieEntry>()
        val colors = ArrayList<Int>()
        
        if (safe > 0) {
            entries.add(PieEntry(safe.toFloat(), "Safe"))
            colors.add(Color.parseColor("#4CAF50"))
        }
        
        if (suspicious > 0) {
            entries.add(PieEntry(suspicious.toFloat(), "Suspicious"))
            colors.add(Color.parseColor("#FF9800"))
        }
        
        if (dangerous > 0) {
            entries.add(PieEntry(dangerous.toFloat(), "Dangerous"))
            colors.add(Color.parseColor("#F44336"))
        }
        
        // Handle empty case
        if (entries.isEmpty()) {
            entries.add(PieEntry(1f, "No Data"))
            colors.add(Color.parseColor("#E0E0E0"))
        }
        
        val dataSet = PieDataSet(entries, "")
        dataSet.colors = colors
        dataSet.sliceSpace = 3f
        dataSet.selectionShift = 5f
        
        val data = PieData(dataSet)
        data.setValueFormatter(PercentFormatter(pieChart))
        data.setValueTextSize(11f)
        data.setValueTextColor(Color.WHITE)
        
        pieChart.data = data
        pieChart.invalidate()
        pieChart.animateY(1400)
    }
}
