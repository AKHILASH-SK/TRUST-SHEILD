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
import com.github.mikephil.charting.charts.BarChart
import com.github.mikephil.charting.components.XAxis
import com.github.mikephil.charting.data.BarData
import com.github.mikephil.charting.data.BarDataSet
import com.github.mikephil.charting.data.BarEntry
import com.github.mikephil.charting.formatter.IndexAxisValueFormatter
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
    private lateinit var barChart: BarChart
    private lateinit var chartProgressBar: ProgressBar
    private lateinit var tvSafePercent: TextView
    private lateinit var pbSafe: ProgressBar
    private lateinit var tvDangerousPercent: TextView
    private lateinit var pbDangerous: ProgressBar
    
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
        barChart = findViewById(R.id.bar_chart)
        chartProgressBar = findViewById(R.id.chart_progress_bar)
        tvSafePercent = findViewById(R.id.tv_safe_percent)
        pbSafe = findViewById(R.id.pb_safe)
        tvDangerousPercent = findViewById(R.id.tv_dangerous_percent)
        pbDangerous = findViewById(R.id.pb_dangerous)
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
            holeRadius = 65f
            transparentCircleRadius = 70f
            setDrawCenterText(true)
            centerText = "Security\nAnalysis"
            setCenterTextSize(14f)
            rotationAngle = 0f
            isRotationEnabled = true
            isHighlightPerTapEnabled = true
            legend.isEnabled = true
            legend.textSize = 12f
            setDrawEntryLabels(false) // Do not draw text on the slices for a cleaner look
        }
        
        barChart.apply {
            description.isEnabled = false
            setDrawGridBackground(false)
            setDrawBarShadow(false)
            setPinchZoom(false)
            setScaleEnabled(false)
            extraBottomOffset = 15f
            
            xAxis.apply {
                position = XAxis.XAxisPosition.BOTTOM
                setDrawGridLines(false)
                granularity = 1f
                valueFormatter = IndexAxisValueFormatter(arrayOf("Safe", "Suspicious", "Dangerous"))
                textSize = 12f
            }
            
            axisLeft.apply {
                setDrawGridLines(true)
                axisMinimum = 0f
                granularity = 1f
                textSize = 12f
            }
            
            axisRight.isEnabled = false
            legend.isEnabled = false
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
                barChart.visibility = View.VISIBLE
                
            } catch (e: Exception) {
                chartProgressBar.visibility = View.GONE
                Log.e(TAG, "Error loading statistics: ${e.message}", e)
                Toast.makeText(this@DashboardActivity, "Network error", Toast.LENGTH_SHORT).show()
            }
        }
    }
    
    private fun updateChart(safe: Int, suspicious: Int, dangerous: Int) {
        // --- Pie Chart Update ---
        val entries = ArrayList<PieEntry>()
        val colors = ArrayList<Int>()
        
        if (safe > 0) {
            entries.add(PieEntry(safe.toFloat(), "Safe"))
            colors.add(Color.parseColor("#00C853")) // Bright Green
        }
        
        if (suspicious > 0) {
            entries.add(PieEntry(suspicious.toFloat(), "Suspicious"))
            colors.add(Color.parseColor("#FFAB00")) // Bright Amber
        }
        
        if (dangerous > 0) {
            entries.add(PieEntry(dangerous.toFloat(), "Dangerous"))
            colors.add(Color.parseColor("#D50000")) // Bright Red
        }
        
        // Handle empty case
        if (entries.isEmpty()) {
            entries.add(PieEntry(1f, "No Data"))
            colors.add(Color.parseColor("#E0E0E0"))
        }
        
        val dataSet = PieDataSet(entries, "")
        dataSet.colors = colors
        dataSet.sliceSpace = 4f
        dataSet.selectionShift = 6f
        dataSet.setDrawValues(false) // Hide percentage text on the pie slices for modern look
        
        val data = PieData(dataSet)
        pieChart.data = data
        pieChart.invalidate()
        pieChart.animateY(1400)
        
        // --- Bar Chart Update ---
        val barEntries = ArrayList<BarEntry>()
        barEntries.add(BarEntry(0f, safe.toFloat()))
        barEntries.add(BarEntry(1f, suspicious.toFloat()))
        barEntries.add(BarEntry(2f, dangerous.toFloat()))
        
        val barDataSet = BarDataSet(barEntries, "Scan Types")
        barDataSet.colors = listOf(
            Color.parseColor("#00C853"), 
            Color.parseColor("#FFAB00"), 
            Color.parseColor("#D50000")
        )
        barDataSet.valueTextSize = 12f
        // Only show value if > 0
        barDataSet.valueFormatter = object : com.github.mikephil.charting.formatter.ValueFormatter() {
            override fun getFormattedValue(value: Float): String {
                return if (value > 0) value.toInt().toString() else ""
            }
        }
        
        val barData = BarData(barDataSet)
        barData.barWidth = 0.5f
        barChart.data = barData
        
        // Ensure max value allows top labels to be seen
        barChart.axisLeft.axisMaximum = (maxOf(safe, suspicious, dangerous) + 1).toFloat()
        
        barChart.invalidate()
        barChart.animateY(1000)
        
        // --- Percentages Update ---
        val total = safe + suspicious + dangerous
        if (total > 0) {
            val safePercent = (safe * 100) / total
            val dangerousPercent = ((suspicious + dangerous) * 100) / total
            
            tvSafePercent.text = "$safePercent%"
            pbSafe.progress = safePercent
            
            tvDangerousPercent.text = "$dangerousPercent%"
            pbDangerous.progress = dangerousPercent
        } else {
            tvSafePercent.text = "0%"
            pbSafe.progress = 0
            
            tvDangerousPercent.text = "0%"
            pbDangerous.progress = 0
        }
    }
}
