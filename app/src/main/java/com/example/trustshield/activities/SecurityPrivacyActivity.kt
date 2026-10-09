package com.example.trustshield.activities

import android.graphics.Color
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import com.example.trustshield.R
import com.example.trustshield.network.NetLevel
import com.example.trustshield.network.NetworkCheckResult
import com.example.trustshield.network.NetworkChecker
import kotlin.concurrent.thread

/**
 * Security & Privacy: the network safety check. Tests whether the network you are on tampers with DNS, certificates or web pages
 * (the visible effects of a person-in-the-middle) and explains each finding in plain words.
 */
class SecurityPrivacyActivity : AppCompatActivity() {

    private lateinit var button: Button
    private lateinit var progress: ProgressBar
    private lateinit var headline: TextView
    private lateinit var findings: LinearLayout
    private lateinit var note: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_network_check)

        val toolbar = findViewById<Toolbar>(R.id.toolbar)
        setSupportActionBar(toolbar)
        supportActionBar?.title = "Security & Privacy"
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        toolbar.setNavigationOnClickListener { onBackPressed() }

        button = findViewById(R.id.btn_check_network)
        progress = findViewById(R.id.progress_check)
        headline = findViewById(R.id.tv_net_headline)
        findings = findViewById(R.id.ll_net_findings)
        note = findViewById(R.id.tv_net_note)

        button.setOnClickListener { runCheck() }
    }

    private fun runCheck() {
        button.isEnabled = false
        button.text = "Checking ..."
        progress.visibility = View.VISIBLE
        headline.visibility = View.GONE
        findings.removeAllViews()
        thread(name = "network-check") {
            val result = try {
                NetworkChecker().run()
            } catch (e: Exception) {
                null
            }
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                progress.visibility = View.GONE
                button.isEnabled = true
                button.text = "Check again"
                if (result != null) show(result) else {
                    headline.visibility = View.VISIBLE
                    headline.setBackgroundColor(Color.parseColor("#64748B"))
                    headline.text = "The check could not run."
                }
            }
        }
    }

    private fun colorFor(level: NetLevel): Int = Color.parseColor(
        when (level) {
            NetLevel.SAFE -> "#15803D"
            NetLevel.WARNING -> "#B45309"
            NetLevel.DANGER -> "#B91C1C"
            NetLevel.UNKNOWN -> "#64748B"
        }
    )

    private fun show(result: NetworkCheckResult) {
        headline.visibility = View.VISIBLE
        headline.setBackgroundColor(colorFor(result.level))
        headline.text = result.headline
        note.visibility = View.VISIBLE
        findings.removeAllViews()
        val pad = (12 * resources.displayMetrics.density).toInt()
        for (finding in result.findings) {
            val row = TextView(this).apply {
                text = "${finding.title}\n${finding.detail}"
                textSize = 13f
                setTextColor(Color.parseColor("#0F172A"))
                setPadding(pad, pad, pad, pad)
                setBackgroundColor(Color.WHITE)
                val params = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)
                params.bottomMargin = (6 * resources.displayMetrics.density).toInt()
                layoutParams = params
            }
            // a coloured bar on the left would need a drawable; the title colour carries the level instead
            row.setTextColor(if (finding.level == NetLevel.SAFE || finding.level == NetLevel.UNKNOWN) Color.parseColor("#0F172A") else colorFor(finding.level))
            findings.addView(row)
        }
    }
}
