package com.example.trustshield.gate

import android.content.Intent
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.example.trustshield.LinkAnalyzer
import com.example.trustshield.LinkRiskLevel
import com.example.trustshield.R
import com.example.trustshield.activities.MainActivity
import com.google.android.material.button.MaterialButton

/**
 * Link Gate. Receives every web link the user taps in WhatsApp, SMS, e-mail and other apps (while TrustShield is the
 * default browser), runs it through the whole phishing pipeline and then:
 *   Safe                  -> opens it automatically in the real browser
 *   Unverified / Dangerous -> shows why, and lets the user go back or continue at their own risk
 */
class LinkGateActivity : AppCompatActivity() {

    private lateinit var url: String
    private var sourceApp: String? = null
    private val ui = Handler(Looper.getMainLooper())
    private var closed = false
    private var confirmArmed = false

    private lateinit var statusIcon: TextView
    private lateinit var title: TextView
    private lateinit var hostView: TextView
    private lateinit var progress: ProgressBar
    private lateinit var statusText: TextView
    private lateinit var reasonsBox: LinearLayout
    private lateinit var primary: MaterialButton
    private lateinit var secondary: MaterialButton

    private val steps = listOf(
        "Checking the known phishing lists…",
        "Opening the page in a safe sandbox…",
        "Looking at what the page asks for…",
        "Getting a second opinion…"
    )
    private var stepIndex = 0
    private val stepTicker = object : Runnable {
        override fun run() {
            if (closed) return
            stepIndex = (stepIndex + 1).coerceAtMost(steps.lastIndex)
            statusText.text = steps[stepIndex]
            ui.postDelayed(this, 4000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val data = intent?.data
        val scheme = data?.scheme?.lowercase()
        if (data == null || (scheme != "http" && scheme != "https")) {
            finish()
            return
        }
        url = data.toString()
        sourceApp = referrer?.host                       // android-app://<package of the app the link was tapped in>
        setContentView(R.layout.activity_link_gate)

        statusIcon = findViewById(R.id.gate_status_icon)
        title = findViewById(R.id.gate_title)
        hostView = findViewById(R.id.gate_host)
        progress = findViewById(R.id.gate_progress)
        statusText = findViewById(R.id.gate_status)
        reasonsBox = findViewById(R.id.gate_reasons)
        primary = findViewById(R.id.btn_primary)
        secondary = findViewById(R.id.btn_secondary)

        findViewById<View>(R.id.gate_root).setOnClickListener { closeGate() }      // tap outside = go back
        findViewById<View>(R.id.gate_card).setOnClickListener { }                  // taps on the card do nothing
        hostView.text = GateText.hostOf(url)

        showChecking()
        Thread {
            val result = GateClient.scan(url, sourceApp)
            runOnUiThread { if (!closed && !isFinishing) render(result) }
        }.start()
    }

    // ---------------------------------------------------------------------------------------------------------------

    private fun showChecking() {
        paint("…", "#64748B")
        title.text = "Checking this link"
        progress.visibility = View.VISIBLE
        statusText.text = steps[0]
        reasonsBox.removeAllViews()
        primary.text = "Cancel"
        primary.setOnClickListener { closeGate() }
        secondary.visibility = View.GONE
        ui.postDelayed(stepTicker, 4000)
        ui.postDelayed({                                   // a long scan: let the user decide, never trap them
            if (!closed && progress.visibility == View.VISIBLE) {
                secondary.visibility = View.VISIBLE
                secondary.text = "Skip the check"
                secondary.setTextColor(Color.parseColor("#64748B"))
                secondary.setOnClickListener { openLink() }
            }
        }, 8000)
    }

    private fun render(result: GateResult) {
        ui.removeCallbacks(stepTicker)
        progress.visibility = View.GONE
        reasonsBox.removeAllViews()
        when (result.level) {
            GateLevel.SAFE -> {
                paint("✓", "#16A34A")
                title.text = "Safe"
                statusText.text = "Verified safe. Opening…"
                primary.visibility = View.GONE
                secondary.visibility = View.GONE
                ui.postDelayed({ openLink() }, 600)
            }
            GateLevel.UNVERIFIED -> showWarning(
                "!", "#D97706", "Unverified – open with care",
                "TrustShield could not confirm that this link is safe.", result.reasons
            )
            GateLevel.DANGEROUS -> showWarning(
                "✕", "#DC2626", "Dangerous link",
                "This link looks like phishing or malware. Opening it could put your accounts or phone at risk.", result.reasons
            )
            GateLevel.ERROR -> showOffline(result.message)
            GateLevel.SIGNED_OUT -> showSignedOut()
        }
    }

    private fun showWarning(glyph: String, color: String, heading: String, text: String, reasons: List<String>) {
        paint(glyph, color)
        title.text = heading
        statusText.text = text
        reasons.forEach { addReason(it) }
        primary.visibility = View.VISIBLE
        primary.text = "Go back"
        primary.setOnClickListener { closeGate() }
        secondary.visibility = View.VISIBLE
        secondary.text = "Continue at your own risk"
        secondary.setTextColor(Color.parseColor(color))
        val dangerous = heading.startsWith("Dangerous")
        confirmArmed = false
        secondary.setOnClickListener {
            if (dangerous && !confirmArmed) {                  // a dangerous link needs a deliberate second tap
                confirmArmed = true
                secondary.text = "Tap again to open it anyway"
            } else {
                openLink()
            }
        }
    }

    /** The server could not be reached: fall back to the rules on this phone and be honest about it. */
    private fun showOffline(message: String) {
        val local = try { LinkAnalyzer().analyzeLink(url) } catch (e: Exception) { null }
        if (local != null && local.riskLevel != LinkRiskLevel.SAFE) {
            val dangerous = local.riskLevel == LinkRiskLevel.DANGEROUS
            showWarning(
                if (dangerous) "✕" else "!", if (dangerous) "#DC2626" else "#D97706",
                if (dangerous) "Dangerous link" else "Unverified – open with care",
                "Checked on this phone only. $message", local.reasons.take(4)
            )
            return
        }
        paint("?", "#64748B")
        title.text = "Couldn’t check this link"
        statusText.text = message.ifBlank { "This link was not checked." }
        primary.visibility = View.VISIBLE
        primary.text = "Go back"
        primary.setOnClickListener { closeGate() }
        secondary.visibility = View.VISIBLE
        secondary.text = "Open without checking"
        secondary.setTextColor(Color.parseColor("#64748B"))
        secondary.setOnClickListener { openLink() }
    }

    private fun showSignedOut() {
        paint("?", "#64748B")
        title.text = "Sign in to check links"
        statusText.text = "TrustShield checks links for you once you are signed in."
        primary.visibility = View.VISIBLE
        primary.text = "Sign in"
        primary.setOnClickListener {
            startActivity(Intent(this, MainActivity::class.java))
            closeGate()
        }
        secondary.visibility = View.VISIBLE
        secondary.text = "Open without checking"
        secondary.setTextColor(Color.parseColor("#64748B"))
        secondary.setOnClickListener { openLink() }
    }

    // ---------------------------------------------------------------------------------------------------------------

    private fun paint(glyph: String, color: String) {
        statusIcon.text = glyph
        val circle = GradientDrawable().apply {
            shape = GradientDrawable.OVAL
            setColor(Color.parseColor(color))
        }
        statusIcon.background = circle
    }

    private fun addReason(text: String) {
        val row = TextView(this).apply {
            this.text = "•  $text"
            textSize = 14f
            setTextColor(Color.parseColor("#334155"))
            setPadding(0, 6, 0, 6)
        }
        reasonsBox.addView(row)
    }

    private fun openLink() {
        if (closed) return
        if (BrowserHandoff.open(this, url)) {
            closeGate()
        } else {
            Toast.makeText(this, "No other browser app was found to open this link.", Toast.LENGTH_LONG).show()
        }
    }

    private fun closeGate() {
        closed = true
        ui.removeCallbacksAndMessages(null)
        finish()
    }

    override fun onDestroy() {
        closed = true
        ui.removeCallbacksAndMessages(null)
        super.onDestroy()
    }
}
