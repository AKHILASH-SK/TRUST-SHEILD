package com.example.trustshield.gate

import android.content.Intent
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Gravity
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
 * default browser) and holds it until the verdict is known:
 *   Safe                   -> opens it automatically in the real browser
 *   Unverified / Dangerous -> shows why, and lets the user go back or continue at their own risk
 *
 * The check is a shared backend job: if the notification scanner already started (or finished) the same link, this
 * screen joins that job, shows its real stage progress from where it is, and never starts the pipeline again.
 */
class LinkGateActivity : AppCompatActivity() {

    private lateinit var url: String
    private var sourceApp: String? = null
    private val ui = Handler(Looper.getMainLooper())
    @Volatile private var closed = false
    private var confirmArmed = false
    private var stagesBuilt = false

    private lateinit var statusIcon: TextView
    private lateinit var title: TextView
    private lateinit var hostView: TextView
    private lateinit var progress: ProgressBar
    private lateinit var stagesBox: LinearLayout
    private lateinit var statusText: TextView
    private lateinit var reasonsBox: LinearLayout
    private lateinit var primary: MaterialButton
    private lateinit var secondary: MaterialButton
    private val stageRows = mutableMapOf<String, Pair<TextView, TextView>>()      // id -> (icon+label, detail)

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
        stagesBox = findViewById(R.id.gate_stages)
        statusText = findViewById(R.id.gate_status)
        reasonsBox = findViewById(R.id.gate_reasons)
        primary = findViewById(R.id.btn_primary)
        secondary = findViewById(R.id.btn_secondary)

        findViewById<View>(R.id.gate_root).setOnClickListener { closeGate() }      // tap outside = go back
        findViewById<View>(R.id.gate_card).setOnClickListener { }                  // taps on the card do nothing
        hostView.text = GateText.hostOf(url)

        showChecking()
        Thread { runCheck() }.start()
    }

    // ---- the check: start or join the shared job, then follow its progress ---------------------------------------------

    private fun runCheck() {
        val started = System.currentTimeMillis()
        var reply = GateClient.startJob(url, sourceApp)
        while (!closed) {
            reply.failure?.let { failure -> post { render(failure) }; return }
            val snap = reply.snapshot ?: return
            post { showProgress(snap) }
            if (snap.state == "done" && snap.result != null) {
                post { render(snap.result) }
                return
            }
            if (snap.state == "error") {
                post { render(GateResult(GateLevel.ERROR, message = snap.error.ifBlank { "The check could not be completed." })) }
                return
            }
            if (System.currentTimeMillis() - started > MAX_WAIT_MS) {
                post { render(GateResult(GateLevel.ERROR, message = "The check is taking too long.")) }
                return
            }
            try { Thread.sleep(POLL_MS) } catch (e: InterruptedException) { return }
            reply = GateClient.pollJob(snap.jobId)
        }
    }

    private fun post(block: () -> Unit) = runOnUiThread { if (!closed && !isFinishing) block() }

    // ---- screens ------------------------------------------------------------------------------------------------------------

    private fun showChecking() {
        paint("…", "#64748B")
        title.text = "Checking this link"
        progress.isIndeterminate = true
        progress.visibility = View.VISIBLE
        statusText.text = "Starting the safety check…"
        reasonsBox.removeAllViews()
        stagesBox.removeAllViews()
        primary.text = "Cancel"
        primary.setOnClickListener { closeGate() }
        secondary.visibility = View.GONE
        ui.postDelayed({                                   // a long scan: let the user decide, never trap them
            if (!closed && progress.visibility == View.VISIBLE) {
                secondary.visibility = View.VISIBLE
                secondary.text = "Skip the check"
                secondary.setTextColor(Color.parseColor("#64748B"))
                secondary.setOnClickListener { openLink() }
            }
        }, SKIP_AFTER_MS)
    }

    /** Live stage list: where the shared scan really is right now. */
    private fun showProgress(snap: JobSnapshot) {
        progress.isIndeterminate = false
        progress.max = 100
        progress.progress = snap.progress
        statusText.text = if (snap.joined && snap.progress in 1..99)
            "Continuing the check that started when the message arrived…" else "Checking in a safe sandbox…"
        if (!stagesBuilt) {
            stagesBox.removeAllViews()
            snap.stages.forEach { stage ->
                val row = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(0, 5, 0, 5) }
                val line = TextView(this).apply { textSize = 15f; gravity = Gravity.START }
                val detail = TextView(this).apply { textSize = 12f; setTextColor(Color.parseColor("#94A3B8")); setPadding(44, 0, 0, 0) }
                row.addView(line); row.addView(detail)
                stagesBox.addView(row)
                stageRows[stage.id] = line to detail
            }
            stagesBuilt = true
        }
        snap.stages.forEach { stage ->
            val (line, detail) = stageRows[stage.id] ?: return@forEach
            val (icon, color) = when (stage.status) {
                "done" -> "✓" to "#16A34A"
                "running" -> "◐" to "#0891B2"
                "skipped" -> "–" to "#94A3B8"
                else -> "○" to "#CBD5E1"
            }
            line.text = "$icon   ${stage.label}"
            line.setTextColor(Color.parseColor(if (stage.status == "pending") "#94A3B8" else if (stage.status == "skipped") "#94A3B8" else "#0F172A"))
            line.setCompoundDrawablesWithIntrinsicBounds(0, 0, 0, 0)
            line.text = android.text.SpannableString("$icon   ${stage.label}").apply {
                setSpan(android.text.style.ForegroundColorSpan(Color.parseColor(color)), 0, 1, 0)
                setSpan(android.text.style.StyleSpan(android.graphics.Typeface.BOLD), 0, 1, 0)
            }
            detail.text = stage.detail
            detail.visibility = if (stage.detail.isBlank()) View.GONE else View.VISIBLE
        }
    }

    private fun render(result: GateResult) {
        progress.visibility = View.GONE
        stagesBox.removeAllViews()
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

    // ---- helpers ---------------------------------------------------------------------------------------------------------------

    private fun paint(glyph: String, color: String) {
        statusIcon.text = glyph
        statusIcon.background = GradientDrawable().apply {
            shape = GradientDrawable.OVAL
            setColor(Color.parseColor(color))
        }
    }

    private fun addReason(text: String) {
        reasonsBox.addView(TextView(this).apply {
            this.text = "•  $text"
            textSize = 14f
            setTextColor(Color.parseColor("#334155"))
            setPadding(0, 6, 0, 6)
        })
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

    companion object {
        private const val POLL_MS = 900L
        private const val MAX_WAIT_MS = 80_000L
        private const val SKIP_AFTER_MS = 8_000L
    }
}
