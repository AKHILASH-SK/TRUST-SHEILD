package com.example.trustshield.gate

import android.util.Log
import com.example.trustshield.BuildConfig
import com.example.trustshield.network.AuthStore
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/** One line of the live progress list ("Safe sandbox browser: running"). */
data class StageInfo(val id: String, val label: String, val status: String, val detail: String)

/** What the backend says about a scan right now. */
data class JobSnapshot(
    val jobId: String,
    val state: String,                 // running | done | error
    val progress: Int,
    val joined: Boolean,               // true when we attached to a scan that was already running
    val stages: List<StageInfo>,
    val result: GateResult?,
    val error: String,
    val refining: Boolean = false        // the first verdict is out; the AI second opinion is still running
)

/** Either a snapshot, or a ready-made failure result (signed out, server unreachable...). */
class JobReply(val snapshot: JobSnapshot? = null, val failure: GateResult? = null)

/**
 * Talks to the backend's scan jobs. There is exactly one analysis per link at any moment: when the notification
 * scanner already started it, starting a job here JOINS that scan and continues from its progress instead of
 * running the whole pipeline again. The backend also saves the scan to the user's history.
 */
object GateClient {
    private const val TAG = "GateClient"
    private const val CONNECT_TIMEOUT_MS = 8000
    private const val READ_TIMEOUT_MS = 15000

    fun startJob(url: String, sourceApp: String?): JobReply {
        val label = "Link Gate" + (sourceApp?.let { " ($it)" } ?: "")
        val body = JSONObject().put("url", url).put("source_app", label).put("record", true).toString()
        return call("POST", "/api/links/scan-jobs", body)
    }

    fun pollJob(jobId: String): JobReply = call("GET", "/api/links/scan-jobs/$jobId", null)

    private fun call(method: String, path: String, body: String?): JobReply {
        val token = AuthStore.token
        if (token.isNullOrBlank()) return JobReply(failure = GateResult(GateLevel.SIGNED_OUT))
        return try {
            val conn = URL(BuildConfig.BASE_URL.removeSuffix("/") + path).openConnection() as HttpURLConnection
            conn.requestMethod = method
            conn.connectTimeout = CONNECT_TIMEOUT_MS
            conn.readTimeout = READ_TIMEOUT_MS
            conn.setRequestProperty("Authorization", "Bearer $token")
            if (body != null) {
                conn.doOutput = true
                conn.setRequestProperty("Content-Type", "application/json")
                conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
            }
            val code = conn.responseCode
            val text = (if (code in 200..299) conn.inputStream else conn.errorStream)
                ?.bufferedReader()?.use { it.readText() } ?: ""
            when {
                code == 401 -> {
                    AuthStore.expireSession()
                    JobReply(failure = GateResult(GateLevel.SIGNED_OUT))
                }
                code == 429 -> JobReply(failure = GateResult(GateLevel.ERROR, message = "Too many checks in a short time. Please wait a moment."))
                code == 404 -> JobReply(failure = GateResult(GateLevel.ERROR, message = "The check expired. Please tap the link again."))
                code !in 200..299 -> JobReply(failure = GateResult(GateLevel.ERROR, message = "The TrustShield server answered with an error ($code)."))
                else -> JobReply(snapshot = parseSnapshot(text))
            }
        } catch (e: Exception) {
            Log.w(TAG, "$method $path failed: ${e.javaClass.simpleName}: ${e.message}")
            JobReply(failure = GateResult(GateLevel.ERROR, message = "TrustShield could not reach its server, so this link was not checked."))
        }
    }

    internal fun parseSnapshot(json: String): JobSnapshot {
        val obj = JSONObject(json)
        val stages = mutableListOf<StageInfo>()
        obj.optJSONArray("stages")?.let { arr ->
            for (i in 0 until arr.length()) {
                val s = arr.getJSONObject(i)
                stages.add(StageInfo(s.optString("id"), s.optString("label"), s.optString("status", "pending"), s.optString("detail")))
            }
        }
        val result = obj.optJSONObject("result")?.let { parseResult(it) }
        return JobSnapshot(
            jobId = obj.optString("job_id"), state = obj.optString("state", "running"), progress = obj.optInt("progress", 0),
            joined = obj.optBoolean("joined", false), stages = stages, result = result, error = obj.optString("error", ""),
            refining = obj.optBoolean("refining", false)
        )
    }

    internal fun parseResult(obj: JSONObject): GateResult {
        val shown = obj.optString("display_verdict", "")
        val verdict = obj.optString("verdict", "").uppercase()
        val level = when {
            shown.contains("Dangerous", ignoreCase = true) -> GateLevel.DANGEROUS
            shown.contains("Unverified", ignoreCase = true) -> GateLevel.UNVERIFIED
            shown.contains("Safe", ignoreCase = true) -> GateLevel.SAFE
            verdict == "DANGEROUS" -> GateLevel.DANGEROUS
            verdict == "SAFE" -> GateLevel.SAFE
            else -> GateLevel.UNVERIFIED
        }
        return GateResult(level, GateText.bullets(obj.optString("reasons", "")), aiPending = obj.optBoolean("ai_pending", false))
    }

    /** Current state of a saved scan: its verdict now, and whether the AI second opinion is still running. */
    data class ScanState(val verdict: String, val reasons: String, val aiPending: Boolean)

    fun fetchScanState(scanId: Int): ScanState? {
        val token = AuthStore.token ?: return null
        return try {
            val conn = URL(BuildConfig.BASE_URL.removeSuffix("/") + "/api/links/scans/$scanId").openConnection() as HttpURLConnection
            conn.connectTimeout = CONNECT_TIMEOUT_MS
            conn.readTimeout = READ_TIMEOUT_MS
            conn.setRequestProperty("Authorization", "Bearer $token")
            if (conn.responseCode !in 200..299) return null
            val obj = JSONObject(conn.inputStream.bufferedReader().use { it.readText() })
            ScanState(obj.optString("verdict", "").uppercase(), obj.optString("reasons", ""), obj.optBoolean("ai_pending", false))
        } catch (e: Exception) {
            Log.w(TAG, "scan state failed: ${e.javaClass.simpleName}")
            null
        }
    }
}
