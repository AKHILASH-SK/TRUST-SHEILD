package com.example.trustshield.gate

import android.util.Log
import com.example.trustshield.BuildConfig
import com.example.trustshield.network.AuthStore
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/**
 * Asks the backend to run a tapped link through the whole phishing pipeline (threat lists, VirusTotal,
 * sandbox browser, ML, AI second opinion) and returns the three-way answer the pop-up needs.
 * The backend also saves the scan to the user's history.
 */
object GateClient {
    private const val TAG = "GateClient"
    private const val CONNECT_TIMEOUT_MS = 8000
    private const val READ_TIMEOUT_MS = 45000          // a full sandbox scan plus AI review can take 20-35 seconds

    fun scan(url: String, sourceApp: String?): GateResult {
        val token = AuthStore.token
        if (token.isNullOrBlank()) return GateResult(GateLevel.SIGNED_OUT)
        return try {
            val conn = URL(BuildConfig.BASE_URL.removeSuffix("/") + "/api/links/scan").openConnection() as HttpURLConnection
            conn.requestMethod = "POST"
            conn.doOutput = true
            conn.connectTimeout = CONNECT_TIMEOUT_MS
            conn.readTimeout = READ_TIMEOUT_MS
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setRequestProperty("Authorization", "Bearer $token")
            val label = "Link Gate" + (sourceApp?.let { " ($it)" } ?: "")
            val body = JSONObject().put("url", url).put("source_app", label).toString()
            conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }

            val code = conn.responseCode
            val text = (if (code in 200..299) conn.inputStream else conn.errorStream)
                ?.bufferedReader()?.use { it.readText() } ?: ""
            when {
                code == 401 -> {
                    AuthStore.expireSession()
                    GateResult(GateLevel.SIGNED_OUT)
                }
                code == 429 -> GateResult(GateLevel.ERROR, message = "Too many checks in a short time. Please wait a moment.")
                code !in 200..299 -> GateResult(GateLevel.ERROR, message = "The TrustShield server answered with an error ($code).")
                else -> parse(text)
            }
        } catch (e: Exception) {
            Log.w(TAG, "scan failed: ${e.javaClass.simpleName}: ${e.message}")
            GateResult(GateLevel.ERROR, message = "TrustShield could not reach its server, so this link was not checked.")
        }
    }

    internal fun parse(json: String): GateResult {
        val obj = JSONObject(json)
        val shown = obj.optString("display_verdict", "")
        val verdict = obj.optString("verdict", obj.optString("risk_level", "")).uppercase()
        val level = when {
            shown.contains("Dangerous", ignoreCase = true) -> GateLevel.DANGEROUS
            shown.contains("Unverified", ignoreCase = true) -> GateLevel.UNVERIFIED
            shown.contains("Safe", ignoreCase = true) -> GateLevel.SAFE
            verdict == "DANGEROUS" -> GateLevel.DANGEROUS
            verdict == "SAFE" -> GateLevel.SAFE
            else -> GateLevel.UNVERIFIED
        }
        return GateResult(level, GateText.bullets(obj.optString("reasons", "")))
    }
}
