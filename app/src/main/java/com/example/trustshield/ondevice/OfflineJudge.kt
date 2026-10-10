package com.example.trustshield.ondevice

import android.content.Context
import com.example.trustshield.LinkAnalysisResult
import com.example.trustshield.LinkAnalyzer
import com.example.trustshield.LinkRiskLevel
import java.util.Locale

/**
 * What the phone says about a link when the TrustShield server cannot be reached (no internet).
 *
 * It combines the rules the app already had with the on-phone model. The cut-offs come from measuring the model on fresh links it had
 * never seen (3,000 phishing links, 3,000 legitimate sites):
 *     score >= 0.9892  -> 48% of phishing, 0.0% of legitimate sites          => Dangerous
 *     score >= 0.5     -> 75% of phishing, 3.3% of legitimate sites          => Unverified
 *     below that                                                              => "looks normal", never a clean Safe
 * Only the TEXT of the link is judged offline: the page itself cannot be opened, and the answer says so.
 */
object OfflineJudge {
    const val UNVERIFIED_FROM = 0.5

    enum class Level { DANGEROUS, UNVERIFIED, LOOKS_NORMAL }

    class Verdict(val level: Level, val headline: String, val reasons: List<String>, val modelProbability: Double?)

    private const val UNKNOWN_DOMAIN_NOTE = "Unknown domain"

    /** Pure decision logic (unit-tested): the rules' result and the model's score in, one verdict out. */
    fun decide(rules: LinkAnalysisResult, score: OnDeviceModel.Score?, tHigh: Double): Verdict {
        val percent = score?.let { String.format(Locale.US, "%.0f%%", it.probability * 100) }
        val modelLine = percent?.let { "On-phone model: $it chance this link text is phishing" }

        if (rules.riskLevel == LinkRiskLevel.DANGEROUS) {
            return Verdict(Level.DANGEROUS, "Dangerous link", rules.reasons + listOfNotNull(modelLine), score?.probability)
        }
        if (rules.riskLevel == LinkRiskLevel.SAFE) {                       // an official domain or a trusted one
            return Verdict(Level.LOOKS_NORMAL, "Looks normal", rules.reasons, score?.probability)
        }
        // the rules were unsure ("Suspicious"): often only because the domain is unknown
        val concrete = rules.reasons.filter { !it.startsWith(UNKNOWN_DOMAIN_NOTE) && !it.contains("requires sandbox analysis") }
        if (score == null) {
            return Verdict(Level.UNVERIFIED, "Unverified – open with care", rules.reasons, null)
        }
        return when {
            score.probability >= tHigh && !score.freeHosting ->
                Verdict(Level.DANGEROUS, "Dangerous link",
                    listOf("The link text strongly resembles known phishing links") + concrete + listOfNotNull(modelLine), score.probability)
            score.probability >= UNVERIFIED_FROM ->
                Verdict(Level.UNVERIFIED, "Unverified – open with care",
                    (if (score.freeHosting) listOf("The site is on a free hosting platform, where anyone can publish a page") else emptyList()) +
                        listOf("The link text looks like phishing links we have seen") + concrete + listOfNotNull(modelLine), score.probability)
            concrete.isNotEmpty() ->
                Verdict(Level.UNVERIFIED, "Unverified – open with care", concrete + listOfNotNull(modelLine), score.probability)
            else ->
                Verdict(Level.LOOKS_NORMAL, "Looks normal",
                    listOf("The link text looks ordinary and no warning signs were found") + listOfNotNull(modelLine), score.probability)
        }
    }

    /** The whole check for the app: never throws; falls back to the rules alone if the model cannot be loaded. */
    fun judge(context: Context, url: String): Verdict {
        val rules = try { LinkAnalyzer().analyzeLink(url) } catch (e: Exception) {
            return Verdict(Level.UNVERIFIED, "Unverified – open with care", listOf("This link could not be analysed on this phone"), null)
        }
        return try {
            val model = OnDeviceModel.get(context)
            decide(rules, model.score(rules.url), model.tHigh)
        } catch (e: Throwable) {
            decide(rules, null, 1.0)
        }
    }
}
