package com.example.trustshield

import com.example.trustshield.ondevice.HostFeatures
import com.example.trustshield.ondevice.OfflineJudge
import com.example.trustshield.ondevice.OnDeviceModel
import com.google.gson.Gson
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import java.io.File

/**
 * Proves the model on the phone gives the same answers as the model on the server.
 * lexical_parity.json is produced by the REAL Python code (python -m ml.export_for_android): for each URL the 28 features, and the
 * calibrated probability. The Kotlin code must reproduce them.
 */
class LexicalParityTest {

    class Case(val url: String, val features: DoubleArray, val raw: Double, val p: Double)
    class Parity(val features: List<String>, val cases: List<Case>)

    companion object {
        private lateinit var model: OnDeviceModel
        private lateinit var parity: Parity

        @BeforeClass
        @JvmStatic
        fun load() {
            val assets = File("src/main/assets/ondevice")
            model = OnDeviceModel.fromStreams(File(assets, "lexical_model.json").inputStream(), File(assets, "public_suffixes.txt").inputStream())
            val stream = LexicalParityTest::class.java.classLoader!!.getResourceAsStream("lexical_parity.json")!!
            parity = stream.bufferedReader(Charsets.UTF_8).use { Gson().fromJson(it, Parity::class.java) }
        }
    }

    @Test
    fun featureNamesAndOrderMatchThePythonModel() {
        assertEquals(HostFeatures.NAMES, parity.features)
    }

    @Test
    fun everyFeatureIsIdenticalToThePythonValue() {
        val problems = mutableListOf<String>()
        for (case in parity.cases) {
            val got = model.features(case.url)
            for (i in got.indices) {
                if (Math.abs(got[i] - case.features[i]) > 1e-9) {
                    problems += "${case.url.take(70)} :: ${HostFeatures.NAMES[i]} kotlin=${got[i]} python=${case.features[i]}"
                }
            }
        }
        assertTrue("${problems.size} feature differences out of ${parity.cases.size} links, first ones:\n" + problems.take(25).joinToString("\n"), problems.isEmpty())
    }

    @Test
    fun everyProbabilityIsTheSameAsOnTheServer() {
        val problems = mutableListOf<String>()
        for (case in parity.cases) {
            val got = model.probability(case.features)                    // from the Python features: isolates the tree code
            if (Math.abs(got - case.p) > 1.1e-4) problems += "${case.url.take(70)} :: kotlin=$got python=${case.p}"
        }
        assertTrue("${problems.size} probability differences, first ones:\n" + problems.take(25).joinToString("\n"), problems.isEmpty())
    }

    @Test
    fun endToEndFromTheLinkTextGivesTheServersProbability() {
        val problems = mutableListOf<String>()
        for (case in parity.cases) {
            val got = model.score(case.url).probability
            if (Math.abs(got - case.p) > 1.1e-4) problems += "${case.url.take(70)} :: kotlin=$got python=${case.p}"
        }
        assertTrue("${problems.size} end-to-end differences, first ones:\n" + problems.take(25).joinToString("\n"), problems.isEmpty())
    }

    // ---- the offline decision (pure logic) --------------------------------------------------------------------------------------
    private fun rules(level: LinkRiskLevel, vararg reasons: String) = LinkAnalysisResult("https://x.example/", level, reasons.toList())
    private fun score(p: Double, hosted: Boolean = false) = OnDeviceModel.Score(p, hosted, DoubleArray(0))
    private val tHigh = 0.9892

    @Test
    fun rulesThatSayDangerousStayDangerous() {
        val v = OfflineJudge.decide(rules(LinkRiskLevel.DANGEROUS, "Brand abuse"), score(0.01), tHigh)
        assertEquals(OfflineJudge.Level.DANGEROUS, v.level)
    }

    @Test
    fun anUnknownDomainWithAHighModelScoreIsDangerousButNotOnFreeHosting() {
        val unknown = rules(LinkRiskLevel.SUSPICIOUS, "Unknown domain - requires sandbox analysis (Tier 3)")
        assertEquals(OfflineJudge.Level.DANGEROUS, OfflineJudge.decide(unknown, score(0.995), tHigh).level)
        assertEquals(OfflineJudge.Level.UNVERIFIED, OfflineJudge.decide(unknown, score(0.995, hosted = true), tHigh).level)   // the hosting lesson
    }

    @Test
    fun aMiddleScoreIsUnverifiedAndALowScoreOfAnUnknownDomainLooksNormalButNeverSafe() {
        val unknown = rules(LinkRiskLevel.SUSPICIOUS, "Unknown domain - requires sandbox analysis (Tier 3)")
        assertEquals(OfflineJudge.Level.UNVERIFIED, OfflineJudge.decide(unknown, score(0.6), tHigh).level)
        val ordinary = OfflineJudge.decide(unknown, score(0.04), tHigh)
        assertEquals(OfflineJudge.Level.LOOKS_NORMAL, ordinary.level)
        assertTrue(ordinary.reasons.any { it.contains("ordinary") })
    }

    @Test
    fun concreteRuleWarningsKeepALowScoreLinkUnverified() {
        val warned = rules(LinkRiskLevel.SUSPICIOUS, "Contains an @ sign before the host")
        assertEquals(OfflineJudge.Level.UNVERIFIED, OfflineJudge.decide(warned, score(0.02), tHigh).level)
    }

    @Test
    fun withoutAModelTheRulesDecideAndTheAnswerIsNeverMoreHopefulThanBefore() {
        val unknown = rules(LinkRiskLevel.SUSPICIOUS, "Unknown domain - requires sandbox analysis (Tier 3)")
        assertEquals(OfflineJudge.Level.UNVERIFIED, OfflineJudge.decide(unknown, null, tHigh).level)
        assertEquals(OfflineJudge.Level.LOOKS_NORMAL, OfflineJudge.decide(rules(LinkRiskLevel.SAFE, "Verified official domain"), null, tHigh).level)
    }
}
