package com.example.trustshield.ondevice

import android.content.Context
import com.google.gson.Gson
import com.google.gson.annotations.SerializedName
import java.io.InputStream
import kotlin.math.exp
import kotlin.math.floor

/**
 * The link-text model, running on the phone with no internet.
 *
 * It is the same LightGBM model the server uses for link text (350 trees, 28 host features), exported by
 * `python -m ml.export_for_android`, plus the isotonic calibration table and the two thresholds. It only ever looks at the TEXT of the
 * link: the page model needs the sandbox browser, which cannot run on a phone.
 */
class OnDeviceModel private constructor(private val data: ModelJson, private val psl: PublicSuffixList) {

    class TreeJson(
        val sf: IntArray, val th: DoubleArray, val dl: IntArray, val mt: IntArray, val ct: List<List<Int>?>,
        val lc: IntArray, val rc: IntArray, val lv: DoubleArray, val root: Int
    )

    class CalibratorJson(val x: DoubleArray, val y: DoubleArray)
    class ThresholdsJson(@SerializedName("t_low") val tLow: Double, @SerializedName("t_high") val tHigh: Double)
    class ListsJson(
        @SerializedName("suspicious_keywords") val keywords: List<String>,
        @SerializedName("free_hosting_suffixes") val freeHosting: List<String>,
        val shorteners: List<String>,
        @SerializedName("abused_tlds") val abusedTlds: List<String>,
        @SerializedName("common_tlds") val commonTlds: List<String>,
        @SerializedName("brand_domains") val brandDomains: Map<String, List<String>>
    )

    class ModelJson(
        val version: String?, val features: List<String>, val trees: List<TreeJson>,
        val calibrator: CalibratorJson, val thresholds: ThresholdsJson, val lists: ListsJson
    )

    private val lists = HostFeatures.Lists(
        data.lists.keywords, data.lists.freeHosting.toSet(), data.lists.shorteners.toSet(), data.lists.abusedTlds.toSet(),
        data.lists.commonTlds, data.lists.brandDomains
    )

    val version: String get() = data.version ?: "unknown"
    val tLow: Double get() = data.thresholds.tLow
    val tHigh: Double get() = data.thresholds.tHigh

    class Score(val probability: Double, val freeHosting: Boolean, val features: DoubleArray)

    /** Features of a link (the same numbers the Python code computes). */
    fun features(url: String): DoubleArray = HostFeatures.compute(url, psl, lists)

    private fun walk(tree: TreeJson, x: DoubleArray): Double {
        var node = tree.root
        while (node >= 0) {
            val v = x[tree.sf[node]]
            val categories = tree.ct[node]
            val goLeft: Boolean = if (categories != null) {
                !v.isNaN() && v >= 0 && floor(v).toInt() in categories           // categorical split: value in the set -> left
            } else {
                val missingNan = v.isNaN()
                val missingZero = tree.mt[node] == 1 && kotlin.math.abs(v) <= 1e-35
                if ((tree.mt[node] == 2 && missingNan) || missingZero) tree.dl[node] == 1
                else (if (missingNan) 0.0 else v) <= tree.th[node]
            }
            node = if (goLeft) tree.lc[node] else tree.rc[node]
        }
        return tree.lv[node.inv()]
    }

    /** Raw model output turned into a calibrated probability (rounded to 4 decimals like the server does). */
    fun probability(x: DoubleArray): Double {
        var raw = 0.0
        for (tree in data.trees) raw += walk(tree, x)
        val sigmoid = 1.0 / (1.0 + exp(-raw))
        return roundTo4(calibrate(sigmoid))
    }

    private fun calibrate(p: Double): Double {
        val xs = data.calibrator.x
        val ys = data.calibrator.y
        if (p <= xs.first()) return ys.first()
        if (p >= xs.last()) return ys.last()
        var lo = 0
        var hi = xs.size - 1
        while (hi - lo > 1) {
            val mid = (lo + hi) ushr 1
            if (xs[mid] <= p) lo = mid else hi = mid
        }
        val span = xs[hi] - xs[lo]
        return if (span <= 0.0) ys[lo] else ys[lo] + (ys[hi] - ys[lo]) * (p - xs[lo]) / span
    }

    private fun roundTo4(v: Double): Double = Math.rint(v * 10000.0) / 10000.0      // half-to-even, like Python's round()

    fun score(url: String): Score {
        val x = features(url)
        val hostedIndex = HostFeatures.NAMES.indexOf("free_hosting")
        return Score(probability(x), x[hostedIndex] == 1.0, x)
    }

    companion object {
        private const val MODEL_ASSET = "ondevice/lexical_model.json"
        private const val SUFFIX_ASSET = "ondevice/public_suffixes.txt"

        @Volatile private var cached: OnDeviceModel? = null

        /** Loads the model from the app's assets once (about a quarter of a second); later calls are instant. */
        fun get(context: Context): OnDeviceModel {
            cached?.let { return it }
            synchronized(this) {
                cached?.let { return it }
                val app = context.applicationContext
                val model = fromStreams(app.assets.open(MODEL_ASSET), app.assets.open(SUFFIX_ASSET))
                cached = model
                return model
            }
        }

        fun fromStreams(model: InputStream, suffixes: InputStream): OnDeviceModel {
            val json = model.bufferedReader().use { Gson().fromJson(it, ModelJson::class.java) }
            require(json.features == HostFeatures.NAMES) { "the model's feature list does not match the app's feature code" }
            return OnDeviceModel(json, PublicSuffixList.load(suffixes))
        }
    }
}
