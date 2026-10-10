package com.example.trustshield.ondevice

import java.io.InputStream
import java.net.IDN
import java.util.Locale
import kotlin.math.ln
import kotlin.math.max

/**
 * The 28 host features of the link-text model, computed on the phone.
 *
 * This file is a line-by-line port of backend/ml/features.py (split_url + lexical_features, host part). The unit test
 * `LexicalParityTest` feeds ~1000 URLs (including awkward ones) through BOTH implementations and demands identical numbers,
 * so a model trained on the server gives the same answer here.
 */

/** Public-suffix splitting, same behaviour as tldextract's bundled snapshot (ICANN rules only). */
class PublicSuffixList(rules: Sequence<String>) {
    private class Node {
        val matches = HashMap<String, Node>()
        var end = false
    }

    private val root = Node()

    init {
        for (rule in rules) {
            val trimmed = rule.trim()
            if (trimmed.isEmpty()) continue
            var node = root
            for (label in trimmed.split(".").asReversed()) node = node.matches.getOrPut(label) { Node() }
            node.end = true
        }
    }

    data class Split(val subdomain: String, val domain: String, val suffix: String)

    private fun decode(label: String): String {
        val lowered = label.lowercase(Locale.ROOT)
        if (lowered.startsWith("xn--")) {
            try {
                return IDN.toUnicode(lowered)
            } catch (e: Exception) { /* keep the ASCII form */ }
        }
        return lowered
    }

    /** tldextract's suffix_index: returns the index of the first public-suffix label, or null when there is no suffix. */
    private fun suffixIndex(labels: List<String>): Int? {
        var node = root
        var suffixIdx = labels.size
        var labelIdx = labels.size
        for (label in labels.asReversed()) {
            val decoded = decode(label)
            val next = node.matches[decoded]
            if (next != null) {
                labelIdx -= 1
                node = next
                if (node.end) suffixIdx = labelIdx
                continue
            }
            if (node.matches.containsKey("*")) {
                val exception = node.matches.containsKey("!$decoded")
                return if (exception) labelIdx else labelIdx - 1
            }
            break
        }
        return if (suffixIdx == labels.size) null else suffixIdx
    }

    /** tldextract(host) for an already extracted host string. */
    fun extract(text: String): Split {
        val netloc = lenientNetloc(text)
        val dotted = netloc.replace('。', '.').replace('．', '.').replace('｡', '.')
        if (dotted.length >= 4 && dotted.first() == '[' && dotted.last() == ']' && looksLikeIpv6(dotted.substring(1, dotted.length - 1))) {
            return Split("", dotted, "")
        }
        val labels = dotted.split(".")
        val index = suffixIndex(labels)
        if (index == null && labels.size == 4 && looksLikeIpv4Text(dotted)) return Split("", dotted, "")
        if (index == null) return Split(labels.dropLast(1).joinToString("."), labels.last(), "")
        val subdomain = if (index >= 2) labels.subList(0, index - 1).joinToString(".") else ""
        val domain = if (index > 0) labels[index - 1] else ""
        val suffix = labels.subList(index, labels.size).joinToString(".")
        return Split(subdomain, domain, suffix)
    }

    companion object {
        private val SCHEME_CHARS = (('a'..'z') + ('A'..'Z') + ('0'..'9') + listOf('+', '-', '.')).toSet()
        private val IPV4_TEXT = Regex("^(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$")

        fun load(stream: InputStream): PublicSuffixList = PublicSuffixList(stream.bufferedReader().useLines { it.toList().asSequence() })

        private fun schemelessUrl(url: String): String {
            val doubleSlashes = url.indexOf("//")
            if (doubleSlashes == 0) return url.substring(2)
            if (doubleSlashes < 2 || url[doubleSlashes - 1] != ':' || url.substring(0, doubleSlashes - 1).any { it !in SCHEME_CHARS }) return url
            return url.substring(doubleSlashes + 2)
        }

        private fun lenientNetloc(url: String): String {
            val afterUserinfo = schemelessUrl(url).substringBefore("/").substringBefore("?").substringBefore("#").substringAfterLast("@")
            if (afterUserinfo.isNotEmpty() && afterUserinfo[0] == '[') {
                val close = afterUserinfo.indexOf(']')
                if (close >= 0) return afterUserinfo.substring(0, close + 1)
            }
            val hostname = afterUserinfo.substringBefore(":").trim()
            return hostname.trimEnd('.', '。', '．', '｡')
        }

        private fun looksLikeIpv4Text(text: String): Boolean = text.isNotEmpty() && text[0].isDigit() && IPV4_TEXT.matches(text)

        private fun looksLikeIpv6(text: String): Boolean = HostFeatures.isIpv6(text)
    }
}

object HostFeatures {
    /** Order of the model's inputs (the model file carries the same list and is checked against it). */
    val NAMES = listOf(
        "host_len", "n_hyphens_host", "n_digits_host", "digit_ratio_host", "entropy_host", "n_subdomains", "is_ip_host", "has_port",
        "nonstd_port", "has_punycode", "tld_id", "tld_len", "tld_abused", "kw_host", "brand_mismatch", "free_hosting", "is_shortener",
        "longest_host_token", "avg_host_token", "vowel_ratio_label", "consonant_run_label", "label_digit_transitions",
        "https_token_in_host", "www_not_first", "n_host_labels", "domain_label_len", "subdomain_len", "has_userinfo"
    )

    class Lists(
        val keywords: List<String>,
        val freeHosting: Set<String>,
        val shorteners: Set<String>,
        val abusedTlds: Set<String>,
        val commonTlds: List<String>,
        val brandDomains: Map<String, List<String>>
    ) {
        val tldId: Map<String, Int> = commonTlds.withIndex().associate { it.value to it.index + 1 }
    }

    // ---- a small, strict re-implementation of the parts of urllib.parse we rely on -------------------------------------------
    class Parsed(val host: String, val port: Int?, val hasUserinfo: Boolean)

    fun parse(rawInput: String): Parsed {
        var raw = rawInput.trim()
        raw = raw.replace("\t", "").replace("\r", "").replace("\n", "")
        val withScheme = if (raw.contains("://")) raw else "http://$raw"
        // scheme
        var rest = withScheme
        val colon = rest.indexOf(':')
        if (colon > 0 && rest[0].isLetter() && rest.substring(0, colon).all { it.isLetterOrDigit() || it == '+' || it == '-' || it == '.' }) {
            rest = rest.substring(colon + 1)
        }
        var netloc = ""
        if (rest.startsWith("//")) {
            var end = rest.length
            for (ch in "/?#") {
                val i = rest.indexOf(ch, 2)
                if (i in 0 until end) end = i
            }
            netloc = rest.substring(2, end)
        }
        val atIndex = netloc.lastIndexOf('@')
        val userinfo = if (atIndex >= 0) netloc.substring(0, atIndex) else ""
        val hostinfo = if (atIndex >= 0) netloc.substring(atIndex + 1) else netloc
        val username = if (atIndex >= 0) userinfo.substringBefore(":") else ""
        val password = if (atIndex >= 0 && userinfo.contains(":")) userinfo.substringAfter(":") else ""
        var hostname: String
        var portText: String?
        val open = hostinfo.indexOf('[')
        if (open >= 0) {
            val bracketed = hostinfo.substring(open + 1)
            hostname = bracketed.substringBefore("]")
            val afterBracket = if (bracketed.contains("]")) bracketed.substringAfter("]") else ""
            portText = if (afterBracket.contains(":")) afterBracket.substringAfter(":") else null
        } else {
            hostname = hostinfo.substringBefore(":")
            portText = if (hostinfo.contains(":")) hostinfo.substringAfter(":") else null
        }
        val port: Int? = portText?.let { t ->
            if (t.isNotEmpty() && t.all { it in '0'..'9' }) t.toLongOrNull()?.takeIf { it in 0..65535 }?.toInt() else null
        }
        val zoneSplit = hostname.indexOf('%')
        hostname = if (hostname.isEmpty()) "" else if (zoneSplit >= 0) hostname.substring(0, zoneSplit).lowercase(Locale.ROOT) + hostname.substring(zoneSplit) else hostname.lowercase(Locale.ROOT)
        return Parsed(hostname, port, username.isNotEmpty() || password.isNotEmpty())
    }

    fun isIpv4(text: String): Boolean {
        val parts = text.split(".")
        if (parts.size != 4) return false
        for (p in parts) {
            if (p.isEmpty() || p.length > 3 || !p.all { it in '0'..'9' }) return false
            if (p.length > 1 && p[0] == '0') return false                    // Python rejects leading zeros
            if (p.toInt() > 255) return false
        }
        return true
    }

    fun isIpv6(textIn: String): Boolean {
        var text = textIn.substringBefore('%')
        if (text.isEmpty() || !text.contains(':')) return false
        var groupsAllowed = 8
        if (text.contains('.')) {                                           // trailing IPv4 part
            val lastColon = text.lastIndexOf(':')
            if (!isIpv4(text.substring(lastColon + 1))) return false
            text = text.substring(0, lastColon + 1) + "0:0"
        }
        if (text.count { it == ':' } < 2 || text.contains(":::")) return false
        val doubleParts = text.split("::")
        if (doubleParts.size > 2) return false
        fun groups(s: String): List<String>? {
            if (s.isEmpty()) return emptyList()
            val g = s.split(":")
            return if (g.all { it.length in 1..4 && it.all { c -> c in '0'..'9' || c in 'a'..'f' || c in 'A'..'F' } }) g else null
        }
        return if (doubleParts.size == 2) {
            val left = groups(doubleParts[0]) ?: return false
            val right = groups(doubleParts[1]) ?: return false
            left.size + right.size <= groupsAllowed - 1
        } else {
            (groups(text) ?: return false).size == groupsAllowed
        }
    }

    private fun entropy(text: String): Double {
        if (text.isEmpty()) return 0.0
        val freq = HashMap<Int, Int>()
        var n = 0
        text.codePoints().forEach { cp -> freq[cp] = (freq[cp] ?: 0) + 1; n++ }
        var sum = 0.0
        for (c in freq.values) {
            val p = c.toDouble() / n
            sum -= p * (ln(p) / ln(2.0))
        }
        return sum
    }

    private fun cpLen(text: String): Int = text.codePointCount(0, text.length)
    private fun isAlpha(cp: Int) = Character.isLetter(cp)
    private fun isDigit(cp: Int) = Character.isDigit(cp)

    fun compute(url: String, psl: PublicSuffixList, lists: Lists): DoubleArray {
        val parsed = parse(url)
        var host = parsed.host.trimEnd('.')
        if (host.startsWith("www.") && host.count { it == '.' } >= 2) host = host.substring(4)
        val ext = psl.extract(host)
        val domainLabel = ext.domain.lowercase(Locale.ROOT)
        val subdomain = ext.subdomain.lowercase(Locale.ROOT)
        val suffix = ext.suffix.lowercase(Locale.ROOT)
        val registered = listOf(ext.domain, ext.suffix).filter { it.isNotEmpty() }.joinToString(".").lowercase(Locale.ROOT)
        val tld = if (suffix.isNotEmpty()) suffix.split(".").last() else ""

        val hostCodePoints = host.codePoints().toArray()
        val hostLen = hostCodePoints.size
        val digits = hostCodePoints.count { isDigit(it) }
        val hostTokens = host.split(Regex("[.\\-]")).filter { it.isNotEmpty() }
        val labelCps = domainLabel.codePoints().toArray()
        val letters = labelCps.count { isAlpha(it) }
        val vowels = labelCps.count { it == 'a'.code || it == 'e'.code || it == 'i'.code || it == 'o'.code || it == 'u'.code }
        var transitions = 0
        for (i in 0 until labelCps.size - 1) {
            val a = labelCps[i]
            val b = labelCps[i + 1]
            if ((isDigit(a) && isAlpha(b)) || (isAlpha(a) && isDigit(b))) transitions++
        }
        var best = 0
        var run = 0
        for (cp in labelCps) {
            if (isAlpha(cp) && cp != 'a'.code && cp != 'e'.code && cp != 'i'.code && cp != 'o'.code && cp != 'u'.code) {
                run++
                best = max(best, run)
            } else {
                run = 0
            }
        }
        val isIp = isIpv4(host.trim('[', ']')) || isIpv6(host.trim('[', ']'))

        val tokens = host.split(Regex("[^a-z0-9]+"))
        val joined = host.replace("-", "").replace(".", "")
        var brandMismatch = 0
        for ((brand, official) in lists.brandDomains) {
            if (tokens.contains(brand) || (brand.length >= 5 && joined.contains(brand))) {
                if (!official.any { registered == it || registered.endsWith(".$it") }) { brandMismatch = 1; break }
            }
        }
        val freeHosting = if (lists.freeHosting.any { host == it || host.endsWith(".$it") }) 1 else 0

        val values = mapOf(
            "host_len" to hostLen.toDouble(),
            "n_hyphens_host" to host.count { it == '-' }.toDouble(),
            "n_digits_host" to digits.toDouble(),
            "digit_ratio_host" to digits.toDouble() / max(1, hostLen),
            "entropy_host" to entropy(host),
            "n_subdomains" to subdomain.split(".").count { it.isNotEmpty() }.toDouble(),
            "is_ip_host" to (if (isIp) 1.0 else 0.0),
            "has_port" to (if (parsed.port != null) 1.0 else 0.0),
            "nonstd_port" to (if (parsed.port != null && parsed.port != 80 && parsed.port != 443) 1.0 else 0.0),
            "has_punycode" to (if (host.contains("xn--")) 1.0 else 0.0),
            "tld_id" to (lists.tldId[tld] ?: 0).toDouble(),
            "tld_len" to cpLen(tld).toDouble(),
            "tld_abused" to (if (tld in lists.abusedTlds) 1.0 else 0.0),
            "kw_host" to lists.keywords.count { host.contains(it) }.toDouble(),
            "brand_mismatch" to brandMismatch.toDouble(),
            "free_hosting" to freeHosting.toDouble(),
            "is_shortener" to (if (registered in lists.shorteners) 1.0 else 0.0),
            "longest_host_token" to (hostTokens.maxOfOrNull { cpLen(it) } ?: 0).toDouble(),
            "avg_host_token" to (if (hostTokens.isEmpty()) 0.0 else hostTokens.sumOf { cpLen(it) }.toDouble() / hostTokens.size),
            "vowel_ratio_label" to (if (letters > 0) vowels.toDouble() / letters else 0.0),
            "consonant_run_label" to best.toDouble(),
            "label_digit_transitions" to transitions.toDouble(),
            "https_token_in_host" to (if (host.contains("https") || host.contains("http")) 1.0 else 0.0),
            "www_not_first" to (if (host.split(".").drop(1).contains("www")) 1.0 else 0.0),
            "n_host_labels" to (if (host.isNotEmpty()) host.split(".").size else 0).toDouble(),
            "domain_label_len" to labelCps.size.toDouble(),
            "subdomain_len" to cpLen(subdomain).toDouble(),
            "has_userinfo" to (if (parsed.hasUserinfo) 1.0 else 0.0)
        )
        return DoubleArray(NAMES.size) { values.getValue(NAMES[it]) }
    }
}
