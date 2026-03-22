package com.example.trustshield

import java.net.IDN
import java.net.URI

data class NormalizedUrl(
    val originalInput: String,
    val normalizedUrl: String,
    val host: String
)

object UrlNormalizer {

    private val STRICT_URL_REGEX = Regex(
        pattern = """(?i)\bhttps?://[^\s<>\"'{}|\\^`\[\]]+"""
    )

    private val DOMAIN_CANDIDATE_REGEX = Regex(
        pattern = """(?i)(?<![@\w])(?:www\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?::\d{2,5})?(?:/[^\s<>\"'{}|\\^`\[\]]*)?"""
    )

    private val SCHEME_REGEX = Regex("""^[a-z][a-z0-9+.-]*://""", RegexOption.IGNORE_CASE)
    private val IP_ADDRESS_REGEX = Regex("""^(\d{1,3}\.){3}\d{1,3}$""")
    private val SECOND_LEVEL_PUBLIC_SUFFIXES = setOf("ac", "co", "com", "edu", "gov", "net", "org")
    private val RESERVED_TLDS = setOf("example", "invalid", "localhost", "local", "test")

    fun extractNormalizedLinks(text: String?): List<String> {
        if (text.isNullOrBlank()) {
            return emptyList()
        }

        val candidates = mutableListOf<Pair<Int, String>>()

        STRICT_URL_REGEX.findAll(text).forEach { match ->
            candidates.add(match.range.first to match.value)
        }

        DOMAIN_CANDIDATE_REGEX.findAll(text).forEach { match ->
            candidates.add(match.range.first to match.value)
        }

        val normalizedLinks = linkedSetOf<String>()
        candidates.sortedBy { it.first }.forEach { (_, candidate) ->
            normalizeCandidate(candidate)?.let { normalizedLinks.add(it.normalizedUrl) }
        }

        return normalizedLinks.toList()
    }

    fun normalizeCandidate(candidate: String): NormalizedUrl? {
        val sanitizedCandidate = sanitizeCandidate(candidate) ?: return null
        val candidateWithScheme = if (SCHEME_REGEX.containsMatchIn(sanitizedCandidate)) {
            sanitizedCandidate
        } else {
            "https://$sanitizedCandidate"
        }

        return try {
            val uri = URI(candidateWithScheme)
            val scheme = uri.scheme?.lowercase() ?: return null
            if (scheme !in setOf("http", "https")) {
                return null
            }

            val host = normalizeHost(uri.host ?: return null) ?: return null
            val port = if (uri.port != -1) ":${uri.port}" else ""
            val path = uri.rawPath ?: ""
            val query = uri.rawQuery?.takeIf { it.isNotBlank() }?.let { "?$it" } ?: ""

            NormalizedUrl(
                originalInput = candidate,
                normalizedUrl = "$scheme://$host$port$path$query",
                host = host
            )
        } catch (_: Exception) {
            null
        }
    }

    fun extractHost(candidate: String): String? {
        return normalizeCandidate(candidate)?.host
    }

    fun isSameOrSubdomain(host: String, rootDomain: String): Boolean {
        val normalizedHost = host.lowercase()
        val normalizedRoot = rootDomain.lowercase()
        return normalizedHost == normalizedRoot || normalizedHost.endsWith(".$normalizedRoot")
    }

    fun extractRegistrableLabel(host: String): String {
        val labels = host.lowercase().split('.').filter { it.isNotBlank() }
        if (labels.isEmpty()) {
            return host.lowercase()
        }

        if (labels.size >= 3 && labels.last().length == 2 && labels[labels.lastIndex - 1] in SECOND_LEVEL_PUBLIC_SUFFIXES) {
            return labels[labels.lastIndex - 2]
        }

        if (labels.size >= 2) {
            return labels[labels.lastIndex - 1]
        }

        return labels.first()
    }

    fun isIpAddress(host: String): Boolean {
        return IP_ADDRESS_REGEX.matches(host)
    }

    private fun sanitizeCandidate(candidate: String): String? {
        val trimmedCandidate = candidate.trim()
            .trimStart('(', '[', '{', '<')
            .trimEnd('.', ',', '!', '?', ';', ':', ')', ']', '}', '>')

        if ('@' in trimmedCandidate) {
            return null
        }

        return trimmedCandidate.takeIf { it.isNotBlank() }
    }

    private fun normalizeHost(host: String): String? {
        val asciiHost = try {
            IDN.toASCII(host.trim().trim('.'), IDN.ALLOW_UNASSIGNED)
        } catch (_: Exception) {
            return null
        }

        val normalizedHost = asciiHost.lowercase().removePrefix("www.")
        return normalizedHost.takeIf { isValidHost(it) }
    }

    private fun isValidHost(host: String): Boolean {
        if (host.isBlank() || host.length > 253) {
            return false
        }

        if (isIpAddress(host)) {
            return true
        }

        if (!host.contains('.')) {
            return false
        }

        val labels = host.split('.')
        if (labels.any { it.isBlank() || it.length > 63 }) {
            return false
        }

        if (labels.last().length < 2) {
            return false
        }

        if (labels.last() in RESERVED_TLDS) {
            return false
        }

        return labels.all { label ->
            label.firstOrNull()?.isLetterOrDigit() == true &&
                label.lastOrNull()?.isLetterOrDigit() == true &&
                label.all { character -> character.isLetterOrDigit() || character == '-' }
        }
    }
}