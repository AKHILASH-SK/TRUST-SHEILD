package com.example.trustshield.gate

/** What the Link Gate shows after checking a tapped link. */
enum class GateLevel { SAFE, UNVERIFIED, DANGEROUS, ERROR, SIGNED_OUT }

data class GateResult(
    val level: GateLevel,
    val reasons: List<String> = emptyList(),
    val message: String = ""
)

/** Turns the backend's long forensic text into a few short bullet points a person can read in a pop-up. */
object GateText {
    private const val MAX_BULLETS = 4
    private const val MAX_LENGTH = 150

    fun bullets(raw: String?): List<String> {
        if (raw.isNullOrBlank()) return emptyList()
        var text: String = raw
        val evidenceStart = text.indexOf("Key Forensic Evidence:")
        if (evidenceStart >= 0) {
            text = text.substring(evidenceStart + "Key Forensic Evidence:".length)
            val actionStart = text.indexOf("Recommended Action:")
            if (actionStart >= 0) text = text.substring(0, actionStart)
        }
        return text.split(';', '\n')
            .map { it.trim().trimStart('-', '•', '*', ' ').trim() }
            .filter { it.length > 3 && !it.startsWith("Threat Summary", ignoreCase = true) }
            .map { if (it.length > MAX_LENGTH) it.take(MAX_LENGTH - 1).trimEnd() + "…" else it }
            .distinct()
            .take(MAX_BULLETS)
    }

    /** "https://www.example.com/a/b?x=1" -> "example.com" */
    fun hostOf(url: String): String =
        try {
            android.net.Uri.parse(url).host?.removePrefix("www.") ?: url
        } catch (e: Exception) {
            url
        }
}
