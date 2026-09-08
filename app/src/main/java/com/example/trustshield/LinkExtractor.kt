package com.example.trustshield

import android.os.Bundle
import android.text.Spanned
import android.text.style.URLSpan
import android.util.Log

/**
 * LinkExtractor
 * 
 * Robust extractor for all types of links from Android notifications and inputs:
 * 1. Plain text URLs (http://, https://, www.*) via UrlNormalizer
 * 2. Android rich-text hyperlinks via URLSpan on Spanned CharSequences
 * 3. Raw HTML anchor tags (<a href="...">)
 * 4. Deep recursive extraction across all keys in an Android notification Bundle
 */
class LinkExtractor {
    
    companion object {
        private const val TAG = "LINK_EXTRACT"
        private val HTML_HREF_REGEX = Regex("""(?i)<a\s+[^>]*?href\s*=\s*["']([^"']+)["']""")
    }
    
    /**
     * Extract all links from a CharSequence, extracting both plain text URLs
     * and underlying hyperlinks attached as URLSpan.
     */
    fun extractLinks(cs: CharSequence?): List<String> {
        if (cs == null || cs.isBlank()) {
            return emptyList()
        }
        
        val foundLinks = linkedSetOf<String>()
        
        // 1. If it's a Spanned string (rich text / HTML from email/chat), extract URLSpans
        if (cs is Spanned) {
            try {
                val urlSpans = cs.getSpans(0, cs.length, URLSpan::class.java)
                for (span in urlSpans) {
                    val rawUrl = span.url
                    if (!rawUrl.isNullOrBlank()) {
                        Log.d(TAG, "🔗 Extracted link from URLSpan: $rawUrl")
                        UrlNormalizer.normalizeCandidate(rawUrl)?.let {
                            foundLinks.add(it.normalizedUrl)
                        }
                    }
                }
            } catch (e: Exception) {
                Log.w(TAG, "Error inspecting URLSpan: ${e.message}")
            }
        }
        
        val text = cs.toString()
        
        // 2. Check for raw HTML tags e.g. <a href="https://...">
        try {
            HTML_HREF_REGEX.findAll(text).forEach { match ->
                val href = match.groupValues[1]
                Log.d(TAG, "🔗 Extracted link from HTML href tag: $href")
                UrlNormalizer.normalizeCandidate(href)?.let {
                    foundLinks.add(it.normalizedUrl)
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Error inspecting HTML href: ${e.message}")
        }
        
        // 3. Extract normalized URLs from plain text via regex
        foundLinks.addAll(UrlNormalizer.extractNormalizedLinks(text))
        
        return foundLinks.toList()
    }
    
    /**
     * Backwards-compatible overload for String
     */
    fun extractLinks(text: String?): List<String> {
        return extractLinks(text as? CharSequence)
    }
    
    /**
     * Deep extraction of all links and URLSpans from a notification Bundle
     * Checks all extras fields, text lines, and nested bundles
     */
    fun extractLinksFromBundle(bundle: Bundle?): List<String> {
        if (bundle == null) return emptyList()
        val foundLinks = linkedSetOf<String>()
        
        try {
            for (key in bundle.keySet()) {
                val value = bundle.get(key) ?: continue
                when (value) {
                    is CharSequence -> {
                        foundLinks.addAll(extractLinks(value))
                    }
                    is Array<*> -> {
                        for (item in value) {
                            if (item is CharSequence) {
                                foundLinks.addAll(extractLinks(item))
                            } else if (item is Bundle) {
                                foundLinks.addAll(extractLinksFromBundle(item))
                            }
                        }
                    }
                    is ArrayList<*> -> {
                        for (item in value) {
                            if (item is CharSequence) {
                                foundLinks.addAll(extractLinks(item))
                            } else if (item is Bundle) {
                                foundLinks.addAll(extractLinksFromBundle(item))
                            }
                        }
                    }
                    is Bundle -> {
                        foundLinks.addAll(extractLinksFromBundle(value))
                    }
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error extracting links from bundle: ${e.message}", e)
        }
        
        return foundLinks.toList()
    }
}

