package com.example.trustshield

import android.util.Log

/**
 * LinkExtractor
 * 
 * Extracts all URLs/links from notification text using regex patterns
 * Supports HTTP, HTTPS, and common shortened URL patterns
 */
class LinkExtractor {
    
    companion object {
        private const val TAG = "LINK_EXTRACT"
        
        // Regex patterns for different URL formats
        // Matches http/https URLs, and common URL patterns
        private val URL_REGEX = Regex(
            "(?:https?://)?(?:www\\.)?[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,6}\\b(?:[-a-zA-Z0-9()@:%_\\+.~#?&/=]*)"
        )
        
        // More strict regex for full URLs with protocol
        private val STRICT_URL_REGEX = Regex(
            "https?://[^\\s<>\"{}|\\\\^`\\[\\]]+"
        )
    }
    
    /**
     * Extract all links from a given text
     * 
     * @param text The text to search for links
     * @return List of extracted URLs
     */
    fun extractLinks(text: String?): List<String> {
        if (text.isNullOrBlank()) {
            return emptyList()
        }
        
        return try {
            val links = mutableListOf<String>()
            
            // First, extract strict HTTP/HTTPS URLs
            STRICT_URL_REGEX.findAll(text).forEach { match ->
                val url = match.value.trim()
                if (url.isNotEmpty() && !links.contains(url)) {
                    links.add(url)
                    Log.d(TAG, "Extracted URL: $url")
                }
            }
            
            // If no strict URLs found, try general URL pattern
            if (links.isEmpty()) {
                URL_REGEX.findAll(text).forEach { match ->
                    val url = match.value.trim()
                    // Filter out common false positives
                    if (isValidUrl(url) && !links.contains(url)) {
                        links.add(url)
                        Log.d(TAG, "Extracted URL (pattern): $url")
                    }
                }
            }
            
            Log.d(TAG, "Found ${links.size} links in text")
            links
            
        } catch (e: Exception) {
            Log.e(TAG, "Error extracting links: ${e.message}", e)
            emptyList()
        }
    }
    
    /**
     * Validate if extracted string is a valid URL
     * Filters out common false positives like email addresses
     */
    private fun isValidUrl(url: String): Boolean {
        return url.length > 3 && 
               !url.startsWith("@") && 
               !url.contains("@") && 
               (url.contains(".") || url.contains("://"))
    }
}
