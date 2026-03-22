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
            val links = UrlNormalizer.extractNormalizedLinks(text)

            links.forEach { url ->
                Log.d(TAG, "Extracted normalized URL: $url")
            }

            Log.d(TAG, "Found ${links.size} links in text")
            links
            
        } catch (e: Exception) {
            Log.e(TAG, "Error extracting links: ${e.message}", e)
            emptyList()
        }
    }
}
