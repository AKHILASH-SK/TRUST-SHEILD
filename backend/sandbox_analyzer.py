"""
Sandbox Analysis Module
Analyzes URLs using VirusTotal API for unknown phishing links
"""

import requests
import json
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SandboxAnalyzer:
    """
    Analyzes URLs that bypass Tier 1 (rule-based) and Tier 2 (Firebase DB)
    Uses VirusTotal API for comprehensive security analysis
    """
    
    def __init__(self, virustotal_api_key):
        """
        Initialize with VirusTotal API key
        Get free key from: https://www.virustotal.com/gui/
        """
        self.vt_api_key = virustotal_api_key
        self.vt_base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": virustotal_api_key
        }
        self.timeout = 10  # seconds
    
    def analyze_url(self, url):
        """
        Analyze URL using VirusTotal
        Returns: {
            "url": str,
            "verdict": "DANGEROUS" | "SUSPICIOUS" | "SAFE",
            "confidence": 0-100,
            "details": str,
            "engines_count": int,
            "malicious_count": int,
            "suspicious_count": int
        }
        """
        try:
            logger.info(f"Analyzing URL via VirusTotal: {url}")
            
            # Step 1: Submit URL to VirusTotal
            submit_response = self._submit_url(url)
            if not submit_response:
                logger.error("Failed to submit URL to VirusTotal")
                return self._safe_response(url, "VirusTotal submission failed")
            
            # Step 2: Get analysis results
            analysis = self._get_analysis_results(url)
            
            # Step 3: Process results
            verdict = self._process_results(analysis)
            
            logger.info(f"Analysis complete: {verdict['verdict']} (confidence: {verdict['confidence']}%)")
            return verdict
            
        except Exception as e:
            logger.error(f"Sandbox analysis error: {str(e)}")
            return self._safe_response(url, f"Analysis error: {str(e)}")
    
    def _submit_url(self, url):
        """Submit URL to VirusTotal for analysis"""
        try:
            data = {"url": url}
            response = requests.post(
                f"{self.vt_base_url}/urls",
                data=data,
                headers=self.headers,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                result = response.json()
                analysis_id = result['data']['id']
                logger.info(f"URL submitted successfully, ID: {analysis_id}")
                return analysis_id
            else:
                logger.error(f"VirusTotal submission failed: {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"Error submitting URL: {str(e)}")
            return None
    
    def _get_analysis_results(self, url):
        """Get analysis results from VirusTotal"""
        try:
            # First try: search for URL to get analysis
            response = requests.get(
                f"{self.vt_base_url}/urls",
                params={"filter": f"url:{url}"},
                headers=self.headers,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                if data['data']:
                    logger.info("Found existing analysis results")
                    return data['data'][0]['attributes']
            
            # If no results found, VirusTotal scan may still be in progress
            logger.info("Analysis results not yet available (scan in progress)")
            return None
            
        except Exception as e:
            logger.error(f"Error getting results: {str(e)}")
            return None
    
    def _process_results(self, analysis):
        """Process VirusTotal analysis results"""
        if not analysis:
            # If analysis not yet available, return SAFE with low confidence
            # Next request will check again
            return {
                "verdict": "SAFE",
                "confidence": 30,  # Low confidence - scan in progress
                "details": "URL scan in progress on VirusTotal - check again in a moment",
                "engines_count": 0,
                "malicious_count": 0,
                "suspicious_count": 0
            }
        
        # Get engine statistics
        stats = analysis.get('last_analysis_stats', {})
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        undetected = stats.get('undetected', 0)
        harmless = stats.get('harmless', 0)
        
        total_engines = malicious + suspicious + undetected + harmless
        
        # Determine verdict
        confidence = 0
        if malicious >= 5:
            verdict = "DANGEROUS"
            confidence = min(100, malicious * 10)
        elif malicious > 0 or suspicious >= 3:
            verdict = "SUSPICIOUS"
            confidence = min(100, (malicious * 10) + (suspicious * 5))
        else:
            verdict = "SAFE"
            confidence = 95
        
        return {
            "verdict": verdict,
            "confidence": confidence,
            "details": f"Malicious: {malicious}, Suspicious: {suspicious}, Safe: {harmless}",
            "engines_count": total_engines,
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "analysis_date": analysis.get('last_analysis_date', 'Unknown')
        }
    
    def _safe_response(self, url, reason):
        """Return safe response when analysis fails"""
        return {
            "verdict": "SAFE",
            "confidence": 50,
            "details": reason,
            "engines_count": 0,
            "malicious_count": 0,
            "suspicious_count": 0
        }


class URLFeatureAnalyzer:
    """
    Extract features from URL for additional analysis
    """
    
    @staticmethod
    def extract_features(url):
        """Extract security-relevant features from URL"""
        features = {
            "url_length": len(url),
            "has_https": url.startswith("https://"),
            "subdomain_count": url.count("."),
            "has_ip_address": URLFeatureAnalyzer._has_ip(url),
            "suspicious_chars": URLFeatureAnalyzer._count_suspicious_chars(url),
            "url_entropy": URLFeatureAnalyzer._calculate_entropy(url)
        }
        return features
    
    @staticmethod
    def _has_ip(url):
        """Check if URL contains IP address"""
        import re
        pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        return bool(re.search(pattern, url))
    
    @staticmethod
    def _count_suspicious_chars(url):
        """Count suspicious characters in URL"""
        suspicious = "!@#$%^&*()"
        return sum(1 for char in url if char in suspicious)
    
    @staticmethod
    def _calculate_entropy(url):
        """Calculate Shannon entropy of URL (higher = more random)"""
        import math
        if not url:
            return 0
        
        entropy = 0
        for char in set(url):
            probability = url.count(char) / len(url)
            entropy -= probability * math.log2(probability)
        
        return round(entropy, 2)
