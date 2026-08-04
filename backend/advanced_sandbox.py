import whois 
import requests
import re
import logging
from bs4 import BeautifulSoup
from datetime import datetime

logger = logging.getLogger(__name__)

class AdvancedSandboxAnalyzer:
    """
    Tier 4: Advanced Cyber-Forensics 
    Runs when Tier 3 returns "Suspicious" but isn't 100% sure.
    Analyzes:
     1. Domain Age (WHOIS)
     2. Social Media Dead Links (Template cloning)
     3. NLP Urgency Keywords
     4. Abnormal Outbound Payment gateways
    """

    def __init__(self):
        # High-risk urgency keywords often used by 0-day scammers
        self.urgency_keywords = [
            "offer expires", "win a free", "account suspended", "claim your prize",
            "limited time only", "verify immediately", "exclusive deal", "login to continue",
            "free spin", "won a lottery", "iphone 16 pro", "your device is infected", "big billion"
        ]

        # Sketchy payment redirects that real E-commerce wouldn't direct-link
        self.sketchy_payment_links = [
            "upi://pay?", "paypal.me/", "t.me/", "coinbase.com/", "bitcoin:", 
            "cash.app/", "venmo.com/"
        ]

    def run_advanced_fortification(self, url):
        """
        Main entry point for Advanced Tier 4 Analysis
        """
        logger.info(f"🛡️ [TIER 4 ADVANCED SANDBOX] Running Deep Forensics on: {url}")
        
        results = {
            "is_phishing": False,
            "risk_score": 0,
            "reasons": []
        }

        from urllib.parse import urlparse
        domain = urlparse(url).netloc.lower()
        if domain.startswith('www.'):
            domain = domain[4:]

        # Step 1: WHOIS Domain Age Analysis
        domain_age_days = self._check_domain_age(domain)
        if domain_age_days is not None and domain_age_days < 30:
            results["risk_score"] += 40
            results["reasons"].append(f"Domain is extremely new ({domain_age_days} days old)")
        
        # Fetch the HTML safely (spoofed browser to avoid bot blocks)
        html_content = self._fetch_html(url)
        if not html_content:
            results["reasons"].append("Failed to fetch HTML for advanced parsing")
            return results

        soup = BeautifulSoup(html_content, 'html.parser')

        # Step 2: Template Cloning (Dead Social Links)
        dead_link_count = self._check_dead_social_links(soup)
        if dead_link_count > 2:
            results["risk_score"] += 25
            results["reasons"].append(f"Found {dead_link_count} broken/template social links (Sign of cloned site)")

        # Step 3: NLP Urgency Keyword Detection
        urgency_count = self._analyze_nlp_urgency(soup)
        if urgency_count > 0:
            results["risk_score"] += (urgency_count * 10)
            results["reasons"].append(f"Found {urgency_count} extreme urgency/scam keywords in text")

        # Step 4: Outbound Sketchy Payment Links
        payment_red_flags = self._analyze_payment_redirects(soup)
        if payment_red_flags:
            results["risk_score"] += 50
            results["reasons"].append(f"High Risk: Found direct sketchy payment links ({', '.join(payment_red_flags)})")

        # Final ML/Threshold Verdict
        logger.info(f"[TIER 4] Final Risk Score: {results['risk_score']} points")
        if results["risk_score"] >= 60:
            results["is_phishing"] = True
            logger.info("[TIER 4 VERDICT]: DANGEROUS 0-DAY PHISHING DETECTED")

        return results

    def _check_domain_age(self, domain):
        """
        Gets the creation date from WHOIS to detect brand-new 0-day domains.
        """
        try:
            domain_info = whois.whois(domain)
            creation_date = domain_info.creation_date
            
            # Sometimes WHOIS returns a list, sometimes a single datetime
            if type(creation_date) is list:
                creation_date = creation_date[0]
                
            if creation_date:
                age = (datetime.now() - creation_date).days
                logger.info(f"[WHOIS] {domain} is {age} days old.")
                return age
            return None
        except Exception as e:
            logger.warning(f"[WHOIS Error] Could not check age for {domain}: {e}")
            return None

    def _fetch_html(self, url):
        try:
            # We spoof a real browser just like in Tier 3 to prevent 403 Forbidden blocks
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            }
            resp = requests.get(url, headers=headers, timeout=10)
            resp.raise_for_status()
            return resp.text
        except:
            return None

    def _check_dead_social_links(self, soup):
        """
        Fake e-commerce uses standard templates with # or javascript:void links 
        for Facebook/Twitter/Instagram footprint links.
        """
        dead_links = 0
        for anchor in soup.find_all('a', href=True):
            href = anchor['href'].lower()
            if href in ['#', 'javascript:void(0)', 'javascript:;']:
                # If these have social icons inside them or class names indicating social
                parent_html = str(anchor).lower()
                if 'facebook' in parent_html or 'twitter' in parent_html or 'instagram' in parent_html:
                    dead_links += 1
            # Check for placeholder default links
            if href in ['https://facebook.com', 'https://twitter.com', 'https://instagram.com']:
                dead_links += 1
        return dead_links

    def _analyze_nlp_urgency(self, soup):
        """
        Extracts visible text and checks for scam trigger phrases.
        """
        text = soup.get_text().lower()
        count = 0
        for keyword in self.urgency_keywords:
            if keyword in text:
                count += 1
                logger.info(f"[NLP Match] Found scam keyword: '{keyword}'")
        return count

    def _analyze_payment_redirects(self, soup):
        """
        Looks for fake store checkout buttons leading directly to UPI 
        or generic PayPal me rather than legitimate payment gateways.
        """
        found_sketchy = []
        for anchor in soup.find_all('a', href=True):
            href = anchor['href'].lower()
            for payment in self.sketchy_payment_links:
                if payment in href:
                    found_sketchy.append(payment)
        return list(set(found_sketchy))
