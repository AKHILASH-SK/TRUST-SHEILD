"""
TrustShield V2 - Unified Phishing Link Pipeline Orchestrator
Coordinates the 4-stage link evaluation lifecycle:
  Stage 1: Fast Heuristic & Rule-Based Parser (< 1 ms)
  Stage 2: Local Threat Database Cache (< 2 ms)
  Stage 3: Headless Chrome Stealth Sandbox Detonation (2 - 4 s)
  Stage 4: Meta-Classifier & LLM Explainer Fusion Engine
"""

import os
import sys
import logging
from typing import Dict, Any, Optional
from urllib.parse import urlparse
import tldextract

# Local Core Engine imports
from .url_heuristics import parse_url_heuristics
from .threat_db import get_threat_db, ThreatIntelDB
from .sandbox_engine import VirtualSandboxAnalyzer
from .final_decision_engine import FinalDecisionEngine

logger = logging.getLogger(__name__)

# High-reputation global domains and official shorteners that bypass sandbox interrogation
GLOBAL_CLEAN_DOMAINS = {
    # Google Ecosystem
    "google.com", "forms.gle", "docs.google.com", "drive.google.com", "forms.google.com",
    "goo.gl", "g.co", "gmail.com", "youtube.com", "youtu.be", "googleusercontent.com", "gstatic.com",
    "google.co.in", "google.co.uk", "google.ca", "google.de", "google.fr", "google.com.au",
    
    # Microsoft & Office / Teams Ecosystem
    "microsoft.com", "office.com", "live.com", "outlook.com", "office365.com", "windows.net",
    "sharepoint.com", "microsoftonline.com", "teams.microsoft.com", "forms.office.com", "forms.microsoft.com",
    "aka.ms", "msft.it", "bing.com", "msn.com",
    
    # Apple Ecosystem
    "apple.com", "icloud.com", "apple.co",
    
    # Amazon & AWS
    "amazon.com", "amazon.in", "amazon.co.uk", "amzn.to", "aws.amazon.com",
    
    # Education & Learning Platforms
    "coursera.org", "edx.org", "udemy.com", "khanacademy.org", "codecademy.com", "datacamp.com",
    "mit.edu", "stanford.edu", "harvard.edu",
    
    # Financial & Payments
    "paypal.com", "paypal.me", "stripe.com", "razorpay.com", "intuit.com",
    
    # Social & Professional Networks
    "linkedin.com", "lnkd.in",
    "twitter.com", "x.com", "t.co",
    "facebook.com", "fb.com", "fb.me", "instagram.com", "instagr.am", "whatsapp.com", "wa.me",
    "telegram.org", "t.me",
    
    # Form, Survey & Collaboration Platforms
    "typeform.com", "jotform.com", "surveymonkey.com", "airtable.com", "zoho.com", "forms.zoho.com",
    "slack.com", "atlassian.com", "jira.com", "trello.com", "asana.com", "figma.com", "dropbox.com", "box.com",
    "salesforce.com", "hubspot.com", "mailchimp.com", "zendesk.com",
    
    # Developer & Infrastructure
    "github.com", "git.io", "gitlab.com", "stackoverflow.com", "bitbucket.org",
    "openai.com", "chatgpt.com",
    "wikipedia.org", "cloudflare.com", "zoom.us", "canva.com", "notion.so", "spotify.com", "spoti.fi",
    "medium.com", "quora.com", "reddit.com", "netflix.com", "uber.com", "adobe.com"
}


class LinkThreatPipeline:
    """
    End-to-End Orchestrator for URL/Link Phishing Intelligence.
    """
    def __init__(self, threat_db: Optional[ThreatIntelDB] = None):
        self.threat_db = threat_db or get_threat_db()
        self.sandbox = VirtualSandboxAnalyzer()
        self.decision_engine = FinalDecisionEngine()
        
        # Optional GoodDomainChecker via VirusTotal API
        vt_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.good_domain_checker = None
        if vt_key:
            try:
                from good_domain_checker import GoodDomainChecker
                self.good_domain_checker = GoodDomainChecker(vt_key)
            except Exception as e:
                logger.debug(f"GoodDomainChecker init info: {e}")

    def is_globally_whitelisted(self, url: str) -> bool:
        """
        Fast-Path Whitelist Check: Verifies if the root domain is a recognized,
        top-tier global service.
        """
        try:
            ext = tldextract.extract(url)
            reg_domain = ext.registered_domain.lower()
            if reg_domain in GLOBAL_CLEAN_DOMAINS:
                return True
                
            # Check VirusTotal Top 500k popularity if enabled
            if self.good_domain_checker and self.good_domain_checker.is_known_good_domain(url):
                return True
        except Exception:
            pass
        return False

    def analyze_url(
        self,
        url: str,
        email_text_context: str = "",
        nlp_score: float = 0.0,
        skip_sandbox: bool = False
    ) -> Dict[str, Any]:
        """
        Executes the 4-stage pipeline on the target URL.
        """
        clean_url = (url or "").strip()
        if not clean_url:
            return {
                "url": "",
                "threat_score": 0.0,
                "verdict": "LEGITIMATE / CLEAN",
                "summary": "• Threat Summary: No URL provided.\n• Key Forensic Evidence: Empty target.\n• Recommended Action: No action needed.",
                "telemetry": {}
            }

        # ----------------------------------------------------
        # Stage 1: Fast Heuristics (< 1 ms) - NEVER STOPS BY ITSELF
        # ----------------------------------------------------
        heuristics = parse_url_heuristics(clean_url)
        heuristic_risk = heuristics.get("heuristic_risk_score", 0.0)
        heuristic_flags = heuristics.get("heuristic_flags", [])

        # ----------------------------------------------------
        # Stage 2: Local Threat DB Check (< 2 ms)
        # ----------------------------------------------------
        is_known_malicious = self.threat_db.check_indicator(clean_url)
        if is_known_malicious:
            # Match Found in Local Threat DB: Instant Block and stop analysis
            return self.decision_engine.evaluate(
                url=clean_url,
                nlp_score=nlp_score,
                heuristic_risk=heuristic_risk,
                heuristic_flags=heuristic_flags,
                known_db_match=1,
                sandbox_threat=100.0,
                vt_risk_score=100.0
            )

        # ----------------------------------------------------
        # Stage 2.5: VirusTotal API Whitelist & Reputation Check
        # ----------------------------------------------------
        vt_risk_score = 35.0  # Default baseline for unverified/new domains
        ext = tldextract.extract(clean_url)
        reg_domain = ext.registered_domain.lower()
        
        # Check hardcoded VIP whitelist
        is_vip_clean = reg_domain in GLOBAL_CLEAN_DOMAINS
        
        # Check VirusTotal API if checker is active
        if self.good_domain_checker:
            vt_rep = self.good_domain_checker.get_vt_reputation(clean_url)
            vt_risk_score = vt_rep.get("vt_risk_score", 35.0)
            if vt_rep.get("is_whitelisted"):
                is_vip_clean = True
            elif vt_rep.get("malicious_count", 0) >= 2:
                # Flagged by VirusTotal vendors
                vt_risk_score = 95.0
        elif is_vip_clean:
            vt_risk_score = 0.0

        if is_vip_clean and vt_risk_score <= 15.0:
            return {
                "url": clean_url,
                "threat_score": 0.0,
                "verdict": "LEGITIMATE / CLEAN",
                "summary": (
                    f"• Threat Summary: Domain '{reg_domain}' is an established, verified global service.\n"
                    f"• Key Forensic Evidence: Fast-Path Whitelist bypass (Global Tier-1 / VirusTotal Top 500k).\n"
                    f"• Recommended Action: No action required. Safe to browse."
                ),
                "telemetry": {
                    "status": "WHITELISTED",
                    "registered_domain": reg_domain,
                    "known_db_match": 0,
                    "vt_risk_score": vt_risk_score,
                    "sandbox_threat_score": 0
                }
            }

        # ----------------------------------------------------
        # Stage 3: Dynamic Stealth Sandbox Detonation (2 - 4 s)
        # ----------------------------------------------------
        sandbox_res: Dict[str, Any] = {}
        if not skip_sandbox:
            sandbox_res = self.sandbox.analyze_link_in_sandbox(clean_url)
        else:
            sandbox_res = {
                "sandbox_has_password_field": 0,
                "external_form_action": 0,
                "suspicious_exfiltration": 0,
                "domain_age_days": -1,
                "domain_risk_score": 0,
                "brand_impersonation": 0,
                "impersonated_brand": None,
                "sandbox_hidden_iframes": 0,
                "sandbox_title_mismatch": 0,
                "sandbox_threat_score": 0
            }

        # ----------------------------------------------------
        # Stage 4: Meta-Classifier & Final Fusion Engine
        # ----------------------------------------------------
        final_result = self.decision_engine.evaluate(
            url=clean_url,
            nlp_score=nlp_score,
            heuristic_risk=heuristic_risk,
            heuristic_flags=heuristic_flags,
            known_db_match=0,
            has_password=sandbox_res.get("sandbox_has_password_field", 0),
            external_form_action=sandbox_res.get("external_form_action", 0),
            suspicious_exfiltration=sandbox_res.get("suspicious_exfiltration", 0),
            domain_age_risk=sandbox_res.get("domain_risk_score", 0),
            domain_age_days=sandbox_res.get("domain_age_days", -1),
            brand_impersonation=sandbox_res.get("brand_impersonation", 0),
            detected_brand=sandbox_res.get("impersonated_brand") or sandbox_res.get("detected_target_brand") or "",
            hidden_iframes=sandbox_res.get("sandbox_hidden_iframes", 0),
            title_mismatch=sandbox_res.get("sandbox_title_mismatch", 0),
            url_entropy_risk=heuristics.get("url_entropy_risk", 0),
            typosquat_risk=1 if heuristics.get("suspicious_subdomain_brand") else 0,
            sandbox_threat=sandbox_res.get("sandbox_threat_score", 0),
            vt_risk_score=vt_risk_score
        )

        return final_result


# Singleton convenience instance
_pipeline_instance: Optional[LinkThreatPipeline] = None

def get_link_pipeline() -> LinkThreatPipeline:
    global _pipeline_instance
    if _pipeline_instance is None:
        _pipeline_instance = LinkThreatPipeline()
    return _pipeline_instance


def analyze_url(
    url: str,
    email_text_context: str = "",
    nlp_score: float = 0.0,
    skip_sandbox: bool = False
) -> Dict[str, Any]:
    """Module-level convenience wrapper to analyze a single URL."""
    return get_link_pipeline().analyze_url(
        url=url,
        email_text_context=email_text_context,
        nlp_score=nlp_score,
        skip_sandbox=skip_sandbox
    )

