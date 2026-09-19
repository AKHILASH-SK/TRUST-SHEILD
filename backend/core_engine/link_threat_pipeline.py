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
import socket
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse
import tldextract

# Local Core Engine imports
from .url_heuristics import parse_url_heuristics, SHARED_FREE_HOSTING_PLATFORMS, OFFICIAL_BRAND_DOMAINS
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
    
    # Financial & Payments
    "paypal.com", "paypal.me",
    
    # Social & Professional Networks
    "linkedin.com", "lnkd.in",
    "twitter.com", "x.com", "t.co",
    "facebook.com", "fb.com", "fb.me", "instagram.com", "instagr.am", "whatsapp.com", "wa.me",
    "telegram.org", "t.me",
    
    # Form, Survey & Collaboration Platforms
    "typeform.com", "jotform.com", "surveymonkey.com", "airtable.com", "zoho.com", "forms.zoho.com",
    
    # Developer & Infrastructure
    "github.com", "git.io", "gitlab.com",
    "openai.com", "chatgpt.com",
    "wikipedia.org", "cloudflare.com", "zoom.us", "canva.com", "notion.so", "spotify.com", "spoti.fi"
}

SOCIAL_ENGINEERING_KEYWORDS = [
    "urgent", "immediately", "immediate action", "unauthorized", "suspended",
    "wire transfer", "verify your identity", "click here", "24 hours", "security alert",
    "unrecognized device", "cancel transfer", "password reset", "account locked",
    "compromised", "fraud alert", "billing issue", "payment required", "identity verification"
]


class LinkThreatPipeline:
    """
    Central Coordinator for URL analysis across heuristics, local threat DB,
    VirusTotal API (optional), headless browser detonation, and meta-classification.
    """
    def __init__(self):
        self.threat_db: ThreatIntelDB = get_threat_db()
        self.sandbox: VirtualSandboxAnalyzer = VirtualSandboxAnalyzer()
        self.decision_engine: FinalDecisionEngine = FinalDecisionEngine()
        
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
        top-tier global service. Multi-tenant hosting (e.g., vercel.app, pages.dev)
        or brand-mimicking subdomains are NEVER whitelisted.
        """
        try:
            ext = tldextract.extract(url)
            reg_domain = ext.registered_domain.lower()
            subdomain = ext.subdomain.lower()

            # 1. Multi-tenant / free shared hosting platforms can be registered by anyone.
            # Never whitelist subdomains on these platforms!
            if reg_domain in SHARED_FREE_HOSTING_PLATFORMS:
                return False

            # 2. If subdomain contains brand keywords (e.g. linkedin.vercel.app or google.somehost.com),
            # never allow fast-path whitelist
            for brand, official_domains in OFFICIAL_BRAND_DOMAINS.items():
                if brand in subdomain:
                    is_official = any(reg_domain == off or reg_domain.endswith("." + off) for off in official_domains)
                    if not is_official:
                        return False

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
        sender_domain: str = "",
        nlp_score: float = 0.0,
        skip_sandbox: bool = False
    ) -> Dict[str, Any]:
        """
        Executes the 4-stage pipeline on the target URL with email contextual correlation.
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
        # Stage 1: Fast Heuristics (< 1 ms)
        # ----------------------------------------------------
        heuristics = parse_url_heuristics(clean_url)
        heuristic_risk = heuristics.get("heuristic_risk_score", 0.0)
        heuristic_flags = list(heuristics.get("heuristic_flags", []))

        # Contextual correlation: Sender Domain vs Link Destination Domain
        ext = tldextract.extract(clean_url)
        reg_domain = ext.registered_domain.lower()
        
        if sender_domain and reg_domain:
            sender_ext = tldextract.extract(sender_domain)
            sender_reg = sender_ext.registered_domain.lower()
            
            if sender_reg and sender_reg != reg_domain:
                # Check if sender claims to be an established brand or company
                sender_is_brand = any(b in sender_reg for b in OFFICIAL_BRAND_DOMAINS.keys())
                link_is_suspicious = bool(heuristics.get("suspicious_tld") or heuristics.get("has_credential_keywords") or heuristics.get("suspicious_brand_spoof"))
                
                if sender_is_brand or link_is_suspicious:
                    mismatch_flag = f"SENDER_LINK_MISMATCH: Sender domain '{sender_reg}' does not align with hyperlink destination '{reg_domain}'"
                    heuristic_flags.append(mismatch_flag)
                    heuristic_risk = min(100.0, heuristic_risk + 35.0)

        # Contextual correlation: Social Engineering / Urgency in Email Body
        if email_text_context:
            context_lower = email_text_context.lower()
            matched_urgency = [kw for kw in SOCIAL_ENGINEERING_KEYWORDS if kw in context_lower]
            if matched_urgency:
                heuristic_flags.append(f"SOCIAL_ENGINEERING_URGENCY: Email text contains coercive pressure phrases: {matched_urgency[:3]}")
                if nlp_score == 0.0:
                    nlp_score = min(100.0, 40.0 + len(matched_urgency) * 20.0)
                # Compounding risk: urgent text + credential keywords in link
                if heuristics.get("has_credential_keywords") or heuristics.get("suspicious_brand_spoof") or heuristics.get("suspicious_tld"):
                    heuristic_risk = min(100.0, heuristic_risk + 25.0)

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
                vt_risk_score=100.0,
                skip_llm=skip_sandbox
            )

        # ----------------------------------------------------
        # Stage 2.5: VirusTotal API Whitelist & Reputation Check
        # ----------------------------------------------------
        vt_risk_score = 35.0  # Default baseline for unverified/new domains
        
        # Check hardcoded VIP whitelist
        is_vip_clean = reg_domain in GLOBAL_CLEAN_DOMAINS
        
        # Check VirusTotal API if checker is active and not skipping sandbox/external network
        if self.good_domain_checker and not skip_sandbox:
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
        is_dns_unresolved = False

        if not skip_sandbox:
            sandbox_res = self.sandbox.analyze_link_in_sandbox(clean_url)
            if sandbox_res.get("sandbox_unreachable") == 1:
                is_dns_unresolved = True
        else:
            # Fast DNS preflight check in Fast Demo Mode (0.05s timeout)
            try:
                target_host = urlparse(clean_url if "://" in clean_url else f"http://{clean_url}").netloc.split(':')[0]
                if target_host and not is_vip_clean:
                    socket.setdefaulttimeout(0.6)
                    socket.getaddrinfo(target_host, None)
            except Exception:
                is_dns_unresolved = True
                heuristic_flags.append("DNS_UNRESOLVED: Target domain failed DNS resolution (unreachable or dead phishing infrastructure)")

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
                "sandbox_unreachable": 1 if is_dns_unresolved else 0,
                "sandbox_error": "ERR_NAME_NOT_RESOLVED" if is_dns_unresolved else "",
                "sandbox_threat_score": 70 if is_dns_unresolved else 0
            }

        if is_dns_unresolved and "DNS_UNRESOLVED" not in str(heuristic_flags):
            heuristic_flags.append("DNS_UNRESOLVED: Domain failed DNS resolution (ERR_NAME_NOT_RESOLVED)")

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
            brand_impersonation=sandbox_res.get("brand_impersonation", 0) or heuristics.get("suspicious_brand_spoof", 0),
            detected_brand=sandbox_res.get("impersonated_brand") or sandbox_res.get("detected_target_brand") or heuristics.get("detected_brand", ""),
            hidden_iframes=sandbox_res.get("sandbox_hidden_iframes", 0),
            title_mismatch=sandbox_res.get("sandbox_title_mismatch", 0),
            url_entropy_risk=heuristics.get("url_entropy_risk", 0),
            typosquat_risk=heuristics.get("typosquat_risk", 0),
            sandbox_threat=sandbox_res.get("sandbox_threat_score", 0),
            vt_risk_score=vt_risk_score,
            skip_llm=skip_sandbox,
            is_unreachable=is_dns_unresolved or (sandbox_res.get("sandbox_unreachable", 0) == 1)
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
    sender_domain: str = "",
    nlp_score: float = 0.0,
    skip_sandbox: bool = False
) -> Dict[str, Any]:
    """Module-level convenience wrapper to analyze a single URL."""
    return get_link_pipeline().analyze_url(
        url=url,
        email_text_context=email_text_context,
        sender_domain=sender_domain,
        nlp_score=nlp_score,
        skip_sandbox=skip_sandbox
    )
