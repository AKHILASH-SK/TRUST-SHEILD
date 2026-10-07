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

# Pure brand domains: the registered domain is operated by one trusted vendor and third
# parties cannot publish arbitrary pages on it. These may skip the sandbox (score 0).
BRAND_FAST_PATH_DOMAINS = {
    # Google
    "google.com", "gmail.com", "youtube.com", "gstatic.com",
    "google.co.in", "google.co.uk", "google.ca", "google.de", "google.fr", "google.com.au",
    # Microsoft
    "microsoft.com", "office.com", "live.com", "outlook.com", "office365.com",
    "microsoftonline.com", "bing.com", "msn.com",
    # Apple / Amazon
    "apple.com", "icloud.com",
    "amazon.com", "amazon.in", "amazon.co.uk",
    # Education
    "coursera.org", "edx.org", "udemy.com", "khanacademy.org", "codecademy.com", "datacamp.com",
    "mit.edu", "stanford.edu", "harvard.edu",
    # Financial & payments
    "paypal.com", "stripe.com", "razorpay.com", "intuit.com",
    # Social & professional
    "linkedin.com", "twitter.com", "x.com", "facebook.com", "fb.com", "instagram.com",
    "whatsapp.com", "telegram.org",
    # Business / collaboration vendors (own sites only)
    "zoho.com", "slack.com", "atlassian.com", "jira.com", "asana.com",
    "salesforce.com", "hubspot.com", "mailchimp.com",
    # Misc brands
    "stackoverflow.com", "openai.com", "chatgpt.com", "wikipedia.org", "cloudflare.com",
    "zoom.us", "spotify.com", "quora.com", "reddit.com", "netflix.com", "uber.com", "adobe.com",
}

# Hosts where third parties publish content (forms, docs, repos, tenants) or that merely
# redirect (shorteners). NEVER auto-safe: always sandboxed. Matched on the exact host AND
# any subdomain of the entry (evil.sharepoint.com). Entries may be full hostnames
# (docs.google.com) even though their registered domain is a brand domain.
USER_CONTENT_HOSTS = {
    # Google user content / shorteners
    "docs.google.com", "drive.google.com", "forms.google.com", "sites.google.com",
    "script.google.com", "storage.googleapis.com", "googleusercontent.com",
    "forms.gle", "goo.gl", "g.co", "youtu.be", "blogspot.com",
    # Microsoft tenants / shorteners
    "sharepoint.com", "windows.net", "azurewebsites.net", "forms.office.com",
    "forms.microsoft.com", "aka.ms", "msft.it", "1drv.ms",
    # Code hosting
    "github.com", "github.io", "githubusercontent.com", "gitlab.com", "gitlab.io",
    "bitbucket.org", "git.io",
    # Docs / forms / collaboration
    "notion.so", "notion.site", "dropbox.com", "box.com", "typeform.com", "jotform.com",
    "surveymonkey.com", "airtable.com", "canva.com", "medium.com", "figma.com", "trello.com",
    "forms.zoho.com", "zendesk.com", "wordpress.com", "weebly.com", "wixsite.com",
    # Messaging / social shorteners
    "t.me", "wa.me", "t.co", "lnkd.in", "fb.me", "instagr.am", "paypal.me",
    # Generic shorteners
    "bit.ly", "tinyurl.com", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
    "shorturl.at", "rb.gy", "amzn.to", "spoti.fi", "apple.co",
}

# Domains whose own login forms / redirects are trusted: brand domains only.
GLOBAL_CLEAN_DOMAINS = BRAND_FAST_PATH_DOMAINS


def extract_host(url: str) -> str:
    """Lower-case hostname of a URL (scheme optional), without port/userinfo/www."""
    try:
        raw = (url or "").strip()
        parsed = urlparse(raw if "://" in raw else f"http://{raw}")
        host = (parsed.hostname or "").lower().rstrip(".")
    except Exception:
        return ""
    return host[4:] if host.startswith("www.") else host


def is_user_content_host(url_or_host: str) -> bool:
    """True if the host (or any parent of it) is a user-content/hosting/shortener host."""
    host = extract_host(url_or_host)
    if not host:
        return False
    return any(host == h or host.endswith("." + h) for h in USER_CONTENT_HOSTS)


def is_brand_fast_path(url_or_host: str) -> bool:
    """True only for a pure brand domain that is not also a user-content host."""
    host = extract_host(url_or_host)
    if not host or is_user_content_host(host):
        return False
    try:
        reg = tldextract.extract(host).registered_domain.lower()
    except Exception:
        return False
    return reg in BRAND_FAST_PATH_DOMAINS


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
        Fast-Path Whitelist Check: True only for pure brand domains (or a VirusTotal
        top-rank host). User-content hosts are never whitelisted.
        """
        try:
            if is_user_content_host(url):
                return False
            if is_brand_fast_path(url):
                return True
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
                "analysis_complete": True,
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
        # Stage 2.5: Brand fast path + VirusTotal reputation
        # ----------------------------------------------------
        vt_risk_score = 35.0  # Default baseline for unverified/new domains
        reg_domain = tldextract.extract(clean_url).registered_domain.lower()
        user_content = is_user_content_host(clean_url)
        is_brand = is_brand_fast_path(clean_url)
        vt_malicious = False
        vt_whitelisted = False

        if self.good_domain_checker:
            try:
                vt_rep = self.good_domain_checker.get_vt_reputation(clean_url)
            except Exception as e:
                logger.debug(f"VT reputation lookup failed: {e}")
                vt_rep = {}
            vt_risk_score = vt_rep.get("vt_risk_score", 35.0)
            if vt_rep.get("malicious_count", 0) >= 2 or vt_risk_score >= 90.0:
                vt_malicious = True
                vt_risk_score = max(vt_risk_score, 95.0)
            elif vt_rep.get("is_whitelisted") and not user_content:
                vt_whitelisted = True
            elif is_brand and vt_risk_score > 15.0:
                # VT rate-limited / failing / unranked: brand status stands.
                vt_risk_score = 0.0
        elif is_brand:
            vt_risk_score = 0.0

        if (is_brand or vt_whitelisted) and not vt_malicious:
            return {
                "url": clean_url,
                "threat_score": 0.0,
                "verdict": "LEGITIMATE / CLEAN",
                "analysis_complete": True,
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
                    "sandbox_threat_score": 0,
                    "analysis_complete": True
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
                "sandbox_unreachable": 0,
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
            vt_risk_score=vt_risk_score,
            sandbox_unreachable=int(sandbox_res.get("sandbox_unreachable", 0) or 0),
            sandbox_blocked=int(sandbox_res.get("sandbox_blocked_unsafe_url", 0) or 0)
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

