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
from .scan_progress import report as _progress
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

# Free hosting / site-builder platforms: anyone gets a subdomain, so the platform's own popularity must never vouch for a
# subdomain (a VirusTotal rank for vercel.app says nothing about evil.vercel.app).
USER_CONTENT_HOSTS |= {
    "amazonaws.com", "storage.googleapis.com", "blob.core.windows.net", "web.core.windows.net", "digitaloceanspaces.com",
    "backblazeb2.com", "storage.yandexcloud.net", "wasabisys.com",
    "vercel.app", "pages.dev", "workers.dev", "netlify.app", "gitlab.io", "weebly.com", "wixsite.com",
    "herokuapp.com", "firebaseapp.com", "web.app", "glitch.me", "onrender.com", "repl.co", "replit.dev",
    "webflow.io", "framer.app", "framer.website", "carrd.co", "000webhostapp.com", "notion.site",
    "godaddysites.com", "myshopify.com", "square.site", "strikingly.com", "surge.sh", "fly.dev",
    "railway.app", "ngrok.io", "ngrok-free.app", "trycloudflare.com", "azurewebsites.net", "cloudfront.net",
    "r2.dev", "my.canva.site", "github.dev", "codesandbox.io", "stackblitz.io", "pythonanywhere.com",
}

# Seen hosting live phishing pages (PhishTank / OpenPhish, October 2026): page builders, form tools, QR-code and
# link-in-bio services, shorteners and e-mail archives. Their popularity must not vouch for a page on them.
USER_CONTENT_HOSTS |= {
    "replit.app", "replit.co", "express.adobe.com", "spark.adobe.com", "lovable.app", "lovable.dev", "wixstudio.com",
    "webwave.dev", "weeblysite.com", "webcindario.com", "twil.io", "forms.app", "hsforms.com", "hsforms.net",
    "hubspotusercontent.com", "campaign-archive.com", "list-manage.com", "mailchi.mp", "bolt.host", "v0.dev",
    "vusercontent.net", "typedream.app", "q-r.to", "qrco.de", "qr-codes.io", "qr.io", "me-qr.com", "l.ead.me",
    "ead.me", "reurl.cc", "beacons.ai", "linktr.ee", "bio.link", "lnk.bio", "linkin.bio", "taplink.cc", "cakeresume.com",
    "sendgrid.net", "mandrillapp.com", "ctctcdn.com", "forms.office.com", "formspree.io", "web3forms.com",
}

# More link shorteners (a short link says nothing about where it leads: the sandbox follows it to the real page) and
# platforms where each customer gets its own sub-domain (a popular platform does not vouch for every tenant).
USER_CONTENT_HOSTS |= {
    "x.gd", "v.gd", "t.ly", "tiny.cc", "s.id", "soo.gd", "u.to", "clck.ru", "vk.cc", "bl.ink", "short.io", "cutt.us",
    "tr.ee", "shrtco.de", "rebrand.ly", "bit.do", "adf.ly", "ouo.io", "link.tree", "gg.gg", "chilp.it", "mcaf.ee",
    "i-webs.jp",
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
        _progress("link_analysis", "running")
        heuristics = parse_url_heuristics(clean_url)
        heuristic_risk = heuristics.get("heuristic_risk_score", 0.0)
        heuristic_flags = heuristics.get("heuristic_flags", [])
        _progress("link_analysis", "done", f"{len(heuristic_flags)} warning sign(s)" if heuristic_flags else "no warning signs")

        # ----------------------------------------------------
        # Stage 2: Local Threat DB Check (< 2 ms)
        # ----------------------------------------------------
        _progress("threat_lists", "running")
        is_known_malicious = self.threat_db.check_indicator(clean_url)
        _progress("threat_lists", "done", "found in a threat list" if is_known_malicious else "not listed")
        if is_known_malicious:
            # Match Found in Local Threat DB: Instant Block and stop analysis
            known = self.decision_engine.evaluate(
                url=clean_url,
                nlp_score=nlp_score,
                heuristic_risk=heuristic_risk,
                heuristic_flags=heuristic_flags,
                known_db_match=1,
                sandbox_threat=100.0,
                vt_risk_score=100.0
            )
            known["display_verdict"], known["decisive"] = DISPLAY_DANGEROUS, True
            return known

        # ----------------------------------------------------
        # Stage 2.5: Brand fast path + VirusTotal reputation
        # ----------------------------------------------------
        _progress("reputation", "running")
        vt_risk_score = 35.0  # Default baseline for unverified/new domains
        reg_domain = tldextract.extract(clean_url).registered_domain.lower()
        user_content = is_user_content_host(clean_url)
        is_brand = is_brand_fast_path(clean_url)
        vt_malicious = False
        vt_whitelisted = False
        vt_detail = None

        if self.good_domain_checker:
            try:
                vt_rep = self.good_domain_checker.get_vt_reputation(clean_url)
            except Exception as e:
                logger.debug(f"VT reputation lookup failed: {e}")
                vt_rep = {}
            vt_risk_score = vt_rep.get("vt_risk_score", 35.0)
            vt_detail = {"malicious": vt_rep.get("malicious_count", 0), "suspicious": vt_rep.get("suspicious_count", 0),
                         "engines": vt_rep.get("total_engines", 0), "ratio": vt_rep.get("detection_ratio", 0.0)}
            if vt_risk_score >= 90.0:   # only a clear consensus of engines blocks by itself; weaker signals go to the sandbox
                vt_malicious = True
                vt_risk_score = max(vt_risk_score, 95.0)
            elif vt_rep.get("is_whitelisted") and not user_content:
                vt_whitelisted = True
            elif is_brand and vt_risk_score > 15.0:
                # VT rate-limited / failing / unranked: brand status stands.
                vt_risk_score = 0.0
        elif is_brand:
            vt_risk_score = 0.0

        _progress("reputation", "done", "trusted domain" if (is_brand or vt_whitelisted) and not vt_malicious else f"risk {int(vt_risk_score)}/100")
        if (is_brand or vt_whitelisted) and not vt_malicious:
            _progress("sandbox", "skipped", "trusted domain")
            _progress("model", "skipped", "trusted domain")
            return {
                "url": clean_url,
                "threat_score": 0.0,
                "verdict": "LEGITIMATE / CLEAN",
                "display_verdict": DISPLAY_SAFE,
                "decisive": True,
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
            _progress("sandbox", "running", "opening the page")
            sandbox_res = self.sandbox.analyze_link_in_sandbox(clean_url)
            _progress("sandbox", "done", "page could not be opened" if sandbox_res.get("sandbox_unreachable") else "page inspected")
        else:
            _progress("sandbox", "skipped")
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
        # Stage 4: Trained ML classifier (page model, or lexical model when the page could not be opened)
        # ----------------------------------------------------
        ml_result = None
        _progress("model", "running")
        try:
            from ml.model_runtime import get_runtime
            ml_result = get_runtime().score(clean_url, sandbox_res, use_page=not skip_sandbox)
        except Exception as e:
            logger.debug(f"ML stage skipped: {e}")
        _progress("model", "done", f"{int(ml_result['probability'] * 100)}% risk" if ml_result else "not available")
        page_text = sandbox_res.get("_text", "") or ""
        # raw page evidence was only needed for ML; never let it leave the pipeline
        sandbox_res.pop("_html", None)
        sandbox_res.pop("_final_url", None)
        sandbox_res.pop("_text", None)
        sandbox_res.pop("_screenshot_b64", None)
        sandbox_res.pop("_credential_page_url", None)

        # ----------------------------------------------------
        # Stage 5: Final fusion (ML verdict + hard security rules)
        # ----------------------------------------------------
        _progress("verdict", "running", "combining the evidence")
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
            sandbox_blocked=int(sandbox_res.get("sandbox_blocked_unsafe_url", 0) or 0),
            ml=ml_result,
            vt_detail=vt_detail,
            sandbox_evidence=sandbox_res,
            free_hosting=bool(user_content)
        )

        return finalize_verdict(final_result, url=clean_url, sandbox_res=sandbox_res, ml_result=ml_result,
                                vt_detail=vt_detail, free_hosting=bool(user_content), page_text=page_text)


DISPLAY_SAFE = "Safe"
DISPLAY_DANGEROUS = "Dangerous"
DISPLAY_UNVERIFIED = "Unverified - open with care"


def display_for(result: Dict[str, Any]) -> str:
    """The three words users see. 'Unverified' is meant to be rare."""
    verdict = str(result.get("verdict", "")).upper()
    score = float(result.get("threat_score", 0) or 0)
    if verdict.startswith("CRITICAL"):
        return DISPLAY_DANGEROUS
    if verdict.startswith("SUSPICIOUS"):
        return DISPLAY_UNVERIFIED
    if verdict.endswith("UNVERIFIED") and score >= 35:
        return DISPLAY_UNVERIFIED          # page could not be inspected AND something looks off
    return DISPLAY_SAFE


def finalize_verdict(result: Dict[str, Any], *, url: str, sandbox_res: Optional[Dict[str, Any]] = None,
                     ml_result: Optional[Dict[str, Any]] = None, vt_detail: Optional[Dict[str, Any]] = None,
                     free_hosting: bool = False, page_text: str = "", reviewer=None) -> Dict[str, Any]:
    """
    Turn the engine's result into a decisive answer wherever the evidence allows it:
      * a dead domain has nothing to open -> Safe (page offline)
      * a score stuck in the uncertain middle -> ask the AI reviewer; act only if it agrees with our own lean
    Hard rules are never touched. Whatever stays uncertain is shown as 'Unverified - open with care'.
    """
    from . import llm_reviewer as default_reviewer
    reviewer = reviewer or default_reviewer
    tel = result.setdefault("telemetry", {})
    sandbox_res = sandbox_res or {}
    score = float(result.get("threat_score", 0) or 0)
    hard = bool(tel.get("hard_override_triggered"))

    if (not hard and tel.get("verification_state") == "unverified" and tel.get("unverified_reason") == "unreachable"
            and score < 60 and str(result.get("verdict", "")).upper().startswith(("LEGITIMATE", "SUSPICIOUS"))):
        result["verdict"] = "LEGITIMATE / OFFLINE"
        result["threat_score"] = min(score, 25.0)
        result["summary"] = (result.get("summary", "") + "\n- This page is offline right now (the address does not respond), "
                             "so there is nothing to open.").strip()
    elif (not hard and str(result.get("verdict", "")).upper().startswith("SUSPICIOUS")
          and not tel.get("ml_capped_uninspected")):
        # (a link whose page could not be opened and that nothing else condemns stays 'Unverified': the reviewer would
        #  only be guessing from the address, with no page content to look at)
        lean = ("DANGEROUS" if (ml_result["probability"] >= 0.5 if ml_result else score >= 65) else "SAFE")
        try:
            review = reviewer.review(url, sandbox_res, page_text, lean, vt=vt_detail, ml=ml_result,
                                     domain_age_days=int(sandbox_res.get("domain_age_days", -1) or -1), free_hosting=free_hosting)
        except Exception:
            review = None
        tel["llm_review"] = review
        if (tel.get("ml_capped_no_evidence") and review and review.get("verdict") in ("SAFE", "DANGEROUS")
                and float(review.get("confidence", 0) or 0) >= getattr(reviewer, "MIN_CONFIDENCE", 0.75)):
            # The model alone says dangerous but the sandbox found nothing concrete: the reviewer, who read the page,
            # arbitrates between the two (SAFE clears it, DANGEROUS confirms the model).
            decision = review["verdict"]
        else:
            decision = reviewer.decide(lean, review)
        if decision == "DANGEROUS":
            result["verdict"] = "CRITICAL FRAUD / PHISHING"
            result["threat_score"] = max(score, 85.0)
        elif decision == "SAFE":
            result["verdict"] = "LEGITIMATE / CLEAN" if result.get("analysis_complete", True) else "LEGITIMATE / UNVERIFIED"
            result["threat_score"] = min(score, 30.0)
        if review and review.get("reasons"):
            result["summary"] = (result.get("summary", "") + "\n- AI review (" + review["verdict"].lower() + ", "
                                 + str(int(review["confidence"] * 100)) + "% sure): " + "; ".join(review["reasons"])).strip()

    result["display_verdict"] = display_for(result)
    result["decisive"] = result["display_verdict"] != DISPLAY_UNVERIFIED
    return result


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

