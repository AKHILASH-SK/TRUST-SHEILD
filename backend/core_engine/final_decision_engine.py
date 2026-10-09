"""
TrustShield V2 - Stage 4: Meta-Classifier & LLM Explainer Fusion Engine
Combines deterministic security guardrails, multi-modal feature weights,
and AI-synthesized forensic incident reporting (Groq / OpenAI or deterministic fallback).
"""

import os
import re
import logging
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional
import requests

logger = logging.getLogger(__name__)

# Verdict thresholds (exported; shared with callers/tests)
SUSPICIOUS_THRESHOLD = 50.0
CRITICAL_THRESHOLD = 80.0

# Hard floors applied by heuristics that are dangerous on their own
RAW_IP_FLOOR = 60.0
BRAND_SUBDOMAIN_FLOOR = 70.0
AT_SPOOF_FLOOR = 65.0
VT_MALICIOUS_FLOOR = 90.0
UNINSPECTED_RISK_FLOOR = 50.0

_SENSITIVE_PATH_RE = re.compile(r"(login|log-in|signin|sign-in|verify|verification|account|secure|update|password|auth|banking)", re.I)


def generate_deterministic_summary(
    url: str,
    threat_score: float,
    verdict: str,
    telemetry: Dict[str, Any]
) -> str:
    """
    Sub-millisecond high-fidelity deterministic 3-bullet forensic summary.
    Generates exact evidence items from multi-modal sandbox and heuristic telemetry.
    """
    evidence_items = []

    sb = telemetry.get("sandbox") or {}
    if telemetry.get("verification_state") == "unverified":
        why = {"bot_protection": "the site blocks automated browsers", "timeout": "the page did not finish loading in time",
               "unreachable": "the page could not be reached", "blocked_url": "the address is not allowed",
               "crashed": "the analysis browser failed"}.get(telemetry.get("unverified_reason"), "it could not be opened")
        evidence_items.append(f"Page could not be verified in the sandbox ({why}); verdict is based on the other checks")
    if sb.get("credential_surface_found"):
        where = ("on the page" if not sb.get("entry_clicks") else
                 f"after {sb['entry_clicks']} click(s) on its sign-in/sign-up buttons")
        evidence_items.append(f"Sandbox found a login/credential form {where}")
    if sb.get("probe_credentials_sent"):
        dest = sb.get("submit_domain") or "its own site"
        evidence_items.append("Sandbox typed fake credentials and saw them being sent to " +
                              ("a messaging/webhook service" if sb.get("submit_to_messaging_api") else dest))
    if sb.get("claimed_brand") and sb.get("brand_owns_domain") is False:
        evidence_items.append(f"Page presents itself as '{sb['claimed_brand']}' but the domain does not belong to that brand")
    if sb.get("login_leads_to_other_domain") and not sb.get("idp_login"):
        evidence_items.append(f"Its login leads to a different site ({sb.get('login_target_domain')})")
    if sb.get("download_executable"):
        evidence_items.append("Page tries to download an app/installer file")

    flagged = telemetry.get("vt_detections")
    if flagged and telemetry.get("vt_engines"):
        strength = ("consensus of engines" if (telemetry.get("vt_risk_score") or 0) >= 90
                    else "weak signal, confirmed or cleared by page analysis")
        evidence_items.append(f"VirusTotal: {flagged} of {telemetry['vt_engines']} engines flag this domain ({strength})")

    if telemetry.get("ml_used") and telemetry.get("ml_probability") is not None:
        ml_line = (f"ML classifier ({telemetry.get('ml_model')} model) rates this link "
                   f"{telemetry['ml_probability'] * 100:.0f}% likely malicious")
        if telemetry.get("ml_signals"):
            ml_line += " - key signals: " + ", ".join(telemetry["ml_signals"][:3])
        evidence_items.append(ml_line)
    if telemetry.get("ml_capped_no_evidence"):
        evidence_items.append("The risk model rates this page as likely malicious, but the sandbox found no concrete evidence "
                              "(no fake brand, nothing sent to another site, no warning signs); it is not announced as dangerous "
                              "on the model's score alone")
    if telemetry.get("ml_capped_uninspected"):
        evidence_items.append("The page could not be opened for inspection and nothing else found is malicious; "
                              "an unusual-looking link alone is not enough to call it dangerous")
    
    if telemetry.get("known_db_match"):
        evidence_items.append("Confirmed malicious signature in threat intelligence database (URLhaus/OpenPhish)")
        
    if telemetry.get("brand_impersonation"):
        brand = telemetry.get("detected_brand") or "high-value brand"
        evidence_items.append(f"Deceptive brand impersonation targeting '{brand}' on unauthorized domain")
        
    if telemetry.get("suspicious_exfiltration"):
        evidence_items.append("Credential form exfiltrates input to malicious channel (Telegram API / Discord / Raw IP)")
        
    if telemetry.get("external_form_action"):
        evidence_items.append("Credential input submits to an untrusted external domain")
        
    if telemetry.get("domain_age_days", -1) >= 0 and telemetry.get("domain_age_days") < 14:
        evidence_items.append(f"Zero-day throwaway domain registered only {telemetry.get('domain_age_days')} days ago (< 14d)")
        
    if telemetry.get("sandbox_has_password") and (
            telemetry.get("brand_impersonation") or telemetry.get("external_form_action")
            or telemetry.get("suspicious_exfiltration") or (telemetry.get("domain_age_risk") or 0) >= 60
            or telemetry.get("title_mismatch")):
        evidence_items.append("Password form combined with other deceptive signals (possible credential harvesting)")
        
    if telemetry.get("heuristic_flags"):
        for flag in telemetry.get("heuristic_flags", []):
            evidence_items.append(flag.split(":")[0].replace("_", " ").title())
            
    if telemetry.get("title_mismatch"):
        evidence_items.append("Page title claims corporate brand while domain does not match")

    if telemetry.get("analysis_complete") is False:
        evidence_items.append("Page could not be inspected")

    if telemetry.get("override_reason") and telemetry.get("hard_override_triggered"):
        evidence_items.append(str(telemetry.get("override_reason")))

    if not evidence_items:
        evidence_items.append("Standard domain lifecycle and clean structural heuristics")

    # Format 3-bullet forensic report
    if threat_score >= CRITICAL_THRESHOLD:
        threat_summary = f"Critical phishing and credential harvesting attack targeting end users via deceptive infrastructure."
        action = "Block URL immediately at firewall/DNS resolver, revoke any entered passwords, and quarantine related emails."
    elif threat_score >= SUSPICIOUS_THRESHOLD:
        threat_summary = f"Suspicious link displaying anomaly indicators and high-risk domain metadata."
        action = "Caution advised. Isolate in sandbox container and inspect sender authenticity before interacting."
    elif telemetry.get("analysis_complete") is False:
        threat_summary = "No threat signatures found, but the page could not be inspected."
        action = "Page could not be inspected. Proceed with caution and avoid entering credentials."
    else:
        threat_summary = f"Domain verified legitimate. No malicious evasion techniques or threat signatures detected."
        action = "No action required. Traffic permitted to proceed normally."

    formatted_evidence = "; ".join(evidence_items[:7])
    
    return (
        f"• Threat Summary: {threat_summary}\n"
        f"• Key Forensic Evidence: {formatted_evidence}\n"
        f"• Recommended Action: {action}"
    )


def generate_llm_incident_summary(
    url: str,
    threat_score: float,
    verdict: str,
    telemetry: Dict[str, Any],
    fast_mode: bool = True
) -> str:
    """
    Synthesizes a 3-bullet forensic report.
    When fast_mode=True (default), returns instant deterministic summary (< 1ms).
    """
    if fast_mode:
        return generate_deterministic_summary(url, threat_score, verdict, telemetry)

    gemini_api_key = os.getenv("GEMINI_API_KEY")
    groq_api_key = os.getenv("GROQ_API_KEY")
    openai_api_key = os.getenv("OPENAI_API_KEY")
    
    # Primary: Google Gemini API with strict 2.5s timeout
    if gemini_api_key:
        def _call_gemini():
            from google import genai
            client = genai.Client(api_key=gemini_api_key)
            prompt = f"""You are a Senior Cybersecurity Incident Responder. Analyze this phishing threat telemetry:
URL: {url}
Verdict: {verdict}
Threat Score: {threat_score}/100
Telemetry: {telemetry}

Synthesize a professional, concise 3-bullet incident summary for a mobile user alert:
• Threat Summary: <1 concise sentence explaining what this link does and why it is dangerous or safe>
• Key Forensic Evidence: <specific technical indicators detected, separated by commas>
• Recommended Action: <immediate clear advice for the mobile recipient>
"""
            # Use valid fast model without retries
            resp = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt
            )
            if resp and resp.text:
                return resp.text.strip()
            return None

        try:
            import concurrent.futures
            executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
            try:
                future = executor.submit(_call_gemini)
                gemini_text = future.result(timeout=2.0)
                if gemini_text:
                    return gemini_text
            finally:
                executor.shutdown(wait=False, cancel_futures=True)
        except Exception as e:
            logger.debug(f"Gemini summary skipped: {e}")

    # Fallback to instant deterministic summary
    return generate_deterministic_summary(url, threat_score, verdict, telemetry)


class FinalDecisionEngine:
    """
    Stage 4: Neuro-Symbolic Multi-Modal Fusion Engine.
    Combines deterministic security overrides, 12-feature ensemble inference,
    and structured forensic explanation generation.
    """
    def __init__(self):
        pass

    def evaluate(
        self,
        url: str,
        nlp_score: float = 0.0,
        heuristic_risk: float = 0.0,
        heuristic_flags: Optional[List[str]] = None,
        known_db_match: int = 0,
        has_password: int = 0,
        external_form_action: int = 0,
        suspicious_exfiltration: int = 0,
        domain_age_risk: float = 0.0,
        domain_age_days: int = -1,
        brand_impersonation: int = 0,
        detected_brand: str = "",
        hidden_iframes: int = 0,
        title_mismatch: int = 0,
        url_entropy_risk: int = 0,
        typosquat_risk: int = 0,
        sandbox_threat: float = 0.0,
        vt_risk_score: float = 0.0,
        sandbox_unreachable: int = 0,
        sandbox_blocked: int = 0,
        known_good: bool = False,
        ml: Optional[Dict[str, Any]] = None,
        vt_detail: Optional[Dict[str, Any]] = None,
        sandbox_evidence: Optional[Dict[str, Any]] = None,
        free_hosting: bool = False
    ) -> Dict[str, Any]:
        """
        Fuses all 12+ telemetry features with deterministic guardrails.
        """
        heuristic_flags = heuristic_flags or []
        _ev = sandbox_evidence or {}
        
        # 1. Deterministic Hard Overrides (Defense-in-Depth)
        hard_override_triggered = False
        override_reason = ""
        threat_score = 0.0

        if known_db_match == 1:
            threat_score = 100.0
            hard_override_triggered = True
            override_reason = "Known Malicious Threat DB Match"
        elif _ev.get("probe_credentials_sent") and _ev.get("submit_to_messaging_api"):
            threat_score = 100.0
            hard_override_triggered = True
            override_reason = "Login form sends the typed credentials to a messaging/webhook service (e.g. Telegram)"
        elif _ev.get("probe_credentials_sent") and _ev.get("submit_cross_domain") and not _ev.get("idp_login") and (
                brand_impersonation == 1 or free_hosting or 0 <= domain_age_days < 180 or bool(heuristic_flags)
                or bool(set(_ev.get("sensitive_field_types") or []) & {"wallet_phrase", "card", "cvv", "gov_id", "pin"})):
            threat_score = 95.0
            hard_override_triggered = True
            override_reason = (f"Login form sends the typed credentials to a different site "
                               f"({_ev.get('submit_domain') or 'unknown'})")
        elif _ev.get("download_executable") and not _ev.get("idp_login"):
            threat_score = 80.0
            hard_override_triggered = True
            override_reason = "Page forces a download of an app or installer file"
        elif suspicious_exfiltration == 1 and has_password == 1:
            threat_score = 100.0
            hard_override_triggered = True
            override_reason = "Malicious Form Exfiltration with Password Field"
        elif brand_impersonation == 1 and has_password == 1:
            threat_score = 100.0
            hard_override_triggered = True
            override_reason = "Brand Impersonation with Password Harvesting"
        elif brand_impersonation == 1 and external_form_action == 1:
            threat_score = 95.0
            hard_override_triggered = True
            override_reason = "Brand Impersonation with External Form Action"
        elif domain_age_risk >= 90 and has_password == 1:
            threat_score = 90.0
            hard_override_triggered = True
            override_reason = "Zero-Day Domain (< 14 days) with Password Harvesting"
        elif vt_risk_score >= 90.0 and has_password == 1:
            threat_score = 95.0
            hard_override_triggered = True
            override_reason = "VirusTotal Flagged Malicious with Password Harvesting"
        elif vt_risk_score >= VT_MALICIOUS_FLOOR:
            threat_score = 90.0
            hard_override_triggered = True
            override_reason = "Flagged malicious by 2+ VirusTotal engines"
            
        # 2. Weighted Ensemble Fusion (If no hard override reached 100)
        if not hard_override_triggered:
            # Weighted feature contributions:
            weights = {
                "sandbox_threat": 0.30,
                "heuristic_risk": 0.15,
                "nlp_score": 0.20,
                "domain_age_risk": 0.15,
                "vt_risk_score": 0.10,
                "typosquat_risk": 0.10
            }
            
            ensemble_base = (
                sandbox_threat * weights["sandbox_threat"] +
                heuristic_risk * weights["heuristic_risk"] +
                nlp_score * weights["nlp_score"] +
                domain_age_risk * weights["domain_age_risk"] +
                vt_risk_score * weights["vt_risk_score"] +
                (75.0 if typosquat_risk else 0.0) * weights["typosquat_risk"]
            )
            
            # Secondary heuristic boosters
            booster = 0.0
            if brand_impersonation == 1: booster += 45.0
            if suspicious_exfiltration == 1: booster += 45.0
            if external_form_action == 1: booster += 35.0
            # Password field only adds risk if coupled with deceptive brand, exfiltration, or zero-day domain
            if has_password == 1 and (brand_impersonation == 1 or external_form_action == 1 or suspicious_exfiltration == 1 or domain_age_risk >= 80 or title_mismatch == 1):
                booster += 30.0
            if title_mismatch == 1: booster += 25.0
            if url_entropy_risk == 1: booster += 15.0
            if hidden_iframes > 0: booster += 20.0
            
            threat_score = round(min(100.0, ensemble_base + booster), 2)

        # 2a. Trained ML classifier (final stage). It sets the score unless a hard rule already fired;
        #     the floors below can still only raise it.
        rule_score = threat_score
        ml_capped_uninspected = False
        ml_capped_no_evidence = False
        hosted_name_ignored = False
        if ml and not hard_override_triggered:
            threat_score = float(ml["score"])
            # Verified-clean rule: the browser really opened the page and found nothing hostile (no login or payment
            # form, no brand claim, no flags, no redirect trick, nothing from VirusTotal, not a fresh or free-host
            # page). A merely moderate model score must not turn such a page into "Unverified".
            if (_ev.get("verification_state") == "verified"
                    and not _ev.get("credential_surface_found") and not _ev.get("sensitive_field_types")
                    and not _ev.get("download_executable") and not _ev.get("redirects_to_popular_site")
                    and not has_password and not brand_impersonation and not external_form_action
                    and not suspicious_exfiltration and not title_mismatch and not hidden_iframes
                    and not heuristic_flags and not typosquat_risk and not free_hosting
                    and vt_risk_score < 40 and not (0 <= domain_age_days < 180)
                    and float(ml.get("probability", 1.0)) < 0.85):
                threat_score = min(threat_score, 25.0)

            # Uninspected-and-uncorroborated rule: when the page could not be opened (timeout, blocked, unreachable) the
            # text of the link is all the model saw. A link that merely LOOKS unusual (many subdomains, a port number,
            # long random path: typical of internal tools and dev servers) is not proof of phishing, so without any
            # independent support the score is held in the "Unverified" band instead of "Dangerous".
            uninspected = (sandbox_unreachable == 1 or sandbox_blocked == 1
                           or _ev.get("verification_state") == "unverified")
            # (shared hosting is deliberately NOT corroboration: on a platform where anyone gets a sub-domain, the host name is
            #  chosen by the page owner and says nothing about safety)
            corroborated = (vt_risk_score >= 40 or heuristic_risk >= 40 or bool(typosquat_risk)
                            or 0 <= domain_age_days < 90 or bool(known_db_match))
            if uninspected and not corroborated and threat_score >= CRITICAL_THRESHOLD:
                threat_score = 55.0
                ml_capped_uninspected = True

            # Model-only conviction rule: the page WAS opened, but the sandbox found no concrete evidence of wrongdoing
            # (no fake brand, nothing sent to another site, no warning sign, no list or VirusTotal signal, not a new
            # domain). A 'dangerous' verdict resting only on the model's score is held at "Unverified" and goes to the AI
            # second opinion instead of being announced as fact. (A real recruitment login page hosted for a company on a
            # shared platform was scored 100% by the model alone.)
            wording = _ev.get("wording") or {}
            concrete_evidence = bool(
                brand_impersonation or external_form_action or suspicious_exfiltration or hidden_iframes or title_mismatch
                or _ev.get("download_executable") or _ev.get("redirects_to_popular_site")
                or (_ev.get("submit_cross_domain") and not _ev.get("idp_login"))
                or (bool(_ev.get("claimed_brand")) and _ev.get("brand_owns_domain") is False)      # titled as a big brand it does not own
                or (_ev.get("form_cross_domain") and not _ev.get("idp_login"))
                or (_ev.get("login_leads_to_other_domain") and not _ev.get("idp_login")) or _ev.get("form_action_is_exfil_host")
                or vt_risk_score >= 40 or heuristic_risk >= 40 or typosquat_risk or known_db_match
                or 0 <= domain_age_days < 90 or wording.get("lure") or wording.get("threat") or wording.get("crypto")
                or (set(_ev.get("sensitive_field_types") or []) & {"card", "cvv", "wallet_phrase", "gov_id", "pin"}))
            # Pages on shared hosting (vercel.app, netlify.app, github.io ...) are held to the same standard from a lower bar:
            # the model learned "free host = phishing" (almost all its hosted training pages were malicious), so even a
            # merely suspicious model score on such a page needs concrete evidence behind it.
            model_alarm = threat_score >= CRITICAL_THRESHOLD or (free_hosting and threat_score >= SUSPICIOUS_THRESHOLD)
            if (_ev.get("verification_state") == "verified" and not uninspected and not concrete_evidence and model_alarm):
                threat_score = 70.0 if threat_score >= CRITICAL_THRESHOLD else 60.0
                ml_capped_no_evidence = True
                hosted_name_ignored = bool(free_hosting)

        # 2b. Heuristic hard floors: each of these is dangerous by itself
        floor_reasons: List[str] = []

        def _floor(value: float, reason: str) -> None:
            nonlocal threat_score, hard_override_triggered, override_reason
            floor_reasons.append(reason)
            if threat_score < value:
                threat_score = value
                hard_override_triggered = True
                override_reason = reason if not override_reason else f"{override_reason}; {reason}"

        flag_text = " ".join(heuristic_flags)
        try:
            parsed = urlparse(url if "://" in url else f"http://{url}")
            path_query = f"{parsed.path} {parsed.query}"
            try:
                port = parsed.port
            except ValueError:
                port = None
        except Exception:
            path_query, port = "", None
        non_standard_port = port is not None and port not in (80, 443)

        if "RAW_IP_HOST" in flag_text and (_SENSITIVE_PATH_RE.search(path_query) or non_standard_port):
            _floor(RAW_IP_FLOOR, "Raw IP host with credential-style path or non-standard port")
        if "BRAND_IN_SUBDOMAIN" in flag_text:
            _floor(BRAND_SUBDOMAIN_FLOOR, "Brand name abused in subdomain of unrelated domain")
        if "USERINFO_AT_SPOOFING" in flag_text:
            _floor(AT_SPOOF_FLOOR, "'@' userinfo used to spoof destination host")
        if vt_risk_score >= VT_MALICIOUS_FLOOR:
            threat_score = max(threat_score, VT_MALICIOUS_FLOOR)
        if free_hosting or (0 <= domain_age_days < 90):
            if _ev.get("redirects_to_popular_site"):
                _floor(60.0, "Page on a free host / brand-new domain bounces visitors to a famous site (cloaking)")
            if (_ev.get("wording") or {}).get("lure", 0):
                _floor(55.0, "Document-sharing lure wording on a free host / brand-new domain")
            if _ev.get("is_spa_shell") and _ev.get("title_support_lure"):
                _floor(55.0, "Empty page shell titled like a help/appeal centre on a free host / brand-new domain")

        # 2c. Incomplete analysis: never report plain clean for an uninspected page
        analysis_complete = True
        if (sandbox_unreachable == 1 or sandbox_blocked == 1) and not known_good:
            analysis_complete = False
            young_domain = 0 <= domain_age_days < 30
            if (young_domain or heuristic_flags or typosquat_risk) and threat_score < UNINSPECTED_RISK_FLOOR:
                threat_score = UNINSPECTED_RISK_FLOOR
                hard_override_triggered = True
                reason = "Page could not be inspected and other risk signals exist"
                override_reason = reason if not override_reason else f"{override_reason}; {reason}"
        threat_score = round(float(threat_score), 2)

        # 3. Categorical Verdict
        if threat_score >= CRITICAL_THRESHOLD:
            verdict = "CRITICAL FRAUD / PHISHING"
        elif threat_score >= SUSPICIOUS_THRESHOLD:
            verdict = "SUSPICIOUS"
        elif not analysis_complete:
            verdict = "LEGITIMATE / UNVERIFIED"       # nothing bad found, but the page could not be inspected
        else:
            verdict = "LEGITIMATE / CLEAN"

        # 4. Telemetry payload
        telemetry = {
            "heuristic_flags": heuristic_flags,
            "heuristic_risk_score": heuristic_risk,
            "known_db_match": known_db_match,
            "sandbox_has_password": has_password,
            "external_form_action": external_form_action,
            "suspicious_exfiltration": suspicious_exfiltration,
            "domain_age_days": domain_age_days,
            "domain_age_risk": domain_age_risk,
            "brand_impersonation": brand_impersonation,
            "detected_brand": detected_brand,
            "title_mismatch": title_mismatch,
            "hidden_iframes": hidden_iframes,
            "url_entropy_risk": url_entropy_risk,
            "typosquat_risk": typosquat_risk,
            "nlp_score": nlp_score,
            "sandbox_threat_score": sandbox_threat,
            "vt_risk_score": vt_risk_score,
            "hard_override_triggered": hard_override_triggered,
            "override_reason": override_reason,
            "heuristic_floors": floor_reasons,
            "sandbox_unreachable": sandbox_unreachable,
            "sandbox_blocked_unsafe_url": sandbox_blocked,
            "analysis_complete": analysis_complete,
            "rule_score": rule_score,
            "verification_state": _ev.get("verification_state", "verified"),
            "unverified_reason": _ev.get("unverified_reason", ""),
            "sandbox_engine": _ev.get("engine"),
            "sandbox": {k: _ev.get(k) for k in (
                "credential_surface_found", "credential_via", "credential_surface_depth", "entry_clicks", "opened_menu",
                "credential_field_types", "form_cross_domain", "form_action_domain", "probe_ran", "probe_credentials_sent",
                "submit_domain", "submit_cross_domain", "submit_to_messaging_api", "login_leads_to_other_domain",
                "login_target_domain", "idp_login", "claimed_brand", "brand_owns_domain", "download_executable",
                "challenge_page", "redirect_domains", "third_party_domains", "has_privacy_link", "has_terms_link",
                "wording", "http_status", "page_title", "redirects_to_popular_site", "title_support_lure") if k in _ev},
            "vt_detections": (vt_detail or {}).get("malicious"),
            "vt_suspicious": (vt_detail or {}).get("suspicious"),
            "vt_engines": (vt_detail or {}).get("engines"),
            "ml_used": bool(ml),
            "ml_probability": ml["probability"] if ml else None,
            "ml_band": ml["band"] if ml else None,
            "ml_model": ml["model"] if ml else None,
            "ml_model_version": ml.get("model_version") if ml else None,
            "ml_lexical_probability": ml.get("lexical_probability") if ml else None,
            "ml_signals": ml.get("signals", []) if ml else [],
            "ml_capped_uninspected": ml_capped_uninspected,
            "ml_capped_no_evidence": ml_capped_no_evidence,
            "hosted_name_ignored": hosted_name_ignored,
            "free_hosting": bool(free_hosting)
        }
        
        # 5. Synthesize Sub-Millisecond (<1ms) Forensic Explanation (Zero Latency)
        summary = generate_deterministic_summary(url, threat_score, verdict, telemetry)
        
        return {
            "url": url,
            "threat_score": threat_score,
            "verdict": verdict,
            "verification_state": telemetry.get("verification_state", "verified") if analysis_complete else "unverified",
            "analysis_complete": analysis_complete,
            "summary": summary,
            "telemetry": telemetry
        }
