"""
TrustShield V2 - Stage 4: Meta-Classifier & LLM Explainer Fusion Engine
Combines deterministic security guardrails, multi-modal feature weights,
and AI-synthesized forensic incident reporting (Groq / OpenAI or deterministic fallback).
"""

import os
import logging
from typing import Dict, Any, List, Optional
import requests

logger = logging.getLogger(__name__)


def generate_llm_incident_summary(
    url: str,
    threat_score: float,
    verdict: str,
    telemetry: Dict[str, Any],
    skip_external: bool = False
) -> str:
    """
    Synthesizes a 3-bullet forensic report using Google Gemini (gemini-3.6-flash),
    Groq Llama 3, OpenAI, or a zero-latency deterministic template fallback.
    """
    if skip_external:
        gemini_api_key = None
        groq_api_key = None
        openai_api_key = None
    else:
        gemini_api_key = os.getenv("GEMINI_API_KEY")
        groq_api_key = os.getenv("GROQ_API_KEY")
        openai_api_key = os.getenv("OPENAI_API_KEY")
    
    # 1. Primary: Google Gemini API (official google-genai SDK) with strict 2.5s timeout
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
            resp = client.models.generate_content(
                model="gemini-3.6-flash",
                contents=prompt
            )
            if resp and resp.text:
                return resp.text.strip()
            return None

        import concurrent.futures
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        try:
            future = executor.submit(_call_gemini)
            gemini_text = future.result(timeout=2.5)
            if gemini_text:
                return gemini_text
        except Exception as e:
            logger.info(f"Google Gemini optional summary completed with fallback: {e}")
        finally:
            executor.shutdown(wait=False)

    # 2. Secondary: Groq (Llama-3.1-8b-instant) if available
    if groq_api_key:
        try:
            prompt = f"""You are a Senior Cybersecurity Incident Responder. Analyze this phishing threat telemetry:
URL: {url}
Verdict: {verdict}
Threat Score: {threat_score}/100
Telemetry: {telemetry}

Provide exactly a 3-bullet forensic incident summary in this format:
• Threat Summary: <1 concise sentence describing the attack type>
• Key Forensic Evidence: <specific technical indicators detected, separated by commas>
• Recommended Action: <immediate security action for SOC / user>
"""
            headers = {
                "Authorization": f"Bearer {groq_api_key}",
                "Content-Type": "application/json"
            }
            payload = {
                "model": "llama-3.1-8b-instant",
                "messages": [
                    {"role": "system", "content": "You are a cyber threat intelligence forensic analyst."},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.1,
                "max_tokens": 200
            }
            resp = requests.post("https://api.groq.com/openai/v1/chat/completions", json=payload, headers=headers, timeout=4.0)
            if resp.status_code == 200:
                summary = resp.json()['choices'][0]['message']['content'].strip()
                return summary
        except Exception as e:
            logger.warning(f"Groq API summary call failed, using template fallback: {e}")

    # 2. Try OpenAI (gpt-4o-mini) if available
    if openai_api_key:
        try:
            prompt = f"""Synthesize a 3-bullet security forensic report for this link scan:
URL: {url}
Threat Score: {threat_score} ({verdict})
Telemetry Flags: {telemetry}

Output format:
• Threat Summary: ...
• Key Forensic Evidence: ...
• Recommended Action: ..."""
            headers = {
                "Authorization": f"Bearer {openai_api_key}",
                "Content-Type": "application/json"
            }
            payload = {
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
                "max_tokens": 200
            }
            resp = requests.post("https://api.openai.com/v1/chat/completions", json=payload, headers=headers, timeout=4.0)
            if resp.status_code == 200:
                summary = resp.json()['choices'][0]['message']['content'].strip()
                return summary
        except Exception as e:
            logger.warning(f"OpenAI API summary call failed, using template fallback: {e}")

    # 3. High-Fidelity Deterministic Template Fallback (Sub-millisecond, $0 cost)
    evidence_items = []
    
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
        
    if telemetry.get("sandbox_has_password"):
        evidence_items.append("Interactive credential harvesting password input detected")
        
    if telemetry.get("heuristic_flags"):
        for flag in telemetry.get("heuristic_flags", []):
            evidence_items.append(flag.split(":")[0].replace("_", " ").title())
            
    if telemetry.get("title_mismatch"):
        evidence_items.append("Page title claims corporate brand while domain does not match")

    if not evidence_items:
        evidence_items.append("Standard domain lifecycle and clean structural heuristics")

    # Format 3-bullet forensic report
    if threat_score >= 80:
        threat_summary = f"Critical phishing and credential harvesting attack targeting end users via deceptive infrastructure."
        action = "Block URL immediately at firewall/DNS resolver, revoke any entered passwords, and quarantine related emails."
    elif threat_score >= 50:
        threat_summary = f"Suspicious link displaying anomaly indicators and high-risk domain metadata."
        action = "Caution advised. Isolate in sandbox container and inspect sender authenticity before interacting."
    else:
        threat_summary = f"Domain verified legitimate. No malicious evasion techniques or threat signatures detected."
        action = "No action required. Traffic permitted to proceed normally."

    formatted_evidence = "; ".join(evidence_items[:4])
    
    return (
        f"• Threat Summary: {threat_summary}\n"
        f"• Key Forensic Evidence: {formatted_evidence}\n"
        f"• Recommended Action: {action}"
    )


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
        skip_llm: bool = False,
        is_unreachable: bool = False
    ) -> Dict[str, Any]:
        """
        Fuses all 12+ telemetry features with deterministic guardrails.
        """
        heuristic_flags = heuristic_flags or []
        
        # 1. Deterministic Hard Overrides (Defense-in-Depth)
        hard_override_triggered = False
        override_reason = ""
        threat_score = 0.0

        if known_db_match == 1:
            threat_score = 100.0
            hard_override_triggered = True
            override_reason = "Known Malicious Threat DB Match"
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
        elif heuristic_risk >= 70.0:
            threat_score = min(100.0, max(85.0, heuristic_risk))
            hard_override_triggered = True
            override_reason = "Deterministic Phishing Pattern (Brand Spoofing / Credential Path / Deceptive Structure)"
        elif domain_age_risk >= 90 and has_password == 1:
            threat_score = 90.0
            hard_override_triggered = True
            override_reason = "Zero-Day Domain (< 14 days) with Password Harvesting"
        elif vt_risk_score >= 90.0 and has_password == 1:
            threat_score = 95.0
            hard_override_triggered = True
            override_reason = "VirusTotal Flagged Malicious with Password Harvesting"
        elif is_unreachable or sandbox_threat >= 60.0:
            # Unresolved dead domain
            if heuristic_risk >= 30.0 or brand_impersonation == 1:
                threat_score = max(threat_score, 80.0)
                override_reason = "Unresolved Evasive Domain with Deceptive Phishing Indicators"
            else:
                threat_score = max(threat_score, 65.0)
                override_reason = "Unresolved Infrastructure (ERR_NAME_NOT_RESOLVED)"
            hard_override_triggered = True
            
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
            if heuristic_risk >= 50.0: booster += 25.0
            # Password field only adds risk if coupled with deceptive brand, exfiltration, or zero-day domain
            if has_password == 1 and (brand_impersonation == 1 or external_form_action == 1 or suspicious_exfiltration == 1 or domain_age_risk >= 80 or title_mismatch == 1):
                booster += 30.0
            if title_mismatch == 1: booster += 25.0
            if url_entropy_risk == 1: booster += 15.0
            if hidden_iframes > 0: booster += 20.0
            
            threat_score = round(min(100.0, ensemble_base + booster), 2)
            
        # 3. Categorical Verdict
        if threat_score >= 80.0:
            verdict = "CRITICAL FRAUD / PHISHING"
        elif is_unreachable or "ERR_NAME_NOT_RESOLVED" in str(heuristic_flags):
            verdict = "SUSPICIOUS / UNRESOLVED DOMAIN"
        elif threat_score >= 50.0:
            verdict = "SUSPICIOUS"
        else:
            verdict = "LEGITIMATE / CLEAN"
            
        # 4. Synthesize human-readable explainable indicators
        indicators = list(heuristic_flags)
        if override_reason and override_reason not in indicators:
            indicators.insert(0, f"[GUARDRAIL_OVERRIDE] {override_reason}")
        if has_password == 1:
            indicators.append("CREDENTIAL_FIELD: Interactive password harvesting input field detected")
        if external_form_action == 1:
            indicators.append("CROSS_DOMAIN_ACTION: Form targets external exfiltration destination")
        if suspicious_exfiltration == 1:
            indicators.append("EXFILTRATION: Form transmits sensitive input to unauthorized host")
        if hidden_iframes > 0:
            indicators.append(f"EVASION: Detected {hidden_iframes} concealed zero-pixel iframe(s)")
            
        # 5. Telemetry payload
        telemetry = {
            "heuristic_flags": heuristic_flags,
            "threat_indicators_detected": indicators,
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
            "is_unreachable": is_unreachable,
            "hard_override_triggered": hard_override_triggered,
            "override_reason": override_reason
        }
        
        # 6. Synthesize 3-bullet Forensic Explanation
        summary = generate_llm_incident_summary(url, threat_score, verdict, telemetry, skip_external=skip_llm)
        
        return {
            "url": url,
            "threat_score": threat_score,
            "verdict": verdict,
            "summary": summary,
            "indicators": indicators,
            "telemetry": telemetry
        }
