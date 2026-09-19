"""
TrustShield V2 - Unified EML Forensic Orchestrator (unified_email_pipeline.py)
Orchestrates end-to-end email analysis by integrating:
  1. Email Forensics Engine (SHA-256, RFC-5322 parsing, SPF/DKIM/DMARC, hop extraction)
  2. GeoLocation Tracer (GPS coordinates, Leaflet route map, Tor/proxy detection)
  3. Dynamic Phishing Link Sandbox & Meta-Classifier (Heuristics, Threat DB, Chrome Sandbox, RF Classifier)
Computes a holistic incident threat score (0-100) and returns a unified dossier for SOC analysts.
"""

import logging
from typing import Dict, Any, List, Optional

# Core Engine Sub-modules
from .email_forensics import parse_email_file
from .geo_tracer import generate_route_map, resolve_ip_location
from .link_threat_pipeline import analyze_url

logger = logging.getLogger(__name__)


def analyze_email_content_social_engineering(subject: str, body_text: str, from_header: str) -> Dict[str, Any]:
    """
    Analyzes email plain text & subject for social engineering and behavioral manipulation tactics:
      - Recruitment / unsolicited job offer lures & unrealistic compensation
      - Free webmail (@gmail.com, @yahoo.com) claiming corporate HR / Executive authority
      - Urgency cues & psychological time pressure
      - Credential harvesting / account verification calls-to-action
      - External hyperlink navigation pressure
    """
    import re
    text = f"{subject}\n{body_text}".lower()
    signals: List[str] = []
    score = 0.0

    # 1. Employment / Job Opportunity Lures with Compensation
    job_patterns = [
        r'\b(?:job offer|business analytics|career opportunity|hiring immediately|interview invitation|candidate profile|recruiting team|hr team|recruitment team)\b',
        r'\b(?:monthly compensation|salary|stipend|per month|per week)\b',
        r'(?:₹|\$|rs\.?|inr)\s*\d+[\d,]*'
    ]
    job_matched = [p for p in job_patterns if re.search(p, text, re.IGNORECASE)]
    if len(job_matched) >= 2:
        score += 35.0
        signals.append("Unsolicited Employment & Compensation Lure Detected (Job Offer / Salary terms)")
    elif len(job_matched) == 1:
        score += 15.0
        signals.append("Employment / Recruitment Lure Detected")

    # 2. Free Webmail Persona Discrepancy (e.g. personal @gmail.com claiming to be Corporate HR/Recruiter)
    from_lower = from_header.lower()
    free_webmail_domains = ["@gmail.com", "@yahoo.com", "@hotmail.com", "@outlook.com", "@aol.com"]
    is_free_webmail = any(dom in from_lower for dom in free_webmail_domains)
    claims_corporate_persona = bool(re.search(r'\b(?:hr|recruitment|recruiter|hiring|security team|support team|administrator|executive|director)\b', text + " " + from_lower))
    
    if is_free_webmail and claims_corporate_persona:
        score += 30.0
        signals.append(f"Persona Discrepancy: Message claims corporate/recruitment authority but was dispatched from personal free webmail ('{from_header}')")

    # 3. Urgency & Coercive Action Pressure
    urgency_patterns = [
        r'\b(?:urgent|immediately|immediate action|action required|within 24 hours|account suspended|unauthorized login|wire transfer|cancel transfer)\b'
    ]
    if any(re.search(p, text, re.IGNORECASE) for p in urgency_patterns):
        score += 25.0
        signals.append("Coercive Urgency / Action Pressure Cues")

    # 4. Credential Harvesting & External Link Pressure
    link_pressure_patterns = [
        r'\b(?:visit the link below|click the link|click here|access portal|review your candidate profile|verify your account|confirm credentials)\b'
    ]
    if any(re.search(p, text, re.IGNORECASE) for p in link_pressure_patterns):
        score += 20.0
        signals.append("External Link Interaction Pressure (Directive to navigate to external URL)")

    content_score = round(min(100.0, score), 1)
    if content_score >= 50.0:
        level = "HIGH"
    elif content_score >= 25.0:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "content_risk_score": content_score,
        "content_risk_level": level,
        "content_signals": signals
    }


def classify_threat_attribution(
    auth_data: Dict[str, Any],
    origin_data: Dict[str, Any],
    metadata: Dict[str, Any],
    mx_data: Dict[str, Any],
    has_critical_link: bool = False,
    max_link_score: float = 0.0
) -> Dict[str, str]:
    """
    Classifies the incident into an explicit threat actor attribution category based on SIH 106 criteria.
    Rules evaluate in strict priority order:
      1. ANONYMIZED_INFRASTRUCTURE: Originating IP is a known Tor/VPN/Proxy node.
      2. SPOOFED_IDENTITY_UNAUTHENTICATED: Sender identity forged; fails DNS authorization (SPF & DMARC fail).
      3. WEAPONIZED_AUTHENTICATED_ACCOUNT: Valid sender SPF/DKIM infrastructure abused to dispatch malicious lookalike/phishing payload.
      4. COMPROMISED_LEGITIMATE_ACCOUNT: BEC tactic detected: Reply-To routes to external infrastructure while SPF passed.
      5. DIRECT_MALICIOUS_MTA: Sender domain lacks MX infrastructure; burner/throwaway domain.
      6. BENIGN_AUTHENTICATED: Email routed normally.
    """
    if origin_data.get("is_anonymized_node") is True:
        return {
            "type": "ANONYMIZED_INFRASTRUCTURE",
            "confidence": "HIGH",
            "details": "Originating IP is a known Tor/VPN/Proxy node."
        }

    if auth_data.get("spf_pass") is False and auth_data.get("dmarc_pass") is False:
        return {
            "type": "SPOOFED_IDENTITY_UNAUTHENTICATED",
            "confidence": "CRITICAL",
            "details": "Sender identity forged; fails DNS authorization."
        }

    if metadata.get("reply_to_mismatch") is True and auth_data.get("spf_pass") is True:
        return {
            "type": "COMPROMISED_LEGITIMATE_ACCOUNT",
            "confidence": "MEDIUM_HIGH",
            "details": "BEC tactic detected: Reply-To routes to external infrastructure."
        }

    # Authenticated service weaponized with malicious/lookalike payload
    if (has_critical_link or max_link_score >= 75.0) and auth_data.get("spf_pass") is True:
        return {
            "type": "WEAPONIZED_AUTHENTICATED_ACCOUNT",
            "confidence": "HIGH",
            "details": "Authenticated email infrastructure weaponized to deliver deceptive lookalike/phishing payload."
        }

    if mx_data.get("has_mx_records") is False:
        return {
            "type": "DIRECT_MALICIOUS_MTA",
            "confidence": "HIGH",
            "details": "Sender domain lacks MX infrastructure; burner/throwaway domain."
        }

    return {
        "type": "BENIGN_AUTHENTICATED",
        "confidence": "LOW",
        "details": "Email routed normally."
    }


def generate_incident_summary(
    verdict: str,
    overall_threat_score: float,
    metadata: Dict[str, Any],
    auth: Dict[str, Any],
    origin: Dict[str, Any],
    link_results: List[Dict[str, Any]],
    risk_factors: List[str],
    attribution: Optional[Dict[str, str]] = None,
    content_analysis: Optional[Dict[str, Any]] = None
) -> str:
    """Generates an executive forensic narrative and court-ready incident summary."""
    subject = metadata.get("subject", "No Subject")
    sender = metadata.get("from", "Unknown Sender")
    from_domain = metadata.get("from_domain", "Unknown Domain")
    origin_ip = origin.get("originating_ip", "Unknown IP")
    origin_country = origin.get("origin_country", "Unknown Location")

    summary_lines = []
    
    # 1. Threat Summary
    attr_type = attribution.get("type", "UNKNOWN") if attribution else "UNKNOWN"
    if verdict == "CRITICAL FRAUD / PHISHING":
        summary_lines.append(
            f"• Threat Summary: CRITICAL SECURITY INCIDENT ({overall_threat_score}/100) [Attribution: {attr_type}]. "
            f"Email '{subject}' dispatched via {origin_ip} ({origin_country}) delivers verified deceptive phishing/lookalike payload."
        )
    elif "BEC" in verdict or "SPOOFING" in verdict:
        summary_lines.append(
            f"• Threat Summary: HIGH-RISK BEC / SPOOFING INCIDENT ({overall_threat_score}/100) [Attribution: {attr_type}]. "
            f"Email '{subject}' exhibits executive identity mismatch with silent external Reply-To redirection."
        )
    elif verdict == "SUSPICIOUS / UNVERIFIED ORIGIN" or "SUSPICIOUS" in verdict:
        summary_lines.append(
            f"• Threat Summary: SUSPICIOUS ACTIVITY ({overall_threat_score}/100) [Attribution: {attr_type}]. "
            f"Email '{subject}' displays anomalous technical headers, unverified authentication, or high-risk link infrastructure."
        )
    else:
        summary_lines.append(
            f"• Threat Summary: LEGITIMATE / CLEAN ({overall_threat_score}/100) [Attribution: {attr_type}]. "
            f"Email '{subject}' from '{sender}' passed standard technical validations."
        )

    # 2. Mixed Telemetry Analysis (when passing auth collides with malicious link)
    if auth.get("spf_pass") and auth.get("dkim_pass") and overall_threat_score >= 75.0:
        summary_lines.append(
            f"• Forensic Correlation of Mixed Telemetry: Sender infrastructure is cryptographically authenticated via "
            f"Google/MTA SPF & DKIM ({from_domain}). However, the message payload delivers deceptive lookalike phishing "
            f"infrastructure. Passing sender authentication does NOT authenticate message body contents."
        )

    # 3. Key Forensic Evidence
    if risk_factors:
        evidence_str = "; ".join(risk_factors[:6])
        summary_lines.append(f"• Key Forensic Evidence: {evidence_str}.")
    else:
        summary_lines.append("• Key Forensic Evidence: All authentication protocols aligned; no malicious URLs detected.")

    # 4. Recommended Action
    if verdict == "CRITICAL FRAUD / PHISHING":
        summary_lines.append(
            "• Recommended Action: QUARANTINE IMMEDIATELY. Block payload URLs across edge firewalls and DNS resolvers. "
            "Alert recipient and SOC security team."
        )
    elif "BEC" in verdict or "SPOOFING" in verdict:
        summary_lines.append(
            "• Recommended Action: ALERT RECIPIENT. Suspected executive impersonation. Mandate verbal out-of-band verification before approving any payment."
        )
    elif "SUSPICIOUS" in verdict:
        summary_lines.append(
            "• Recommended Action: FLAG TO USER. Apply warning banner to message and restrict external link execution."
        )
    else:
        summary_lines.append(
            "• Recommended Action: ALLOW. Message passes technical envelope checks."
        )

    return "\n".join(summary_lines)



def analyze_email_pipeline(eml_bytes: bytes, skip_link_sandbox: bool = False, demo_mode: bool = False) -> Dict[str, Any]:
    if demo_mode:
        skip_link_sandbox = True
    """
    Main Ingestion Controller: Executes the full multi-engine forensic pipeline on raw .eml bytes.
    
    Steps:
      Step A: Parse RFC-5322 Envelope & Authentication (email_forensics.py)
      Step B: Trace Server Hops & Geolocation (geo_tracer.py)
      Step C: Detonate Embedded Links (link_threat_pipeline.py)
      Step D: Calculate Global Email Threat Score (0.0 - 100.0)
      Step E: Classify Final Verdict
      Step F: Produce Standardized Output Schema
    """
    if not eml_bytes:
        return {
            "evidence_hash_sha256": "",
            "overall_threat_score": 0.0,
            "verdict": "LEGITIMATE / AUTHENTICATED",
            "metadata": {},
            "authentication": {"spf_pass": False, "dkim_pass": False, "dmarc_pass": False},
            "origin_intelligence": {
                "originating_ip": None,
                "origin_country": "Unknown",
                "origin_isp": "Unknown",
                "is_anonymized_node": False,
                "total_hops": 0,
                "route_map": []
            },
            "link_investigation": [],
            "incident_summary": "• Threat Summary: Empty or invalid email file provided.\n• Key Forensic Evidence: No data.\n• Recommended Action: Upload valid .eml file."
        }

    # =========================================================================
    # Step A: Parse RFC-5322 Envelope & Authentication Records
    # =========================================================================
    forensics = parse_email_file(eml_bytes)
    
    evidence_hash = forensics.get("evidence_hash_sha256", "")
    metadata = forensics.get("metadata", {})
    auth = forensics.get("authentication", {})
    origin_tracing = forensics.get("origin_tracing", {})
    payload = forensics.get("payload", {})

    originating_ip = origin_tracing.get("originating_ip")
    hops_data = origin_tracing.get("hops", [])

    # =========================================================================
    # Step B: Trace Server Hops & Geolocation
    # =========================================================================
    route_map = generate_route_map(hops_data)

    # Identify originating node details
    origin_geo = None
    if originating_ip:
        # Check if already resolved in route_map
        for hop in route_map:
            if hop.get("ip") == originating_ip:
                origin_geo = hop
                break
        # Fallback to direct resolution if not matched
        if not origin_geo:
            origin_geo = resolve_ip_location(originating_ip)
    
    origin_country = origin_geo.get("country", "Unknown") if origin_geo else "Unknown"
    origin_isp = origin_geo.get("isp", "Unknown") if origin_geo else "Unknown"
    is_proxy = bool(origin_geo.get("is_proxy", False) or origin_geo.get("is_suspicious_proxy", False)) if origin_geo else False
    is_hosting = bool(origin_geo.get("is_hosting", False)) if origin_geo else False
    is_anonymized_node = is_proxy

    origin_intelligence = {
        "originating_ip": originating_ip or "Unknown",
        "origin_country": origin_country,
        "origin_isp": origin_isp,
        "is_anonymized_node": is_anonymized_node,
        "is_proxy": is_proxy,
        "is_hosting": is_hosting,
        "total_hops": origin_tracing.get("total_hops", len(route_map)),
        "route_map": route_map
    }

    # =========================================================================
    # Step C: Detonate Embedded Links in Threat Sandbox
    # =========================================================================
    extracted_links = payload.get("extracted_links", [])
    body_text = payload.get("body_text", "")
    from_domain = metadata.get("from_domain", "")

    link_investigation = []
    max_link_score = 0.0
    critical_link_detected = False
    all_link_indicators = []

    for link in extracted_links:
        try:
            link_analysis = analyze_url(
                url=link,
                email_text_context=body_text,
                sender_domain=from_domain,
                skip_sandbox=skip_link_sandbox
            )
            score = float(link_analysis.get("threat_score", 0.0))
            verdict = link_analysis.get("verdict", "UNKNOWN")
            indicators = link_analysis.get("indicators") or link_analysis.get("telemetry", {}).get("threat_indicators_detected", [])

            if score > max_link_score:
                max_link_score = score
            if score >= 75.0:
                critical_link_detected = True
            if indicators:
                all_link_indicators.extend(indicators)

            link_investigation.append({
                "url": link,
                "threat_score": score,
                "verdict": verdict,
                "classification": verdict,
                "indicators": indicators,
                "summary": link_analysis.get("summary", ""),
                "telemetry": link_analysis.get("telemetry", {})
            })
        except Exception as e:
            logger.error(f"Error analyzing URL {link}: {e}")
            link_investigation.append({
                "url": link,
                "threat_score": 50.0,
                "verdict": "SUSPICIOUS / ANALYSIS_ERROR",
                "classification": "SUSPICIOUS / ANALYSIS_ERROR",
                "indicators": [f"Analysis error: {str(e)}"],
                "summary": f"Sandbox analysis encountered an error: {str(e)}",
                "telemetry": {}
            })

    # =========================================================================
    # Step D: Content & Social Engineering Risk Analysis
    # =========================================================================
    content_analysis = analyze_email_content_social_engineering(
        subject=metadata.get("subject", ""),
        body_text=body_text,
        from_header=metadata.get("from", "")
    )
    content_risk_score = float(content_analysis.get("content_risk_score", 0.0))

    # =========================================================================
    # Step E: Calculate Global Multi-Layer Email Threat Score (0.0 to 100.0)
    # =========================================================================
    # Multi-track indicator fusion:
    # 1. Base score from link investigation
    if max_link_score >= 50.0:
        base_threat = max_link_score
    elif max_link_score > 0.0:
        base_threat = max_link_score * 0.5
    else:
        base_threat = 0.0

    risk_factors = []

    # Incorporate link risk findings
    if critical_link_detected or max_link_score >= 80.0:
        risk_factors.append(f"High-Risk Phishing Link Identified (Threat Score: {max_link_score}/100)")
    elif max_link_score >= 50.0:
        risk_factors.append(f"Suspicious Embedded Hyperlink Detected (Threat Score: {max_link_score}/100)")

    for ind in all_link_indicators:
        clean_ind = ind.split(":", 1)[-1].strip() if ":" in ind else ind
        if clean_ind not in risk_factors and len(risk_factors) < 10:
            risk_factors.append(clean_ind)

    # Incorporate content / social engineering findings
    if content_risk_score >= 25.0:
        base_threat += (20.0 if content_risk_score >= 50.0 else 10.0)
        for sig in content_analysis.get("content_signals", []):
            if sig not in risk_factors and len(risk_factors) < 10:
                risk_factors.append(sig)

    # 2. Authentication Failures (+30 points if both SPF and DMARC fail)
    spf_pass = bool(auth.get("spf_pass", False))
    dkim_pass = bool(auth.get("dkim_pass", False))
    dmarc_pass = bool(auth.get("dmarc_pass", False))

    if not spf_pass and not dmarc_pass:
        base_threat += 30.0
        risk_factors.append("Failed SPF & DMARC Sender Identity Verification")
    elif not dmarc_pass:
        base_threat += 15.0
        risk_factors.append("Failed DMARC Policy Alignment")

    # 3. Reply-To Mismatch (BEC spoofing indicator: +35 points)
    reply_to_mismatch = bool(metadata.get("reply_to_mismatch", False))
    if reply_to_mismatch:
        base_threat += 35.0
        risk_factors.append(f"BEC Domain Spoofing: Reply-To ({metadata.get('reply_to')}) differs from From ({metadata.get('from')})")

    # 4. Infrastructure Anomaly (Tor/VPN/Datacenter proxy origin: +20 points)
    if is_anonymized_node:
        base_threat += 20.0
        risk_factors.append(f"Originating MTA ({originating_ip}) is an Anonymized Proxy / Tor / Hosting Infrastructure ({origin_isp})")

    # DEFENSE-IN-DEPTH HARD OVERRIDE:
    # Passing SPF/DKIM sender authentication must NEVER dilute or override a high-risk phishing/lookalike link!
    if max_link_score >= 80.0:
        overall_threat_score = round(max(min(100.0, base_threat), max_link_score), 1)
    else:
        overall_threat_score = round(max(0.0, min(100.0, base_threat)), 1)

    # =========================================================================
    # Step F: Classify Final Verdict & Threat Actor Attribution
    # =========================================================================
    if overall_threat_score >= 80.0:
        final_verdict = "CRITICAL FRAUD / PHISHING"
    elif reply_to_mismatch and overall_threat_score >= 50.0:
        final_verdict = "HIGH-RISK BEC / SPOOFING"
    elif max_link_score >= 50.0 or overall_threat_score >= 50.0:
        final_verdict = "SUSPICIOUS / DECEPTIVE PAYLOAD"
    else:
        final_verdict = "LEGITIMATE / AUTHENTICATED"

    # Threat Actor Attribution Classification
    mx_data = forensics.get("sender_domain_intelligence", {})
    threat_attribution = classify_threat_attribution(
        auth_data=auth,
        origin_data=origin_intelligence,
        metadata=metadata,
        mx_data=mx_data,
        has_critical_link=critical_link_detected,
        max_link_score=max_link_score
    )

    # Determine recommended action text
    if final_verdict == "CRITICAL FRAUD / PHISHING":
        recommended_action = "QUARANTINE IMMEDIATELY. Block sender domain and originating IP across edge mail gateways. Alert recipient and SOC team."
    elif final_verdict == "HIGH-RISK BEC / SPOOFING":
        recommended_action = "ALERT RECIPIENT. Suspected executive impersonation / payroll redirection. Mandate verbal out-of-band verification before approving any payment."
    elif "SUSPICIOUS" in final_verdict:
        recommended_action = "FLAG TO USER. Apply warning banner to message, quarantine attachments, and restrict external hyperlink navigation."
    else:
        recommended_action = "ALLOW. Message passed technical envelope, cryptographic authentication, and hyperlink security audits."

    confidence_level = "HIGH" if (overall_threat_score >= 75.0 or overall_threat_score <= 25.0) else "MODERATE"

    # =========================================================================
    # Step G: Generate Executive Narrative Incident Summary
    # =========================================================================
    incident_summary = generate_incident_summary(
        verdict=final_verdict,
        overall_threat_score=overall_threat_score,
        metadata=metadata,
        auth=auth,
        origin=origin_intelligence,
        link_results=link_investigation,
        risk_factors=risk_factors,
        attribution=threat_attribution,
        content_analysis=content_analysis
    )

    # =========================================================================
    # Step H: Return Standard Unified Forensics Schema
    # =========================================================================
    enrichment_status = {
        "geolocation": "RESOLVED" if origin_country not in ("Unknown", "Lookup Unavailable") else "OFFLINE / TIMED OUT",
        "whois": "SKIPPED_IN_DEMO" if (skip_link_sandbox or demo_mode) else "AUDITED",
        "sandbox": "SKIPPED_FAST_DEMO" if (skip_link_sandbox or demo_mode) else "DETONATED_STEALTH_BROWSER",
        "ai_summary": "SYNTHESIZED"
    }

    # Independent Layer Status for Explanations
    auth_status = "PASS" if (spf_pass and dkim_pass and dmarc_pass) else ("FAIL" if (not spf_pass and not dmarc_pass) else "PARTIAL")
    link_status = "CRITICAL" if max_link_score >= 80 else ("HIGH" if max_link_score >= 65 else ("SUSPICIOUS" if max_link_score >= 50 else "CLEAN"))

    return {
        "evidence_hash_sha256": evidence_hash,
        "overall_threat_score": overall_threat_score,
        "verdict": final_verdict,
        "confidence": confidence_level,
        "recommended_action": recommended_action,
        "primary_evidence": risk_factors,
        "threat_indicators_detected": risk_factors,
        "analysis_type": "DEMO_SCENARIO" if demo_mode else "LIVE_ANALYSIS",
        "evidence_source": "SYNTHETIC_DEMO" if demo_mode else "LIVE_UPLOADED_EML",
        "analysis_mode": "FAST_DEMO" if demo_mode else ("FAST_EVALUATION" if skip_link_sandbox else "DEEP_SANDBOX"),
        "enrichment_status": enrichment_status,
        "threat_attribution": threat_attribution,
        "layered_evidence": {
            "authentication": {
                "status": auth_status,
                "spf_pass": spf_pass,
                "dkim_pass": dkim_pass,
                "dmarc_pass": dmarc_pass,
                "from_reply_to_aligned": not reply_to_mismatch
            },
            "link_threat": {
                "status": link_status,
                "max_score": max_link_score,
                "total_links": len(extracted_links),
                "critical_link_detected": critical_link_detected
            },
            "content_social_engineering": {
                "status": content_analysis.get("content_risk_level", "LOW"),
                "score": content_risk_score,
                "signals": content_analysis.get("content_signals", [])
            },
            "infrastructure_origin": {
                "originating_ip": originating_ip or "Unknown",
                "is_anonymized": is_anonymized_node
            }
        },
        "content_analysis": content_analysis,
        "metadata": {
            "subject": metadata.get("subject", ""),
            "from": metadata.get("from", ""),
            "from_domain": metadata.get("from_domain", ""),
            "to": metadata.get("to", ""),
            "date": metadata.get("date", ""),
            "message_id": metadata.get("message_id", ""),
            "return_path": metadata.get("return_path", ""),
            "reply_to": metadata.get("reply_to", ""),
            "reply_to_mismatch": reply_to_mismatch
        },
        "authentication": {
            "spf_pass": spf_pass,
            "spf_details": auth.get("spf_details", ""),
            "dkim_pass": dkim_pass,
            "dkim_details": auth.get("dkim_details", ""),
            "dmarc_pass": dmarc_pass,
            "dmarc_details": auth.get("dmarc_details", "")
        },
        "sender_domain_intelligence": mx_data,
        "origin_intelligence": origin_intelligence,
        "link_investigation": link_investigation,
        "incident_summary": incident_summary
    }



# Convenience alias
analyze_email_file = analyze_email_pipeline
