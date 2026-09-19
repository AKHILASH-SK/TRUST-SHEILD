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


def classify_threat_attribution(
    auth_data: Dict[str, Any],
    origin_data: Dict[str, Any],
    metadata: Dict[str, Any],
    mx_data: Dict[str, Any],
    max_link_score: float = 0.0,
    overall_threat_score: float = 0.0
) -> Dict[str, str]:
    """
    Classifies the incident into an explicit threat actor attribution category based on SIH 106 criteria.
    Rules evaluate in strict priority order:
      1. ANONYMIZED_INFRASTRUCTURE: Originating IP is a known Tor/VPN/Proxy node.
      2. SPOOFED_IDENTITY_UNAUTHENTICATED: Sender identity forged; fails DNS authorization (SPF & DMARC fail).
      3. COMPROMISED_LEGITIMATE_ACCOUNT: BEC tactic detected: Reply-To routes to external infrastructure while SPF passed.
      4. DIRECT_MALICIOUS_MTA: Sender domain lacks MX infrastructure; burner/throwaway domain.
      5. MALICIOUS_PAYLOAD_AUTHENTICATED_CHANNEL: envelope/identity checks are clean, but the message
         carries a confirmed malicious payload (e.g. a compromised account or abused free-hosting link).
      6. BENIGN_AUTHENTICATED: Email routed normally, no malicious indicators found anywhere.

    max_link_score / overall_threat_score are passed in so this function can never emit a
    reassuring attribution (BENIGN_AUTHENTICATED) for an email the fusion engine has already
    scored as critical — that self-contradiction (e.g. "100/100 CRITICAL" next to "benign,
    routed normally") is exactly the kind of inconsistency that undermines a forensic tool's
    credibility, so it's treated as a hard invariant rather than left to chance.
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

    if mx_data.get("has_mx_records") is False:
        return {
            "type": "DIRECT_MALICIOUS_MTA",
            "confidence": "HIGH",
            "details": "Sender domain lacks MX infrastructure; burner/throwaway domain."
        }

    # Envelope/identity/infrastructure all look clean — but if the sandbox confirmed a
    # dangerous payload (or the fused score is elevated for any other reason), a "benign"
    # label would contradict the verdict. Attribute it to the channel being abused instead.
    if max_link_score >= 70.0 or overall_threat_score >= 50.0:
        return {
            "type": "MALICIOUS_PAYLOAD_AUTHENTICATED_CHANNEL",
            "confidence": "MEDIUM_HIGH" if max_link_score >= 70.0 else "MEDIUM",
            "details": "Sender infrastructure passes authentication, but the message carries a "
                       "confirmed malicious payload — indicates likely account compromise or "
                       "abuse of legitimate third-party hosting."
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
    attribution: Optional[Dict[str, str]] = None
) -> str:
    """Generates an executive forensic narrative and court-ready incident summary."""
    subject = metadata.get("subject", "No Subject")
    sender = metadata.get("from", "Unknown Sender")
    origin_ip = origin.get("originating_ip", "Unknown IP")
    origin_country = origin.get("origin_country", "Unknown Location")

    summary_lines = []
    
    # 1. Threat Summary
    attr_type = attribution.get("type", "UNKNOWN") if attribution else "UNKNOWN"
    if verdict == "CRITICAL FRAUD / PHISHING":
        summary_lines.append(
            f"• Threat Summary: CRITICAL SECURITY INCIDENT ({overall_threat_score}/100) [Attribution: {attr_type}]. "
            f"Email '{subject}' sent from {origin_ip} ({origin_country}) exhibits severe identity spoofing "
            f"and malicious payload indicators."
        )
    elif verdict == "SUSPICIOUS / UNVERIFIED ORIGIN":
        summary_lines.append(
            f"• Threat Summary: SUSPICIOUS ACTIVITY ({overall_threat_score}/100) [Attribution: {attr_type}]. "
            f"Email '{subject}' displays anomalous technical headers or unverified authentication protocols."
        )
    else:
        summary_lines.append(
            f"• Threat Summary: LEGITIMATE / CLEAN ({overall_threat_score}/100) [Attribution: {attr_type}]. "
            f"Email '{subject}' from '{sender}' passed standard technical validations."
        )

    # 2. Key Forensic Evidence
    if risk_factors:
        evidence_str = "; ".join(risk_factors)
        summary_lines.append(f"• Key Forensic Evidence: {evidence_str}.")
    else:
        summary_lines.append("• Key Forensic Evidence: All authentication protocols aligned; no malicious URLs detected.")

    # 3. Recommended Action
    if verdict == "CRITICAL FRAUD / PHISHING":
        summary_lines.append(
            "• Recommended Action: QUARANTINE IMMEDIATELY. Block sender domain and originating IP across edge gateways. "
            "Purge copies from recipient mailboxes and alert SOC team."
        )
    elif verdict == "SUSPICIOUS / UNVERIFIED ORIGIN":
        summary_lines.append(
            "• Recommended Action: FLAG TO USER. Apply warning banner to message and restrict external link execution."
        )
    else:
        summary_lines.append(
            "• Recommended Action: ALLOW. Message passes technical envelope checks."
        )

    return "\n".join(summary_lines)



def analyze_email_pipeline(eml_bytes: bytes, skip_link_sandbox: bool = False) -> Dict[str, Any]:
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
    is_proxy = bool(origin_geo.get("is_proxy", False)) if origin_geo else False
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

    link_investigation = []
    max_link_score = 0.0
    critical_link_detected = False

    unique_links = list(dict.fromkeys(extracted_links))[:3]

    for idx, link in enumerate(unique_links):
        try:
            # If critical threat already confirmed on previous link, run fast-path heuristics on remaining
            should_skip_sandbox = skip_link_sandbox or (critical_link_detected and idx > 0)
            link_analysis = analyze_url(
                url=link,
                email_text_context=body_text,
                skip_sandbox=should_skip_sandbox
            )
            score = float(link_analysis.get("threat_score", 0.0))
            verdict = link_analysis.get("verdict", "UNKNOWN")

            if score > max_link_score:
                max_link_score = score
            if score >= 80.0:
                critical_link_detected = True

            link_investigation.append({
                "url": link,
                "threat_score": score,
                "verdict": verdict,
                "summary": link_analysis.get("summary", ""),
                "telemetry": link_analysis.get("telemetry", {})
            })
        except Exception as e:
            logger.error(f"Error analyzing URL {link}: {e}")
            link_investigation.append({
                "url": link,
                "threat_score": 50.0,
                "verdict": "SUSPICIOUS / ANALYSIS_ERROR",
                "summary": f"Sandbox analysis encountered an error: {str(e)}",
                "telemetry": {}
            })

    # =========================================================================
    # Step D: Calculate Global Email Threat Score (0.0 to 100.0)
    # =========================================================================
    # Multi-track indicator fusion:
    # 1. Base score from link investigation
    if max_link_score >= 80.0:
        base_threat = max_link_score
    elif max_link_score > 0.0:
        base_threat = max_link_score * 0.5
    else:
        base_threat = 0.0

    risk_factors = []

    if critical_link_detected:
        risk_factors.append(f"High-Risk Phishing Link Identified (Score: {max_link_score}/100)")

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

    # Cap score strictly between 0.0 and 100.0
    overall_threat_score = round(max(0.0, min(100.0, base_threat)), 1)

    # =========================================================================
    # Step E: Classify Final Verdict & Threat Actor Attribution
    # =========================================================================
    if overall_threat_score >= 80.0:
        final_verdict = "CRITICAL FRAUD / PHISHING"
    elif overall_threat_score >= 50.0:
        final_verdict = "SUSPICIOUS / UNVERIFIED ORIGIN"
    else:
        final_verdict = "LEGITIMATE / AUTHENTICATED"

    # Threat Actor Attribution Classification
    mx_data = forensics.get("sender_domain_intelligence", {})
    threat_attribution = classify_threat_attribution(
        auth_data=auth,
        origin_data=origin_intelligence,
        metadata=metadata,
        mx_data=mx_data,
        max_link_score=max_link_score,
        overall_threat_score=overall_threat_score
    )

    # =========================================================================
    # Step F: Generate Executive Narrative Incident Summary
    # =========================================================================
    incident_summary = generate_incident_summary(
        verdict=final_verdict,
        overall_threat_score=overall_threat_score,
        metadata=metadata,
        auth=auth,
        origin=origin_intelligence,
        link_results=link_investigation,
        risk_factors=risk_factors,
        attribution=threat_attribution
    )

    # =========================================================================
    # Step G: Return Standard Unified Forensics Schema
    # =========================================================================
    return {
        "evidence_hash_sha256": evidence_hash,
        "overall_threat_score": overall_threat_score,
        "verdict": final_verdict,
        "threat_attribution": threat_attribution,
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
