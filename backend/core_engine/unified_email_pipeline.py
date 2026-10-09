"""
TrustShield V2 - Unified EML Forensic Orchestrator (unified_email_pipeline.py)
Orchestrates end-to-end email analysis by integrating:
  1. Email Forensics Engine (SHA-256, RFC-5322 parsing, SPF/DKIM/DMARC, hop extraction)
  2. GeoLocation Tracer (GPS coordinates, Leaflet route map, Tor/proxy detection)
  3. Dynamic Phishing Link Sandbox & Meta-Classifier (Heuristics, Threat DB, Chrome Sandbox, RF Classifier)
  4. BEC & NLP Body Analyser (5-class taxonomy: LEGITIMATE/SUSPICIOUS/IMPERSONATED/PHISHING/BEC_FRAUD)
  5. WHOIS & Domain Intelligence (domain age, registrar risk, privacy shield, DNS anomalies)
  6. Attachment Risk Analyser (executable detection, macro docs, archive wrappers, double-extension)
  7. Graph Correlation Engine (D3.js-ready threat infra graph across sender/IP/ASN/URL nodes)
  8. Campaign Case Manager (groups related incidents into searchable campaign clusters)
Computes a holistic incident threat score (0-100) and returns a unified dossier for SOC analysts.
"""

import logging
from typing import Dict, Any, List, Optional

# Core Engine Sub-modules
from .email_forensics import parse_email_file
from .geo_tracer import generate_route_map, resolve_ip_location
from .link_threat_pipeline import analyze_url
from .url_heuristics import parse_url_heuristics

MAX_LINKS_ANALYZED = 12

# New SIH-required modules
try:
    from .bec_nlp_analyser import analyse_eml_for_bec
    _BEC_NLP_AVAILABLE = True
except ImportError:
    _BEC_NLP_AVAILABLE = False

try:
    from .whois_intel import lookup_whois
    _WHOIS_AVAILABLE = True
except ImportError:
    _WHOIS_AVAILABLE = False

try:
    from .attachment_analyser import analyse_attachments
    _ATTACHMENT_ANALYSER_AVAILABLE = True
except ImportError:
    _ATTACHMENT_ANALYSER_AVAILABLE = False

try:
    from .graph_correlation import ingest_analysis_to_graph, get_graph_d3_data
    _GRAPH_AVAILABLE = True
except ImportError:
    _GRAPH_AVAILABLE = False

try:
    from .campaign_manager import get_case_manager
    _CAMPAIGN_MANAGER_AVAILABLE = True
except ImportError:
    _CAMPAIGN_MANAGER_AVAILABLE = False

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

    spf_state = auth_data.get("spf_state") or ("pass" if auth_data.get("spf_pass") else "fail")
    dmarc_state = auth_data.get("dmarc_state") or ("pass" if auth_data.get("dmarc_pass") else "fail")
    if spf_state == "fail" and dmarc_state == "fail":
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

    if mx_data.get("has_mx_records") is False and not mx_data.get("lookup_error"):
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
    attribution: Optional[Dict[str, str]] = None,
    analysis_complete: bool = True
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
    elif not analysis_complete:
        summary_lines.append(
            f"• Threat Summary: ANALYSIS INCOMPLETE ({overall_threat_score}/100) [Attribution: {attr_type}]. "
            f"No threat indicators were found in the stages that completed for '{subject}' from '{sender}', "
            f"but some analysis stages failed, so this is NOT a clean verdict."
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
        summary_lines.append("• Key Forensic Evidence: No indicators found in completed stages." if not analysis_complete
                             else "• Key Forensic Evidence: All authentication protocols aligned; no malicious URLs detected.")

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
    elif not analysis_complete:
        summary_lines.append(
            "• Recommended Action: REVIEW MANUALLY. Analysis was incomplete; re-run or inspect the failed stages."
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
            "analysis_errors": ["Empty input"],
            "analysis_complete": False,
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

    analysis_errors: List[str] = list(forensics.get("analysis_errors", []))
    originating_ip = origin_tracing.get("originating_ip")
    hops_data = origin_tracing.get("hops", [])

    # =========================================================================
    # Step B: Trace Server Hops & Geolocation
    # =========================================================================
    try:
        route_map = generate_route_map(hops_data)
    except Exception as e:
        logger.warning(f"Geo route map error: {e}")
        analysis_errors.append(f"Geolocation stage failed: {type(e).__name__}: {e}")
        route_map = []

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
            try:
                origin_geo = resolve_ip_location(originating_ip)
            except Exception as e:
                analysis_errors.append(f"Origin geolocation failed: {type(e).__name__}: {e}")
    
    origin_country = origin_geo.get("country", "Unknown") if origin_geo else "Unknown"
    origin_isp = origin_geo.get("isp", "Unknown") if origin_geo else "Unknown"
    is_proxy = bool(origin_geo.get("is_proxy", False)) if origin_geo else False
    is_hosting = bool(origin_geo.get("is_hosting", False)) if origin_geo else False
    is_anonymized_node = is_proxy

    origin_intelligence = {
        "originating_ip": originating_ip or "Unknown",
        "origin_ip": originating_ip or "Unknown",
        "connecting_ip": origin_tracing.get("connecting_ip") or "Unknown",
        "routes_truncated": any(h.get("hops_truncated") for h in route_map),
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

    unique_links = list(dict.fromkeys(extracted_links))

    # Score every link with the cheap heuristics first; fully analyse the riskiest MAX_LINKS_ANALYZED.
    heuristics: Dict[str, Dict[str, Any]] = {}
    for link in unique_links:
        try:
            heuristics[link] = parse_url_heuristics(link)
        except Exception as e:
            # a failed check is "unavailable", never threat evidence
            heuristics[link] = {"heuristic_risk_score": 0.0, "heuristic_flags": [f"HEURISTIC_ERROR: {e}"],
                                "analysis_unavailable": True}
            analysis_errors.append(f"Link heuristics failed for {link[:80]}: {type(e).__name__}")
    ranked = sorted(unique_links, key=lambda u: float(heuristics[u].get("heuristic_risk_score", 0.0)), reverse=True)
    to_analyze = set(ranked[:MAX_LINKS_ANALYZED])
    ordered_full = [u for u in ranked if u in to_analyze]
    skipped = [u for u in unique_links if u not in to_analyze]

    for idx, link in enumerate(ordered_full):
        try:
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
            if score >= 75.0:
                critical_link_detected = True

            link_investigation.append({
                "url": link,
                "threat_score": score,
                "verdict": verdict,
                "summary": link_analysis.get("summary", ""),
                "telemetry": link_analysis.get("telemetry", {}),
                "analysis_depth": "full"
            })
        except Exception as e:
            logger.error(f"Error analyzing URL {link}: {e}")
            analysis_errors.append(f"Link analysis failed for {link[:80]}: {type(e).__name__}: {e}")
            link_investigation.append({
                "url": link,
                "threat_score": 0.0,
                "verdict": "ANALYSIS UNAVAILABLE",
                "summary": ("This link could not be analysed (the analysis service failed). "
                            "This is NOT evidence that the link is malicious or safe."),
                "telemetry": {"analysis_unavailable": True, "analysis_complete": False},
                "analysis_unavailable": True,
                "analysis_depth": "error"
            })

    # Skipped links still get heuristic-only results; heuristic-flagged ones count as issues.
    for link in skipped:
        h = heuristics[link]
        hscore = float(h.get("heuristic_risk_score", 0.0))
        flagged = hscore >= 50.0
        if flagged:
            max_link_score = max(max_link_score, hscore)
        link_investigation.append({
            "url": link,
            "threat_score": hscore,
            "verdict": "SUSPICIOUS (HEURISTIC ONLY)" if flagged else "NOT FULLY ANALYSED (HEURISTIC ONLY)",
            "summary": "; ".join(h.get("heuristic_flags", [])[:3]),
            "telemetry": {"heuristic_flags": h.get("heuristic_flags", [])},
            "analysis_depth": "heuristic_only"
        })
    links_total = len(unique_links)
    links_analyzed = len(ordered_full)
    links_skipped = len(skipped)

    # How does the attackers' domain behave (rotating addresses) and is its certificate worth trusting?
    try:
        from .infrastructure import inspect_links
        infrastructure = inspect_links(unique_links)
    except Exception as e:
        logger.warning(f"Infrastructure check error: {e}")
        infrastructure = {"domains": [], "flux_domains": 0, "untrusted_certificates": 0}

    # =========================================================================
    # Step D: Calculate Global Email Threat Score (0.0 to 100.0)
    # =========================================================================
    # Multi-track indicator fusion:
    # 1. Base score from link investigation
    if max_link_score >= 70.0:
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

    spf_state = auth.get("spf_state") or ("pass" if spf_pass else "fail")
    dmarc_state = auth.get("dmarc_state") or ("pass" if dmarc_pass else "fail")
    if spf_state == "fail" and dmarc_state == "fail":
        base_threat += 30.0
        risk_factors.append("Failed SPF & DMARC Sender Identity Verification")
    elif dmarc_state == "fail":
        base_threat += 15.0
        risk_factors.append("Failed DMARC Policy Alignment")
    elif dmarc_state == "indeterminate" or spf_state == "indeterminate":
        risk_factors.append("SPF/DMARC could not be fully evaluated (DNS error) - not scored as failure")

    # 2b. "Who is pretending to be whom": the checks above plus display name, lookalike domain, forwarding and the receiving
    #     provider's own report. Adds only what the plain failure points above did not already count.
    sender_assessment: Dict[str, Any] = {}
    try:
        from .sender_impersonation import assess_sender, score_contribution
        sender_assessment = assess_sender(forensics, eml_bytes)
        points, why = score_contribution(sender_assessment)
        already = 30.0 if (spf_state == "fail" and dmarc_state == "fail") else (15.0 if dmarc_state == "fail" else 0.0)
        if points > already:
            base_threat += points - already
            risk_factors.append(why)
    except Exception as e:                                   # never let the extra analysis break the email verdict
        logger.warning(f"Sender impersonation analysis error: {e}")

    # 2c. Infrastructure: rotating addresses (fast-flux) are a real sign of an attacker's domain; an untrusted certificate
    #     adds a little. Neither is enough alone, so both are small and only add weight to other findings.
    if infrastructure.get("flux_domains"):
        base_threat += 15.0
        flux = [d["domain"] for d in infrastructure["domains"] if d["fast_flux"].get("level") == "fast_flux"]
        risk_factors.append(f"Fast-flux infrastructure: {', '.join(flux[:3])} keeps changing the addresses it points to")
    if infrastructure.get("untrusted_certificates"):
        base_threat += 5.0
        risk_factors.append("A linked site presents a certificate that a browser would not trust")

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
        attribution=threat_attribution,
        analysis_complete=not analysis_errors
    )

    # =========================================================================
    # Step G: BEC & NLP Body Analysis (5-class taxonomy)
    # =========================================================================
    nlp_analysis = {}
    if _BEC_NLP_AVAILABLE:
        try:
            nlp_analysis = analyse_eml_for_bec(
                forensics_payload=payload,
                metadata=metadata
            )
            # Boost threat score if BEC_FRAUD or PHISHING class detected
            nlp_class = nlp_analysis.get("nlp_class", "LEGITIMATE")
            nlp_risk = float(nlp_analysis.get("nlp_risk_score", 0.0))
            if nlp_class in ("BEC_FRAUD", "PHISHING") and nlp_risk >= 50.0:
                boost = min(20.0, nlp_risk * 0.25)
                overall_threat_score = round(min(100.0, overall_threat_score + boost), 1)
                risk_factors.append(f"NLP Body Analysis: {nlp_class} detected (score {nlp_risk}/100)")
        except Exception as e:
            logger.warning(f"BEC/NLP analyser error: {e}")
            analysis_errors.append(f"BEC/NLP stage failed: {type(e).__name__}: {e}")
    else:
        analysis_errors.append("BEC/NLP stage unavailable (module import failed)")

    # =========================================================================
    # Step H: WHOIS & Domain Intelligence
    # =========================================================================
    whois_intelligence = {}
    if _WHOIS_AVAILABLE:
        try:
            from_domain_for_whois = metadata.get("from_domain", "")
            if from_domain_for_whois:
                whois_intelligence = lookup_whois(from_domain_for_whois)
                whois_risk = float(whois_intelligence.get("whois_risk_score", 0.0))
                # Contribute max +20 pts to overall score
                whois_contribution = min(20.0, whois_risk * 0.3)
                if whois_contribution > 0:
                    overall_threat_score = round(min(100.0, overall_threat_score + whois_contribution), 1)
                if whois_intelligence.get("is_newly_registered"):
                    risk_factors.append(f"WHOIS: Domain registered {whois_intelligence.get('domain_age_days')} day(s) ago (newly registered burner domain)")
                if any(str(f).startswith("UNREGISTERED_DOMAIN") for f in whois_intelligence.get("whois_risk_flags", [])):
                    risk_factors.append("WHOIS: Sender domain has no registration record")
        except Exception as e:
            logger.warning(f"WHOIS intel error: {e}")
            analysis_errors.append(f"WHOIS stage failed: {type(e).__name__}: {e}")
    else:
        analysis_errors.append("WHOIS stage unavailable (module import failed)")

    # =========================================================================
    # Step I: Attachment Risk Analysis
    # =========================================================================
    attachment_analysis = {}
    if _ATTACHMENT_ANALYSER_AVAILABLE:
        try:
            attachment_analysis = analyse_attachments(eml_bytes)
            attach_risk = float(attachment_analysis.get("attachment_risk_score", 0.0))
            if attach_risk >= 60.0:
                boost = min(25.0, attach_risk * 0.3)
                overall_threat_score = round(min(100.0, overall_threat_score + boost), 1)
                risk_factors.append(f"Attachment Risk: {attachment_analysis.get('attachment_risk_level')} — {attachment_analysis.get('suspicious_attachments', attachment_analysis.get('total_attachments'))} suspicious attachment(s) detected")
        except Exception as e:
            logger.warning(f"Attachment analyser error: {e}")
            analysis_errors.append(f"Attachment stage failed: {type(e).__name__}: {e}")
    else:
        analysis_errors.append("Attachment stage unavailable (module import failed)")

    # Recalculate final verdict after all boosts
    if overall_threat_score >= 80.0:
        final_verdict = "CRITICAL FRAUD / PHISHING"
    elif overall_threat_score >= 50.0:
        final_verdict = "SUSPICIOUS / UNVERIFIED ORIGIN"
    else:
        final_verdict = "LEGITIMATE / AUTHENTICATED"
    # A message whose sender checks failed is never labelled "authenticated", whatever its score
    if final_verdict.startswith("LEGITIMATE") and sender_assessment.get("level") in ("suspicious", "spoofed"):
        final_verdict = "SUSPICIOUS / UNVERIFIED ORIGIN"

    # Rebuild incident summary with updated score
    incident_summary = generate_incident_summary(
        verdict=final_verdict,
        overall_threat_score=overall_threat_score,
        metadata=metadata,
        auth=auth,
        origin=origin_intelligence,
        link_results=link_investigation,
        risk_factors=risk_factors,
        attribution=threat_attribution,
        analysis_complete=not analysis_errors
    )

    # =========================================================================
    # Step J: Build complete result schema
    # =========================================================================
    result = {
        "evidence_hash_sha256": evidence_hash,
        "evidence_hash": evidence_hash,
        "raw_size_bytes": forensics.get("raw_size_bytes", len(eml_bytes)),
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
            "dmarc_details": auth.get("dmarc_details", ""),
            "spf_state": spf_state,
            "dkim_state": auth.get("dkim_state", "pass" if dkim_pass else "fail"),
            "dmarc_state": dmarc_state,
            "dmarc_policy": auth.get("dmarc_policy"),
        },
        "sender_assessment": sender_assessment,
        "infrastructure": infrastructure,
        "links_total": links_total,
        "links_analyzed": links_analyzed,
        "links_skipped": links_skipped,
        "sender_domain_intelligence": mx_data,
        "origin_intelligence": origin_intelligence,
        "link_investigation": link_investigation,
        "nlp_analysis": nlp_analysis,
        "whois_intelligence": whois_intelligence,
        "attachment_analysis": attachment_analysis,
        "incident_summary": incident_summary,
        "analysis_errors": analysis_errors,
        "analysis_complete": not analysis_errors
    }

    # =========================================================================
    # Step K: Graph Correlation & Campaign Grouping (non-blocking)
    # =========================================================================
    if _GRAPH_AVAILABLE:
        try:
            graph_delta = ingest_analysis_to_graph(result)
            result["graph_delta"] = graph_delta
        except Exception as e:
            logger.warning(f"Graph correlation error: {e}")

    if _CAMPAIGN_MANAGER_AVAILABLE:
        try:
            campaign_info = get_case_manager().ingest_incident(result)
            result["campaign_info"] = campaign_info
        except Exception as e:
            logger.warning(f"Campaign manager error: {e}")

    return result



# Convenience alias
analyze_email_file = analyze_email_pipeline
