"""
TrustShield V2 - BEC & NLP Email Body Analyser (bec_nlp_analyser.py)
Performs rule-based + lightweight ML NLP analysis of email subject and body text to:
  - Detect Business Email Compromise (BEC) patterns: payment diversion, executive
    impersonation, fake invoice requests, credential harvesting intent.
  - Classify emails into a 5-class taxonomy required by SIH26106:
      LEGITIMATE | SUSPICIOUS | IMPERSONATED | PHISHING | BEC_FRAUD
  - Produce urgency-cue detection, social engineering pattern matching.
  - Return a structured NLP risk assessment with confidence and matched evidence.

Design: Works in ZERO-dependency mode (pure Python regex + keyword heuristics)
as primary engine. Optionally uses the pre-trained HuggingFace BERT phishing
classifier from ml_engine.py if available.
"""

import re
import logging
from typing import Dict, Any, List, Tuple

logger = logging.getLogger(__name__)

# ============================================================================
# PATTERN LIBRARIES
# ============================================================================

# BEC: Payment Diversion / Finance Fraud
BEC_PAYMENT_PATTERNS = [
    r"wire\s+transfer", r"urgent\s+payment", r"change\s+(of\s+)?bank\s+(account|details)",
    r"update\s+(your\s+)?payment\s+(information|details|method)",
    r"new\s+bank\s+account", r"direct\s+deposit\s+change",
    r"vendor\s+payment", r"invoice\s+due", r"outstanding\s+invoice",
    r"pay\s+immediately", r"transfer\s+funds", r"remittance\s+advice",
    r"ACH\s+transfer", r"RTGS\s+transfer", r"NEFT\s+payment",
]

# BEC: Executive Impersonation
BEC_EXEC_IMPERSONATION_PATTERNS = [
    r"(ceo|cfo|coo|director|president|md|managing\s+director)\s+(is\s+)?(asking|request(ing)?|needs?|want)",
    r"on\s+behalf\s+of\s+(the\s+)?(ceo|cfo|director|president|management)",
    r"confidential\s+(request|task|matter)",
    r"do\s+not\s+(discuss|share|mention)\s+this",
    r"this\s+is\s+(urgent|confidential|top.?priority)",
    r"i\s+(need|want)\s+you\s+to\s+(process|handle|complete)\s+(this\s+)?immediately",
]

# BEC: Fake Invoice / Vendor Fraud
BEC_INVOICE_PATTERNS = [
    r"attached\s+(is\s+)?(the\s+)?(invoice|receipt|bill|purchase\s+order)",
    r"invoice\s+#?\d+", r"payment\s+receipt", r"overdue\s+(payment|invoice|balance)",
    r"final\s+(notice|reminder)\s+(for\s+)?payment",
    r"please\s+(process|approve|authorize)\s+(the\s+)?(payment|invoice|transfer)",
]

# Credential Harvesting / Phishing
CREDENTIAL_HARVESTING_PATTERNS = [
    r"verify\s+(your\s+)?(account|identity|email|password|login)",
    r"confirm\s+(your\s+)?(account|identity|details|information)",
    r"(click|tap)\s+(here|the\s+link)\s+to\s+(verify|confirm|login|sign\s*in|reset)",
    r"your\s+account\s+(has\s+been\s+)?(suspended|locked|compromised|hacked|breached)",
    r"unauthorized\s+(access|login|activity)\s+(detected|found|identified)",
    r"reset\s+your\s+password", r"re-?verify\s+your\s+(account|email)",
    r"account\s+will\s+be\s+(terminated|deleted|suspended|closed)",
    r"security\s+(alert|warning|notification|breach)",
]

# Social Engineering: Urgency & Fear
URGENCY_PATTERNS = [
    r"\burgent\b", r"\bimmediately\b", r"\bact\s+now\b", r"\btime.?sensitive\b",
    r"\bexpires?\s+(in|within)\s+\d+\s+(hour|minute|day|hr|min)",
    r"\b24\s+hours?\b", r"\b48\s+hours?\b", r"\btoday\s+only\b",
    r"\bfinal\s+(warning|notice|reminder)\b", r"\blast\s+(chance|opportunity|notice)\b",
    r"\bdo\s+not\s+ignore\b", r"\bimmediate\s+(action|response|attention)\s+(required|needed)\b",
]

# Impersonation: Claiming to be a trusted brand/entity
IMPERSONATION_PATTERNS = [
    r"(your\s+)?(apple|google|microsoft|amazon|paypal|netflix|bank|linkedin|facebook|instagram|whatsapp|twitter)\s+(account|team|security|support)",
    r"(from\s+)?(apple|google|microsoft|amazon|paypal|netflix)\s+(inc|corp|ltd|team)",
    r"(noreply|no-reply|security|support|admin|helpdesk)@",
    r"this\s+(email|message)\s+is\s+from\s+\w+\s+(team|security|support|department)",
]

# Display-name spoofing markers
DISPLAY_NAME_SPOOFING_PATTERNS = [
    r"your\s+(it|security|hr|finance|payroll)\s+(department|team|manager)",
    r"(dear\s+)?(customer|user|member|client|valued\s+customer)",
    r"from\s+the\s+desk\s+of",
]

# ============================================================================
# TAXONOMY
# ============================================================================

EMAIL_CLASSES = {
    "LEGITIMATE": {
        "description": "Email appears to be a normal, benign communication.",
        "color": "green",
        "severity": 0
    },
    "SUSPICIOUS": {
        "description": "Email shows some anomalous patterns but cannot be definitively classified.",
        "color": "yellow",
        "severity": 1
    },
    "IMPERSONATED": {
        "description": "Email appears to impersonate a trusted brand, executive, or institution.",
        "color": "orange",
        "severity": 2
    },
    "PHISHING": {
        "description": "Email is designed to steal credentials or personal data via deceptive links or forms.",
        "color": "red",
        "severity": 3
    },
    "BEC_FRAUD": {
        "description": "Business Email Compromise: email attempts payment diversion, executive impersonation, or invoice fraud.",
        "color": "darkred",
        "severity": 4
    }
}


def _count_pattern_matches(text: str, patterns: List[str]) -> Tuple[int, List[str]]:
    """Count how many regex patterns match in text and return matched evidence snippets."""
    matches = []
    for pattern in patterns:
        found = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        if found:
            # Return the matched snippet (max 60 chars) as evidence
            snippet = found.group(0)[:60].strip()
            matches.append(snippet)
    return len(matches), matches


def analyse_email_body(subject: str, body: str, sender_display_name: str = "") -> Dict[str, Any]:
    """
    Main NLP analysis function. Performs 5-class taxonomy classification of the email.

    Args:
        subject: Email subject line
        body: Plain text email body
        sender_display_name: The display name portion of the From: header

    Returns:
        {
          "nlp_class": str (one of 5 taxonomy classes),
          "nlp_risk_score": float (0–100),
          "confidence": float (0–100),
          "evidence": list[str],
          "bec_indicators": dict,
          "phishing_indicators": dict,
          "urgency_score": float (0–100),
          "social_engineering_summary": str,
          "taxonomy_description": str
        }
    """
    combined = f"Subject: {subject or ''}\n\nBody: {body or ''}\n\nSender: {sender_display_name or ''}".lower()

    evidence: List[str] = []
    risk_score = 0.0
    bec_indicators = {}
    phishing_indicators = {}

    # ------------------------------------------------------------------
    # BEC Detection
    # ------------------------------------------------------------------
    bec_payment_count, bec_payment_matches = _count_pattern_matches(combined, BEC_PAYMENT_PATTERNS)
    bec_exec_count, bec_exec_matches = _count_pattern_matches(combined, BEC_EXEC_IMPERSONATION_PATTERNS)
    bec_invoice_count, bec_invoice_matches = _count_pattern_matches(combined, BEC_INVOICE_PATTERNS)

    bec_total = bec_payment_count + bec_exec_count + bec_invoice_count
    bec_risk = min(100.0, bec_total * 25.0)

    bec_indicators = {
        "payment_diversion_signals": bec_payment_count,
        "payment_evidence": bec_payment_matches[:3],
        "executive_impersonation_signals": bec_exec_count,
        "exec_evidence": bec_exec_matches[:2],
        "fake_invoice_signals": bec_invoice_count,
        "invoice_evidence": bec_invoice_matches[:2],
        "bec_risk_score": round(bec_risk, 1)
    }

    if bec_payment_count > 0:
        evidence.append(f"BEC Payment Diversion: '{bec_payment_matches[0]}'")
    if bec_exec_count > 0:
        evidence.append(f"BEC Executive Impersonation: '{bec_exec_matches[0]}'")
    if bec_invoice_count > 0:
        evidence.append(f"BEC Fake Invoice: '{bec_invoice_matches[0]}'")

    # ------------------------------------------------------------------
    # Credential Harvesting / Phishing Detection
    # ------------------------------------------------------------------
    cred_count, cred_matches = _count_pattern_matches(combined, CREDENTIAL_HARVESTING_PATTERNS)
    impersonate_count, impersonate_matches = _count_pattern_matches(combined, IMPERSONATION_PATTERNS)
    display_spoof_count, display_spoof_matches = _count_pattern_matches(combined, DISPLAY_NAME_SPOOFING_PATTERNS)

    phish_risk = min(100.0, (cred_count * 30.0) + (impersonate_count * 20.0) + (display_spoof_count * 10.0))

    phishing_indicators = {
        "credential_harvesting_signals": cred_count,
        "credential_evidence": cred_matches[:3],
        "impersonation_signals": impersonate_count,
        "impersonation_evidence": impersonate_matches[:2],
        "display_name_spoof_signals": display_spoof_count,
        "phishing_risk_score": round(phish_risk, 1)
    }

    if cred_count > 0:
        evidence.append(f"Credential Harvesting: '{cred_matches[0]}'")
    if impersonate_count > 0:
        evidence.append(f"Brand Impersonation: '{impersonate_matches[0]}'")

    # ------------------------------------------------------------------
    # Urgency / Social Engineering
    # ------------------------------------------------------------------
    urgency_count, urgency_matches = _count_pattern_matches(combined, URGENCY_PATTERNS)
    urgency_score = min(100.0, urgency_count * 20.0)
    if urgency_count > 0:
        evidence.append(f"Urgency Cue: '{urgency_matches[0]}'")

    # ------------------------------------------------------------------
    # 5-Class Taxonomy Classification
    # ------------------------------------------------------------------
    nlp_class = "LEGITIMATE"

    # Priority order: BEC > PHISHING > IMPERSONATED > SUSPICIOUS > LEGITIMATE
    if bec_total >= 2 or (bec_total >= 1 and urgency_count >= 1):
        nlp_class = "BEC_FRAUD"
        risk_score = max(bec_risk, 75.0)
    elif cred_count >= 2 or (cred_count >= 1 and urgency_count >= 1):
        nlp_class = "PHISHING"
        risk_score = max(phish_risk, 70.0)
    elif impersonate_count >= 2 or (impersonate_count >= 1 and (cred_count >= 1 or urgency_count >= 1)):
        nlp_class = "IMPERSONATED"
        risk_score = max(phish_risk, 55.0)
    elif bec_total >= 1 or cred_count >= 1 or impersonate_count >= 1 or urgency_count >= 2:
        nlp_class = "SUSPICIOUS"
        risk_score = max(bec_risk, phish_risk, urgency_score * 0.5, 30.0)
    else:
        nlp_class = "LEGITIMATE"
        risk_score = min(20.0, urgency_score * 0.2)

    # Confidence: higher when more signals are found
    total_signals = bec_total + cred_count + impersonate_count + urgency_count
    if total_signals == 0:
        confidence = 80.0  # High confidence in LEGITIMATE verdict
    elif total_signals >= 4:
        confidence = 95.0
    elif total_signals >= 2:
        confidence = 88.0
    else:
        confidence = 75.0

    # Social engineering summary
    summary_parts = []
    if bec_total > 0:
        summary_parts.append(f"BEC patterns detected ({bec_total} signal{'s' if bec_total > 1 else ''})")
    if cred_count > 0:
        summary_parts.append(f"credential harvesting cues ({cred_count})")
    if urgency_count > 0:
        summary_parts.append(f"urgency language ({urgency_count} instance{'s' if urgency_count > 1 else ''})")
    if impersonate_count > 0:
        summary_parts.append(f"brand/entity impersonation ({impersonate_count})")

    social_engineering_summary = (
        "Detected: " + "; ".join(summary_parts) + "."
        if summary_parts
        else "No social engineering patterns detected."
    )

    return {
        "nlp_class": nlp_class,
        "nlp_risk_score": round(min(100.0, risk_score), 1),
        "confidence": round(confidence, 1),
        "evidence": evidence[:8],  # Top 8 evidence snippets
        "bec_indicators": bec_indicators,
        "phishing_indicators": phishing_indicators,
        "urgency_score": round(urgency_score, 1),
        "urgency_signals": urgency_count,
        "social_engineering_summary": social_engineering_summary,
        "taxonomy_description": EMAIL_CLASSES[nlp_class]["description"],
        "taxonomy_severity": EMAIL_CLASSES[nlp_class]["severity"],
        "taxonomy_color": EMAIL_CLASSES[nlp_class]["color"]
    }


def analyse_eml_for_bec(forensics_payload: Dict[str, Any], metadata: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convenience wrapper that reads body/subject from a forensics result dict
    and runs the NLP analyser. Returns the NLP result dict ready for inclusion
    in the unified pipeline output.
    """
    subject = metadata.get("subject", "")
    from_header = metadata.get("from", "")
    body = forensics_payload.get("body_text", "")

    # Extract display name from From header: "Display Name <email@domain.com>"
    display_name_match = re.match(r'^(.+?)\s*<', from_header)
    display_name = display_name_match.group(1).strip() if display_name_match else ""

    return analyse_email_body(subject=subject, body=body, sender_display_name=display_name)
