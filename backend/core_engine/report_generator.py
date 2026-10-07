"""
TrustShield - PDF Forensic Dossier Generator (report_generator.py)
Renders the Unified Forensic JSON dossier as a PDF incident report.

The report prints ONLY what the dossier says about evidence integrity (``dossier['integrity']``);
it never asserts that evidence is sealed, verified or admissible on its own. Every dynamic value is
XML-escaped before it reaches reportlab's Paragraph parser, so attacker-controlled headers (subject,
URLs, ...) cannot inject markup or crash the build.
"""

import io
import os
import re
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from xml.sax.saxutils import escape as _xml_escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Table,
    TableStyle,
    Spacer,
    KeepTogether,
    HRFlowable
)


_CTRL_RE = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')
_MAX_FIELD_CHARS = 1500


def _e(value: Any, max_len: int = _MAX_FIELD_CHARS) -> str:
    """Coerce to str, strip control characters, truncate, and XML-escape for Paragraph markup."""
    if value is None:
        text = ""
    elif isinstance(value, bytes):
        text = value.decode("utf-8", errors="replace")
    else:
        text = str(value)
    text = _CTRL_RE.sub("", text)
    if len(text) > max_len:
        text = text[:max_len] + "...[truncated]"
    return _xml_escape(text)


def _f(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


_INTEGRITY_STATUSES = ("VERIFIED", "UNVERIFIED", "NOT SEALED")


def _integrity_block(report_json: Dict[str, Any]) -> Dict[str, str]:
    """Normalises dossier['integrity'] to printable strings. Default: NOT SEALED."""
    raw = report_json.get("integrity")
    raw = raw if isinstance(raw, dict) else {}
    status = str(raw.get("status") or "NOT SEALED").upper()
    if status not in _INTEGRITY_STATUSES:
        status = "UNVERIFIED"
    return {
        "status": status,
        "signature": str(raw["signature"]) if raw.get("signature") else "None",
        "sealed_at": str(raw["sealed_at"]) if raw.get("sealed_at") else "N/A",
        "algorithm": str(raw.get("algorithm") or "HMAC-SHA256"),
    }


def _get_verdict_color(score: float) -> colors.Color:
    """Returns dynamic color based on incident threat severity."""
    if score >= 80.0:
        return colors.HexColor("#b91c1c")  # Deep Crimson Red
    elif score >= 50.0:
        return colors.HexColor("#b45309")  # Dark Amber
    else:
        return colors.HexColor("#047857")  # Forest Emerald


def generate_pdf_dossier(report_json: Dict[str, Any], output_path: str = "forensic_report.pdf") -> str:
    """
    Compiles the forensic PDF dossier from the analysis JSON and writes it to ``output_path``.

    Returns:
        Absolute path to the saved PDF file.
    """
    pdf_bytes = generate_pdf_dossier_bytes(report_json)
    abs_output_path = os.path.abspath(output_path)
    os.makedirs(os.path.dirname(abs_output_path) or ".", exist_ok=True)
    with open(abs_output_path, "wb") as fh:
        fh.write(pdf_bytes)
    return abs_output_path


def generate_pdf_dossier_bytes(report_json: Dict[str, Any]) -> bytes:
    """Compiles the forensic PDF dossier and returns it as bytes (no filesystem access)."""
    report_json = report_json if isinstance(report_json, dict) else {}
    buffer = io.BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        wordWrap='CJK',
        fontName='Helvetica-Bold',
        fontSize=17,
        leading=21,
        textColor=colors.HexColor("#0f172a")
    )
    
    meta_header_style = ParagraphStyle(
        'DocMetaHeader',
        parent=styles['Normal'],
        wordWrap='CJK',
        fontName='Helvetica',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#334155"),
        alignment=2
    )
    
    section_heading = ParagraphStyle(
        'SectionHeading',
        parent=styles['Normal'],
        wordWrap='CJK',
        fontName='Helvetica-Bold',
        fontSize=10.5,
        leading=14,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=8,
        spaceAfter=3
    )

    th_style = ParagraphStyle(
        'TableHead',
        parent=styles['Normal'],
        wordWrap='CJK',
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=10,
        textColor=colors.white
    )

    cell_bold = ParagraphStyle(
        'CellBold',
        parent=styles['Normal'],
        wordWrap='CJK',
        fontName='Helvetica-Bold',
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor("#1e293b")
    )

    cell_normal = ParagraphStyle(
        'CellNormal',
        parent=styles['Normal'],
        wordWrap='CJK',
        fontName='Helvetica',
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor("#334155")
    )

    cell_mono = ParagraphStyle(
        'CellMono',
        parent=styles['Normal'],
        wordWrap='CJK',
        fontName='Courier',
        fontSize=7,
        leading=9,
        textColor=colors.HexColor("#0f172a")
    )

    summary_text = ParagraphStyle(
        'SummaryText',
        parent=styles['Normal'],
        wordWrap='CJK',
        fontName='Helvetica',
        fontSize=8,
        leading=12,
        textColor=colors.HexColor("#1e293b")
    )

    cert_text = ParagraphStyle(
        'CertText',
        parent=styles['Normal'],
        wordWrap='CJK',
        fontName='Helvetica-Oblique',
        fontSize=7.5,
        leading=11,
        textColor=colors.HexColor("#334155")
    )

    story = []

    # =========================================================================
    # 1. Header Banner & Institutional Identification
    # =========================================================================
    now_utc = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    evidence_hash = str(report_json.get("evidence_hash_sha256") or report_json.get("evidence_hash") or "UNKNOWN")
    case_ref = f"TSF-{evidence_hash[:8].upper()}" if evidence_hash != "UNKNOWN" else "TSF-EVIDENCE"
    integrity = _integrity_block(report_json)
    integrity_color = {"VERIFIED": "#047857", "UNVERIFIED": "#b45309"}.get(integrity["status"], "#b91c1c")

    header_data = [
        [
            Paragraph("<b>TRUSTSHIELD DIGITAL FORENSICS</b><br/><font size='10' color='#2563eb'><b>EMAIL INCIDENT DOSSIER</b></font>", title_style),
            Paragraph(f"<b>Record ID:</b> {_e(case_ref)}<br/><b>Generated:</b> {_e(now_utc)}<br/><b>Evidence integrity:</b> {_e(integrity['status'])}", meta_header_style)
        ]
    ]
    header_table = Table(header_data, colWidths=[350, 190])
    header_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
    ]))
    story.append(header_table)
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0f172a"), spaceBefore=3, spaceAfter=6))

    # Evidence hash & integrity status (rendered exactly from the dossier)
    evidence_banner = [
        [
            Paragraph("<b>EVIDENCE HASH (SHA-256 of uploaded bytes):</b>", cell_bold),
            Paragraph(_e(evidence_hash), cell_mono),
            Paragraph(f"<font color='{integrity_color}'><b>[{_e(integrity['status'])}]</b></font>", ParagraphStyle('SealStat', fontName='Helvetica-Bold', fontSize=7, leading=9, alignment=2, wordWrap='CJK'))
        ]
    ]
    hash_table = Table(evidence_banner, colWidths=[160, 280, 100])
    hash_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(hash_table)
    story.append(Spacer(1, 6))

    # =========================================================================
    # 2. Executive Incident Verdict & Attribution
    # =========================================================================
    overall_score = _f(report_json.get("overall_threat_score", 0.0))
    verdict = report_json.get("verdict", "UNKNOWN")
    threat_attr = report_json.get("threat_attribution") or {}
    attr_type = threat_attr.get("type", "UNKNOWN")
    attr_confidence = threat_attr.get("confidence", "UNKNOWN")
    attr_details = threat_attr.get("details", "")
    analysis_complete = report_json.get("analysis_complete", True)

    verdict_color = _get_verdict_color(overall_score)
    origin_intel = report_json.get('origin_intelligence') or {}
    origin_ip = origin_intel.get('originating_ip', 'N/A')
    is_anon = origin_intel.get('is_anonymized_node', False)
    infra_type = "Anonymized Node (Tor / Proxy / VPN)" if is_anon else "Direct Autonomous System Transit"
    
    exec_data = [
        [
            Paragraph(f"<font color='white'><b>EXECUTIVE VERDICT: {_e(verdict)}{'' if analysis_complete else ' (ANALYSIS INCOMPLETE)'}</b></font>", ParagraphStyle('V', fontName='Helvetica-Bold', fontSize=10.5, leading=13, wordWrap='CJK')),
            Paragraph(f"<font color='white'><b>FRAUD RISK SCORE: {overall_score:.1f} / 100</b></font>", ParagraphStyle('S', fontName='Helvetica-Bold', fontSize=10.5, leading=13, alignment=2, wordWrap='CJK'))
        ],
        [
            Paragraph(
                f"<b>Threat Classification:</b> {_e(attr_type)} &nbsp;|&nbsp; <b>Confidence:</b> {_e(attr_confidence)}<br/>"
                f"<b>Attribution Finding:</b> {_e(attr_details)}",
                cell_normal
            ),
            Paragraph(
                f"<b>Originating IP:</b> {_e(origin_ip)}<br/>"
                f"<b>Infrastructure:</b> {_e(infra_type)}",
                cell_normal
            )
        ]
    ]
    exec_table = Table(exec_data, colWidths=[340, 200])
    exec_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (1, 0), verdict_color),
        ('BACKGROUND', (0, 1), (1, 1), colors.HexColor("#f8fafc")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0, 1), (1, 1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(exec_table)
    story.append(Spacer(1, 6))

    # =========================================================================
    # 3. Message Envelope Metadata
    # =========================================================================
    meta = report_json.get("metadata") or {}
    story.append(Paragraph("1. RFC-5322 Technical Message Envelope", section_heading))
    
    reply_to_mismatch = meta.get("reply_to_mismatch", False)
    reply_to_flag = " <font color='#b91c1c'><b>[CRITICAL: BEC MISMATCH DETECTED]</b></font>" if reply_to_mismatch else ""

    meta_table_data = [
        [Paragraph("<b>Subject:</b>", cell_bold), Paragraph(_e(meta.get("subject", "N/A")), cell_normal)],
        [Paragraph("<b>From (Visible):</b>", cell_bold), Paragraph(_e(meta.get("from", "N/A")), cell_normal)],
        [Paragraph("<b>Reply-To:</b>", cell_bold), Paragraph(f"{_e(meta.get('reply_to', 'None'))}{reply_to_flag}", cell_normal)],
        [Paragraph("<b>Return-Path:</b>", cell_bold), Paragraph(_e(meta.get("return_path", "N/A")), cell_normal)],
        [Paragraph("<b>Recipient (To):</b>", cell_bold), Paragraph(_e(meta.get("to", "N/A")), cell_normal)],
        [Paragraph("<b>Transmission Date:</b>", cell_bold), Paragraph(_e(meta.get("date", "N/A")), cell_normal)],
        [Paragraph("<b>Message-ID:</b>", cell_bold), Paragraph(_e(meta.get("message_id", "N/A")), cell_mono)]
    ]
    meta_table = Table(meta_table_data, colWidths=[95, 445])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor("#f8fafc")),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 6))

    # =========================================================================
    # 4. Authentication & Domain Infrastructure (SPF, DKIM, DMARC, MX)
    # =========================================================================
    auth = report_json.get("authentication") or {}
    mx_data = report_json.get("sender_domain_intelligence") or {}
    
    story.append(Paragraph("2. Identity & Protocol Authentication Audit", section_heading))

    def _fmt_pass_fail(status: bool, state: Optional[str] = None) -> str:
        if state == "indeterminate":
            return "<font color='#b45309'><b>INDETERMINATE</b></font>"
        return "<font color='#047857'><b>PASS</b></font>" if status else "<font color='#b91c1c'><b>FAIL / REJECT</b></font>"

    auth_table_data = [
        [
            Paragraph("Protocol Specification", th_style),
            Paragraph("Verification Status", th_style),
            Paragraph("Forensic Telemetry & Alignment Evaluation", th_style)
        ],
        [
            Paragraph("<b>SPF</b> (Sender Policy Framework)", cell_normal),
            Paragraph(_fmt_pass_fail(auth.get("spf_pass", False), auth.get("spf_state")), cell_normal),
            Paragraph(_e(auth.get("spf_details", "No SPF record found on sending domain")), cell_normal)
        ],
        [
            Paragraph("<b>DKIM</b> (DomainKeys Identified Mail)", cell_normal),
            Paragraph(_fmt_pass_fail(auth.get("dkim_pass", False), auth.get("dkim_state")), cell_normal),
            Paragraph(_e(auth.get("dkim_details", "No cryptographic DKIM signature present")), cell_normal)
        ],
        [
            Paragraph("<b>DMARC</b> (Domain-based Alignment)", cell_normal),
            Paragraph(_fmt_pass_fail(auth.get("dmarc_pass", False), auth.get("dmarc_state")), cell_normal),
            Paragraph(_e(auth.get("dmarc_details", "DMARC policy failed alignment checks")), cell_normal)
        ],
        [
            Paragraph("<b>MX Infrastructure</b>", cell_normal),
            Paragraph(_fmt_pass_fail(mx_data.get("has_mx_records", False)), cell_normal),
            Paragraph(
                f"Domain: {_e(mx_data.get('from_domain', 'N/A'))} | Primary MX: {_e(mx_data.get('primary_mx') or 'None (Burner/Unroutable)')}",
                cell_normal
            )
        ]
    ]
    auth_table = Table(auth_table_data, colWidths=[130, 85, 325])
    auth_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ('TOPPADDING', (0, 0), (-1, -1), 3.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3.5),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(auth_table)
    story.append(Spacer(1, 6))

    # =========================================================================
    # 5. Mail Routing & Hop Tracing Table
    # =========================================================================
    route_map = origin_intel.get("route_map") or []
    story.append(Paragraph("3. Mail Transmission Hop Tracing & Infrastructure Geolocation", section_heading))

    hop_headers = [
        Paragraph("Hop #", th_style),
        Paragraph("Node IP Address", th_style),
        Paragraph("Physical Geolocation", th_style),
        Paragraph("ISP / Autonomous System (ASN)", th_style),
        Paragraph("Security Assessment", th_style)
    ]
    hop_rows = [hop_headers]

    for hop in route_map:
        is_susp = hop.get("is_suspicious_proxy", False) or hop.get("is_proxy", False)
        proxy_badge = "<font color='#b91c1c'><b>ANONYMIZED PROXY</b></font>" if is_susp else "<font color='#047857'>CLEAN TRANSIT</font>"
        
        loc_str = f"{_e(hop.get('city', 'Unknown'))}, {_e(hop.get('country', 'Unknown'))}"
        lat, lon = _f(hop.get("lat")), _f(hop.get("lon"))
        if lat != 0.0 or lon != 0.0:
            loc_str += f" ({lat:.2f}, {lon:.2f})"

        hop_rows.append([
            Paragraph(_e(hop.get("hop_number", "-")), cell_normal),
            Paragraph(_e(hop.get("ip", "Unknown")), cell_mono),
            Paragraph(loc_str, cell_normal),
            Paragraph(f"{_e(hop.get('isp', 'Unknown'))} ({_e(hop.get('asn', 'N/A'))})", cell_normal),
            Paragraph(proxy_badge, cell_normal)
        ])

    if len(hop_rows) == 1:
        hop_rows.append([
            Paragraph("-", cell_normal),
            Paragraph("No external intermediate hops parsed", cell_normal),
            Paragraph("-", cell_normal),
            Paragraph("-", cell_normal),
            Paragraph("-", cell_normal)
        ])

    hop_table = Table(hop_rows, colWidths=[38, 95, 140, 167, 100])
    hop_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ('TOPPADDING', (0, 0), (-1, -1), 3.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3.5),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(hop_table)
    story.append(Spacer(1, 6))

    # =========================================================================
    # 6. Embedded Link Sandbox Detonation Summary
    # =========================================================================
    links = report_json.get("link_investigation") or []
    story.append(Paragraph("4. Payload Hyperlink Investigation & Sandbox Detonation", section_heading))

    link_headers = [
        Paragraph("Target URL Exhibit", th_style),
        Paragraph("Threat Score", th_style),
        Paragraph("Detonation Verdict", th_style),
        Paragraph("Exfiltration & Evasion Telemetry", th_style)
    ]
    link_rows = [link_headers]

    for link in links:
        score = _f(link.get("threat_score", 0.0))
        score_color = "#b91c1c" if score >= 80.0 else ("#b45309" if score >= 50.0 else "#047857")
        telemetry = link.get("telemetry") or {}
        
        signatures = []
        if telemetry.get("known_db_match"):
            signatures.append("Known Threat Intelligence Match")
        if telemetry.get("sandbox_has_password"):
            signatures.append("Credential Interceptor Form")
        if telemetry.get("brand_impersonation"):
            brand = telemetry.get("detected_brand", "Unknown")
            signatures.append(f"Brand Impersonation: {_e(brand)}")
        if telemetry.get("suspicious_exfiltration"):
            signatures.append("Malicious Form Action Exfiltration")
        if not signatures:
            signatures.append("Standard Non-Malicious Structure")

        link_rows.append([
            Paragraph(_e(link.get('url', ''), 600), cell_mono),
            Paragraph(f"<font color='{score_color}'><b>{score:.1f} / 100</b></font>", cell_normal),
            Paragraph(_e(link.get("verdict", "UNKNOWN")), cell_normal),
            Paragraph(", ".join(signatures), cell_normal)
        ])

    if len(link_rows) == 1:
        link_rows.append([
            Paragraph("No embedded hyperlinks detected in evidence", cell_normal),
            Paragraph("0.0 / 100", cell_normal),
            Paragraph("CLEAN", cell_normal),
            Paragraph("No payload exhibits extracted", cell_normal)
        ])

    link_table = Table(link_rows, colWidths=[190, 75, 125, 150])
    link_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ('TOPPADDING', (0, 0), (-1, -1), 3.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3.5),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(link_table)
    story.append(Spacer(1, 6))

    # =========================================================================
    # 7. Forensic Incident Narrative & Recommended Containment
    # =========================================================================
    story.append(Paragraph("5. Forensic Narrative & Technical Findings", section_heading))
    incident_narrative = str(report_json.get("incident_summary") or "No technical summary recorded.")
    if not analysis_complete:
        errs = report_json.get("analysis_errors") or []
        incident_narrative += "\n- ANALYSIS INCOMPLETE: " + "; ".join(str(x) for x in errs[:8])
    
    narrative_rows = []
    for line in incident_narrative.split("\n"):
        clean_line = line.strip()
        if clean_line:
            narrative_rows.append([Paragraph(_e(clean_line, 3000), summary_text)])

    if not narrative_rows:
        narrative_rows.append([Paragraph("No narrative generated.", summary_text)])

    narrative_table = Table(narrative_rows, colWidths=[540])
    narrative_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0, 0), (-1, -1), 4.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4.5),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(narrative_table)
    story.append(Spacer(1, 8))

    # =========================================================================
    # 8. Evidence Handling Notes (rendered from dossier['integrity'])
    # =========================================================================
    cert_heading = Paragraph("6. Evidence Handling Notes", section_heading)
    cert_body = Paragraph(
        "<i>This report was generated automatically by TrustShield. The SHA-256 above was computed over the "
        "bytes of the uploaded message. Whether this record has been sealed or independently verified is "
        "stated below exactly as recorded in the dossier. Use of this report as evidence in any proceeding "
        "may require a separate certificate from a responsible person under applicable law; this document "
        "does not itself constitute such a certificate.</i>",
        cert_text
    )

    sign_data = [
        [
            Paragraph("<b>Generated by:</b><br/>TrustShield automated forensic pipeline", cell_normal),
            Paragraph(
                f"<b>Generated:</b> {_e(now_utc)}<br/>"
                f"<b>Integrity status:</b> {_e(integrity['status'])}<br/>"
                f"<b>Algorithm:</b> {_e(integrity['algorithm'])}<br/>"
                f"<b>Sealed at:</b> {_e(integrity['sealed_at'])}<br/>"
                f"<b>Signature:</b> {_e(integrity['signature'], 200)}",
                cell_normal)
        ]
    ]
    sign_table = Table(sign_data, colWidths=[270, 270])
    sign_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
    ]))

    story.append(KeepTogether([
        cert_heading,
        cert_body,
        Spacer(1, 4),
        sign_table
    ]))

    # Build Document
    doc.build(story)
    return buffer.getvalue()

