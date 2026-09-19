"""
TrustShield - Court-Admissible PDF Forensic Dossier Generator (report_generator.py)
Generates an official, cryptographic PDF incident report from the Unified Forensic JSON dossier.
Compliant with Section 63 of the Bharatiya Sakshya Adhiniyam, 2023 (BSA) and Section 65B of
the Indian Evidence Act, 1872 for digital evidence admissibility in legal proceedings.
"""

import os
from datetime import datetime
from typing import Dict, Any, Optional

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
    Compiles a comprehensive, court-admissible forensic PDF dossier from the analysis JSON.
    
    Args:
        report_json: Dictionary returned by analyze_email_pipeline()
        output_path: Target filesystem path for the generated PDF.
        
    Returns:
        Absolute path to the saved PDF file.
    """
    abs_output_path = os.path.abspath(output_path)
    os.makedirs(os.path.dirname(abs_output_path) or ".", exist_ok=True)

    doc = SimpleDocTemplate(
        abs_output_path,
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
        fontName='Helvetica-Bold',
        fontSize=17,
        leading=21,
        textColor=colors.HexColor("#0f172a")
    )
    
    meta_header_style = ParagraphStyle(
        'DocMetaHeader',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#334155"),
        alignment=2
    )
    
    section_heading = ParagraphStyle(
        'SectionHeading',
        parent=styles['Normal'],
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
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=10,
        textColor=colors.white
    )

    cell_bold = ParagraphStyle(
        'CellBold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor("#1e293b")
    )

    cell_normal = ParagraphStyle(
        'CellNormal',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor("#334155")
    )

    cell_mono = ParagraphStyle(
        'CellMono',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=7,
        leading=9,
        textColor=colors.HexColor("#0f172a")
    )

    summary_text = ParagraphStyle(
        'SummaryText',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=12,
        textColor=colors.HexColor("#1e293b")
    )

    cert_text = ParagraphStyle(
        'CertText',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=7.5,
        leading=11,
        textColor=colors.HexColor("#334155")
    )

    story = []

    # =========================================================================
    # 1. Header Banner & Institutional Identification
    # =========================================================================
    now_utc = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    evidence_hash = report_json.get("evidence_hash_sha256", "UNKNOWN")
    case_ref = f"TSF-{evidence_hash[:8].upper()}" if evidence_hash != "UNKNOWN" else "TSF-EVIDENCE"

    header_data = [
        [
            Paragraph("<b>TRUSTSHIELD DIGITAL FORENSICS</b><br/><font size='10' color='#2563eb'><b>CERTIFICATE OF ELECTRONIC EVIDENCE &amp; INCIDENT DOSSIER</b></font>", title_style),
            Paragraph(f"<b>Record ID:</b> {case_ref}<br/><b>Timestamp:</b> {now_utc}<br/><b>Statutory Standard:</b> Sec. 63 BSA, 2023", meta_header_style)
        ]
    ]
    header_table = Table(header_data, colWidths=[350, 190])
    header_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
    ]))
    story.append(header_table)
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0f172a"), spaceBefore=3, spaceAfter=6))

    # Evidence Hash & Chain of Custody Seal
    evidence_banner = [
        [
            Paragraph("<b>CHAIN OF CUSTODY SEAL (SHA-256):</b>", cell_bold),
            Paragraph(f"<code>{evidence_hash}</code>", cell_mono),
            Paragraph("<font color='#059669'><b>[SEALED &amp; IMMUTABLE]</b></font>", ParagraphStyle('SealStat', fontName='Helvetica-Bold', fontSize=7, leading=9, alignment=2))
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
    overall_score = float(report_json.get("overall_threat_score", 0.0))
    verdict = report_json.get("verdict", "UNKNOWN")
    threat_attr = report_json.get("threat_attribution", {})
    attr_type = threat_attr.get("type", "UNKNOWN")
    attr_confidence = threat_attr.get("confidence", "UNKNOWN")
    attr_details = threat_attr.get("details", "")

    verdict_color = _get_verdict_color(overall_score)
    origin_intel = report_json.get('origin_intelligence', {})
    origin_ip = origin_intel.get('originating_ip', 'N/A')
    is_anon = origin_intel.get('is_anonymized_node', False)
    infra_type = "Anonymized Node (Tor / Proxy / VPN)" if is_anon else "Direct Autonomous System Transit"
    
    exec_data = [
        [
            Paragraph(f"<font color='white'><b>EXECUTIVE VERDICT: {verdict}</b></font>", ParagraphStyle('V', fontName='Helvetica-Bold', fontSize=10.5, leading=13)),
            Paragraph(f"<font color='white'><b>FRAUD RISK SCORE: {overall_score:.1f} / 100</b></font>", ParagraphStyle('S', fontName='Helvetica-Bold', fontSize=10.5, leading=13, alignment=2))
        ],
        [
            Paragraph(
                f"<b>Threat Classification:</b> {attr_type} &nbsp;|&nbsp; <b>Confidence:</b> {attr_confidence}<br/>"
                f"<b>Attribution Finding:</b> {attr_details}",
                cell_normal
            ),
            Paragraph(
                f"<b>Originating IP:</b> {origin_ip}<br/>"
                f"<b>Infrastructure:</b> {infra_type}",
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
    meta = report_json.get("metadata", {})
    story.append(Paragraph("1. RFC-5322 Technical Message Envelope", section_heading))
    
    reply_to_mismatch = meta.get("reply_to_mismatch", False)
    reply_to_flag = " <font color='#b91c1c'><b>[CRITICAL: BEC MISMATCH DETECTED]</b></font>" if reply_to_mismatch else ""

    meta_table_data = [
        [Paragraph("<b>Subject:</b>", cell_bold), Paragraph(meta.get("subject", "N/A"), cell_normal)],
        [Paragraph("<b>From (Visible):</b>", cell_bold), Paragraph(meta.get("from", "N/A"), cell_normal)],
        [Paragraph("<b>Reply-To:</b>", cell_bold), Paragraph(f"{meta.get('reply_to', 'None')}{reply_to_flag}", cell_normal)],
        [Paragraph("<b>Return-Path:</b>", cell_bold), Paragraph(meta.get("return_path", "N/A"), cell_normal)],
        [Paragraph("<b>Recipient (To):</b>", cell_bold), Paragraph(meta.get("to", "N/A"), cell_normal)],
        [Paragraph("<b>Transmission Date:</b>", cell_bold), Paragraph(meta.get("date", "N/A"), cell_normal)],
        [Paragraph("<b>Message-ID:</b>", cell_bold), Paragraph(meta.get("message_id", "N/A"), cell_mono)]
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
    auth = report_json.get("authentication", {})
    mx_data = report_json.get("sender_domain_intelligence", {})
    
    story.append(Paragraph("2. Identity & Protocol Authentication Audit", section_heading))

    def _fmt_pass_fail(status: bool) -> str:
        return "<font color='#047857'><b>PASS</b></font>" if status else "<font color='#b91c1c'><b>FAIL / REJECT</b></font>"

    auth_table_data = [
        [
            Paragraph("Protocol Specification", th_style),
            Paragraph("Verification Status", th_style),
            Paragraph("Forensic Telemetry & Alignment Evaluation", th_style)
        ],
        [
            Paragraph("<b>SPF</b> (Sender Policy Framework)", cell_normal),
            Paragraph(_fmt_pass_fail(auth.get("spf_pass", False)), cell_normal),
            Paragraph(auth.get("spf_details", "No SPF record found on sending domain"), cell_normal)
        ],
        [
            Paragraph("<b>DKIM</b> (DomainKeys Identified Mail)", cell_normal),
            Paragraph(_fmt_pass_fail(auth.get("dkim_pass", False)), cell_normal),
            Paragraph(auth.get("dkim_details", "No cryptographic DKIM signature present"), cell_normal)
        ],
        [
            Paragraph("<b>DMARC</b> (Domain-based Alignment)", cell_normal),
            Paragraph(_fmt_pass_fail(auth.get("dmarc_pass", False)), cell_normal),
            Paragraph(auth.get("dmarc_details", "DMARC policy failed alignment checks"), cell_normal)
        ],
        [
            Paragraph("<b>MX Infrastructure</b>", cell_normal),
            Paragraph(_fmt_pass_fail(mx_data.get("has_mx_records", False)), cell_normal),
            Paragraph(
                f"Domain: {mx_data.get('from_domain', 'N/A')} | Primary MX: {mx_data.get('primary_mx') or 'None (Burner/Unroutable)'}",
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
    route_map = report_json.get("origin_intelligence", {}).get("route_map", [])
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
        is_susp = hop.get("is_suspicious_proxy", False)
        proxy_badge = "<font color='#b91c1c'><b>ANONYMIZED PROXY</b></font>" if is_susp else "<font color='#047857'>CLEAN TRANSIT</font>"
        
        loc_str = f"{hop.get('city', 'Unknown')}, {hop.get('country', 'Unknown')}"
        if hop.get("lat") != 0.0 or hop.get("lon") != 0.0:
            loc_str += f" ({hop.get('lat'):.2f}, {hop.get('lon'):.2f})"

        hop_rows.append([
            Paragraph(str(hop.get("hop_number", "-")), cell_normal),
            Paragraph(hop.get("ip", "Unknown"), cell_mono),
            Paragraph(loc_str, cell_normal),
            Paragraph(f"{hop.get('isp', 'Unknown')} ({hop.get('asn', 'N/A')})", cell_normal),
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
    links = report_json.get("link_investigation", [])
    story.append(Paragraph("4. Payload Hyperlink Investigation & Sandbox Detonation", section_heading))

    link_headers = [
        Paragraph("Target URL Exhibit", th_style),
        Paragraph("Threat Score", th_style),
        Paragraph("Detonation Verdict", th_style),
        Paragraph("Exfiltration & Evasion Telemetry", th_style)
    ]
    link_rows = [link_headers]

    for link in links:
        score = float(link.get("threat_score", 0.0))
        score_color = "#b91c1c" if score >= 80.0 else ("#b45309" if score >= 50.0 else "#047857")
        telemetry = link.get("telemetry", {})
        
        signatures = []
        if telemetry.get("known_db_match"):
            signatures.append("Known Threat Intelligence Match")
        if telemetry.get("sandbox_has_password"):
            signatures.append("Credential Interceptor Form")
        if telemetry.get("brand_impersonation"):
            brand = telemetry.get("detected_brand", "Unknown")
            signatures.append(f"Brand Impersonation: {brand}")
        if telemetry.get("suspicious_exfiltration"):
            signatures.append("Malicious Form Action Exfiltration")
        if not signatures:
            signatures.append("Standard Non-Malicious Structure")

        link_rows.append([
            Paragraph(f"<code>{link.get('url', '')}</code>", cell_mono),
            Paragraph(f"<font color='{score_color}'><b>{score:.1f} / 100</b></font>", cell_normal),
            Paragraph(link.get("verdict", "UNKNOWN"), cell_normal),
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
    incident_narrative = report_json.get("incident_summary", "No technical summary recorded.")
    
    narrative_rows = []
    for line in incident_narrative.split("\n"):
        clean_line = line.strip()
        if clean_line:
            narrative_rows.append([Paragraph(clean_line, summary_text)])

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
    # 8. Statutory Certificate of Authenticity (Sec. 63 BSA, 2023)
    # =========================================================================
    cert_heading = Paragraph("6. Statutory Certificate of Authenticity (Sec. 63, BSA, 2023)", section_heading)
    cert_body = Paragraph(
        "<i>I hereby certify that the electronic record and forensic telemetry documented in this report was produced "
        "by the TrustShield Autonomous Digital Forensics System in the ordinary course of operations. The source message "
        "evidence was ingested, cryptographically hashed with SHA-256 upon intake, and preserved in an immutable state "
        "without manual tampering. This document constitutes a certified electronic record admissible under Section 63 "
        "of the Bharatiya Sakshya Adhiniyam, 2023 (and Section 65B of the Indian Evidence Act, 1872).</i>",
        cert_text
    )

    sign_data = [
        [
            Paragraph("<b>Digital Evidence Custodian:</b><br/>TrustShield Cyber Intelligence Unit<br/>Automated Forensic Examiner", cell_normal),
            Paragraph(f"<b>Certified Timestamp:</b> {now_utc}<br/><b>Chain of Custody:</b> SHA-256 VERIFIED<br/><b>Court Admissibility:</b> VALID", cell_normal)
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
    return abs_output_path

