"""
TrustShield V2 - Court-Admissible PDF Forensic Dossier Generator (report_generator.py)
Generates an official, cryptographic PDF incident report from the Unified Forensic JSON dossier.
Includes Chain of Custody (SHA-256), Threat Attribution, Hop Tracing, Protocol Verification,
and Sandbox Detonation Intelligence using ReportLab Platypus.
"""

import os
from datetime import datetime
from typing import Dict, Any, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
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
        return colors.HexColor("#dc2626")  # Critical Red
    elif score >= 50.0:
        return colors.HexColor("#d97706")  # Suspicious Amber
    else:
        return colors.HexColor("#16a34a")  # Safe Green


def generate_pdf_dossier(report_json: Dict[str, Any], output_path: str = "forensic_report.pdf") -> str:
    """
    Compiles a comprehensive, court-admissible forensic PDF dossier from the analysis JSON.
    
    Args:
        report_json: Dictionary returned by analyze_email_pipeline()
        output_path: Target filesystem path for the generated PDF.
        
    Returns:
        Absolute path to the saved PDF file.
    """
    # Ensure parent directories exist
    abs_output_path = os.path.abspath(output_path)
    os.makedirs(os.path.dirname(abs_output_path) or ".", exist_ok=True)

    # Document Setup (Letter size, 0.5-inch margins for maximum technical density)
    doc = SimpleDocTemplate(
        abs_output_path,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    
    # Custom Typography Styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a")
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#64748b")
    )
    
    section_heading = ParagraphStyle(
        'SectionHeading',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=10,
        spaceAfter=4
    )

    cell_bold = ParagraphStyle(
        'CellBold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#1e293b")
    )

    cell_header = ParagraphStyle(
        'CellHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=11,
        textColor=colors.white
    )

    cell_normal = ParagraphStyle(
        'CellNormal',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#334155")
    )

    cell_mono = ParagraphStyle(
        'CellMono',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor("#0f172a")
    )

    summary_text = ParagraphStyle(
        'SummaryText',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=13,
        textColor=colors.HexColor("#1e293b")
    )

    story = []

    # =========================================================================
    # 1. Header Banner & Chain of Custody
    # =========================================================================
    header_data = [
        [
            Paragraph("🛡️ TRUSTSHIELD V2 FORENSIC DOSSIER", title_style),
            Paragraph(f"<b>Generated:</b> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}<br/><b>Jurisdiction:</b> SIH-106 Cyber Defense", subtitle_style)
        ]
    ]
    header_table = Table(header_data, colWidths=[360, 180])
    header_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('ALIGN', (1, 0), (1, 0), 'RIGHT'),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 6))

    # Evidence Hash Banner (Chain of Custody)
    evidence_hash = report_json.get("evidence_hash_sha256", "UNKNOWN")
    evidence_banner = [
        [
            Paragraph("<b>EVIDENCE HASH (SHA-256):</b>", cell_bold),
            Paragraph(f"<code>{evidence_hash}</code>", cell_mono)
        ]
    ]
    hash_table = Table(evidence_banner, colWidths=[160, 380])
    hash_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(hash_table)
    story.append(Spacer(1, 10))

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
    
    exec_data = [
        [
            Paragraph(f"<font color='white'><b>VERDICT: {verdict}</b></font>", ParagraphStyle('V', fontName='Helvetica-Bold', fontSize=12, leading=15)),
            Paragraph(f"<font color='white'><b>THREAT SCORE: {overall_score:.1f} / 100</b></font>", ParagraphStyle('S', fontName='Helvetica-Bold', fontSize=12, leading=15, alignment=2))
        ],
        [
            Paragraph(
                f"<b>Threat Attribution:</b> {attr_type} (Confidence: {attr_confidence})<br/>"
                f"<b>Attribution Rationale:</b> {attr_details}",
                cell_normal
            ),
            Paragraph(
                f"<b>Originating Public IP:</b> {report_json.get('origin_intelligence', {}).get('originating_ip', 'N/A')}<br/>"
                f"<b>Infrastructure:</b> {'Tor / Proxy / Bulletproof' if report_json.get('origin_intelligence', {}).get('is_anonymized_node') else 'Standard Transit'}",
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
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(exec_table)
    story.append(Spacer(1, 10))

    # =========================================================================
    # 3. Message Envelope Metadata
    # =========================================================================
    meta = report_json.get("metadata", {})
    story.append(Paragraph("1. RFC-5322 Technical Message Envelope", section_heading))
    
    reply_to_mismatch = meta.get("reply_to_mismatch", False)
    reply_to_flag = "<font color='#dc2626'><b> [BEC MISMATCH ALERT]</b></font>" if reply_to_mismatch else ""

    meta_table_data = [
        [Paragraph("<b>Subject:</b>", cell_bold), Paragraph(meta.get("subject", "N/A"), cell_normal)],
        [Paragraph("<b>From:</b>", cell_bold), Paragraph(meta.get("from", "N/A"), cell_normal)],
        [Paragraph("<b>Reply-To:</b>", cell_bold), Paragraph(f"{meta.get('reply_to', 'None')}{reply_to_flag}", cell_normal)],
        [Paragraph("<b>Return-Path:</b>", cell_bold), Paragraph(meta.get("return_path", "N/A"), cell_normal)],
        [Paragraph("<b>To / Date:</b>", cell_bold), Paragraph(f"{meta.get('to', 'N/A')} | {meta.get('date', 'N/A')}", cell_normal)],
        [Paragraph("<b>Message-ID:</b>", cell_bold), Paragraph(meta.get("message_id", "N/A"), cell_mono)]
    ]
    meta_table = Table(meta_table_data, colWidths=[90, 450])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor("#f8fafc")),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 10))

    # =========================================================================
    # 4. Authentication & Domain Infrastructure (SPF, DKIM, DMARC, MX)
    # =========================================================================
    auth = report_json.get("authentication", {})
    mx_data = report_json.get("sender_domain_intelligence", {})
    
    story.append(Paragraph("2. Identity & Protocol Authentication Audit", section_heading))

    def _fmt_pass_fail(status: bool) -> str:
        return "<font color='#16a34a'><b>PASS</b></font>" if status else "<font color='#dc2626'><b>FAIL / REJECT</b></font>"

    auth_table_data = [
        [
            Paragraph("<font color='white'><b>Protocol</b></font>", cell_header),
            Paragraph("<font color='white'><b>Status</b></font>", cell_header),
            Paragraph("<font color='white'><b>Forensic Evaluation & Reason</b></font>", cell_header)
        ],
        [
            Paragraph("<b>SPF</b> (Sender Policy)", cell_normal),
            Paragraph(_fmt_pass_fail(auth.get("spf_pass", False)), cell_normal),
            Paragraph(auth.get("spf_details", "No SPF details"), cell_normal)
        ],
        [
            Paragraph("<b>DKIM</b> (Cryptographic)", cell_normal),
            Paragraph(_fmt_pass_fail(auth.get("dkim_pass", False)), cell_normal),
            Paragraph(auth.get("dkim_details", "No DKIM signature"), cell_normal)
        ],
        [
            Paragraph("<b>DMARC</b> (Policy Alignment)", cell_normal),
            Paragraph(_fmt_pass_fail(auth.get("dmarc_pass", False)), cell_normal),
            Paragraph(auth.get("dmarc_details", "No DMARC record"), cell_normal)
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
    auth_table = Table(auth_table_data, colWidths=[120, 80, 340])
    auth_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(auth_table)
    story.append(Spacer(1, 10))

    # =========================================================================
    # 5. Mail Routing & Hop Tracing Table (Leaflet Map Route)
    # =========================================================================
    route_map = report_json.get("origin_intelligence", {}).get("route_map", [])
    story.append(Paragraph("3. Mail Transmission Hop Tracing & Infrastructure Geolocation", section_heading))

    hop_headers = [
        Paragraph("<font color='white'><b>Hop #</b></font>", cell_header),
        Paragraph("<font color='white'><b>Node IP Address</b></font>", cell_header),
        Paragraph("<font color='white'><b>Location</b></font>", cell_header),
        Paragraph("<font color='white'><b>ISP / Autonomous System</b></font>", cell_header),
        Paragraph("<font color='white'><b>Proxy / VPN Flag</b></font>", cell_header)
    ]
    hop_rows = [hop_headers]

    for hop in route_map:
        is_susp = hop.get("is_suspicious_proxy", False)
        proxy_badge = "<font color='#dc2626'><b>YES (TOR/PROXY)</b></font>" if is_susp else "<font color='#16a34a'>CLEAN</font>"
        
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
            Paragraph("No external hops parsed", cell_normal),
            Paragraph("-", cell_normal),
            Paragraph("-", cell_normal),
            Paragraph("-", cell_normal)
        ])

    hop_table = Table(hop_rows, colWidths=[40, 110, 150, 150, 90])
    hop_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(hop_table)
    story.append(Spacer(1, 10))

    # =========================================================================
    # 6. Embedded Link Sandbox Detonation Summary
    # =========================================================================
    links = report_json.get("link_investigation", [])
    story.append(Paragraph("4. Payload Hyperlink Investigation & Sandbox Detonation", section_heading))

    link_headers = [
        Paragraph("<font color='white'><b>Target URL</b></font>", cell_header),
        Paragraph("<font color='white'><b>Threat Score</b></font>", cell_header),
        Paragraph("<font color='white'><b>Sandbox Verdict</b></font>", cell_header),
        Paragraph("<font color='white'><b>Exfiltration / Evasion Signatures</b></font>", cell_header)
    ]
    link_rows = [link_headers]

    for link in links:
        score = float(link.get("threat_score", 0.0))
        score_color = "#dc2626" if score >= 80.0 else ("#d97706" if score >= 50.0 else "#16a34a")
        telemetry = link.get("telemetry", {})
        
        signatures = []
        if telemetry.get("known_db_match"):
            signatures.append("Known Threat DB")
        if telemetry.get("sandbox_has_password"):
            signatures.append("Credential Interceptor")
        if telemetry.get("brand_impersonation"):
            brand = telemetry.get("detected_brand", "Unknown")
            signatures.append(f"Impersonating: {brand}")
        if telemetry.get("suspicious_exfiltration"):
            signatures.append("External Data Exfiltration")
        if not signatures:
            signatures.append("Standard Web Structure")

        link_rows.append([
            Paragraph(f"<code>{link.get('url', '')}</code>", cell_mono),
            Paragraph(f"<font color='{score_color}'><b>{score:.1f} / 100</b></font>", cell_normal),
            Paragraph(link.get("verdict", "UNKNOWN"), cell_normal),
            Paragraph(", ".join(signatures), cell_normal)
        ])

    if len(link_rows) == 1:
        link_rows.append([
            Paragraph("No embedded URLs detected in message body", cell_normal),
            Paragraph("-", cell_normal),
            Paragraph("CLEAN", cell_normal),
            Paragraph("None", cell_normal)
        ])

    link_table = Table(link_rows, colWidths=[200, 75, 125, 140])
    link_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(link_table)
    story.append(Spacer(1, 10))

    # =========================================================================
    # 7. Forensic Incident Narrative & Recommended Containment
    # =========================================================================
    story.append(Paragraph("5. Forensic Narrative & Legal Dossier Summary", section_heading))
    incident_narrative = report_json.get("incident_summary", "No summary generated.")
    
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
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
    ]))
    story.append(narrative_table)
    story.append(Spacer(1, 14))


    # Sign-off footer
    footer_text = Paragraph(
        "<i>This technical dossier was automatically assembled and cryptographically hashed by TrustShield V2 SIH-106 "
        "Autonomous Forensics Engine. Certified court-admissible electronic record under Section 65B of the Indian Evidence Act.</i>",
        subtitle_style
    )
    story.append(footer_text)

    # Build Document
    doc.build(story)
    return abs_output_path
