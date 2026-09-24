"""
TrustShield V2 - Attachment Risk Analyser (attachment_analyser.py)
Analyses email MIME parts for suspicious file attachments:
  - Dangerous executable/script MIME types
  - Double-extension camouflage (e.g., invoice.pdf.exe)
  - Macro-enabled Office documents (.docm, .xlsm, .pptm)
  - Archive wrapping commonly used to bypass filters (.zip, .rar, .7z, .iso)
  - Filename-content type mismatch
  - Excessive attachment size anomalies

Integrates into parse_email_file() in email_forensics.py.
"""

import email
import logging
import re
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

# ============================================================================
# RISK CLASSIFICATION TABLES
# ============================================================================

# MIME types that are inherently high-risk executables
HIGH_RISK_MIME_TYPES = {
    "application/x-msdownload",         # .exe
    "application/x-executable",
    "application/x-dosexec",
    "application/vnd.microsoft.portable-executable",
    "application/x-msdos-program",
    "application/x-javascript",
    "text/javascript",
    "application/x-sh",                 # shell scripts
    "application/x-bat",
    "application/x-msi",                # Windows installer
    "application/x-powershell",
    "application/java-archive",         # .jar
    "application/x-java-archive",
}

# Dangerous file extensions regardless of MIME type
HIGH_RISK_EXTENSIONS = {
    ".exe", ".com", ".bat", ".cmd", ".scr", ".pif", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".ps1", ".ps2", ".psm1",
    ".sh", ".bash", ".msi", ".jar", ".reg", ".hta", ".lnk", ".cpl",
}

# Macro-enabled Office documents
MACRO_ENABLED_EXTENSIONS = {
    ".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".pptm", ".potm",
    ".ppam", ".ppsm", ".sldm",
}

# Archive types used to hide payloads
ARCHIVE_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".iso", ".img",
    ".cab", ".ace", ".arj",
}

# Medium risk — documents that can embed macros or scripts
MEDIUM_RISK_EXTENSIONS = {
    ".doc", ".xls", ".ppt",        # Legacy Office formats (can contain macros)
    ".rtf",                         # Can embed OLE objects
    ".pdf",                         # Can embed JavaScript
    ".html", ".htm",                # Can contain phishing pages
    ".svg",                         # Can contain embedded JS
}


def _get_extension(filename: str) -> str:
    """Extracts the lowercase file extension from a filename."""
    if not filename:
        return ""
    # Handle double extensions: e.g., "invoice.pdf.exe" → ".exe"
    parts = filename.lower().rsplit(".", maxsplit=2)
    if len(parts) >= 2:
        return f".{parts[-1]}"
    return ""


def _has_double_extension(filename: str) -> bool:
    """Detects double-extension camouflage e.g. 'photo.jpg.exe'."""
    if not filename:
        return False
    parts = filename.lower().split(".")
    if len(parts) >= 3:
        inner_ext = f".{parts[-2]}"
        outer_ext = f".{parts[-1]}"
        # Suspicious if inner extension is a known document type and outer is executable
        known_doc_extensions = {".pdf", ".jpg", ".jpeg", ".png", ".doc", ".docx", ".xls", ".txt"}
        if inner_ext in known_doc_extensions and outer_ext in HIGH_RISK_EXTENSIONS:
            return True
    return False


def analyse_attachments(raw_email_bytes: bytes) -> Dict[str, Any]:
    """
    Parses all MIME parts of a raw email and analyses attachments for risk.

    Returns:
        {
          "total_attachments": int,
          "attachment_risk_score": float (0–100),
          "attachment_risk_level": str,
          "attachments": list[dict],   # Per-attachment detail
          "risk_flags": list[str],
          "has_high_risk_attachment": bool,
          "has_macro_enabled_document": bool,
          "has_archive_attachment": bool,
          "has_double_extension": bool
        }
    """
    result = {
        "total_attachments": 0,
        "attachment_risk_score": 0.0,
        "attachment_risk_level": "NONE",
        "attachments": [],
        "risk_flags": [],
        "has_high_risk_attachment": False,
        "has_macro_enabled_document": False,
        "has_archive_attachment": False,
        "has_double_extension": False
    }

    if not raw_email_bytes:
        return result

    try:
        msg = email.message_from_bytes(raw_email_bytes)
    except Exception as e:
        logger.warning(f"Attachment analyser: failed to parse email bytes: {e}")
        return result

    attachment_details = []
    cumulative_risk = 0.0
    flags = []

    for part in msg.walk():
        content_disposition = str(part.get("Content-Disposition", "")).lower()
        content_type = (part.get_content_type() or "").lower()
        filename = part.get_filename() or ""

        # Only inspect parts with a filename or explicit attachment disposition
        is_attachment = "attachment" in content_disposition or (
            filename and "inline" not in content_disposition
        )
        if not is_attachment or not filename:
            continue

        result["total_attachments"] += 1
        ext = _get_extension(filename)
        double_ext = _has_double_extension(filename)

        attachment_risk = 0.0
        attachment_flags = []
        risk_category = "LOW"

        # Rule 1: High-risk MIME type
        if content_type in HIGH_RISK_MIME_TYPES:
            attachment_risk += 80.0
            attachment_flags.append(f"HIGH_RISK_MIME_TYPE: {content_type}")
            result["has_high_risk_attachment"] = True
            risk_category = "CRITICAL"

        # Rule 2: High-risk file extension
        if ext in HIGH_RISK_EXTENSIONS:
            attachment_risk = max(attachment_risk, 80.0)
            attachment_flags.append(f"DANGEROUS_EXTENSION: {ext} — executable/script file")
            result["has_high_risk_attachment"] = True
            risk_category = "CRITICAL"

        # Rule 3: Macro-enabled Office document
        if ext in MACRO_ENABLED_EXTENSIONS:
            attachment_risk = max(attachment_risk, 65.0)
            attachment_flags.append(f"MACRO_ENABLED_DOCUMENT: {ext} can contain embedded macros (common malware vector)")
            result["has_macro_enabled_document"] = True
            risk_category = "HIGH"

        # Rule 4: Archive wrapping (may hide payload)
        if ext in ARCHIVE_EXTENSIONS:
            attachment_risk = max(attachment_risk, 40.0)
            attachment_flags.append(f"ARCHIVE_ATTACHMENT: {ext} archives can conceal malicious payloads")
            result["has_archive_attachment"] = True
            if risk_category == "LOW":
                risk_category = "MEDIUM"

        # Rule 5: Double-extension camouflage
        if double_ext:
            attachment_risk = max(attachment_risk, 85.0)
            attachment_flags.append(f"DOUBLE_EXTENSION_CAMOUFLAGE: '{filename}' uses double extension to disguise executable as document")
            result["has_double_extension"] = True
            result["has_high_risk_attachment"] = True
            risk_category = "CRITICAL"

        # Rule 6: Medium-risk documents
        if ext in MEDIUM_RISK_EXTENSIONS and not attachment_flags:
            attachment_risk = max(attachment_risk, 20.0)
            attachment_flags.append(f"MEDIUM_RISK_DOCUMENT: {ext} can potentially embed scripts or macros")
            risk_category = "LOW_MEDIUM"

        # Rule 7: MIME/extension mismatch
        claimed_mime_ext_map = {
            "application/pdf": ".pdf",
            "image/jpeg": ".jpg",
            "image/png": ".png",
            "application/zip": ".zip",
        }
        expected_ext = claimed_mime_ext_map.get(content_type)
        if expected_ext and ext != expected_ext and ext in HIGH_RISK_EXTENSIONS:
            attachment_risk = max(attachment_risk, 90.0)
            attachment_flags.append(f"MIME_EXTENSION_MISMATCH: Claimed {content_type} but filename ends with {ext}")
            risk_category = "CRITICAL"

        # Estimate file size from payload
        try:
            payload = part.get_payload(decode=True)
            file_size = len(payload) if payload else 0
        except Exception:
            file_size = 0

        attachment_entry = {
            "filename": filename,
            "extension": ext,
            "mime_type": content_type,
            "file_size_bytes": file_size,
            "risk_category": risk_category,
            "attachment_risk_score": round(min(100.0, attachment_risk), 1),
            "flags": attachment_flags,
            "has_double_extension": double_ext
        }
        attachment_details.append(attachment_entry)

        if attachment_flags:
            flags.extend([f"[{filename}] {flag}" for flag in attachment_flags])

        cumulative_risk = max(cumulative_risk, attachment_risk)

    # Determine overall attachment risk level
    if cumulative_risk >= 80.0:
        risk_level = "CRITICAL"
    elif cumulative_risk >= 60.0:
        risk_level = "HIGH"
    elif cumulative_risk >= 35.0:
        risk_level = "MEDIUM"
    elif cumulative_risk > 0.0:
        risk_level = "LOW"
    else:
        risk_level = "NONE"

    result["attachment_risk_score"] = round(min(100.0, cumulative_risk), 1)
    result["attachment_risk_level"] = risk_level
    result["attachments"] = attachment_details
    result["risk_flags"] = flags

    return result
