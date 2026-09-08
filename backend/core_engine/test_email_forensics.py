"""
TrustShield V2 - Email Forensics Engine Unit & Integration Test
Validates:
1. SHA-256 evidence hashing for chain of custody.
2. Bottom-up Received: header parsing and RFC-1918 private IP filtering to isolate true public originating IP.
3. SPF, DKIM, and DMARC protocol verification and default handling.
4. HTML payload unpacking and embedded hyperlink extraction.
"""

import sys
import json
from pathlib import Path

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from core_engine.email_forensics import parse_email_file


def generate_synthetic_phishing_eml() -> bytes:
    """
    Constructs a synthetic RFC-5322 .eml byte sequence simulating a real-world phishing attack:
    - Hop 1 (Bottom-most): Internal client 10.0.0.5 connects to attacker MTA.
    - Hop 2: Attacker MTA (185.220.101.5 - Tor Exit / Bulletproof Host) sends to intermediary relay.
    - Hop 3: Corporate Edge Relay (192.168.1.1) forwards to internal mail gateway.
    - Hop 4 (Top-most): Internal MX server (10.0.2.15) delivers to recipient mailbox.
    - Body contains phishing HTML with embedded href and text.
    """
    raw_eml = (
        "Delivered-To: victim.executive@company.com\r\n"
        "Received: from mx.internal.company.com (mx.internal.company.com [10.0.2.15])\r\n"
        "\tby mailbox.company.com (Postfix) with ESMTP id 4X9F8D01;\r\n"
        "\tMon, 7 Sep 2026 14:35:12 +0000 (UTC)\r\n"
        "Received: from edge-relay.company.com (edge-relay.company.com [192.168.1.1])\r\n"
        "\tby mx.internal.company.com with ESMTP id 3B8C1A22;\r\n"
        "\tMon, 7 Sep 2026 14:35:10 +0000 (UTC)\r\n"
        "Received: from mail.spoofed-sender.xyz (unknown [185.220.101.5])\r\n"
        "\tby edge-relay.company.com (Postfix) with ESMTPS id 1A2B3C4D;\r\n"
        "\tMon, 7 Sep 2026 14:35:05 +0000 (UTC)\r\n"
        "Received: from attacker-laptop (unknown [10.0.0.5])\r\n"
        "\tby mail.spoofed-sender.xyz (Postfix) with ESMTPA id 99887766;\r\n"
        "\tMon, 7 Sep 2026 14:34:58 +0000 (UTC)\r\n"
        "Return-Path: <spoofed-account@spoofed-sender.xyz>\r\n"
        "From: \"Executive Security Alert\" <security@paypal-verification.top>\r\n"
        "To: victim.executive@company.com\r\n"
        "Subject: URGENT: Unauthorized Wire Transfer Detected - Verify Identity\r\n"
        "Date: Mon, 7 Sep 2026 14:34:55 +0000\r\n"
        "Message-ID: <20260907143455.ABC123XYZ@spoofed-sender.xyz>\r\n"
        "Reply-To: phisher-drop@external-scam.biz\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: multipart/alternative; boundary=\"----=_Part_12345_67890\"\r\n"
        "\r\n"
        "------=_Part_12345_67890\r\n"
        "Content-Type: text/plain; charset=UTF-8\r\n"
        "Content-Transfer-Encoding: 7bit\r\n"
        "\r\n"
        "Urgent Notice:\r\n"
        "We detected an unauthorized login attempt from an unrecognized device.\r\n"
        "Please cancel this transaction immediately by visiting https://example.com/phish\r\n"
        "Alternatively review your case here: https://portal-resolve.top/ticket?id=99281\r\n"
        "\r\n"
        "------=_Part_12345_67890\r\n"
        "Content-Type: text/html; charset=UTF-8\r\n"
        "Content-Transfer-Encoding: 7bit\r\n"
        "\r\n"
        "<!DOCTYPE html>\r\n"
        "<html>\r\n"
        "<body>\r\n"
        "  <h2>Security Notification</h2>\r\n"
        "  <p>An unauthorized login was detected from foreign IP <strong>185.220.101.5</strong>.</p>\r\n"
        "  <p>If you did not authorize this, cancel immediately:</p>\r\n"
        "  <p><a href=\"https://example.com/phish\" style=\"color:red;\">Click Here to Cancel Transfer</a></p>\r\n"
        "  <p>Help Center: <a href=\"https://portal-resolve.top/ticket?id=99281\">Support Portal</a></p>\r\n"
        "</body>\r\n"
        "</html>\r\n"
        "------=_Part_12345_67890--\r\n"
    )
    return raw_eml.encode("utf-8")


def test_email_forensics_pipeline():
    print("=" * 80)
    print("🛡️  TESTING TRUSTSHIELD V2: EMAIL FORENSICS & INGESTION ENGINE")
    print("=" * 80)

    # 1. Generate Synthetic Email
    raw_bytes = generate_synthetic_phishing_eml()
    print(f"\n[+] Generated Synthetic .eml ({len(raw_bytes)} bytes)")

    # 2. Ingest through Forensic Parser
    result = parse_email_file(raw_bytes)

    # 3. Pretty Print Output
    print("\n[+] Ingestion Result Schema:")
    print(json.dumps(result, indent=2))

    # 4. Assertions
    print("\n" + "=" * 80)
    print("🔍 VALIDATING FORENSIC ENGINE SPECIFICATIONS")
    print("=" * 80)

    # Check 1: SHA-256 Chain of Custody Hash
    sha256_hash = result.get("evidence_hash_sha256")
    assert sha256_hash is not None, "Evidence hash must not be None"
    assert len(sha256_hash) == 64, f"Evidence hash must be 64 characters (got {len(sha256_hash)})"
    print(f"  [✓] Evidence SHA-256 Hash verified: {sha256_hash[:16]}...{sha256_hash[-8:]}")

    # Check 2: Metadata Extraction
    metadata = result.get("metadata", {})
    assert "URGENT" in metadata.get("subject", ""), "Subject was not extracted correctly"
    assert "paypal-verification.top" in metadata.get("from", ""), "From header was not extracted correctly"
    assert metadata.get("from_domain") == "paypal-verification.top", "From domain parse mismatch"
    assert metadata.get("reply_to_mismatch") is True, "Reply-To mismatch (BEC indicator) should be detected"
    print(f"  [✓] Metadata extracted: Subject='{metadata.get('subject')}'")
    print(f"  [✓] BEC Indicator Detected: reply_to_mismatch={metadata.get('reply_to_mismatch')}")

    # Check 3: Origin Tracing & Private IP Filtering
    origin_info = result.get("origin_tracing", {})
    origin_ip = origin_info.get("originating_ip")
    total_hops = origin_info.get("total_hops")

    assert total_hops == 4, f"Expected 4 hops, got {total_hops}"
    assert origin_ip == "185.220.101.5", (
        f"Expected earliest public originating IP '185.220.101.5', got '{origin_ip}'! "
        f"(Should skip 10.0.0.5 internal IP)"
    )
    print(f"  [✓] Hop Tracing Success: Total Hops = {total_hops}")
    print(f"  [✓] RFC-1918 Private IP Filter Success: Skipped 10.0.0.5 -> Originating Public IP = '{origin_ip}'")

    # Check 4: Authentication Protocols
    auth = result.get("authentication", {})
    assert "spf_pass" in auth, "SPF flag missing in auth dictionary"
    assert "dkim_pass" in auth, "DKIM flag missing in auth dictionary"
    assert "dmarc_pass" in auth, "DMARC flag missing in auth dictionary"
    print(f"  [✓] Authentication Protocol Verification Handled: SPF={auth.get('spf_pass')}, DKIM={auth.get('dkim_pass')}, DMARC={auth.get('dmarc_pass')}")

    # Check 5: Payload Extraction & URL Sanitization
    payload = result.get("payload", {})
    body_text = payload.get("body_text", "")
    extracted_links = payload.get("extracted_links", [])

    assert "Security Notification" in body_text or "unauthorized" in body_text.lower(), "Body text not extracted"
    assert "https://example.com/phish" in extracted_links, "Missing expected link 'https://example.com/phish'"
    assert "https://portal-resolve.top/ticket?id=99281" in extracted_links, "Missing expected link 'https://portal-resolve.top/ticket?id=99281'"
    print(f"  [✓] Body Text Extracted ({len(body_text)} chars)")
    print(f"  [✓] Extracted URLs ({len(extracted_links)} unique): {extracted_links}")

    print("\n" + "=" * 80)
    print("🎯 ALL EMAIL FORENSICS CHECKS PASSED SUCCESSFULLY!")
    print("=" * 80)


if __name__ == "__main__":
    test_email_forensics_pipeline()
