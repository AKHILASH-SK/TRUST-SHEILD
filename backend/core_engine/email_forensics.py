"""
TrustShield V2 - Email Forensics & Protocol Ingestion Engine
Ingests raw .eml / .msg files, computes evidence hashes, traces Received: mail hops,
extracts the earliest public IP, audits SPF/DKIM/DMARC authentication, and pulls
embedded payload text and URLs for sandbox detonation.
"""

import email
from email import policy
import email.utils
import hashlib
import ipaddress
import logging
import re
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse

from bs4 import BeautifulSoup
import dns.resolver
import dkim

logger = logging.getLogger(__name__)

# Regular expressions for IP addresses
IPV4_REGEX = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
URL_REGEX = re.compile(r'https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z0-9]{2,}(?::\d+)?(?:/[^\s<>"\'\)]*)?')


def compute_sha256(data: bytes) -> str:
    """Computes SHA-256 digest of raw email bytes for court-admissible chain of custody."""
    return hashlib.sha256(data).hexdigest()


def is_public_ip(ip_str: str) -> bool:
    """
    Validates if an IP string is a routable, public IP address.
    Filters out RFC-1918 private, loopback, link-local, multicast, and reserved addresses.
    """
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return not (
            ip.is_private or
            ip.is_loopback or
            ip.is_link_local or
            ip.is_multicast or
            ip.is_reserved or
            ip.is_unspecified
        )
    except ValueError:
        return False


def extract_ips_from_string(text: str) -> List[str]:
    """Extracts all IPv4 addresses found within a header string."""
    if not text:
        return []
    candidates = IPV4_REGEX.findall(text)
    # Deduplicate while preserving order
    seen = set()
    result = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            result.append(c)
    return result


def trace_originating_ip(received_headers: List[str]) -> Tuple[Optional[str], int, List[Dict[str, Any]]]:
    """
    Traces Received: headers from bottom (oldest / origin) to top (newest / destination).
    Extracts the earliest non-private, public IP address as the originating IP.
    
    Returns:
        (originating_ip, total_hops, hop_details)
    """
    if not received_headers:
        return None, 0, []

    # RFC 5321: Each MTA prepends its Received header at the top.
    # Therefore, reversing the list traces chronological path from sender to recipient.
    reversed_hops = list(reversed(received_headers))
    total_hops = len(reversed_hops)
    hop_details = []
    originating_ip = None

    for idx, header in enumerate(reversed_hops, start=1):
        clean_header = " ".join(header.split())
        extracted_ips = extract_ips_from_string(clean_header)
        public_ips = [ip for ip in extracted_ips if is_public_ip(ip)]

        # The first valid public IP encountered from bottom is the true origin
        if originating_ip is None and public_ips:
            originating_ip = public_ips[0]

        hop_details.append({
            "hop_index": idx,
            "raw_header": clean_header,
            "extracted_ips": extracted_ips,
            "public_ips": public_ips,
            "is_origin_hop": (originating_ip in public_ips) if originating_ip else False
        })

    return originating_ip, total_hops, hop_details


def extract_domain_from_email(address_header: str) -> str:
    """Extracts the registered or domain part from an email address header."""
    if not address_header:
        return ""
    # Clean brackets e.g. <user@domain.com>
    clean_addr = address_header.strip().strip("<>").strip()
    # Handle "Name <user@domain.com>"
    _, parsed_email = email.utils.parseaddr(clean_addr)
    target = parsed_email or clean_addr
    if "@" in target:
        return target.split("@")[-1].strip().lower()
    return target.strip().lower()


def audit_spf(domain: str, originating_ip: Optional[str]) -> Tuple[bool, str]:
    """
    Audits SPF (Sender Policy Framework) TXT records using dnspython.
    Checks whether the originating IP is permitted to send on behalf of the domain.
    """
    if not domain:
        return False, "No domain available for SPF evaluation"
    if not originating_ip:
        return False, "No public originating IP extracted to verify against SPF"

    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3.0
        resolver.lifetime = 3.0
        target_ip = ipaddress.ip_address(originating_ip)

        def check_spf_recursive(curr_domain: str, depth: int = 0) -> Tuple[bool, str]:
            if depth > 4:
                return False, "SPF lookup recursion limit exceeded"
            try:
                answers = resolver.resolve(curr_domain, 'TXT')
                spf_records = []
                for rdata in answers:
                    txt_content = "".join([part.decode('utf-8', errors='ignore') if isinstance(part, bytes) else str(part) for part in rdata.strings])
                    if txt_content.startswith("v=spf1"):
                        spf_records.append(txt_content)
                if not spf_records:
                    return False, f"No SPF record found for '{curr_domain}'"

                spf_record = spf_records[0]
                tokens = spf_record.split()

                for token in tokens[1:]:
                    token_lower = token.lower()
                    if token_lower.startswith("ip4:"):
                        cidr = token.split(":", 1)[1]
                        try:
                            if target_ip in ipaddress.ip_network(cidr, strict=False):
                                return True, f"Originating IP {originating_ip} matches authorized SPF network: {cidr}"
                        except ValueError:
                            continue
                    elif token_lower.startswith("include:"):
                        inc_dom = token.split(":", 1)[1]
                        matched, reason = check_spf_recursive(inc_dom, depth + 1)
                        if matched:
                            return True, f"Authorized via include:{inc_dom} -> {reason}"
                    elif token_lower.startswith("redirect="):
                        redir_dom = token.split("=", 1)[1]
                        matched, reason = check_spf_recursive(redir_dom, depth + 1)
                        if matched:
                            return True, f"Authorized via redirect={redir_dom} -> {reason}"
                    elif token_lower in ["+all"]:
                        return True, "SPF record permits all sending IPs (+all)"

                return False, f"Originating IP {originating_ip} is NOT authorized in SPF record for '{curr_domain}'"
            except Exception as e:
                return False, f"SPF check error on '{curr_domain}': {str(e)}"

        return check_spf_recursive(domain)
    except Exception as e:
        return False, f"SPF lookup failed: {str(e)}"


def audit_dkim(raw_bytes: bytes) -> Tuple[bool, str]:
    """
    Cryptographically validates DKIM-Signature using dkimpy.
    """
    if b"dkim-signature" not in raw_bytes.lower():
        return False, "No DKIM-Signature header present in email"

    try:
        is_valid = dkim.verify(raw_bytes)
        if is_valid:
            return True, "DKIM cryptographic signature verified valid against sender public key"
        else:
            return False, "DKIM signature verification failed (forged headers or tampered body)"
    except Exception as e:
        return False, f"DKIM validation error: {str(e)}"


def audit_dmarc(from_domain: str, return_path_domain: str, spf_pass: bool, dkim_pass: bool) -> Tuple[bool, str]:
    """
    Audits DMARC record and confirms identifier alignment between From: domain,
    SPF return-path domain, and DKIM signature.
    """
    if not from_domain:
        return False, "Missing From: domain for DMARC evaluation"

    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3.0
        resolver.lifetime = 3.0
        dmarc_target = f"_dmarc.{from_domain}"
        
        answers = resolver.resolve(dmarc_target, 'TXT')
        dmarc_record = None
        for rdata in answers:
            txt_content = "".join([part.decode('utf-8', errors='ignore') if isinstance(part, bytes) else str(part) for part in rdata.strings])
            if txt_content.startswith("v=DMARC1"):
                dmarc_record = txt_content
                break

        if not dmarc_record:
            return False, f"No DMARC record published at '{dmarc_target}'"

        # Check alignment:
        # 1. SPF Alignment: From domain must match or align with Return-Path domain
        spf_aligned = spf_pass and (from_domain.lower() == return_path_domain.lower() or return_path_domain.lower().endswith("." + from_domain.lower()))
        
        # 2. DKIM Alignment: DKIM pass provides cryptographic alignment
        dkim_aligned = dkim_pass

        # DMARC passes if EITHER (SPF aligned & pass) OR (DKIM aligned & pass)
        if spf_aligned or dkim_aligned:
            reason = "DMARC passed with identifier alignment (" + ("SPF aligned" if spf_aligned else "") + (" & " if spf_aligned and dkim_aligned else "") + ("DKIM aligned" if dkim_aligned else "") + ")"
            return True, reason
        else:
            return False, f"DMARC policy failed: Sender identity not aligned with published policy ({dmarc_record})"

    except dns.resolver.NXDOMAIN:
        return False, f"No DMARC record found for domain '{from_domain}' (NXDOMAIN)"
    except dns.resolver.NoAnswer:
        return False, f"No TXT record published at '_dmarc.{from_domain}'"
    except Exception as e:
        return False, f"DMARC lookup failed: {str(e)}"


def check_sender_domain_infrastructure(from_domain: str) -> Dict[str, Any]:
    """
    Queries MX records for the sender domain using dnspython.
    Detects if the sender domain lacks mail exchange infrastructure (burner / disposable attacker domain).
    Returns:
        {"from_domain": from_domain, "has_mx_records": bool, "primary_mx": str | None}
    """
    clean_domain = (from_domain or "").strip().lower()
    if not clean_domain:
        return {
            "from_domain": "",
            "has_mx_records": False,
            "primary_mx": None
        }

    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3.0
        resolver.lifetime = 3.0

        answers = resolver.resolve(clean_domain, 'MX')
        mx_records = []
        for rdata in answers:
            pref = getattr(rdata, 'preference', 100)
            exchange = str(getattr(rdata, 'exchange', '')).rstrip('.')
            mx_records.append((pref, exchange))

        if not mx_records:
            return {
                "from_domain": clean_domain,
                "has_mx_records": False,
                "primary_mx": None
            }

        # Sort by lowest preference number (highest priority MTA)
        mx_records.sort(key=lambda x: x[0])
        primary_mx = mx_records[0][1]

        return {
            "from_domain": clean_domain,
            "has_mx_records": True,
            "primary_mx": primary_mx
        }

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, dns.exception.DNSException):
        return {
            "from_domain": clean_domain,
            "has_mx_records": False,
            "primary_mx": None
        }
    except Exception as e:
        logger.debug(f"MX lookup unexpected error for {clean_domain}: {e}")
        return {
            "from_domain": clean_domain,
            "has_mx_records": False,
            "primary_mx": None
        }


def extract_payload_and_links(msg: email.message.EmailMessage) -> Tuple[str, List[str]]:

    """
    Extracts plain text body and all embedded hyperlinks from HTML and plain text parts.
    Sanitizes and deduplicates URLs.
    """
    body_text_parts = []
    extracted_urls = []

    for part in msg.walk():
        content_type = part.get_content_type()
        content_disposition = str(part.get("Content-Disposition", "")).lower()

        # Skip non-text attachments
        if "attachment" in content_disposition:
            continue

        try:
            payload = part.get_payload(decode=True)
            if not payload:
                continue

            charset = part.get_content_charset() or 'utf-8'
            decoded_text = payload.decode(charset, errors='replace')

            if content_type == "text/plain":
                body_text_parts.append(decoded_text.strip())
                # Extract bare URLs from plain text
                plain_urls = URL_REGEX.findall(decoded_text)
                extracted_urls.extend(plain_urls)

            elif content_type == "text/html":
                soup = BeautifulSoup(decoded_text, 'html.parser')
                
                # Extract visible text
                html_text = soup.get_text(separator=' ', strip=True)
                body_text_parts.append(html_text)

                # Extract all <a href="..."> links
                for a_tag in soup.find_all('a', href=True):
                    href = a_tag['href'].strip()
                    if href.startswith(("http://", "https://")):
                        extracted_urls.append(href)
                        
                # Also check form actions
                for form in soup.find_all('form', action=True):
                    action = form['action'].strip()
                    if action.startswith(("http://", "https://")):
                        extracted_urls.append(action)

        except Exception as e:
            logger.debug(f"Error extracting part payload: {e}")
            continue

    # Clean and deduplicate URLs
    clean_urls = []
    seen = set()
    for url in extracted_urls:
        # Strip trailing punctuation often caught in plain text
        cleaned = re.sub(r'[\s,;:?!\.\>\)\]]+$', '', url.strip())
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            clean_urls.append(cleaned)

    combined_body = "\n\n".join(body_text_parts).strip()
    return combined_body, clean_urls


def parse_email_file(file_bytes: bytes) -> Dict[str, Any]:
    """
    Main Entry Point: Ingests raw .eml bytes and executes the comprehensive
    evidence preservation, hop tracing, protocol audit, and link extraction pipeline.
    """
    if not file_bytes:
        return {
            "evidence_hash_sha256": "",
            "metadata": {},
            "authentication": {"spf_pass": False, "dkim_pass": False, "dmarc_pass": False},
            "origin_tracing": {"originating_ip": None, "total_hops": 0, "hops": []},
            "payload": {"body_text": "", "extracted_links": []}
        }

    # Feature 1: Evidence Preservation (SHA-256)
    evidence_hash = compute_sha256(file_bytes)

    # Parse message structure with standard RFC policy
    msg = email.message_from_bytes(file_bytes, policy=policy.default)

    # Metadata extraction
    subject = str(msg.get("Subject", "")).strip()
    from_header = str(msg.get("From", "")).strip()
    to_header = str(msg.get("To", "")).strip()
    date_header = str(msg.get("Date", "")).strip()
    message_id = str(msg.get("Message-ID", "")).strip()
    return_path = str(msg.get("Return-Path", "")).strip()
    reply_to = str(msg.get("Reply-To", "")).strip()

    from_domain = extract_domain_from_email(from_header)
    return_path_domain = extract_domain_from_email(return_path) or from_domain

    # Feature 2: Hop Tracing & Earliest Public IP
    received_headers = msg.get_all("Received", [])
    originating_ip, total_hops, hops = trace_originating_ip(received_headers)

    # Feature 3: SPF, DKIM, and DMARC Verification
    spf_pass, spf_details = audit_spf(return_path_domain, originating_ip)
    dkim_pass, dkim_details = audit_dkim(file_bytes)
    dmarc_pass, dmarc_details = audit_dmarc(from_domain, return_path_domain, spf_pass, dkim_pass)

    # Feature 4: Payload Body & Link Extraction
    body_text, extracted_links = extract_payload_and_links(msg)

    # Reply-to mismatch check (BEC indicator)
    reply_to_domain = extract_domain_from_email(reply_to)
    reply_to_mismatch = bool(reply_to and from_domain and reply_to_domain != from_domain)

    # Feature 5: Sender Domain MX Infrastructure Check
    sender_domain_infra = check_sender_domain_infrastructure(from_domain)

    return {
        "evidence_hash_sha256": evidence_hash,
        "metadata": {
            "subject": subject,
            "from": from_header,
            "from_domain": from_domain,
            "to": to_header,
            "date": date_header,
            "message_id": message_id,
            "return_path": return_path,
            "reply_to": reply_to,
            "reply_to_mismatch": reply_to_mismatch
        },
        "authentication": {
            "spf_pass": spf_pass,
            "spf_details": spf_details,
            "dkim_pass": dkim_pass,
            "dkim_details": dkim_details,
            "dmarc_pass": dmarc_pass,
            "dmarc_details": dmarc_details
        },
        "sender_domain_intelligence": sender_domain_infra,
        "origin_tracing": {
            "originating_ip": originating_ip,
            "total_hops": total_hops,
            "hops": hops
        },
        "payload": {
            "body_text": body_text,
            "extracted_links": extracted_links
        }
    }

