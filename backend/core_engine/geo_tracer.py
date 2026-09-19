"""
TrustShield V2 - GeoLocation & Infrastructure Tracer (geo_tracer.py)
Resolves public IP addresses extracted from email Received: hops into physical GPS coordinates,
ISP/ASN network details, and proxy/VPN flags formatted for frontend Leaflet interactive maps.
"""

import ipaddress
import logging
from typing import Dict, Any, List, Union
import requests

logger = logging.getLogger(__name__)

# Free, no-key IP-API endpoint with forensic fields
IP_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,city,lat,lon,isp,as,proxy,hosting"
DEFAULT_TIMEOUT = 3.0

# Simple in-memory cache to prevent redundant lookups and respect rate limits
_GEO_CACHE: Dict[str, Dict[str, Any]] = {}

# Free IP-intelligence APIs flag entire cloud/hosting ASN ranges as "proxy" even
# when the IP is a legitimate provider's own outbound mail server (e.g. Gmail's
# sending IPs sit in Google's own datacenter ASN, which trips the generic
# "hosting = possible proxy" heuristic). Without this allowlist, any email routed
# through a major provider gets mislabeled as anonymized/Tor infrastructure.
_KNOWN_LEGITIMATE_MAIL_PROVIDERS = (
    "google", "microsoft", "outlook", "amazon", "yahoo",
    "zoho", "mailgun", "sendgrid", "proofpoint", "mimecast",
)


def _is_known_legitimate_mail_provider(isp: str, asn: str) -> bool:
    """True if the ISP/ASN string matches a well-known legitimate mail provider,
    so a raw 'proxy'/'hosting' flag from a free geo-IP API shouldn't be trusted
    as evidence of anonymized/Tor infrastructure."""
    haystack = f"{isp or ''} {asn or ''}".lower()
    return any(name in haystack for name in _KNOWN_LEGITIMATE_MAIL_PROVIDERS)


def is_rfc1918_or_private(ip_str: str) -> bool:
    """Checks if an IP is private, loopback, or reserved."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return (
            ip.is_private or
            ip.is_loopback or
            ip.is_link_local or
            ip.is_reserved or
            ip.is_unspecified
        )
    except ValueError:
        return False


def resolve_ip_location(ip_address: str, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """
    Resolves an IPv4/IPv6 address into geographical and network intelligence.
    
    Queries ip-api.com with strict timeout and fallback resilience:
    - Extracts GPS coordinates (lat/lon), City, Country, ISP, and ASN.
    - Flags suspicious infrastructure: proxy=true (VPN/Tor) or hosting=true (Datacenter).
    - Returns safe default values if the lookup fails or times out.
    """
    clean_ip = str(ip_address).strip()
    
    # Check cache first (only return if successfully resolved)
    if clean_ip in _GEO_CACHE and _GEO_CACHE[clean_ip].get("status") == "success":
        return dict(_GEO_CACHE[clean_ip])

    # Handle private / internal networks locally without wasting external API requests
    if is_rfc1918_or_private(clean_ip):
        fallback = {
            "ip": clean_ip,
            "city": "Internal LAN",
            "country": "Private Network (RFC-1918)",
            "lat": 0.0,
            "lon": 0.0,
            "isp": "Local / Corporate Gateway",
            "asn": "N/A",
            "is_suspicious_proxy": False,
            "is_private": True,
            "status": "internal"
        }
        _GEO_CACHE[clean_ip] = fallback
        return dict(fallback)

    # Safe fallback dictionary
    fallback_result = {
        "ip": clean_ip,
        "city": "Unknown",
        "country": "Unknown",
        "lat": 0.0,
        "lon": 0.0,
        "isp": "Unknown",
        "asn": "Unknown",
        "is_suspicious_proxy": False,
        "is_private": False,
        "status": "fail"
    }

    # Provider 1: ip-api.com
    try:
        url = IP_API_URL.format(ip=clean_ip)
        response = requests.get(url, timeout=timeout)
        
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                isp_name = data.get("isp") or "Unknown"
                asn_name = data.get("as") or "Unknown"
                is_proxy = bool(data.get("proxy", False))
                is_hosting = bool(data.get("hosting", False))
                if is_proxy and _is_known_legitimate_mail_provider(isp_name, asn_name):
                    logger.info(f"Overriding proxy flag for {clean_ip}: matches known mail provider '{isp_name}'")
                    is_proxy = False
                result = {
                    "ip": clean_ip,
                    "city": data.get("city") or "Unknown",
                    "country": data.get("country") or "Unknown",
                    "lat": float(data.get("lat", 0.0)),
                    "lon": float(data.get("lon", 0.0)),
                    "isp": isp_name,
                    "asn": asn_name,
                    "is_suspicious_proxy": is_proxy,
                    "is_proxy": is_proxy,
                    "is_hosting": is_hosting,
                    "is_private": False,
                    "status": "success"
                }
                _GEO_CACHE[clean_ip] = result
                return dict(result)
            else:
                logger.warning(f"IP-API returned fail for {clean_ip}: {data.get('message')}")
    except Exception as e:
        logger.warning(f"Primary IP-API lookup failed for {clean_ip}: {e}")

    # Provider 2 Fallback: ipwho.is
    try:
        url2 = f"https://ipwho.is/{clean_ip}"
        res2 = requests.get(url2, timeout=timeout)
        if res2.status_code == 200:
            d2 = res2.json()
            if d2.get("success"):
                conn = d2.get("connection", {})
                lat = float(d2.get("latitude", 0.0))
                lon = float(d2.get("longitude", 0.0))
                result = {
                    "ip": clean_ip,
                    "city": d2.get("city") or "Unknown",
                    "country": d2.get("country") or "Unknown",
                    "lat": lat,
                    "lon": lon,
                    "isp": conn.get("isp") or "Unknown",
                    "asn": str(conn.get("asn") or "Unknown"),
                    "is_suspicious_proxy": False,
                    "is_proxy": False,
                    "is_hosting": False,
                    "is_private": False,
                    "status": "success"
                }
                _GEO_CACHE[clean_ip] = result
                return dict(result)
    except Exception as e:
        logger.warning(f"Secondary IPWHO.IS lookup failed for {clean_ip}: {e}")

    # Do NOT cache failures in _GEO_CACHE so subsequent scans can retry!
    return dict(fallback_result)


def generate_route_map(ip_list: List[Union[str, Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """
    Iterates through a list of IPs (or hop dictionaries) and maps each node
    to GPS coordinates and network metadata formatted specifically for Leaflet map rendering.
    
    Args:
        ip_list: List of IP strings (e.g. ["185.220.101.5", "142.250.190.68"])
                 OR list of hop dicts from email_forensics.py.
                 
    Returns:
        List of hop dicts with hop_number, lat, lon, city, country, isp, asn, and is_suspicious_proxy.
    """
    route_map = []
    hop_counter = 1

    for item in ip_list:
        ip_str = None

        # Handle both raw strings and hop dictionary structures
        if isinstance(item, str):
            ip_str = item.strip()
        elif isinstance(item, dict):
            # If item comes from email_forensics hop_details
            if "public_ips" in item and item["public_ips"]:
                ip_str = item["public_ips"][0]
            elif "extracted_ips" in item and item["extracted_ips"]:
                ip_str = item["extracted_ips"][0]
            elif "ip" in item:
                ip_str = item["ip"]

        if not ip_str:
            continue

        geo_info = resolve_ip_location(ip_str)

        hop_entry = {
            "hop_number": hop_counter,
            "ip": geo_info.get("ip", ip_str),
            "city": geo_info.get("city", "Unknown"),
            "country": geo_info.get("country", "Unknown"),
            "lat": geo_info.get("lat", 0.0),
            "lon": geo_info.get("lon", 0.0),
            "isp": geo_info.get("isp", "Unknown"),
            "asn": geo_info.get("asn", "Unknown"),
            "is_suspicious_proxy": geo_info.get("is_suspicious_proxy", False)
        }
        route_map.append(hop_entry)
        hop_counter += 1

    return route_map
