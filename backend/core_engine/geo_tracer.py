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
    
    # Check cache first
    if clean_ip in _GEO_CACHE:
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

    try:
        url = IP_API_URL.format(ip=clean_ip)
        response = requests.get(url, timeout=timeout)
        
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                # Detect suspicious proxy: proxy=True (VPN/Tor/Public Proxy) OR hosting=True (Datacenter)
                is_proxy = bool(data.get("proxy", False))
                is_hosting = bool(data.get("hosting", False))
                is_suspicious = is_proxy

                result = {
                    "ip": clean_ip,
                    "city": data.get("city") or "Unknown",
                    "country": data.get("country") or "Unknown",
                    "lat": float(data.get("lat", 0.0)),
                    "lon": float(data.get("lon", 0.0)),
                    "isp": data.get("isp") or "Unknown",
                    "asn": data.get("as") or "Unknown",
                    "is_suspicious_proxy": is_suspicious,
                    "is_proxy": is_proxy,
                    "is_hosting": is_hosting,
                    "is_private": False,
                    "status": "success"
                }
                _GEO_CACHE[clean_ip] = result
                return dict(result)
            else:
                logger.warning(f"IP-API returned fail status for {clean_ip}: {data.get('message')}")
                fallback_result["message"] = data.get("message", "Lookup failed")
        else:
            logger.warning(f"IP-API HTTP error {response.status_code} for {clean_ip}")
            fallback_result["message"] = f"HTTP {response.status_code}"

    except requests.exceptions.Timeout:
        logger.warning(f"IP-API lookup timed out after {timeout}s for {clean_ip}")
        fallback_result["message"] = "Lookup timeout"
    except Exception as e:
        logger.warning(f"Unexpected error resolving IP {clean_ip}: {str(e)}")
        fallback_result["message"] = str(e)

    _GEO_CACHE[clean_ip] = fallback_result
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
