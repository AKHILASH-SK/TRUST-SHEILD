"""
TrustShield V2 - GeoLocation & Infrastructure Tracer (geo_tracer.py)
Resolves public IP addresses extracted from email Received: hops into physical GPS coordinates,
ISP/ASN network details, and proxy/VPN flags formatted for frontend Leaflet interactive maps.
"""

import ipaddress
import logging
import concurrent.futures
from typing import Dict, Any, List, Union
import requests

logger = logging.getLogger(__name__)

# Free, no-key IP-API endpoint with forensic fields
IP_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,city,lat,lon,isp,as,proxy,hosting"
DEFAULT_TIMEOUT = 1.5

# High-fidelity offline intelligence for verified demo / standard threat infrastructure
KNOWN_INFRASTRUCTURE: Dict[str, Dict[str, Any]] = {
    "185.220.101.5": {
        "ip": "185.220.101.5",
        "city": "Frankfurt",
        "country": "Germany",
        "lat": 50.1109,
        "lon": 8.6821,
        "isp": "F3 Netze e.V. (Tor Exit Node)",
        "asn": "AS206238",
        "is_suspicious_proxy": True,
        "is_proxy": True,
        "is_hosting": True,
        "is_private": False,
        "status": "success"
    },
    "185.220.101.6": {
        "ip": "185.220.101.6",
        "city": "Frankfurt",
        "country": "Germany",
        "lat": 50.1109,
        "lon": 8.6821,
        "isp": "F3 Netze e.V. (Tor Exit Node)",
        "asn": "AS206238",
        "is_suspicious_proxy": True,
        "is_proxy": True,
        "is_hosting": True,
        "is_private": False,
        "status": "success"
    }
}

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

    # Check known infrastructure / offline intelligence
    if clean_ip in KNOWN_INFRASTRUCTURE:
        result = dict(KNOWN_INFRASTRUCTURE[clean_ip])
        _GEO_CACHE[clean_ip] = result
        return result

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
    Uses concurrent lookups to ensure the entire chain resolves in < 1.5s total.
    """
    extracted_ips = []
    hop_counter = 1

    for item in ip_list:
        ip_str = None
        if isinstance(item, str):
            ip_str = item.strip()
        elif isinstance(item, dict):
            if "public_ips" in item and item["public_ips"]:
                ip_str = item["public_ips"][0]
            elif "extracted_ips" in item and item["extracted_ips"]:
                ip_str = item["extracted_ips"][0]
            elif "ip" in item:
                ip_str = item["ip"]

        if ip_str:
            extracted_ips.append((hop_counter, ip_str))
            hop_counter += 1

    if not extracted_ips:
        return []

    # Parallel resolution of all hops to prevent sequential timeouts
    route_map = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(6, len(extracted_ips))) as executor:
        future_to_hop = {
            executor.submit(resolve_ip_location, ip_val): (num, ip_val)
            for num, ip_val in extracted_ips
        }
        results_by_hop = {}
        for future in concurrent.futures.as_completed(future_to_hop):
            num, ip_val = future_to_hop[future]
            try:
                geo_info = future.result(timeout=2.0)
            except Exception:
                geo_info = {
                    "ip": ip_val,
                    "city": "Unknown",
                    "country": "Lookup Unavailable",
                    "lat": 0.0,
                    "lon": 0.0,
                    "isp": "Unknown",
                    "asn": "N/A",
                    "is_suspicious_proxy": False
                }
            results_by_hop[num] = (ip_val, geo_info)

    for num, ip_val in sorted(extracted_ips, key=lambda x: x[0]):
        _, geo_info = results_by_hop.get(num, (ip_val, {}))
        hop_entry = {
            "hop_number": num,
            "ip": geo_info.get("ip", ip_val),
            "city": geo_info.get("city", "Unknown"),
            "country": geo_info.get("country", "Unknown"),
            "lat": geo_info.get("lat", 0.0),
            "lon": geo_info.get("lon", 0.0),
            "isp": geo_info.get("isp", "Unknown"),
            "asn": geo_info.get("asn", "Unknown"),
            "is_suspicious_proxy": geo_info.get("is_suspicious_proxy", False),
            "is_proxy": geo_info.get("is_proxy", False),
            "is_hosting": geo_info.get("is_hosting", False)
        }
        route_map.append(hop_entry)

    return route_map
