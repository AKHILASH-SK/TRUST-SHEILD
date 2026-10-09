"""
TrustShield V2 - GeoLocation & Infrastructure Tracer (geo_tracer.py)
Resolves public IP addresses extracted from email Received: hops into physical GPS coordinates,
ISP/ASN network details, and proxy/VPN flags formatted for frontend Leaflet interactive maps.

Provider order: ipwho.is (HTTPS) first; ip-api.com is a FALLBACK only because its free tier is
HTTP-only (the queried IP is therefore sent in clear text - this is logged). Only ip-api supplies
reliable proxy/hosting flags on the free tier.
"""

import ipaddress
import logging
import re
import threading
import time
from collections import OrderedDict
from typing import Dict, Any, List, Optional, Union

import requests

logger = logging.getLogger(__name__)

# ip-api.com free tier is HTTP-only. Used only as a fallback.
IP_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,city,lat,lon,isp,as,proxy,hosting"
IPWHO_URL = "https://ipwho.is/{ip}"
DEFAULT_TIMEOUT = 3.0
GEO_OVERRIDE = None          # callable(ip) -> geo dict or None; set by the lab (backend/lab) and never in production

MAX_ROUTE_HOPS = 15
ROUTE_TIME_BUDGET = 12.0

_CACHE_MAX = 512
_SUCCESS_TTL = 3600.0
_FAILURE_TTL = 60.0

# Bounded LRU: ip -> (expires_at_monotonic, result)
_GEO_CACHE: "OrderedDict[str, tuple]" = OrderedDict()
_CACHE_LOCK = threading.Lock()

# ---------------------------------------------------------------------------
# Proxy-flag override for genuine mail-provider infrastructure.
#
# Free geo-IP APIs flag whole datacenter ASNs as "proxy/hosting". Gmail / Outlook outbound
# servers live in such ASNs, so we clear the *proxy* flag for them. We deliberately do NOT do a
# substring match on the ISP name: an attacker renting a VM at a big cloud (AWS, Google Cloud,
# Azure) must not be cleared just because the ISP string contains "amazon".
#   - ASNs that are overwhelmingly first-party mail infrastructure: Google (15169),
#     Microsoft (8075, 8068, 8069).
#   - Multi-tenant clouds (AWS 16509/14618) are cleared ONLY when the caller supplies a
#     verified reverse-DNS hostname matching a known mail-relay pattern.
# ---------------------------------------------------------------------------
_MAIL_PROVIDER_ASNS = {15169, 8075, 8068, 8069}
_MULTI_TENANT_CLOUD_ASNS = {16509, 14618}
_MAIL_RELAY_HOST_PATTERNS = (
    re.compile(r"(^|\.)mail-[a-z0-9-]+\.google\.com$"),
    re.compile(r"(^|\.)mail\.protection\.outlook\.com$"),
    re.compile(r"(^|\.)outbound\.protection\.outlook\.com$"),
    re.compile(r"(^|\.)amazonses\.com$"),
)


def _parse_asn(asn: str) -> Optional[int]:
    m = re.search(r"(?:AS)?(\d{2,10})", str(asn or ""), re.IGNORECASE)
    return int(m.group(1)) if m else None


def _is_known_legitimate_mail_provider(isp: str, asn: str, hostname: Optional[str] = None) -> bool:
    """True only for first-party mail ASNs, or a multi-tenant cloud ASN + verified mail-relay hostname."""
    number = _parse_asn(asn)
    host = (hostname or "").strip().lower().rstrip(".")
    host_ok = bool(host) and any(p.search(host) for p in _MAIL_RELAY_HOST_PATTERNS)
    if number in _MAIL_PROVIDER_ASNS:
        return True
    if number in _MULTI_TENANT_CLOUD_ASNS:
        return host_ok
    return False


def is_rfc1918_or_private(ip_str: str) -> bool:
    """True for any non-public address (private, loopback, link-local, CGNAT, reserved, ...)."""
    try:
        ip = ipaddress.ip_address(str(ip_str).strip().split("%")[0].strip("[]"))
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return not ip.is_global


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------
def _cache_get(ip: str) -> Optional[Dict[str, Any]]:
    with _CACHE_LOCK:
        entry = _GEO_CACHE.get(ip)
        if not entry:
            return None
        expires, value = entry
        if expires < time.monotonic():
            _GEO_CACHE.pop(ip, None)
            return None
        _GEO_CACHE.move_to_end(ip)
        return dict(value)


def _cache_put(ip: str, value: Dict[str, Any], ttl: float) -> None:
    with _CACHE_LOCK:
        _GEO_CACHE[ip] = (time.monotonic() + ttl, dict(value))
        _GEO_CACHE.move_to_end(ip)
        while len(_GEO_CACHE) > _CACHE_MAX:
            _GEO_CACHE.popitem(last=False)


def clear_geo_cache() -> None:
    with _CACHE_LOCK:
        _GEO_CACHE.clear()


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------
def _fail_result(ip: str, status: str = "fail") -> Dict[str, Any]:
    return {
        "ip": ip, "city": "Unknown", "country": "Unknown", "lat": 0.0, "lon": 0.0,
        "isp": "Unknown", "asn": "Unknown",
        "is_suspicious_proxy": False, "is_proxy": False, "is_hosting": False,
        "is_private": False, "status": status,
    }


def resolve_ip_location(ip_address: str, timeout: float = DEFAULT_TIMEOUT,
                        deadline: Optional[float] = None, hostname: Optional[str] = None) -> Dict[str, Any]:
    """
    Resolves an IPv4/IPv6 address into geographical and network intelligence.

    ``deadline`` is an optional time.monotonic() value; no provider call is made after it and
    per-call timeouts are clamped to the time left. ``hostname`` is an optional VERIFIED reverse-DNS
    name used only by the mail-provider proxy override.
    """
    clean_ip = str(ip_address).strip()

    if GEO_OVERRIDE is not None:                      # lab only: pretend locations for the simulated sender addresses
        simulated = GEO_OVERRIDE(clean_ip)
        if simulated is not None:
            return dict(simulated)

    cached = _cache_get(clean_ip)
    if cached is not None:
        return cached

    if is_rfc1918_or_private(clean_ip):
        result = {
            "ip": clean_ip, "city": "Internal LAN", "country": "Private Network (RFC-1918)",
            "lat": 0.0, "lon": 0.0, "isp": "Local / Corporate Gateway", "asn": "N/A",
            "is_suspicious_proxy": False, "is_proxy": False, "is_hosting": False,
            "is_private": True, "status": "internal",
        }
        _cache_put(clean_ip, result, _SUCCESS_TTL)
        return dict(result)

    def call_timeout() -> Optional[float]:
        if deadline is None:
            return timeout
        remaining = deadline - time.monotonic()
        if remaining <= 0.05:
            return None
        return min(timeout, remaining)

    # Provider 1: ipwho.is over HTTPS
    t = call_timeout()
    if t is not None:
        try:
            res = requests.get(IPWHO_URL.format(ip=clean_ip), timeout=t)
            if res.status_code == 200:
                d = res.json()
                if d.get("success"):
                    conn = d.get("connection") or {}
                    sec = d.get("security") or {}
                    is_proxy = bool(sec.get("proxy") or sec.get("vpn") or sec.get("tor"))
                    is_hosting = bool(sec.get("hosting"))
                    asn = f"AS{conn['asn']}" if conn.get("asn") else "Unknown"
                    isp = conn.get("isp") or conn.get("org") or "Unknown"
                    if not sec:
                        # ipwho.is free tier has no proxy/hosting data: consult ip-api for the flags only
                        # (plain HTTP, logged) so Tor/VPN/hosting detection is not lost.
                        t2 = call_timeout()
                        if t2 is not None:
                            try:
                                logger.info(f"Querying plain-HTTP ip-api.com for proxy flags of {clean_ip}")
                                r2 = requests.get(IP_API_URL.format(ip=clean_ip), timeout=t2)
                                d2 = r2.json() if r2.status_code == 200 else {}
                                if d2.get("status") == "success":
                                    is_proxy = bool(d2.get("proxy", False))
                                    is_hosting = bool(d2.get("hosting", False))
                            except Exception as e:
                                logger.warning(f"ip-api.com flag lookup failed for {clean_ip}: {e}")
                    if is_proxy and _is_known_legitimate_mail_provider(isp, asn, hostname):
                        is_proxy = False
                    result = {
                        "ip": clean_ip, "city": d.get("city") or "Unknown",
                        "country": d.get("country") or "Unknown",
                        "lat": float(d.get("latitude") or 0.0), "lon": float(d.get("longitude") or 0.0),
                        "isp": isp, "asn": asn,
                        "is_suspicious_proxy": is_proxy, "is_proxy": is_proxy, "is_hosting": is_hosting,
                        "is_private": False, "status": "success", "provider": "ipwho.is",
                    }
                    _cache_put(clean_ip, result, _SUCCESS_TTL)
                    return dict(result)
        except Exception as e:
            logger.warning(f"ipwho.is lookup failed for {clean_ip}: {e}")

    # Provider 2 (fallback): ip-api.com - HTTP ONLY on the free tier.
    t = call_timeout()
    if t is not None:
        try:
            logger.info(f"Falling back to plain-HTTP ip-api.com for {clean_ip} (free tier has no HTTPS)")
            response = requests.get(IP_API_URL.format(ip=clean_ip), timeout=t)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    isp_name = data.get("isp") or "Unknown"
                    asn_name = data.get("as") or "Unknown"
                    is_proxy = bool(data.get("proxy", False))
                    is_hosting = bool(data.get("hosting", False))
                    if is_proxy and _is_known_legitimate_mail_provider(isp_name, asn_name, hostname):
                        logger.info(f"Clearing proxy flag for {clean_ip}: first-party mail provider ASN {asn_name}")
                        is_proxy = False
                    result = {
                        "ip": clean_ip, "city": data.get("city") or "Unknown",
                        "country": data.get("country") or "Unknown",
                        "lat": float(data.get("lat", 0.0)), "lon": float(data.get("lon", 0.0)),
                        "isp": isp_name, "asn": asn_name,
                        "is_suspicious_proxy": is_proxy, "is_proxy": is_proxy, "is_hosting": is_hosting,
                        "is_private": False, "status": "success", "provider": "ip-api.com",
                    }
                    _cache_put(clean_ip, result, _SUCCESS_TTL)
                    return dict(result)
                logger.warning(f"IP-API returned fail for {clean_ip}: {data.get('message')}")
        except Exception as e:
            logger.warning(f"ip-api.com lookup failed for {clean_ip}: {e}")

    out_of_time = deadline is not None and (deadline - time.monotonic()) <= 0.05
    failure = _fail_result(clean_ip, "timeout" if out_of_time else "fail")
    if not out_of_time:
        _cache_put(clean_ip, failure, _FAILURE_TTL)  # brief negative cache
    return dict(failure)


def generate_route_map(ip_list: List[Union[str, Dict[str, Any]]],
                       max_hops: int = MAX_ROUTE_HOPS,
                       time_budget: float = ROUTE_TIME_BUDGET) -> List[Dict[str, Any]]:
    """
    Maps each IP (or hop dict from email_forensics) to GPS coordinates and network metadata.

    At most ``max_hops`` (15) hops are resolved and all lookups share ``time_budget`` seconds.
    Every entry carries ``hops_truncated`` (True when the input had more addressable hops than
    ``max_hops``), ``is_proxy``, ``is_hosting`` and ``is_suspicious_proxy``.
    """
    deadline = time.monotonic() + time_budget

    targets: List[str] = []
    for item in ip_list or []:
        ip_str = None
        if isinstance(item, str):
            ip_str = item.strip()
        elif isinstance(item, dict):
            if item.get("public_ips"):
                ip_str = item["public_ips"][0]
            elif item.get("extracted_ips"):
                ip_str = item["extracted_ips"][0]
            elif item.get("ip"):
                ip_str = item["ip"]
        if ip_str:
            targets.append(ip_str)

    truncated = len(targets) > max_hops
    targets = targets[:max_hops]

    route_map = []
    for counter, ip_str in enumerate(targets, start=1):
        geo_info = resolve_ip_location(ip_str, deadline=deadline)
        route_map.append({
            "hop_number": counter,
            "ip": geo_info.get("ip", ip_str),
            "city": geo_info.get("city", "Unknown"),
            "country": geo_info.get("country", "Unknown"),
            "lat": geo_info.get("lat", 0.0),
            "lon": geo_info.get("lon", 0.0),
            "isp": geo_info.get("isp", "Unknown"),
            "asn": geo_info.get("asn", "Unknown"),
            "is_suspicious_proxy": bool(geo_info.get("is_suspicious_proxy", False)),
            "is_proxy": bool(geo_info.get("is_proxy", False)),
            "is_hosting": bool(geo_info.get("is_hosting", False)),
            "geo_status": geo_info.get("status", "fail"),
            "hops_truncated": truncated,
        })
    return route_map
