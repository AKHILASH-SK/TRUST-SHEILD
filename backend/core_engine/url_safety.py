"""
TrustShield - URL safety guard (SSRF protection).

Every place that makes the server fetch a user-supplied URL (sandbox, redirect
following, forensic link analysis) must call `assert_public_url` first, and again
for every redirect hop. It rejects non-http(s) schemes, credentials in the URL,
and any host that resolves to a private, loopback, link-local, multicast,
reserved or otherwise non-global address.
"""

import ipaddress
import socket
from typing import List
from urllib.parse import urlparse

ALLOWED_SCHEMES = ("http", "https")
MAX_URL_LENGTH = 2048


class UnsafeUrlError(ValueError):
    """Raised when a URL must not be fetched by the server."""


def _is_public_ip(ip_text: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_text.split("%")[0])
    except ValueError:
        return False
    # IPv4-mapped IPv6 (::ffff:10.0.0.1) must be judged by the embedded address.
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return ip.is_global and not ip.is_multicast


def resolve_host(host: str) -> List[str]:
    """Resolve a hostname to all of its IP addresses (A and AAAA)."""
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return sorted({info[4][0] for info in infos})


def assert_public_url(url: str) -> str:
    """
    Return the URL unchanged if it is safe to fetch, otherwise raise UnsafeUrlError.
    DNS is resolved here, so call this immediately before each fetch.
    """
    if not url or len(url) > MAX_URL_LENGTH:
        raise UnsafeUrlError("URL is empty or too long")

    parsed = urlparse(url if "://" in url else f"http://{url}")
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise UnsafeUrlError(f"Scheme '{parsed.scheme}' is not allowed")
    if parsed.username or parsed.password:
        raise UnsafeUrlError("Credentials in URL are not allowed")

    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if not host:
        raise UnsafeUrlError("URL has no host")
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
        raise UnsafeUrlError("Local hostnames are not allowed")

    try:
        addresses = [host] if _looks_like_ip(host) else resolve_host(host)
    except socket.gaierror:
        raise UnsafeUrlError("Host does not resolve")

    if not addresses:
        raise UnsafeUrlError("Host does not resolve")
    for address in addresses:
        if not _is_public_ip(address):
            raise UnsafeUrlError("Host resolves to a non-public address")
    return url


def is_public_url(url: str) -> bool:
    """Boolean wrapper around assert_public_url."""
    try:
        assert_public_url(url)
        return True
    except UnsafeUrlError:
        return False


def _looks_like_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False
