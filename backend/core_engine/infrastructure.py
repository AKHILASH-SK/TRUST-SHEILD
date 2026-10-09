"""
Infrastructure check for the links of an email: how does the attacker's domain behave (fast-flux) and is its certificate worth
trusting. Trusted companies, hosting platforms, shorteners and bare IP addresses are skipped (their DNS and certificates say
nothing about the page). Everything is time-boxed: a slow DNS server or an unreachable port never holds up the verdict.
"""
import logging
import os
from concurrent.futures import ThreadPoolExecutor, wait
from typing import Any, Dict, List
from urllib.parse import urlparse

import tldextract

from . import fast_flux, tls_inspector

logger = logging.getLogger(__name__)

MAX_DOMAINS = 5
TOTAL_SECONDS = 7.0
_TLD = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def _lab() -> bool:
    return os.environ.get("TRUSTSHIELD_LAB_MODE", "").strip() == "1"


def _candidates(urls: List[str]) -> List[Dict[str, Any]]:
    from .link_threat_pipeline import is_brand_fast_path, is_user_content_host, is_collab_platform
    seen: Dict[str, Dict[str, Any]] = {}
    for url in urls:
        try:
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower().rstrip(".")
        except Exception:
            continue
        if not host or host in seen:
            continue
        if host.replace(".", "").isdigit() or ":" in host:
            continue                                                    # a bare IP address
        if is_brand_fast_path(url) or is_collab_platform(url) or is_user_content_host(url):
            continue
        seen[host] = {"host": host, "https": parsed.scheme == "https", "port": parsed.port or 443}
        if len(seen) >= MAX_DOMAINS:
            break
    return list(seen.values())


def _inspect_one(item: Dict[str, Any]) -> Dict[str, Any]:
    host = item["host"]
    lab_dns = _lab() and host.endswith(".test")
    lookup = fast_flux.system_lookup_factory("127.0.0.1", 5353) if lab_dns else None
    flux = fast_flux.inspect_domain(host, lookup=lookup)
    cert = None
    if item["https"] and not lab_dns:
        cert = tls_inspector.inspect_certificate(host, item["port"])
    return {"domain": host, "fast_flux": flux, "certificate": cert}


def inspect_links(urls: List[str]) -> Dict[str, Any]:
    """{"domains": [...], "flux_domains": n, "untrusted_certificates": n}. Never raises."""
    try:
        items = _candidates(urls)
        if not items:
            return {"domains": [], "flux_domains": 0, "untrusted_certificates": 0}
        pool = ThreadPoolExecutor(max_workers=len(items))
        futures = {pool.submit(_inspect_one, it): it for it in items}
        done, _pending = wait(futures, timeout=TOTAL_SECONDS)
        pool.shutdown(wait=False, cancel_futures=True)
        results = []
        for fut in done:
            try:
                results.append(fut.result())
            except Exception as exc:
                logger.debug("infrastructure check failed: %s", exc)
        results.sort(key=lambda r: r["domain"])
        return {"domains": results,
                "flux_domains": sum(1 for r in results if r["fast_flux"].get("level") == "fast_flux"),
                "untrusted_certificates": sum(1 for r in results if (r.get("certificate") or {}).get("level") == "untrusted")}
    except Exception as exc:
        logger.warning("infrastructure check error: %s", exc)
        return {"domains": [], "flux_domains": 0, "untrusted_certificates": 0}
