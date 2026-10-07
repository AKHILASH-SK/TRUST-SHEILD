"""
TrustShield V2 - WHOIS & Domain Intelligence Module (whois_intel.py)
Performs domain registration intelligence analysis to identify:
  - Newly registered / burner domains (< 30 days old)
  - Privacy-redacted registrations (informational only, never penalised)
  - DNS record anomalies
Uses ICANN RDAP (REST over HTTPS - port 443) via rdap.org as the ONLY registration lookup
engine (works on cloud hosts that block outbound port 43). There is deliberately no port-43
python-whois fallback. Registrar identity is NOT used as a risk signal: Namecheap, Tucows,
Porkbun, etc. are used by millions of legitimate domains.
"""

import logging
import re
import threading
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Set
from urllib.parse import quote, urljoin

import requests
import tldextract
import dns.resolver
import dns.exception

from .url_safety import assert_public_url, UnsafeUrlError

logger = logging.getLogger(__name__)

RDAP_BASE = "https://rdap.org/domain/"
RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
RDAP_TIMEOUT = (3.0, 3.5)  # (connect, read)
DNS_TIMEOUT = 2.5
_MAX_REDIRECTS = 3

# Offline-safe public-suffix extractor (bundled snapshot, no network fetch).
_TLD = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

# Strict hostname: dot-separated LDH labels, alphabetic (or punycode) TLD, <= 253 chars.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$"
)

# Markers (matched against REGISTRANT entity name/handle only) for privacy-redacted records.
# Informational only - privacy redaction is the GDPR default for most registrars.
PRIVACY_SHIELD_MARKERS = [
    "redacted for privacy", "whoisguard", "domains by proxy", "domainsbyproxy",
    "contact privacy", "privacy service", "privacyguardian", "withheld for privacy",
    "statutory masking", "identity protection service",
]

# ccTLD to country mapping for reliable fallback
TLD_COUNTRY_MAP = {
    "in": "India", "co.in": "India", "net.in": "India", "org.in": "India",
    "uk": "United Kingdom", "co.uk": "United Kingdom",
    "us": "United States", "ca": "Canada", "de": "Germany", "fr": "France",
    "au": "Australia", "jp": "Japan", "ru": "Russia", "cn": "China",
    "sg": "Singapore", "nl": "Netherlands", "br": "Brazil", "ch": "Switzerland"
}

# Authoritative registration metadata for well-known infrastructure domains
WELL_KNOWN_DOMAINS = {
    "gmail.com": {"registrar": "MarkMonitor Inc.", "creation_date": "1995-08-13T04:00:00Z", "country": "United States"},
    "google.com": {"registrar": "MarkMonitor Inc.", "creation_date": "1997-09-15T04:00:00Z", "country": "United States"},
    "microsoft.com": {"registrar": "MarkMonitor Inc.", "creation_date": "1991-05-02T04:00:00Z", "country": "United States"},
    "yahoo.com": {"registrar": "MarkMonitor Inc.", "creation_date": "1995-01-18T05:00:00Z", "country": "United States"},
    "apple.com": {"registrar": "CSC Corporate Domains, Inc.", "creation_date": "1987-02-19T05:00:00Z", "country": "United States"},
    "linkedin.com": {"registrar": "MarkMonitor Inc.", "creation_date": "2002-11-02T15:38:11Z", "country": "United States"},
    "github.com": {"registrar": "MarkMonitor Inc.", "creation_date": "2007-10-09T18:20:50Z", "country": "United States"},
    "outlook.com": {"registrar": "MarkMonitor Inc.", "creation_date": "1998-05-05T04:00:00Z", "country": "United States"}
}


def _days_since(dt: Optional[datetime]) -> Optional[int]:
    """Returns the number of days since a given datetime, or None if dt is None."""
    if dt is None:
        return None
    try:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        delta = datetime.now(timezone.utc) - dt
        return max(0, delta.days)
    except Exception:
        return None


def _safe_str(val) -> str:
    """Safely convert a field value (may be list or string) to a plain string."""
    if val is None:
        return ""
    if isinstance(val, list):
        return str(val[0]) if val else ""
    return str(val).strip()


def _infer_country(domain: str, adr_country: str = "") -> str:
    """Infers domain registrant country using address, TLD heuristics, or well-known lookup."""
    if adr_country and adr_country.upper() not in ["UNKNOWN", "NONE", ""]:
        return adr_country

    d_clean = domain.lower().strip()
    if d_clean in WELL_KNOWN_DOMAINS:
        return WELL_KNOWN_DOMAINS[d_clean].get("country", "United States")

    parts = d_clean.split(".")
    if len(parts) >= 2:
        tld = parts[-1]
        if tld in TLD_COUNTRY_MAP:
            return TLD_COUNTRY_MAP[tld]
        if len(parts) >= 3:
            two_part = f"{parts[-2]}.{parts[-1]}"
            if two_part in TLD_COUNTRY_MAP:
                return TLD_COUNTRY_MAP[two_part]

    if d_clean.endswith(".com") or d_clean.endswith(".net") or d_clean.endswith(".org"):
        return "United States"

    return "Global / Unrestricted"


_bootstrap_lock = threading.Lock()
_bootstrap_cache: Dict[str, Any] = {"tlds": None, "fetched": 0.0}
_BOOTSTRAP_TTL = 86400.0


def _normalise_domain(domain: str) -> Optional[str]:
    """Validate strictly and reduce to the registrable domain, or None if invalid."""
    d = (domain or "").strip().lower().rstrip(".")
    if not _DOMAIN_RE.match(d):
        return None
    try:
        res = _TLD(d)
        reg = getattr(res, 'top_domain_under_public_suffix', None) or res.registered_domain
    except Exception:
        reg = ""
    reg = (reg or "").lower()
    return reg if reg and _DOMAIN_RE.match(reg) else None


def _rdap_get(url: str):
    """GET with SSRF checks on the URL and every redirect hop (rdap.org redirects to registries)."""
    headers = {
        "Accept": "application/rdap+json, application/json",
        "User-Agent": "TrustShield-Forensics/2.0 (Forensic Intelligence Platform)",
    }
    for _ in range(_MAX_REDIRECTS + 1):
        assert_public_url(url)
        resp = requests.get(url, headers=headers, timeout=RDAP_TIMEOUT, allow_redirects=False)
        if resp.status_code in (301, 302, 303, 307, 308) and resp.headers.get("Location"):
            url = urljoin(url, resp.headers["Location"])
            continue
        return resp
    return None


def _rdap_supported_tlds() -> Optional[Set[str]]:
    """TLDs that have an RDAP service per the IANA bootstrap file; None if it cannot be fetched."""
    with _bootstrap_lock:
        cached = _bootstrap_cache["tlds"]
        if cached is not None and time.monotonic() - _bootstrap_cache["fetched"] < _BOOTSTRAP_TTL:
            return cached
    try:
        resp = _rdap_get(RDAP_BOOTSTRAP_URL)
        if resp is None or resp.status_code != 200:
            return None
        tlds: Set[str] = set()
        for entry in resp.json().get("services", []):
            for t in entry[0]:
                tlds.add(str(t).lower())
        with _bootstrap_lock:
            _bootstrap_cache["tlds"] = tlds
            _bootstrap_cache["fetched"] = time.monotonic()
        return tlds
    except Exception as e:
        logger.debug(f"RDAP bootstrap fetch failed: {e}")
        return None


def _lookup_rdap(registrable: str) -> Optional[Dict[str, Any]]:
    """
    RDAP query (RFC 7482 / 9083) for a REGISTRABLE domain.
    Returns the RDAP JSON; {"unregistered": True} only when the registrable domain 404s on a TLD
    that is known to support RDAP; {"unknown": True} for any other 404; None on failure.
    """
    try:
        resp = _rdap_get(RDAP_BASE + quote(registrable, safe=""))
    except UnsafeUrlError as e:
        logger.warning(f"RDAP URL rejected by SSRF guard: {e}")
        return None
    except Exception as e:
        logger.debug(f"RDAP query failed for {registrable}: {e}")
        return None
    if resp is None:
        return None
    if resp.status_code == 200:
        try:
            return resp.json()
        except ValueError:
            return None
    if resp.status_code == 404:
        tld = registrable.rsplit(".", 1)[-1]
        supported = _rdap_supported_tlds()
        if supported is not None and tld in supported:
            return {"unregistered": True}
        return {"unknown": True}
    return None


def lookup_whois(domain: str) -> Dict[str, Any]:
    """
    Performs an RDAP lookup on the registrable domain of ``domain`` and returns structured intelligence.

    Returns:
        {
          "domain": str, "registrable_domain": str | None,
          "registrar": str, "creation_date": str (ISO), "expiry_date": str (ISO),
          "domain_age_days": int | None,
          "is_newly_registered": bool,      # True if < 30 days old
          "is_privacy_shielded": bool,      # Registrant redacted (informational only)
          "is_suspicious_registrar": bool,  # always False (registrar is not a risk signal)
          "registrant_country": str,
          "whois_risk_score": float,        # 0.0 - 100.0
          "whois_risk_flags": list[str],
          "whois_available": bool           # False if the lookup failed / was inconclusive
        }
    """
    domain = (domain or "").strip().lower()
    base = {
        "domain": domain,
        "registrable_domain": None,
        "registrar": "Unknown",
        "creation_date": None,
        "expiry_date": None,
        "domain_age_days": None,
        "is_newly_registered": False,
        "is_privacy_shielded": False,
        "is_suspicious_registrar": False,
        "registrant_country": "Unknown",
        "whois_risk_score": 0.0,
        "whois_risk_flags": [],
        "whois_available": False
    }

    registrable = _normalise_domain(domain)
    if not registrable:
        base["whois_risk_flags"].append("INFO: Not a valid registrable hostname; RDAP lookup skipped")
        return base
    base["registrable_domain"] = registrable

    risk_score = 0.0
    flags = base["whois_risk_flags"]
    rdap_success = False

    rdap_data = _lookup_rdap(registrable)
    unregistered = bool(rdap_data and rdap_data.get("unregistered"))

    if unregistered:
        flags.append("UNREGISTERED_DOMAIN: Registrable domain has no registration record (RDAP 404)")
        risk_score += 35.0
    elif rdap_data and rdap_data.get("unknown"):
        flags.append("INFO: RDAP returned 404 but registration status could not be established "
                     "(TLD without RDAP or bootstrap unavailable)")
    elif rdap_data:
        base["whois_available"] = True
        rdap_success = True

        for ev in rdap_data.get("events", []):
            act = ev.get("eventAction")
            dt = ev.get("eventDate")
            if act == "registration" and dt:
                base["creation_date"] = dt
            elif act == "expiration" and dt:
                base["expiry_date"] = dt

        adr_country = ""
        for ent in rdap_data.get("entities", []):
            roles = ent.get("roles", [])
            vcard = ent.get("vcardArray", [])
            items = vcard[1] if len(vcard) > 1 and isinstance(vcard[1], list) else []

            if "registrar" in roles:
                for item in items:
                    if item and item[0] == "fn" and item[3]:
                        base["registrar"] = str(item[3]).strip()

            for item in items:
                if item and item[0] == "adr" and isinstance(item[3], list) and item[3]:
                    cand = str(item[3][-1]).strip()
                    if cand and len(cand) <= 3:
                        adr_country = cand

            if "registrant" in roles:
                ent_name = ""
                for item in items:
                    if item and item[0] == "fn":
                        ent_name = str(item[3]).lower()
                combined_entity = f"{str(ent.get('handle', '')).lower()} {ent_name}"
                if any(p in combined_entity for p in PRIVACY_SHIELD_MARKERS):
                    base["is_privacy_shielded"] = True

        base["registrant_country"] = _infer_country(registrable, adr_country)

    # Well-known infrastructure fast-path (if RDAP didn't populate)
    if not rdap_success and not unregistered and registrable in WELL_KNOWN_DOMAINS:
        wk = WELL_KNOWN_DOMAINS[registrable]
        base["whois_available"] = True
        base["registrar"] = wk["registrar"]
        base["creation_date"] = wk["creation_date"]
        base["registrant_country"] = wk["country"]

    # Domain age & risk
    if base["creation_date"]:
        try:
            c_str = str(base["creation_date"]).replace("Z", "+00:00")
            c_dt = datetime.fromisoformat(c_str) if "T" in c_str else datetime.strptime(c_str[:10], "%Y-%m-%d")
            age_days = _days_since(c_dt)
            base["domain_age_days"] = age_days

            if age_days is not None and age_days < 30:
                base["is_newly_registered"] = True
                risk_score += 40.0
                flags.append(f"NEWLY_REGISTERED_DOMAIN: Domain registered only {age_days} day(s) ago (< 30 days)")
            elif age_days is not None and age_days < 90:
                risk_score += 15.0
                flags.append(f"RECENTLY_REGISTERED_DOMAIN: Domain registered {age_days} days ago (< 90 days)")
        except Exception:
            pass

    if base["is_privacy_shielded"]:
        flags.append("INFO: Registrant details are privacy-redacted (common default; not scored)")

    if not base["registrant_country"] or base["registrant_country"] == "Unknown":
        base["registrant_country"] = _infer_country(registrable)

    # DNS anomaly checks (only definitive NXDOMAIN/NoAnswer count; timeouts are ignored)
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT
        absent = (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer)

        try:
            resolver.resolve(domain, 'A')
        except absent:
            flags.append("NO_A_RECORD: Domain does not resolve to any IP address")
            risk_score += 10.0
        except Exception:
            pass

        try:
            resolver.resolve(domain, 'MX')
        except absent:
            flags.append("NO_MX_RECORD: Domain has no mail exchange records - likely a burner/attacker domain")
            risk_score += 20.0
        except Exception:
            pass

        try:
            txt_answers = resolver.resolve(domain, 'TXT')
            txt_strings = []
            for rdata in txt_answers:
                for part in rdata.strings:
                    txt_strings.append(part.decode('utf-8', errors='ignore') if isinstance(part, bytes) else str(part))
            if not any(t.lower().startswith("v=spf1") for t in txt_strings):
                flags.append("NO_SPF_RECORD: Domain publishes no SPF policy - easy to spoof")
                risk_score += 10.0
        except dns.resolver.NoAnswer:
            flags.append("NO_SPF_RECORD: Domain publishes no SPF policy - easy to spoof")
            risk_score += 10.0
        except Exception:
            pass
    except Exception as e:
        logger.debug(f"DNS checks failed for {domain}: {e}")

    base["whois_risk_score"] = round(min(100.0, risk_score), 1)
    return base


def enrich_forensics_with_whois(forensics_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convenience wrapper: reads from_domain out of a forensics result dict,
    runs WHOIS lookup, and injects the result as 'whois_intelligence' key.
    Also bumps overall_threat_score proportionally if high WHOIS risk is found.
    """
    from_domain = (
        forensics_result.get("metadata", {}).get("from_domain", "") or
        forensics_result.get("sender_domain_intelligence", {}).get("from_domain", "")
    )

    whois_data = lookup_whois(from_domain)
    forensics_result["whois_intelligence"] = whois_data

    # Contribute WHOIS risk to overall threat score (max +25 pts)
    whois_contribution = min(25.0, whois_data["whois_risk_score"] * 0.35)
    current_score = float(forensics_result.get("overall_threat_score", 0.0))
    new_score = round(min(100.0, current_score + whois_contribution), 1)
    forensics_result["overall_threat_score"] = new_score

    return forensics_result
