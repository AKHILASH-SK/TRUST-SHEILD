"""
TrustShield V2 - WHOIS & Domain Intelligence Module (whois_intel.py)
Performs domain registration intelligence analysis to identify:
  - Newly registered / burner domains (< 30 days old)
  - Privacy-shielded registrations
  - Suspicious registrar patterns
  - DNS record anomalies
Integrates into the unified email forensics pipeline as Tier 3 infrastructure attribution.
"""

import logging
import re
from datetime import datetime, timezone
from typing import Dict, Any, Optional

import dns.resolver
import dns.exception

logger = logging.getLogger(__name__)

# Registrars commonly used by attackers for anonymous bulk registrations
SUSPICIOUS_REGISTRARS = [
    "namecheap", "porkbun", "njalla", "privacyguardian", "domainsbyproxy",
    "whoisguard", "privacyprotect", "networksolutions privacy", "contactprivacy",
    "identity protection"
]

# Privacy shield markers found in WHOIS data
PRIVACY_SHIELD_MARKERS = [
    "privacy", "whoisguard", "redacted for privacy", "identity shield",
    "contact privacy", "domains by proxy", "protected", "registrant name: redacted"
]


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
    """Safely convert a whois field value (may be list or string) to a plain string."""
    if val is None:
        return ""
    if isinstance(val, list):
        return str(val[0]) if val else ""
    return str(val)


def lookup_whois(domain: str) -> Dict[str, Any]:
    """
    Performs a WHOIS lookup on the given domain and returns structured intelligence.

    Returns:
        {
          "domain": str,
          "registrar": str,
          "creation_date": str (ISO),
          "expiry_date": str (ISO),
          "domain_age_days": int | None,
          "is_newly_registered": bool,   # True if < 30 days old
          "is_privacy_shielded": bool,   # Registrant details hidden
          "is_suspicious_registrar": bool,
          "registrant_country": str,
          "whois_risk_score": float,     # 0.0 – 100.0
          "whois_risk_flags": list[str],
          "whois_available": bool        # False if WHOIS lookup failed
        }
    """
    base = {
        "domain": domain,
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

    if not domain or len(domain) < 3:
        return base

    # ---- Try python-whois ------------------------------------------------
    try:
        import whois as pywhois  # package name: python-whois (whois==0.9.7 in requirements)
        w = pywhois.whois(domain)
    except Exception as e:
        logger.warning(f"WHOIS lookup failed for {domain}: {e}")
        base["whois_risk_flags"].append(f"WHOIS lookup unavailable: {str(e)[:80]}")
        # Even without WHOIS, we can still run a basic DNS check
        base["whois_available"] = False
        # Don't abort — fall through to DNS checks
        w = None

    risk_score = 0.0
    flags = []

    if w is not None:
        base["whois_available"] = True

        # Registrar
        registrar = _safe_str(getattr(w, "registrar", None))
        base["registrar"] = registrar or "Unknown"

        registrar_lower = registrar.lower()
        if any(susp in registrar_lower for susp in SUSPICIOUS_REGISTRARS):
            base["is_suspicious_registrar"] = True
            risk_score += 20.0
            flags.append(f"SUSPICIOUS_REGISTRAR: '{registrar}' commonly used for anonymous bulk registrations")

        # Creation date
        creation = getattr(w, "creation_date", None)
        if isinstance(creation, list):
            creation = creation[0]
        base["creation_date"] = creation.isoformat() if hasattr(creation, "isoformat") else str(creation or "Unknown")
        age_days = _days_since(creation if isinstance(creation, datetime) else None)
        base["domain_age_days"] = age_days

        if age_days is not None and age_days < 30:
            base["is_newly_registered"] = True
            risk_score += 40.0
            flags.append(f"NEWLY_REGISTERED_DOMAIN: Domain registered only {age_days} day(s) ago (< 30 days)")
        elif age_days is not None and age_days < 90:
            risk_score += 15.0
            flags.append(f"RECENTLY_REGISTERED_DOMAIN: Domain registered {age_days} days ago (< 90 days)")

        # Expiry date
        expiry = getattr(w, "expiration_date", None)
        if isinstance(expiry, list):
            expiry = expiry[0]
        base["expiry_date"] = expiry.isoformat() if hasattr(expiry, "isoformat") else str(expiry or "Unknown")

        # Registrant country
        country = _safe_str(getattr(w, "country", None))
        base["registrant_country"] = country or "Unknown"

        # Privacy shielding
        registrant_name = _safe_str(getattr(w, "name", None)).lower()
        org = _safe_str(getattr(w, "org", None)).lower()
        combined_text = f"{registrant_name} {org} {registrar_lower}"
        if any(marker in combined_text for marker in PRIVACY_SHIELD_MARKERS):
            base["is_privacy_shielded"] = True
            risk_score += 15.0
            flags.append("PRIVACY_SHIELDED: Registrant identity hidden behind privacy protection service")

    # ---- DNS anomaly checks (always run, even if WHOIS failed) ------------
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3.0
        resolver.lifetime = 3.0

        # Check for A record — domain must resolve to something
        try:
            a_records = resolver.resolve(domain, 'A')
            a_ips = [str(r) for r in a_records]
            # Flag if domain resolves to known free hosting (vercel, netlify, github pages)
            free_hosting_patterns = ["vercel", "netlify", "github", "render", "glitch", "replit", "pages.dev"]
            for ip_or_host in a_ips:
                pass  # IP-level hosting check done in geo_tracer
        except Exception:
            flags.append("NO_A_RECORD: Domain does not resolve to any IP address")
            risk_score += 10.0

        # Check for MX records (already done in email_forensics, but recheck here for completeness)
        try:
            resolver.resolve(domain, 'MX')
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            flags.append("NO_MX_RECORD: Domain has no mail exchange records — likely a burner/attacker domain")
            risk_score += 20.0
        except Exception:
            pass

        # Check for TXT / SPF
        try:
            txt_answers = resolver.resolve(domain, 'TXT')
            txt_strings = []
            for rdata in txt_answers:
                for s in rdata.strings:
                    txt_strings.append(s.decode('utf-8', errors='ignore') if isinstance(s, bytes) else str(s))
            has_spf = any(t.startswith("v=spf1") for t in txt_strings)
            if not has_spf:
                flags.append("NO_SPF_RECORD: Domain publishes no SPF policy — easy to spoof")
                risk_score += 10.0
        except Exception:
            pass

    except Exception as e:
        logger.debug(f"DNS checks failed for {domain}: {e}")

    # Cap score
    base["whois_risk_score"] = round(min(100.0, risk_score), 1)
    base["whois_risk_flags"] = flags
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
