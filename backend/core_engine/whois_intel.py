"""
TrustShield V2 - WHOIS & Domain Intelligence Module (whois_intel.py)
Performs domain registration intelligence analysis to identify:
  - Newly registered / burner domains (< 30 days old)
  - Privacy-shielded registrations
  - Suspicious registrar patterns
  - DNS record anomalies
Uses ICANN RDAP (REST over HTTPS - port 443) as primary lookup engine to ensure
100% cloud compatibility (bypassing outbound port 43 firewall blocks on Render / AWS),
with graceful fallback to python-whois and DNS heuristics.
"""

import logging
import re
from datetime import datetime, timezone
from typing import Dict, Any, Optional

import requests
import dns.resolver
import dns.exception

logger = logging.getLogger(__name__)

# Registrars commonly used by attackers for anonymous bulk registrations
SUSPICIOUS_REGISTRARS = [
    "namecheap", "porkbun", "njalla", "privacyguardian", "domainsbyproxy",
    "whoisguard", "privacyprotect", "networksolutions privacy", "contactprivacy",
    "identity protection", "tucows domains"
]

# Privacy shield markers found in WHOIS data
PRIVACY_SHIELD_MARKERS = [
    "privacy", "whoisguard", "redacted for privacy", "identity shield",
    "contact privacy", "domains by proxy", "protected", "registrant name: redacted",
    "withheld", "statutory masking"
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


def _lookup_rdap(domain: str) -> Optional[Dict[str, Any]]:
    """
    Performs an ICANN RDAP (RFC 7482 / RFC 9083) query over standard HTTPS (port 443).
    Bypasses port 43 firewall restrictions present on Render, AWS, and modern cloud platforms.
    """
    try:
        url = f"https://rdap.org/domain/{domain}"
        headers = {
            "Accept": "application/rdap+json, application/json",
            "User-Agent": "TrustShield-Forensics/2.0 (Forensic Intelligence Platform)"
        }
        resp = requests.get(url, headers=headers, timeout=3.5, allow_redirects=True)
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 404:
            logger.info(f"RDAP returned 404 for {domain} (unregistered or NXDOMAIN)")
            return {"unregistered": True}
    except Exception as e:
        logger.debug(f"RDAP query failed for {domain}: {e}")
    return None


def lookup_whois(domain: str) -> Dict[str, Any]:
    """
    Performs a WHOIS / RDAP lookup on the given domain and returns structured intelligence.

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
    domain = (domain or "").strip().lower()
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

    if not domain or len(domain) < 3 or "." not in domain:
        return base

    risk_score = 0.0
    flags = []
    rdap_success = False

    # ---- 1. Primary: ICANN RDAP via HTTPS ---------------------------------
    rdap_data = _lookup_rdap(domain)

    if rdap_data:
        if rdap_data.get("unregistered"):
            flags.append("UNREGISTERED_DOMAIN: Domain has no active WHOIS registration record")
            risk_score += 35.0
            base["whois_available"] = False
        else:
            base["whois_available"] = True
            rdap_success = True

            # Registration / Expiry dates
            for ev in rdap_data.get("events", []):
                act = ev.get("eventAction")
                dt = ev.get("eventDate")
                if act == "registration" and dt:
                    base["creation_date"] = dt
                elif act == "expiration" and dt:
                    base["expiry_date"] = dt

            # Entities: Registrar, Country, Privacy Shield
            adr_country = ""
            for ent in rdap_data.get("entities", []):
                roles = ent.get("roles", [])
                vcard = ent.get("vcardArray", [])

                # Registrar name
                if "registrar" in roles and len(vcard) > 1:
                    for item in vcard[1]:
                        if item[0] == "fn" and item[3]:
                            base["registrar"] = str(item[3]).strip()

                # Registrant address / country
                if len(vcard) > 1:
                    for item in vcard[1]:
                        if item[0] == "adr" and isinstance(item[3], list) and item[3]:
                            cand = str(item[3][-1]).strip()
                            if cand and len(cand) <= 3:
                                adr_country = cand

                # Privacy indicators
                handle = str(ent.get("handle", "")).lower()
                ent_name = ""
                if len(vcard) > 1:
                    for item in vcard[1]:
                        if item[0] == "fn":
                            ent_name = str(item[3]).lower()
                combined_entity = f"{handle} {ent_name}"
                if any(p in combined_entity for p in PRIVACY_SHIELD_MARKERS):
                    base["is_privacy_shielded"] = True

            base["registrant_country"] = _infer_country(domain, adr_country)

    # ---- 2. Well-Known Domain Fast-Path (if RDAP didn't populate) ---------
    if not rdap_success and domain in WELL_KNOWN_DOMAINS:
        wk = WELL_KNOWN_DOMAINS[domain]
        base["whois_available"] = True
        base["registrar"] = wk["registrar"]
        base["creation_date"] = wk["creation_date"]
        base["registrant_country"] = wk["country"]
        rdap_success = True

    # ---- 3. Fallback: python-whois (for local execution) -----------------
    if not rdap_success:
        try:
            import whois as pywhois
            w = pywhois.whois(domain)
            if w and getattr(w, "domain_name", None):
                base["whois_available"] = True
                registrar = _safe_str(getattr(w, "registrar", None))
                if registrar:
                    base["registrar"] = registrar

                creation = getattr(w, "creation_date", None)
                if isinstance(creation, list):
                    creation = creation[0]
                if creation:
                    base["creation_date"] = creation.isoformat() if hasattr(creation, "isoformat") else str(creation)

                expiry = getattr(w, "expiration_date", None)
                if isinstance(expiry, list):
                    expiry = expiry[0]
                if expiry:
                    base["expiry_date"] = expiry.isoformat() if hasattr(expiry, "isoformat") else str(expiry)

                country = _safe_str(getattr(w, "country", None))
                base["registrant_country"] = _infer_country(domain, country)

                # Privacy check
                registrant_name = _safe_str(getattr(w, "name", None)).lower()
                org = _safe_str(getattr(w, "org", None)).lower()
                combined_text = f"{registrant_name} {org} {registrar.lower()}"
                if any(marker in combined_text for marker in PRIVACY_SHIELD_MARKERS):
                    base["is_privacy_shielded"] = True
        except Exception as e:
            logger.debug(f"Local python-whois fallback failed for {domain}: {e}")

    # ---- 4. Calculate Domain Age & Evaluate Risk --------------------------
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

    # Check suspicious registrar
    registrar_lower = (base.get("registrar") or "").lower()
    if any(susp in registrar_lower for susp in SUSPICIOUS_REGISTRARS):
        base["is_suspicious_registrar"] = True
        risk_score += 20.0
        flags.append(f"SUSPICIOUS_REGISTRAR: '{base['registrar']}' commonly used for anonymous bulk registrations")

    # Check privacy shield
    if base["is_privacy_shielded"]:
        risk_score += 15.0
        flags.append("PRIVACY_SHIELDED: Registrant identity hidden behind privacy protection service")

    # Ensure country is always a human-readable string
    if not base["registrant_country"] or base["registrant_country"] == "Unknown":
        base["registrant_country"] = _infer_country(domain)

    # ---- 5. DNS Anomaly Checks (always run) ------------------------------
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.5
        resolver.lifetime = 2.5

        # Check for A record
        try:
            resolver.resolve(domain, 'A')
        except Exception:
            flags.append("NO_A_RECORD: Domain does not resolve to any IP address")
            risk_score += 10.0

        # Check for MX records
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
