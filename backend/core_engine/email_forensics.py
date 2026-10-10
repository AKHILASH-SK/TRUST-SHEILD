"""
TrustShield V2 - Email Forensics & Protocol Ingestion Engine
Ingests raw .eml / .msg files, computes evidence hashes, traces Received: mail hops,
extracts the connecting / originating IPs, audits SPF/DKIM/DMARC authentication, and pulls
embedded payload text and URLs for sandbox detonation.

Authentication results are TRI-STATE ('pass' / 'fail' / 'indeterminate'). A DNS timeout or
SERVFAIL never produces a 'pass' and is never reported as a definitive 'fail': it yields
'indeterminate'. The legacy booleans (spf_pass / dkim_pass / dmarc_pass) are kept and are
True only for state == 'pass'.
"""

import email
import email.utils
import hashlib
import ipaddress
import logging
import os
import re
import time
from email import policy
from typing import Dict, Any, List, Optional, Tuple

from .htmlsafe import make_soup
import dns.resolver
import dns.exception
import dns.name
import dkim
import tldextract

logger = logging.getLogger(__name__)

# Per-lookup DNS timeout / lifetime (seconds) and the overall SPF evaluation budget.
DNS_TIMEOUT = 3.0
SPF_TIME_BUDGET = 6.0
SPF_MAX_LOOKUPS = 10
SPF_MAX_DEPTH = 10

# Lab only (see backend/lab): simulate senders with loopback addresses and answer DNS from a table instead of the internet.
LAB_MODE = os.environ.get("TRUSTSHIELD_LAB_MODE", "").strip() == "1"
DNS_OVERRIDE = None          # callable(name, rtype) -> list of strings, or None to fall through to real DNS

# Offline-safe tldextract: use the bundled public-suffix snapshot, never fetch over the network.
_TLD = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

IPV4_REGEX = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
# Candidate IPv6 tokens (validated afterwards with ipaddress); must contain ':'.
IPV6_CANDIDATE_REGEX = re.compile(r'(?<![0-9A-Za-z])[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*(?:%[0-9A-Za-z]+)?')

_HOST_PART = r'(?:(?:[a-z0-9-]+\.)+[a-z0-9]{2,}|(?:\d{1,3}\.){3}\d{1,3}|\[[0-9a-f:.]+\])'
URL_REGEX = re.compile(
    r'https?://' + _HOST_PART + r'(?::\d+)?(?:[/?#][^\s<>"\'\)]*)?',
    re.IGNORECASE,
)
# Scheme-less IP URL in plain text, e.g. "198.51.100.7/login" (a path is required to avoid
# matching version numbers / bare addresses).
BARE_IP_URL_REGEX = re.compile(
    r'(?<![\w./:@-])((?:\d{1,3}\.){3}\d{1,3}(?::\d+)?/[^\s<>"\'\)]*)',
)


class _DnsTempError(Exception):
    """A DNS lookup failed for a reason that is not a definitive 'no such record'."""


# ----------------------------------------------------------------------------
# Hashing / basic helpers
# ----------------------------------------------------------------------------
def compute_sha256(data: bytes) -> str:
    """SHA-256 digest of raw email bytes (evidence integrity)."""
    return hashlib.sha256(data).hexdigest()


def registered_domain(host: str) -> str:
    """Organizational (registrable) domain of a host, or the host itself if none."""
    host = (host or "").strip().strip(".").lower()
    if not host:
        return ""
    try:
        res = _TLD(host)
        reg = getattr(res, 'top_domain_under_public_suffix', None) or res.registered_domain
    except Exception:
        reg = ""
    return (reg or host).lower()


def is_public_ip(ip_str: str) -> bool:
    """
    True only for globally routable unicast addresses. Uses ipaddress' ``is_global`` so that
    private, loopback, link-local, CGNAT (100.64/10), documentation, reserved and multicast
    ranges are all treated as non-public. IPv4-mapped IPv6 is judged by the embedded address.
    """
    try:
        ip = ipaddress.ip_address(str(ip_str).strip().split("%")[0].strip("[]"))
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    if LAB_MODE and (ip.is_loopback or ip.is_private) and not ip.is_multicast:
        return True                  # the local lab simulates senders with 127.0.0.x addresses
    return bool(ip.is_global and not ip.is_multicast)


def extract_ips_from_string(text: str) -> List[str]:
    """Extracts all IPv4 and IPv6 addresses found within a header string (order preserved)."""
    if not text:
        return []
    found: List[Tuple[int, str]] = []
    for m in IPV4_REGEX.finditer(text):
        found.append((m.start(), m.group(0)))
    for m in IPV6_CANDIDATE_REGEX.finditer(text):
        cand = m.group(0).rstrip(".:").split("%")[0]
        if ":" not in cand:
            continue
        try:
            found.append((m.start(), str(ipaddress.IPv6Address(cand))))
        except ValueError:
            continue
    found.sort(key=lambda t: t[0])
    seen = set()
    result = []
    for _, ip in found:
        if ip not in seen:
            seen.add(ip)
            result.append(ip)
    return result


# "from helo.name (reverse.dns [203.0.113.9]) by ...": the address in square brackets inside the from-clause is the one the
# RECEIVING server saw on the connection. The HELO name before it is whatever the sender chose to say, so an address written
# there (or anywhere else in the header) must never be mistaken for the connecting IP.
_CONNECTION_IP = re.compile(r"\(\s*[^()]*?\[([0-9a-fA-F:.]+)\][^()]*\)")


def find_connecting_ip(received_headers: List[str]) -> Optional[str]:
    """
    The connecting IP is the address of the client that handed the message to OUR receiving
    MTA: it is recorded in the TOPMOST Received header (each MTA prepends its own). Headers
    holding only non-public addresses (internal hops) are skipped going downwards.
    The bracketed address of the from-clause is preferred; other addresses in the header are used only when the header
    has no bracketed one at all.
    """
    for header in received_headers or []:
        clean = " ".join(str(header).split())
        from_clause = clean.split(" by ", 1)[0]
        bracketed = [m.group(1) for m in _CONNECTION_IP.finditer(from_clause)]
        if bracketed:
            for ip in bracketed:
                if is_public_ip(ip):
                    return ip
            continue                                     # an internal hop: look further down, never at the HELO text
        for ip in extract_ips_from_string(clean):
            if is_public_ip(ip):
                return ip
    return None


def trace_originating_ip(received_headers: List[str]) -> Tuple[Optional[str], int, List[Dict[str, Any]]]:
    """
    Traces Received: headers from bottom (oldest) to top (newest).
    The earliest public IP is the CLAIMED originating IP: Received headers below the first
    trusted hop are attacker-controlled, so this is for attribution/geolocation only, never
    for authentication (use find_connecting_ip for SPF).

    Returns:
        (originating_ip, total_hops, hop_details)
    """
    if not received_headers:
        return None, 0, []

    reversed_hops = list(reversed([str(h) for h in received_headers]))
    total_hops = len(reversed_hops)
    hop_details = []
    originating_ip = None

    for idx, header in enumerate(reversed_hops, start=1):
        clean_header = " ".join(header.split())
        extracted_ips = extract_ips_from_string(clean_header)
        # the address the receiving server recorded (in brackets) comes first: text the sender chose (HELO) must not lead
        bracketed = [m.group(1) for m in _CONNECTION_IP.finditer(clean_header.split(" by ", 1)[0])]
        extracted_ips = [ip for ip in bracketed if ip in extracted_ips] + [ip for ip in extracted_ips if ip not in bracketed]
        public_ips = [ip for ip in extracted_ips if is_public_ip(ip)]

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
    """Extracts the domain part from an email address header."""
    if not address_header:
        return ""
    clean_addr = str(address_header).strip().strip("<>").strip()
    _, parsed_email = email.utils.parseaddr(clean_addr)
    target = parsed_email or clean_addr
    if "@" in target:
        return target.split("@")[-1].strip().strip(">").lower()
    return target.strip().lower()


# ----------------------------------------------------------------------------
# DNS
# ----------------------------------------------------------------------------
def _dns_lookup(name: str, rtype: str, timeout: float = DNS_TIMEOUT) -> List[str]:
    """
    Resolve ``name``/``rtype`` and return plain strings:
      TXT -> joined character-strings, A/AAAA -> address, MX -> "pref host".
    NXDOMAIN / NoAnswer -> [] (definitive). Timeouts, SERVFAIL etc. -> _DnsTempError.
    """
    if DNS_OVERRIDE is not None:
        answered = DNS_OVERRIDE(name, rtype)
        if answered is not None:
            return list(answered)
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    try:
        answers = resolver.resolve(name, rtype)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except (dns.name.NameTooLong, dns.name.LabelTooLong, dns.name.EmptyLabel):
        return []
    except dns.exception.DNSException as e:
        raise _DnsTempError(f"{type(e).__name__} resolving {rtype} {name}")
    out: List[str] = []
    for rdata in answers:
        if rtype == "TXT":
            out.append("".join(
                p.decode("utf-8", errors="ignore") if isinstance(p, bytes) else str(p)
                for p in rdata.strings))
        elif rtype in ("A", "AAAA"):
            out.append(str(rdata.address))
        elif rtype == "MX":
            out.append(f"{rdata.preference} {str(rdata.exchange).rstrip('.')}")
        else:
            out.append(str(rdata))
    return out


# ----------------------------------------------------------------------------
# SPF (RFC 7208 subset)
# ----------------------------------------------------------------------------
class _SpfAbort(Exception):
    def __init__(self, result: str, explanation: str):
        super().__init__(explanation)
        self.result = result
        self.explanation = explanation


class _SpfContext:
    def __init__(self, ip: "ipaddress._BaseAddress", budget: float):
        self.ip = ip
        self.deadline = time.monotonic() + budget
        self.lookups = 0

    def count_lookup(self) -> None:
        self.lookups += 1
        if self.lookups > SPF_MAX_LOOKUPS:
            raise _SpfAbort("permerror", f"SPF exceeded the {SPF_MAX_LOOKUPS} DNS-lookup limit")

    def dns(self, name: str, rtype: str) -> List[str]:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise _SpfAbort("temperror", "SPF evaluation exceeded its time budget")
        try:
            return _dns_lookup(name, rtype, timeout=min(DNS_TIMEOUT, remaining))
        except _DnsTempError as e:
            raise _SpfAbort("temperror", f"DNS error during SPF evaluation: {e}")


_MACRO_RE = re.compile(r'%\{([a-zA-Z])(\d*)(r?)([.\-+,/_=]*)\}|%%|%_|%-')


def _spf_expand(spec: str, domain: str, ctx: _SpfContext) -> str:
    if "%" not in spec:
        return spec

    def repl(m: "re.Match") -> str:
        tok = m.group(0)
        if tok == "%%":
            return "%"
        if tok == "%_":
            return " "
        if tok == "%-":
            return "%20"
        letter = m.group(1).lower()
        if letter == "d":
            val = domain
        elif letter == "i":
            val = ".".join(str(ctx.ip).split(".")) if ctx.ip.version == 4 else ".".join(ctx.ip.exploded.replace(":", ""))
        elif letter == "v":
            val = "in-addr" if ctx.ip.version == 4 else "ip6"
        else:
            raise _SpfAbort("temperror", f"SPF macro %{{{m.group(1)}}} is not supported")
        labels = val.split(".")
        if m.group(3):
            labels.reverse()
        if m.group(2):
            n = int(m.group(2))
            if n > 0:
                labels = labels[-n:]
        return ".".join(labels)

    return _MACRO_RE.sub(repl, spec)


def _split_cidr(spec: str) -> Tuple[str, Optional[int], Optional[int]]:
    """'dom/24//64' -> ('dom', 24, 64)."""
    c4 = c6 = None
    try:
        if "//" in spec:
            spec, tail = spec.split("//", 1)
            c6 = int(tail)
        if "/" in spec:
            spec, tail = spec.split("/", 1)
            c4 = int(tail)
    except ValueError:
        raise _SpfAbort("permerror", "Malformed CIDR length in SPF mechanism")
    return spec, c4, c6


def _addr_matches(ctx: _SpfContext, addrs: List[str], c4: Optional[int], c6: Optional[int]) -> bool:
    for a in addrs:
        try:
            cand = ipaddress.ip_address(a)
        except ValueError:
            continue
        if cand.version != ctx.ip.version:
            continue
        prefix = (c4 if cand.version == 4 else c6)
        if prefix is None:
            prefix = 32 if cand.version == 4 else 128
        try:
            if ctx.ip in ipaddress.ip_network(f"{cand}/{prefix}", strict=False):
                return True
        except ValueError:
            raise _SpfAbort("permerror", "Invalid CIDR length in SPF mechanism")
    return False


def _spf_eval(ctx: _SpfContext, domain: str, depth: int) -> Tuple[str, str]:
    if depth > SPF_MAX_DEPTH:
        raise _SpfAbort("permerror", "SPF include/redirect recursion limit exceeded")

    txts = ctx.dns(domain, "TXT")
    records = [t for t in txts if t.lower().startswith("v=spf1") and (len(t) == 6 or t[6].isspace())]
    if not records:
        return "none", f"No SPF record found for '{domain}'"
    if len(records) > 1:
        return "permerror", f"Multiple SPF records published for '{domain}'"

    redirect: Optional[str] = None
    for raw_term in records[0].split()[1:]:
        # Modifiers: name=value
        mod = re.match(r'^([A-Za-z][A-Za-z0-9_.\-]*)=(.*)$', raw_term)
        if mod:
            if mod.group(1).lower() == "redirect":
                if redirect is not None:
                    return "permerror", "Duplicate redirect modifier"
                redirect = mod.group(2)
            continue

        qual = "+"
        term = raw_term
        if term[0] in "+-~?":
            qual, term = term[0], term[1:]
        nm = re.match(r'^([A-Za-z0-9]+)(.*)$', term)
        if not nm:
            return "permerror", f"Unparseable SPF term '{raw_term}'"
        name = nm.group(1).lower()
        rest = nm.group(2)
        spec = rest[1:] if rest.startswith(":") else rest
        matched = False

        if name == "all":
            matched = True
        elif name in ("ip4", "ip6"):
            try:
                net = ipaddress.ip_network(spec, strict=False)
            except ValueError:
                return "permerror", f"Invalid {name} network '{spec}'"
            want = 4 if name == "ip4" else 6
            if net.version != want:
                return "permerror", f"Invalid {name} network '{spec}'"
            matched = ctx.ip.version == want and ctx.ip in net
        elif name == "a":
            ctx.count_lookup()
            dom, c4, c6 = _split_cidr(spec)
            target = _spf_expand(dom, domain, ctx) if dom else domain
            matched = _addr_matches(ctx, ctx.dns(target, "A" if ctx.ip.version == 4 else "AAAA"), c4, c6)
        elif name == "mx":
            ctx.count_lookup()
            dom, c4, c6 = _split_cidr(spec)
            target = _spf_expand(dom, domain, ctx) if dom else domain
            mx_hosts = []
            for rec in ctx.dns(target, "MX"):
                pref, _, host = rec.partition(" ")
                try:
                    mx_hosts.append((int(pref), host))
                except ValueError:
                    continue
            mx_hosts.sort()
            if len(mx_hosts) > SPF_MAX_LOOKUPS:
                return "permerror", f"mx mechanism for '{target}' has more than {SPF_MAX_LOOKUPS} hosts"
            for _, host in mx_hosts:
                if _addr_matches(ctx, ctx.dns(host, "A" if ctx.ip.version == 4 else "AAAA"), c4, c6):
                    matched = True
                    break
        elif name == "include":
            ctx.count_lookup()
            if not spec:
                return "permerror", "include mechanism without a domain"
            target = _spf_expand(spec, domain, ctx)
            sub, why = _spf_eval(ctx, target, depth + 1)
            if sub == "pass":
                matched = True
            elif sub == "none":
                return "permerror", f"include:{target} has no SPF record"
            elif sub in ("temperror", "permerror"):
                return sub, why
        elif name == "exists":
            ctx.count_lookup()
            if not spec:
                return "permerror", "exists mechanism without a domain"
            matched = bool(ctx.dns(_spf_expand(spec, domain, ctx), "A"))
        elif name == "ptr":
            # Deprecated by RFC 7208 and expensive; deliberately unsupported -> indeterminate.
            return "temperror", "SPF 'ptr' mechanism is not supported by this evaluator"
        else:
            return "permerror", f"Unknown SPF mechanism '{raw_term}'"

        if matched:
            result = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}[qual]
            return result, f"Matched '{raw_term}' in SPF record of '{domain}'"

    if redirect is not None:
        ctx.count_lookup()
        target = _spf_expand(redirect, domain, ctx)
        sub, why = _spf_eval(ctx, target, depth + 1)
        if sub == "none":
            return "permerror", f"redirect={target} has no SPF record"
        return sub, why
    return "neutral", f"No SPF mechanism matched for '{domain}'"


def evaluate_spf(domain: str, ip: Optional[str], time_budget: float = SPF_TIME_BUDGET) -> Dict[str, Any]:
    """
    RFC 7208 check_host() subset. Returns:
        {"result": pass|fail|softfail|neutral|none|temperror|permerror,
         "state": pass|fail|indeterminate, "explanation": str, "lookups": int}
    State: pass -> 'pass'; temperror -> 'indeterminate'; everything else -> 'fail'.
    """
    if not domain:
        return {"result": "none", "state": "fail", "explanation": "No domain available for SPF evaluation", "lookups": 0}
    if not ip:
        return {"result": "temperror", "state": "indeterminate",
                "explanation": "No public connecting IP extracted to verify against SPF", "lookups": 0}
    try:
        ip_obj = ipaddress.ip_address(ip)
        if getattr(ip_obj, "ipv4_mapped", None) is not None:
            ip_obj = ip_obj.ipv4_mapped
    except ValueError:
        return {"result": "permerror", "state": "fail", "explanation": f"Invalid IP '{ip}'", "lookups": 0}

    ctx = _SpfContext(ip_obj, time_budget)
    try:
        result, why = _spf_eval(ctx, domain, 0)
    except _SpfAbort as a:
        result, why = a.result, a.explanation
    state = "pass" if result == "pass" else ("indeterminate" if result == "temperror" else "fail")
    return {"result": result, "state": state, "explanation": f"SPF {result} for {ip} / '{domain}': {why}",
            "lookups": ctx.lookups}


def audit_spf(domain: str, originating_ip: Optional[str]) -> Tuple[bool, str]:
    """Backward-compatible wrapper: (passed, details)."""
    res = evaluate_spf(domain, originating_ip)
    return res["state"] == "pass", res["explanation"]


# ----------------------------------------------------------------------------
# DKIM
# ----------------------------------------------------------------------------
def _parse_dkim_signatures(raw_bytes: bytes) -> List[Dict[str, str]]:
    try:
        msg = email.message_from_bytes(raw_bytes)
        headers = msg.get_all("DKIM-Signature", []) or []
    except Exception:
        return []
    sigs = []
    for h in headers:
        tags = {}
        for part in str(h).split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                tags[k.strip().lower()] = "".join(v.split())
        sigs.append({"d": tags.get("d", "").lower(), "s": tags.get("s", "")})
    return sigs


def _dkim_dnsfunc(name, timeout=DNS_TIMEOUT):
    """dnsfunc for dkimpy: returns the key record bytes, None if absent, raises on temp errors."""
    if isinstance(name, bytes):
        name = name.decode("ascii", errors="ignore")
    for txt in _dns_lookup(name.rstrip("."), "TXT", timeout=min(float(timeout or DNS_TIMEOUT), DNS_TIMEOUT)):
        if "p=" in txt:
            return txt.encode("utf-8")
    return None


def evaluate_dkim(raw_bytes: bytes, fallback_bytes: Optional[bytes] = None) -> Dict[str, Any]:
    """
    Verify every DKIM-Signature. Tries the ORIGINAL bytes first and only then a normalised copy.
    Returns {"state", "signatures": [{"domain","selector","verified","error","bytes_used"}], "details"}.
    """
    sigs = _parse_dkim_signatures(raw_bytes)
    if not sigs:
        return {"state": "fail", "signatures": [], "details": "No DKIM-Signature header present in email"}

    results = []
    any_temp = False
    for idx, sig in enumerate(sigs):
        entry = {"domain": sig["d"], "selector": sig["s"], "verified": False, "error": None, "bytes_used": None}
        candidates = [("original", raw_bytes)]
        if fallback_bytes is not None and fallback_bytes != raw_bytes:
            candidates.append(("normalised", fallback_bytes))
        for label, data in candidates:
            try:
                ok = dkim.DKIM(data, timeout=int(DNS_TIMEOUT)).verify(idx=idx, dnsfunc=_dkim_dnsfunc)
            except _DnsTempError as e:
                entry["error"] = f"DNS temporary error: {e}"
                any_temp = True
                break
            except Exception as e:
                entry["error"] = f"DKIM validation error: {e}"
                continue
            if ok:
                entry.update(verified=True, error=None, bytes_used=label)
                break
            entry["error"] = entry["error"] or "DKIM signature verification failed (forged headers, tampered body or missing key)"
        results.append(entry)

    if any(r["verified"] for r in results):
        state = "pass"
        ok_domains = ", ".join(sorted({r["domain"] for r in results if r["verified"]}))
        details = f"DKIM signature verified (d={ok_domains})"
    elif any_temp:
        state = "indeterminate"
        details = "DKIM could not be verified: DNS key lookup failed temporarily"
    else:
        state = "fail"
        details = results[0]["error"] or "DKIM signature verification failed"
    return {"state": state, "signatures": results, "details": details}


def audit_dkim(raw_bytes: bytes) -> Tuple[bool, str]:
    """Backward-compatible wrapper: (passed, details)."""
    res = evaluate_dkim(raw_bytes)
    return res["state"] == "pass", res["details"]


# ----------------------------------------------------------------------------
# DMARC
# ----------------------------------------------------------------------------
def _parse_dmarc_record(record: str) -> Dict[str, str]:
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip().lower()
    return tags


def _domains_aligned(a: str, b: str, strict: bool) -> bool:
    a, b = (a or "").lower().strip("."), (b or "").lower().strip(".")
    if not a or not b:
        return False
    if strict:
        return a == b
    return registered_domain(a) == registered_domain(b)


def _fetch_dmarc(from_domain: str) -> Tuple[Optional[str], str]:
    """Returns (record, queried_name); falls back to the organizational domain (RFC 7489 6.6.3)."""
    names = [from_domain]
    org = registered_domain(from_domain)
    if org and org != from_domain:
        names.append(org)
    last = names[0]
    for n in names:
        last = n
        for txt in _dns_lookup(f"_dmarc.{n}", "TXT"):
            if txt.strip().lower().startswith("v=dmarc1"):
                return txt, n
    return None, last


def evaluate_dmarc(from_domain: str, return_path_domain: str, spf_state: str,
                   dkim_signatures: Optional[List[Dict[str, Any]]] = None,
                   dkim_state: str = "fail") -> Dict[str, Any]:
    """
    Tri-state DMARC evaluation with identifier alignment.
    SPF alignment: spf_state == 'pass' AND MAIL FROM domain aligned with From.
    DKIM alignment: a VERIFIED signature whose d= is aligned with From (relaxed unless adkim=s).
    """
    out = {"state": "fail", "policy": None, "adkim": "r", "aspf": "r", "pct": None, "subdomain_policy": None,
           "spf_aligned": False, "dkim_aligned": False, "details": ""}
    if not from_domain:
        out["details"] = "Missing From: domain for DMARC evaluation"
        return out
    try:
        record, qname = _fetch_dmarc(from_domain)
    except _DnsTempError as e:
        out["state"] = "indeterminate"
        out["details"] = f"DMARC check indeterminate: DNS lookup for '_dmarc.{from_domain}' failed ({e}); not treated as pass or fail"
        return out
    if not record:
        out["details"] = f"No DMARC record published at '_dmarc.{from_domain}'"
        return out

    tags = _parse_dmarc_record(record)
    out["policy"] = tags.get("p")
    out["subdomain_policy"] = tags.get("sp")
    out["adkim"] = tags.get("adkim", "r")
    out["aspf"] = tags.get("aspf", "r")
    out["pct"] = tags.get("pct")

    out["spf_aligned"] = (spf_state == "pass") and _domains_aligned(
        from_domain, return_path_domain, out["aspf"] == "s")
    out["dkim_aligned"] = any(
        s.get("verified") and _domains_aligned(from_domain, s.get("domain", ""), out["adkim"] == "s")
        for s in (dkim_signatures or []))

    if out["spf_aligned"] or out["dkim_aligned"]:
        parts = [n for n, f in (("SPF aligned", out["spf_aligned"]), ("DKIM aligned", out["dkim_aligned"])) if f]
        out["state"] = "pass"
        out["details"] = f"DMARC passed with identifier alignment ({' & '.join(parts)}); published policy p={out['policy']}"
        return out

    if spf_state == "indeterminate" or dkim_state == "indeterminate":
        out["state"] = "indeterminate"
        out["details"] = ("DMARC indeterminate: SPF/DKIM could not be fully evaluated (DNS errors) and no "
                          f"aligned pass was observed; published policy p={out['policy']}")
        return out

    out["details"] = (f"DMARC failed: no aligned SPF or DKIM pass (published policy p={out['policy']}, "
                      f"adkim={out['adkim']}, aspf={out['aspf']})")
    return out


def audit_dmarc(from_domain: str, return_path_domain: str, spf_pass: bool, dkim_pass: bool,
                dkim_domains: Optional[List[str]] = None) -> Tuple[bool, str]:
    """
    Backward-compatible wrapper. DKIM alignment can only be established when the signing
    domains are supplied (``dkim_domains``); a bare ``dkim_pass=True`` is NOT enough.
    """
    sigs = [{"verified": True, "domain": d} for d in (dkim_domains or [])] if dkim_pass else []
    res = evaluate_dmarc(from_domain, return_path_domain, "pass" if spf_pass else "fail", sigs,
                         "pass" if dkim_pass else "fail")
    return res["state"] == "pass", res["details"]


# ----------------------------------------------------------------------------
# Sender domain infrastructure
# ----------------------------------------------------------------------------
def check_sender_domain_infrastructure(from_domain: str) -> Dict[str, Any]:
    """
    Queries MX records for the sender domain. Returns
    {"from_domain", "has_mx_records", "primary_mx"} plus "lookup_error" (str) when the lookup was
    inconclusive (timeout/SERVFAIL) - in that case has_mx_records is False but NOT evidence of a
    burner domain.
    """
    clean_domain = (from_domain or "").strip().lower()
    base = {"from_domain": clean_domain, "has_mx_records": False, "primary_mx": None}
    if not clean_domain:
        return base
    try:
        records = _dns_lookup(clean_domain, "MX")
    except _DnsTempError as e:
        base["lookup_error"] = str(e)
        return base
    except Exception as e:
        logger.debug(f"MX lookup unexpected error for {clean_domain}: {e}")
        base["lookup_error"] = str(e)
        return base

    mx = []
    for rec in records:
        pref, _, host = rec.partition(" ")
        try:
            mx.append((int(pref), host))
        except ValueError:
            continue
    if not mx:
        return base
    mx.sort()
    base["has_mx_records"] = True
    base["primary_mx"] = mx[0][1]
    return base


# ----------------------------------------------------------------------------
# Payload / link extraction
# ----------------------------------------------------------------------------
def _decode_part(payload: bytes, charset: Optional[str], notes: List[str]) -> str:
    try:
        return payload.decode(charset or "utf-8", errors="replace")
    except LookupError:
        notes.append(f"Unknown charset '{charset}'; decoded as latin-1 with replacement")
        return payload.decode("latin-1", errors="replace")


def _clean_url(url: str) -> str:
    url = re.sub(r'[\t\r\n\x00]', '', url.strip())
    return re.sub(r'[\s,;:?!\.\>\)\]]+$', '', url)


def _scan_text_urls(text: str) -> List[str]:
    """URLs written in free text: scheme URLs plus scheme-less IPv4 URLs that have a path."""
    urls = list(URL_REGEX.findall(text))
    for m in BARE_IP_URL_REGEX.findall(text):
        host = m.split("/", 1)[0].split(":")[0]
        try:
            ipaddress.IPv4Address(host)
        except ValueError:
            continue
        urls.append("http://" + m)
    return urls


def extract_payload_and_links_ex(msg: email.message.EmailMessage) -> Tuple[str, List[str], List[str], List[str]]:
    """
    Extracts plain text body and all embedded hyperlinks.
    Returns (body_text, links, errors, notes). ``errors`` are parts that could not be analysed
    (analysis is incomplete); ``notes`` are recoverable observations.
    """
    body_text_parts: List[str] = []
    extracted_urls: List[str] = []
    errors: List[str] = []
    notes: List[str] = []
    skipped_protocol_relative = 0

    for part in msg.walk():
        content_type = part.get_content_type()
        if content_type not in ("text/plain", "text/html"):
            continue

        # Only skip REAL attachments (disposition attachment AND a filename).
        disposition = str(part.get("Content-Disposition", "")).lower()
        if "attachment" in disposition and part.get_filename():
            continue

        try:
            payload = part.get_payload(decode=True)
            if not payload:
                continue
            decoded_text = _decode_part(payload, part.get_content_charset(), notes)

            if content_type == "text/plain":
                body_text_parts.append(decoded_text.strip())
                extracted_urls.extend(_scan_text_urls(decoded_text))
            else:
                soup = make_soup(decoded_text)
                body_text_parts.append(soup.get_text(separator=" ", strip=True))

                base_host_scheme = None
                base_tag = soup.find("base", href=True)
                if base_tag:
                    bm = re.match(r'(?i)^(https?):', str(base_tag["href"]).strip())
                    if bm:
                        base_host_scheme = bm.group(1).lower()

                candidates = [a["href"] for a in soup.find_all("a", href=True)]
                candidates += [f["action"] for f in soup.find_all("form", action=True)]
                for raw in candidates:
                    href = re.sub(r'[\t\r\n\x00]', '', str(raw).strip())
                    low = href.lower()
                    if low.startswith(("http://", "https://")):
                        extracted_urls.append(href)
                    elif href.startswith("//"):
                        if base_host_scheme:
                            extracted_urls.append(f"{base_host_scheme}:{href}")
                        else:
                            skipped_protocol_relative += 1
                # Bare URLs written in the visible text of the HTML.
                extracted_urls.extend(_scan_text_urls(soup.get_text(separator=" ")))
        except Exception as e:
            logger.debug(f"Error extracting part payload: {e}")
            errors.append(f"Failed to extract {content_type} part: {type(e).__name__}: {e}")
            continue

    if skipped_protocol_relative:
        notes.append(f"Skipped {skipped_protocol_relative} protocol-relative link(s) with no <base> host")

    clean_urls: List[str] = []
    seen = set()
    for url in extracted_urls:
        cleaned = _clean_url(url)
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            clean_urls.append(cleaned)

    return "\n\n".join(body_text_parts).strip(), clean_urls, errors, notes


def extract_payload_and_links(msg: email.message.EmailMessage) -> Tuple[str, List[str]]:
    """Backward-compatible wrapper returning (body_text, links)."""
    body, links, _errors, _notes = extract_payload_and_links_ex(msg)
    return body, links


# ----------------------------------------------------------------------------
# Main entry point
# ----------------------------------------------------------------------------
def _empty_result() -> Dict[str, Any]:
    return {
        "evidence_hash_sha256": "",
        "evidence_hash": "",
        "raw_size_bytes": 0,
        "metadata": {},
        "authentication": {
            "spf_pass": False, "dkim_pass": False, "dmarc_pass": False,
            "spf_state": "indeterminate", "dkim_state": "indeterminate", "dmarc_state": "indeterminate",
        },
        "origin_tracing": {"originating_ip": None, "origin_ip": None, "connecting_ip": None,
                           "total_hops": 0, "hops": []},
        "payload": {"body_text": "", "extracted_links": []},
        "analysis_errors": ["Empty input"],
        "analysis_complete": False,
    }


def parse_email_file(file_bytes: bytes) -> Dict[str, Any]:
    """
    Main Entry Point: Ingests raw .eml bytes and executes the comprehensive
    evidence preservation, hop tracing, protocol audit, and link extraction pipeline.
    """
    if not file_bytes:
        return _empty_result()

    errors: List[str] = []

    # Evidence integrity: hash the ORIGINAL uploaded bytes. Only a COPY is normalised (for parsing).
    original_bytes = bytes(file_bytes)
    evidence_hash = compute_sha256(original_bytes)
    normalised = original_bytes.replace(b"\r\r\n", b"\r\n")

    msg = email.message_from_bytes(normalised, policy=policy.default)

    subject = str(msg.get("Subject", "")).strip()
    from_header = str(msg.get("From", "")).strip()
    to_header = str(msg.get("To", "")).strip()
    date_header = str(msg.get("Date", "")).strip()
    message_id = str(msg.get("Message-ID", "")).strip()
    return_path = str(msg.get("Return-Path", "")).strip()
    reply_to = str(msg.get("Reply-To", "")).strip()

    from_domain = extract_domain_from_email(from_header)
    return_path_domain = extract_domain_from_email(return_path) or from_domain

    # Hop tracing: topmost hop = connecting IP (for SPF); bottom-most public = claimed origin.
    received_headers = [str(h) for h in msg.get_all("Received", [])]
    originating_ip, total_hops, hops = trace_originating_ip(received_headers)
    connecting_ip = find_connecting_ip(received_headers)

    # Authentication (tri-state)
    try:
        spf = evaluate_spf(return_path_domain, connecting_ip)
    except Exception as e:  # defensive: never let the evaluator abort the whole analysis
        spf = {"result": "temperror", "state": "indeterminate", "explanation": f"SPF evaluation error: {e}", "lookups": 0}
    try:
        dkim_res = evaluate_dkim(original_bytes, normalised if normalised != original_bytes else None)
    except Exception as e:
        dkim_res = {"state": "indeterminate", "signatures": [], "details": f"DKIM evaluation error: {e}"}
    try:
        dmarc = evaluate_dmarc(from_domain, return_path_domain, spf["state"], dkim_res["signatures"], dkim_res["state"])
    except Exception as e:
        dmarc = {"state": "indeterminate", "policy": None, "adkim": "r", "aspf": "r", "pct": None,
                 "subdomain_policy": None, "spf_aligned": False, "dkim_aligned": False,
                 "details": f"DMARC evaluation error: {e}"}

    for label, state, why in (("SPF", spf["state"], spf["explanation"]),
                              ("DKIM", dkim_res["state"], dkim_res["details"]),
                              ("DMARC", dmarc["state"], dmarc["details"])):
        if state == "indeterminate":
            errors.append(f"{label} indeterminate: {why}")

    # Payload
    try:
        body_text, extracted_links, payload_errors, payload_notes = extract_payload_and_links_ex(msg)
        errors.extend(payload_errors)
    except Exception as e:
        body_text, extracted_links, payload_notes = "", [], []
        errors.append(f"Payload extraction failed: {e}")

    reply_to_domain = extract_domain_from_email(reply_to)
    # Same company is not a mismatch: replies to bookmyshow.com for mail sent from info.bookmyshow.com are normal. A Reply-To on a
    # DIFFERENT registered domain (the business-email-compromise trick) is still flagged.
    reply_to_mismatch = bool(reply_to and from_domain and registered_domain(reply_to_domain) != registered_domain(from_domain))

    sender_domain_infra = check_sender_domain_infrastructure(from_domain)
    if sender_domain_infra.get("lookup_error"):
        errors.append(f"Sender MX lookup inconclusive: {sender_domain_infra['lookup_error']}")

    return {
        "evidence_hash_sha256": evidence_hash,
        "evidence_hash": evidence_hash,
        "raw_size_bytes": len(original_bytes),
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
            "spf_pass": spf["state"] == "pass",
            "spf_state": spf["state"],
            "spf_result": spf["result"],
            "spf_details": spf["explanation"],
            "spf_dns_lookups": spf["lookups"],
            "dkim_pass": dkim_res["state"] == "pass",
            "dkim_state": dkim_res["state"],
            "dkim_details": dkim_res["details"],
            "dkim_signatures": dkim_res["signatures"],
            "dmarc_pass": dmarc["state"] == "pass",
            "dmarc_state": dmarc["state"],
            "dmarc_details": dmarc["details"],
            "dmarc_policy": dmarc["policy"],
            "dmarc_adkim": dmarc["adkim"],
            "dmarc_aspf": dmarc["aspf"],
            "dmarc_spf_aligned": dmarc["spf_aligned"],
            "dmarc_dkim_aligned": dmarc["dkim_aligned"],
        },
        "sender_domain_intelligence": sender_domain_infra,
        "origin_tracing": {
            "originating_ip": originating_ip,
            "origin_ip": originating_ip,
            "connecting_ip": connecting_ip,
            "total_hops": total_hops,
            "hops": hops
        },
        "payload": {
            "body_text": body_text,
            "extracted_links": extracted_links,
            "extraction_notes": payload_notes,
        },
        "analysis_errors": errors,
        "analysis_complete": not errors,
    }
