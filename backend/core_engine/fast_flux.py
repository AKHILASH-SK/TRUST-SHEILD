"""
Fast-flux detection: "the attacker keeps changing the IP address".

A normal site keeps one or a few stable addresses for hours. A fast-flux phishing domain is pointed at a different set of
addresses every few minutes (hacked home computers, cheap hosts in many countries) so that blocking an IP achieves nothing.
We cannot see the attacker, but we can watch the DOMAIN behave: ask DNS the same question several times and look at

    * how many different addresses come back,
    * how short the time-to-live (TTL) is (how soon the answer expires),
    * how widely those addresses are spread over unrelated networks (/16 blocks).

Big CDNs (Cloudflare, Akamai ...) also show many addresses and short TTLs, so trusted domains are never examined and a
verdict needs ALL of the signs together. The result is an indicator for the analyst, never a conviction on its own.
"""
import ipaddress
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, List, Optional, Tuple

import dns.exception
import dns.resolver

logger = logging.getLogger(__name__)

ROUNDS = 4                 # how many times the domain is looked up
ROUND_PAUSE = 0.15         # seconds between lookups
TIMEOUT = 2.0              # per lookup
SHORT_TTL = 300            # seconds; "answer expires within 5 minutes"
MANY_ADDRESSES = 5         # distinct addresses seen across the lookups
MANY_NETWORKS = 3          # distinct /16 networks among them

Lookup = Callable[[str], Tuple[List[str], Optional[int]]]       # domain -> (addresses, ttl)


def system_lookup_factory(nameserver: Optional[str] = None, port: int = 53) -> Lookup:
    """A lookup function using the machine's resolvers (or one chosen resolver, used by the lab)."""
    resolver = dns.resolver.Resolver(configure=nameserver is None)
    if nameserver:
        resolver.nameservers = [nameserver]
        resolver.port = port
    resolver.timeout = TIMEOUT
    resolver.lifetime = TIMEOUT
    resolver.cache = None                                         # every round must really ask

    def lookup(domain: str) -> Tuple[List[str], Optional[int]]:
        try:
            answer = resolver.resolve(domain, "A")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return [], None
        except dns.exception.DNSException:
            return [], None
        return [str(r.address) for r in answer], int(answer.rrset.ttl) if answer.rrset is not None else None

    return lookup


def _network16(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version == 4:
            return ".".join(ip.split(".")[:2]) + ".0.0/16"
    except ValueError:
        pass
    return ip


def assess(rounds: List[Tuple[List[str], Optional[int]]]) -> Dict[str, Any]:
    """Turn the raw answers of several lookups into the indicator. Pure function: easy to test."""
    seen: List[str] = []
    ttls: List[int] = []
    answered = 0
    changes = 0
    previous: Optional[frozenset] = None
    for ips, ttl in rounds:
        if not ips:
            continue
        answered += 1
        current = frozenset(ips)
        if previous is not None and current != previous:
            changes += 1
        previous = current
        seen.extend(ip for ip in ips if ip not in seen)
        if ttl is not None:
            ttls.append(ttl)
    networks = sorted({_network16(ip) for ip in seen})
    min_ttl = min(ttls) if ttls else None
    short_ttl = min_ttl is not None and min_ttl <= SHORT_TTL
    many_ips = len(seen) >= MANY_ADDRESSES
    many_nets = len(networks) >= MANY_NETWORKS

    signs = []
    if many_ips:
        signs.append(f"{len(seen)} different IP addresses in {answered} lookups")
    if short_ttl:
        signs.append(f"answers expire within {min_ttl} seconds")
    if many_nets:
        signs.append(f"addresses spread over {len(networks)} unrelated networks")
    if changes >= 2:
        signs.append("the set of addresses changed between lookups")

    if answered == 0:
        level, headline = "unknown", "The domain did not resolve."
    elif many_ips and short_ttl and many_nets and changes >= 1:
        level = "fast_flux"
        headline = ("This domain keeps changing the addresses it points to (fast-flux). Blocking one IP would not stop it: "
                    "attackers use this to keep a phishing site alive.")
    elif sum([many_ips, short_ttl, many_nets]) >= 2:
        level = "possible"
        headline = "Some signs of rotating infrastructure, not enough to be sure."
    else:
        level = "normal"
        headline = "The domain points to a stable set of addresses."
    return {"level": level, "headline": headline, "signs": signs, "distinct_ips": len(seen), "addresses": seen[:12],
            "networks": networks[:12], "min_ttl": min_ttl, "lookups_answered": answered, "set_changes": changes}


def inspect_domain(domain: str, lookup: Optional[Lookup] = None, rounds: int = ROUNDS, pause: float = ROUND_PAUSE) -> Dict[str, Any]:
    """Look the domain up several times and judge the pattern. Never raises."""
    domain = (domain or "").strip().strip(".").lower()
    out: Dict[str, Any] = {"domain": domain}
    if not domain:
        return {**out, "level": "unknown", "headline": "No domain.", "signs": []}
    try:
        ipaddress.ip_address(domain)
        return {**out, "level": "unknown", "headline": "A bare IP address has no DNS record to watch.", "signs": []}
    except ValueError:
        pass
    lookup = lookup or system_lookup_factory()
    answers = []
    try:
        for i in range(rounds):
            answers.append(lookup(domain))
            if i < rounds - 1:
                time.sleep(pause)
    except Exception as exc:                                       # a broken resolver must not break the scan
        logger.warning("fast-flux lookup failed for %s: %s", domain, exc)
        return {**out, "level": "unknown", "headline": "The check could not be completed.", "signs": []}
    return {**out, **assess(answers)}


def inspect_many(domains: List[str], lookup: Optional[Lookup] = None, max_domains: int = 5) -> List[Dict[str, Any]]:
    """Several domains at once (used for the links of one email); the whole call stays short."""
    unique = list(dict.fromkeys(d for d in domains if d))[:max_domains]
    if not unique:
        return []
    with ThreadPoolExecutor(max_workers=min(5, len(unique))) as pool:
        return list(pool.map(lambda d: inspect_domain(d, lookup), unique))
