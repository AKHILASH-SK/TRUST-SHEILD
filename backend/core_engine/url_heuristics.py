"""
TrustShield V2 - Stage 1: Fast Heuristic & Rule-Based URL Parser
Analyzes URLs in sub-millisecond time using deterministic regex,
subdomain structural analysis, Shannon entropy, brand spoofing,
credential keywords, disposable TLDs, punycode, and typosquatting detection.
"""

import math
import re
from typing import Dict, Any, List, Optional, Set
from urllib.parse import urlparse, parse_qs, unquote
import tldextract
import Levenshtein

# High-value targeted brands and their official domains
OFFICIAL_BRAND_DOMAINS: Dict[str, List[str]] = {
    "paypal": ["paypal.com", "paypal.me"],
    "google": ["google.com", "accounts.google.com", "google.co.in", "google.co.uk", "google.ca", "google.de"],
    "microsoft": ["microsoft.com", "office.com", "live.com", "outlook.com", "office365.com", "windows.net", "sharepoint.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.in", "amazon.co.uk", "aws.amazon.com"],
    "netflix": ["netflix.com"],
    "sbi": ["onlinesbi.sbi", "sbi.co.in", "onlinesbi.com"],
    "hdfc": ["hdfcbank.com"],
    "icici": ["icicibank.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
    "chatgpt": ["chatgpt.com", "openai.com"],
    "openai": ["openai.com", "chatgpt.com"],
    "dhl": ["dhl.com", "dhl.de"],
    "fedex": ["fedex.com"],
    "meta": ["meta.com", "facebook.com", "instagram.com", "whatsapp.com"],
    "facebook": ["facebook.com", "fb.com"],
    "whatsapp": ["whatsapp.com"],
    "telegram": ["telegram.org", "t.me"],
    "binance": ["binance.com"],
    "coinbase": ["coinbase.com"],
    "metamask": ["metamask.io"],
    "linkedin": ["linkedin.com", "lnkd.in"],
    "github": ["github.com"],
    "twitter": ["twitter.com", "x.com", "t.co"],
    "instagram": ["instagram.com"],
    "dropbox": ["dropbox.com"],
    "adobe": ["adobe.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "zoom": ["zoom.us"]
}

# Multi-tenant and free hosting platforms where subdomains can be registered by threat actors
SHARED_FREE_HOSTING_PLATFORMS: Set[str] = {
    "vercel.app", "netlify.app", "pages.dev", "firebaseapp.com", "weebly.com",
    "wixsite.com", "github.io", "appspot.com", "glitch.me", "onrender.com",
    "web.app", "000webhostapp.com", "surge.sh", "railway.app", "fly.dev"
}

TARGETED_BRAND_KEYWORDS = list(OFFICIAL_BRAND_DOMAINS.keys()) + [
    "office365", "outlook", "onedrive", "azure", "gmail", "googledrive", "workspace",
    "paypal-security", "amazon-prime", "appleid", "onlinesbi", "hdfcbank"
]

DECEPTIVE_SUBDOMAIN_TERMS = [
    "login", "signin", "verify", "verification", "secure",
    "account", "update", "banking", "auth", "portal", "support"
]

CREDENTIAL_PATH_KEYWORDS = [
    "login", "signin", "verify", "verification", "secure", "security",
    "account", "update", "banking", "auth", "portal", "support",
    "confirm", "wire", "transfer", "wallet", "billing", "invoice",
    "password", "reset", "webscr", "cgi-bin", "kyc", "otp",
    "re-activate", "unlock", "ticket", "authorize", "validation"
]

SUSPICIOUS_DISPOSABLE_TLDS = {
    "top", "xyz", "site", "buzz", "work", "click", "link", "live",
    "online", "club", "support", "vip", "icu", "loan", "tk", "ml",
    "ga", "cf", "gq", "rest", "cam", "fit", "beauty", "stream", "bid"
}

IPV4_PATTERN = re.compile(r'^(?:https?://)?(?:\S+@)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?(?:/.*)?$', re.IGNORECASE)
IPV6_PATTERN = re.compile(r'^(?:https?://)?(?:\S+@)?(\[[0-9a-fA-F:]+\])(?::\d+)?(?:/.*)?$', re.IGNORECASE)
OPEN_REDIRECT_KEYS = {"redirect", "redirect_url", "url", "next", "dest", "destination", "target", "return", "return_url", "goto"}

def generate_lookalike_variants(token: str) -> Set[str]:
    """
    Generates normalized variants of a domain token to detect visual homoglyphs,
    leetspeak substitutions (e.g. 1->i/l, 0->o, rn->m), and consecutive duplicate characters.
    """
    base = token.lower().strip()
    variants: Set[str] = {base}
    
    # 1. Collapsed consecutive duplicates (e.g., linkediin -> linkedin, paypaal -> paypal)
    collapsed = re.sub(r'(.)\1+', r'\1', base)
    variants.add(collapsed)

    # 2. Common single-character homoglyph substitutions
    sub_pairs = [
        ("1", "i"), ("1", "l"), ("l", "i"), ("0", "o"),
        ("3", "e"), ("5", "s"), ("8", "b"), ("@", "a"),
        ("$", "s"), ("vv", "w"), ("rn", "m")
    ]
    for src, dst in sub_pairs:
        if src in base:
            v = base.replace(src, dst)
            variants.add(v)
            variants.add(re.sub(r'(.)\1+', r'\1', v))

    # 3. Multi-character leetspeak combos (e.g. l1nked1n -> linkedin, g00gle -> google)
    multi_combo_1 = base
    for s, d in [("1", "i"), ("0", "o"), ("3", "e"), ("5", "s"), ("@", "a"), ("rn", "m"), ("vv", "w")]:
        multi_combo_1 = multi_combo_1.replace(s, d)
    variants.add(multi_combo_1)
    variants.add(re.sub(r'(.)\1+', r'\1', multi_combo_1))

    multi_combo_2 = base
    for s, d in [("1", "l"), ("0", "o"), ("3", "e"), ("5", "s"), ("@", "a"), ("rn", "m"), ("vv", "w")]:
        multi_combo_2 = multi_combo_2.replace(s, d)
    variants.add(multi_combo_2)
    variants.add(re.sub(r'(.)\1+', r'\1', multi_combo_2))

    return variants


def calculate_shannon_entropy(text: str) -> float:
    """
    Calculates the Shannon Entropy of a string: H = -sum(p * log2(p)).
    Higher entropy (> 4.3) indicates randomly generated (DGA) or heavily obfuscated URLs.
    """
    if not text:
        return 0.0
    
    length = len(text)
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
        
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
        
    return round(entropy, 3)


def parse_url_heuristics(url: str) -> Dict[str, Any]:
    """
    Executes sub-millisecond static heuristic checks on the provided URL.
    Returns:
        heuristic_risk_score (0.0 to 100.0)
        heuristic_flags (list of strings describing triggered rules)
        raw feature indicators for meta-classifier consumption
    """
    clean_url = (url or "").strip()
    flags: List[str] = []
    
    # 1. URL Length, Encoding, and Base Extraction
    url_len = len(clean_url)
    entropy = calculate_shannon_entropy(clean_url)
    
    parsed = urlparse(clean_url if "://" in clean_url else f"http://{clean_url}")
    netloc = (parsed.netloc or "").lower()
    path = (parsed.path or "").lower()
    query = (parsed.query or "").lower()
    
    ext = tldextract.extract(clean_url)
    subdomain = ext.subdomain.lower()
    root_domain = ext.registered_domain.lower()
    domain_name = ext.domain.lower()
    suffix = ext.suffix.lower()
    
    # 2. IP Address in URL Check
    has_ip = 0
    host_only = netloc.split('@')[-1].split(':')[0].strip('[]')
    is_ipv4 = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host_only))
    is_ipv6 = bool(':' in host_only and not host_only.endswith('.com'))
    if is_ipv4 or is_ipv6 or IPV4_PATTERN.match(clean_url) or IPV6_PATTERN.match(clean_url):
        has_ip = 1
        flags.append("RAW_IP_HOST: Hostname uses a raw IP address instead of a domain name")
        
    # 3. Userinfo '@' Symbol Spoofing Check
    has_at = 0
    if '@' in parsed.netloc or ('@' in clean_url.split('?')[0] and '://' in clean_url):
        has_at = 1
        flags.append("USERINFO_AT_SPOOFING: '@' symbol used in authority to deceive destination host")
        
    # 4. Punycode / IDN Homograph Check
    has_punycode = 0
    if "xn--" in netloc:
        has_punycode = 1
        flags.append("PUNYCODE_IDN_HOMOGRAPH: Hostname uses internationalized punycode (xn--) encoding")

    # 5. URL Entropy Check (Obfuscation / DGA)
    entropy_risk = 0
    if entropy > 4.3:
        entropy_risk = 1
        flags.append(f"HIGH_SHANNON_ENTROPY: URL entropy is {entropy:.2f} (> 4.3), indicating algorithmic generation or obfuscation")
        
    # 6. Excessive Subdomains (Subdomain Stacking)
    subdomain_parts = [p for p in subdomain.split('.') if p]
    subdomain_count = len(subdomain_parts)
    excessive_subdomains = 0
    if subdomain_count >= 3:
        excessive_subdomains = 1
        flags.append(f"EXCESSIVE_SUBDOMAINS: {subdomain_count} nested subdomains detected (subdomain stacking evasion)")
    elif subdomain_count == 2 and any(t in subdomain for t in DECEPTIVE_SUBDOMAIN_TERMS):
        flags.append(f"DECEPTIVE_SUBDOMAIN_STACKING: Nested subdomains contain deceptive portal keywords")

    # 7 & 8: Brand Spoofing & Lookalike Typosquatting Analysis across Domain & Subdomains
    suspicious_brand_spoof = 0
    matched_brand = None
    typosquat_risk = 0
    typosquat_brand = None

    # Collect all tokens from both subdomain and domain
    subdomain_parts = [p for p in subdomain.split('.') if p]
    subdomain_tokens = []
    for part in subdomain_parts:
        subdomain_tokens.append(part)
        for subpart in re.split(r'[-_]', part):
            if subpart and subpart not in subdomain_tokens:
                subdomain_tokens.append(subpart)

    domain_tokens = []
    if domain_name:
        domain_tokens.append(domain_name)
        for subpart in re.split(r'[-_]', domain_name):
            if subpart and subpart not in domain_tokens:
                domain_tokens.append(subpart)

    is_shared_platform = root_domain in SHARED_FREE_HOSTING_PLATFORMS

    # Evaluate each protected brand
    for brand, official_domains in OFFICIAL_BRAND_DOMAINS.items():
        is_official = any(root_domain == off or root_domain.endswith("." + off) for off in official_domains)
        if is_official:
            continue

        # Check subdomains for exact brand, homoglyph lookalikes, or Levenshtein typosquatting
        for tok in subdomain_tokens:
            if len(tok) < 4:
                continue
            variants = generate_lookalike_variants(tok)
            dist = Levenshtein.distance(tok, brand)
            is_exact = (tok == brand or brand in tok)
            is_homoglyph = (brand in variants)
            is_levenshtein = (len(brand) >= 6 and 0 < dist <= 2) or (len(brand) < 6 and dist == 1)

            if is_exact or is_homoglyph or is_levenshtein:
                suspicious_brand_spoof = 1
                matched_brand = brand
                if is_homoglyph or is_levenshtein:
                    typosquat_risk = 1
                    typosquat_brand = brand

                if is_shared_platform:
                    flags.append(f"BRAND_LOOKALIKE_ON_SHARED_HOSTING: Lookalike/impersonation of brand '{brand}' ('{tok}') hosted on public cloud platform '{root_domain}'")
                elif is_exact:
                    flags.append(f"BRAND_IN_SUBDOMAIN: Target brand '{brand}' abused in subdomain while registered domain is '{root_domain}'")
                else:
                    flags.append(f"TYPOSQUAT_LOOKALIKE: Subdomain token '{tok}' is a lookalike of brand '{brand}' (homoglyph/edit distance: {dist})")
                break

        # Check domain_name for exact brand or lookalikes
        if not suspicious_brand_spoof or not typosquat_risk:
            for tok in domain_tokens:
                if len(tok) < 4:
                    continue
                variants = generate_lookalike_variants(tok)
                dist = Levenshtein.distance(tok, brand)
                is_exact = (tok == brand or brand in tok)
                is_homoglyph = (brand in variants)
                is_levenshtein = (len(brand) >= 6 and 0 < dist <= 2) or (len(brand) < 6 and dist == 1)

                if is_exact or is_homoglyph or is_levenshtein:
                    if is_exact:
                        suspicious_brand_spoof = 1
                        matched_brand = brand
                        flags.append(f"DECEPTIVE_BRAND_DOMAIN: Target brand '{brand}' spoofed inside unauthorized registered domain '{root_domain}'")
                    else:
                        typosquat_risk = 1
                        typosquat_brand = brand
                        flags.append(f"TYPOSQUAT_LOOKALIKE: Domain token '{tok}' is a lookalike of brand '{brand}' (homoglyph/edit distance: {dist})")
                    break

        if suspicious_brand_spoof and typosquat_risk:
            break

    # 9. Suspicious / Disposable Phishing TLD Check
    suspicious_tld_flag = 0
    if suffix in SUSPICIOUS_DISPOSABLE_TLDS:
        suspicious_tld_flag = 1
        flags.append(f"SUSPICIOUS_TLD: Domain uses high-risk disposable TLD '.{suffix}' commonly used in phishing campaigns")

    # 10. Credential Harvesting & Deceptive Action Keywords in Path/Query
    # Note: If the domain is officially verified as the brand's own domain (e.g. paypal.com/signin),
    # legitimate authentication paths are normal and should not be penalized.
    is_official_brand_domain = any(
        root_domain == off or root_domain.endswith("." + off)
        for off_list in OFFICIAL_BRAND_DOMAINS.values()
        for off in off_list
    )

    path_and_query = f"{path} {query} {domain_name}".lower()
    matched_cred_terms = [term for term in CREDENTIAL_PATH_KEYWORDS if re.search(r'\b' + re.escape(term) + r'\b', path_and_query) or f"-{term}" in path_and_query or f"{term}-" in path_and_query or f"/{term}" in path_and_query]
    has_credential_keywords = 0
    if matched_cred_terms and not is_official_brand_domain:
        has_credential_keywords = 1
        flags.append(f"CREDENTIAL_ACTION_KEYWORDS: URL structure contains sensitive authentication/action terms: {matched_cred_terms[:4]}")

    # 11. Open Redirect & Parameter Evasion
    open_redirect_flag = 0
    if query:
        parsed_q = parse_qs(query)
        for key in parsed_q.keys():
            if key.lower() in OPEN_REDIRECT_KEYS:
                val = parsed_q[key][0] if parsed_q[key] else ""
                if val.startswith("http://") or val.startswith("https://") or "//" in val:
                    open_redirect_flag = 1
                    flags.append(f"OPEN_REDIRECT_EVASION: Parameter '{key}' forwards to external destination URL")
                    break

    # 12. Excessive Hex / Percent Encoding
    excessive_encoding = 0
    if clean_url.count('%') >= 3:
        excessive_encoding = 1
        flags.append("HEX_ENCODED_OBFUSCATION: URL contains multiple percent-encoded characters to evade filters")

    # ----------------------------------------------------
    # Calculate Continuous Heuristic Risk Score (0 - 100)
    # ----------------------------------------------------
    score = 0.0
    if has_ip: score += 45.0
    if has_at: score += 40.0
    if has_punycode: score += 35.0
    if suspicious_brand_spoof: score += 55.0
    if typosquat_risk: score += 45.0
    if is_shared_platform and (suspicious_brand_spoof or typosquat_risk): score += 35.0
    if excessive_subdomains: score += 25.0
    if entropy_risk: score += 20.0
    if suspicious_tld_flag: score += 25.0
    if has_credential_keywords: score += 25.0
    if open_redirect_flag: score += 30.0
    if excessive_encoding: score += 15.0
    if url_len > 120: score += 10.0

    # Compounding risk: Suspicious TLD + Credential keywords is heavily associated with phishing
    if suspicious_tld_flag and has_credential_keywords:
        score += 20.0
    # Compounding risk: Brand spoofing + Credential keywords
    if suspicious_brand_spoof and has_credential_keywords:
        score += 25.0

    heuristic_risk_score = round(min(100.0, score), 2)
    
    return {
        "url": clean_url,
        "heuristic_risk_score": heuristic_risk_score,
        "heuristic_flags": flags,
        "has_ip_in_url": has_ip,
        "has_at_symbol": has_at,
        "has_punycode": has_punycode,
        "url_entropy": entropy,
        "url_entropy_risk": entropy_risk,
        "subdomain_count": subdomain_count,
        "excessive_subdomains": excessive_subdomains,
        "suspicious_subdomain_brand": suspicious_brand_spoof,
        "suspicious_brand_spoof": suspicious_brand_spoof,
        "abused_brand_in_subdomain": matched_brand,
        "detected_brand": matched_brand or typosquat_brand or "",
        "typosquat_risk": typosquat_risk,
        "typosquat_brand": typosquat_brand,
        "suspicious_tld": suspicious_tld_flag,
        "has_credential_keywords": has_credential_keywords,
        "matched_credential_terms": matched_cred_terms,
        "open_redirect": open_redirect_flag,
        "registered_domain": root_domain,
        "subdomain": subdomain,
        "url_length": url_len
    }
