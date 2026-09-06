"""
TrustShield V2 - Stage 1: Fast Heuristic & Rule-Based URL Parser
Analyzes URLs in sub-millisecond time using deterministic regex,
subdomain structural analysis, Shannon entropy, and userinfo spoofing checks.
"""

import math
import re
from typing import Dict, Any, List
from urllib.parse import urlparse
import tldextract

# High-value targeted brands to look for when abused in subdomains
TARGETED_BRAND_KEYWORDS = [
    "microsoft", "office365", "outlook", "onedrive", "azure",
    "google", "gmail", "googledrive", "workspace",
    "paypal", "paypal-security",
    "amazon", "amazon-prime", "aws",
    "apple", "icloud", "appleid",
    "netflix",
    "sbi", "onlinesbi", "hdfc", "hdfcbank",
    "chase", "wellsfargo", "bankofamerica",
    "chatgpt", "openai", "dhl"
]

DECEPTIVE_SUBDOMAIN_TERMS = [
    "login", "signin", "verify", "verification", "secure",
    "account", "update", "banking", "auth", "portal", "support"
]

IPV4_PATTERN = re.compile(r'^(?:https?://)?(?:\S+@)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?(?:/.*)?$', re.IGNORECASE)
IPV6_PATTERN = re.compile(r'^(?:https?://)?(?:\S+@)?(\[[0-9a-fA-F:]+\])(?::\d+)?(?:/.*)?$', re.IGNORECASE)


def calculate_shannon_entropy(text: str) -> float:
    """
    Calculates the Shannon Entropy of a string: H = -sum(p * log2(p)).
    Higher entropy (> 4.5) indicates randomly generated (DGA) or heavily obfuscated URLs.
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
    
    # 1. URL Length and Base Extraction
    url_len = len(clean_url)
    entropy = calculate_shannon_entropy(clean_url)
    
    parsed = urlparse(clean_url if "://" in clean_url else f"http://{clean_url}")
    netloc = parsed.netloc or ""
    
    ext = tldextract.extract(clean_url)
    subdomain = ext.subdomain.lower()
    root_domain = ext.registered_domain.lower()
    
    # 2. IP Address in URL Check
    has_ip = 0
    # Check netloc or regex
    host_only = netloc.split('@')[-1].split(':')[0].strip('[]')
    is_ipv4 = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host_only))
    is_ipv6 = bool(':' in host_only and not host_only.endswith('.com'))
    if is_ipv4 or is_ipv6 or IPV4_PATTERN.match(clean_url) or IPV6_PATTERN.match(clean_url):
        has_ip = 1
        flags.append("RAW_IP_HOST: Hostname uses a raw IP address instead of a domain")
        
    # 3. Userinfo '@' Symbol Spoofing Check
    has_at = 0
    if '@' in parsed.netloc or ('@' in clean_url.split('?')[0] and '://' in clean_url):
        has_at = 1
        flags.append("USERINFO_AT_SPOOFING: '@' symbol used to deceive user regarding destination host")
        
    # 4. URL Entropy Check (Obfuscation / DGA)
    entropy_risk = 0
    if entropy > 4.5:
        entropy_risk = 1
        flags.append(f"HIGH_SHANNON_ENTROPY: URL entropy is {entropy} (> 4.5), indicating obfuscation or DGA")
        
    # 5. Excessive Subdomains (Subdomain Stacking)
    subdomain_parts = [p for p in subdomain.split('.') if p]
    subdomain_count = len(subdomain_parts)
    excessive_subdomains = 0
    if subdomain_count >= 3:
        excessive_subdomains = 1
        flags.append(f"EXCESSIVE_SUBDOMAINS: {subdomain_count} nested subdomains detected (subdomain stacking)")
        
    # 6. Brand & Deceptive Keywords Abuse in Subdomains
    suspicious_subdomain_brand = 0
    matched_brand = None
    
    # Check if a major brand keyword is nestled inside subdomains while root domain is different
    for brand in TARGETED_BRAND_KEYWORDS:
        if any(brand in part for part in subdomain_parts):
            # Verify if this brand is in the legitimate root domain
            if brand not in root_domain:
                suspicious_subdomain_brand = 1
                matched_brand = brand
                flags.append(f"BRAND_IN_SUBDOMAIN: Target brand '{brand}' abused in subdomain while root is '{root_domain}'")
                break
                
    # Also check deceptive action words in subdomains if no brand was caught
    if not suspicious_subdomain_brand:
        deceptive_matches = [term for term in DECEPTIVE_SUBDOMAIN_TERMS if any(term in part for part in subdomain_parts)]
        if deceptive_matches and subdomain_count >= 2:
            flags.append(f"DECEPTIVE_SUBDOMAIN_KEYWORD: Suspicious portal terms {deceptive_matches} in subdomains")

    # 7. Calculate Continuous Heuristic Risk Score (0 - 100)
    score = 0.0
    if has_ip: score += 45.0
    if has_at: score += 40.0
    if suspicious_subdomain_brand: score += 50.0
    if excessive_subdomains: score += 25.0
    if entropy_risk: score += 20.0
    if url_len > 120: score += 10.0
    
    heuristic_risk_score = round(min(100.0, score), 2)
    
    return {
        "url": clean_url,
        "heuristic_risk_score": heuristic_risk_score,
        "heuristic_flags": flags,
        "has_ip_in_url": has_ip,
        "has_at_symbol": has_at,
        "url_entropy": entropy,
        "url_entropy_risk": entropy_risk,
        "subdomain_count": subdomain_count,
        "excessive_subdomains": excessive_subdomains,
        "suspicious_subdomain_brand": suspicious_subdomain_brand,
        "abused_brand_in_subdomain": matched_brand,
        "registered_domain": root_domain,
        "subdomain": subdomain,
        "url_length": url_len
    }
