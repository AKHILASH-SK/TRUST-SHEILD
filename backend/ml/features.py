"""
TrustShield ML - feature extraction.

This module is the single source of truth for features. The dataset collector, the
training scripts and the live link pipeline all call the same functions, so a model
trained offline sees exactly what it will see in production.

Two feature groups:
  * lexical_features(url)         - computed from the URL text alone (fast, always available)
  * page_features(html, ...)      - computed from what the sandbox saw on the page

Never add a feature that encodes "this URL is in a threat feed": the labels come from
those feeds, so such a feature would let the model cheat and fail on new links.
"""

import math
import re
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlparse

import tldextract

# Offline public-suffix snapshot: no network fetch, same result everywhere
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

FEATURE_VERSION = 1

# ---------------------------------------------------------------------------
# Reference lists
# ---------------------------------------------------------------------------

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "logon", "verify", "verification", "secure", "security", "account",
    "update", "confirm", "password", "passwd", "credential", "banking", "bank", "wallet", "recover",
    "recovery", "unlock", "suspend", "suspended", "alert", "billing", "invoice", "payment", "refund",
    "support", "helpdesk", "kyc", "otp", "claim", "reward", "prize", "gift", "airdrop", "connect",
    "validate", "authenticate", "authorize", "restore", "limited", "webscr", "auth", "portal",
]

FREE_HOSTING_SUFFIXES = {
    "vercel.app", "pages.dev", "workers.dev", "netlify.app", "github.io", "gitlab.io", "weebly.com",
    "wixsite.com", "blogspot.com", "wordpress.com", "herokuapp.com", "firebaseapp.com", "web.app",
    "glitch.me", "onrender.com", "repl.co", "replit.dev", "webflow.io", "framer.app", "framer.website",
    "carrd.co", "000webhostapp.com", "sites.google.com", "notion.site", "godaddysites.com",
    "myshopify.com", "square.site", "strikingly.com", "surge.sh", "fly.dev", "railway.app",
    "ngrok.io", "ngrok-free.app", "trycloudflare.com", "azurewebsites.net", "cloudfront.net",
    "s3.amazonaws.com", "storage.googleapis.com", "r2.dev", "oraclecloud.com", "my.canva.site",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rebrand.ly",
    "tiny.cc", "shorturl.at", "t.ly", "rb.gy", "lnkd.in", "s.id", "qr.ae", "adf.ly", "bl.ink",
}

ABUSED_TLDS = {
    "top", "xyz", "sbs", "icu", "cyou", "click", "buzz", "cc", "ink", "link", "live", "online", "site",
    "store", "tk", "ml", "ga", "cf", "gq", "cfd", "rest", "monster", "quest", "lol", "bond", "fun",
    "work", "support", "shop", "vip", "wang", "zip", "mov", "su", "ru", "pw", "bar", "one", "uno",
}

COMMON_TLDS = [
    "com", "org", "net", "edu", "gov", "in", "co", "io", "uk", "de", "fr", "jp", "cn", "ru", "br",
    "au", "ca", "it", "es", "nl", "pl", "info", "biz", "me", "tv", "app", "dev", "ai", "us", "eu",
    "ac", "mil", "int", "tech", "cloud", "page", "site", "online", "store", "xyz", "top", "icu",
]
_TLD_ID = {t: i + 1 for i, t in enumerate(COMMON_TLDS)}

# Brand -> registrable domains that legitimately belong to it
BRAND_DOMAINS: Dict[str, List[str]] = {
    "paypal": ["paypal.com", "paypal.me"], "apple": ["apple.com", "icloud.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "microsoftonline.com", "outlook.com"],
    "google": ["google.com", "gmail.com", "youtube.com", "googleusercontent.com"],
    "amazon": ["amazon.com", "amazon.in", "amazon.co.uk", "amazonaws.com", "amazon.de"],
    "netflix": ["netflix.com"], "facebook": ["facebook.com", "fb.com", "meta.com"],
    "instagram": ["instagram.com"], "whatsapp": ["whatsapp.com", "wa.me"], "telegram": ["telegram.org", "t.me"],
    "linkedin": ["linkedin.com"], "dropbox": ["dropbox.com"], "docusign": ["docusign.com", "docusign.net"],
    "adobe": ["adobe.com"], "dhl": ["dhl.com", "dhl.de"], "fedex": ["fedex.com"], "ups": ["ups.com"],
    "usps": ["usps.com"], "sbi": ["sbi.co.in", "onlinesbi.sbi", "onlinesbi.com"],
    "hdfc": ["hdfcbank.com"], "icici": ["icicibank.com"], "axis": ["axisbank.com"],
    "paytm": ["paytm.com"], "phonepe": ["phonepe.com"], "irctc": ["irctc.co.in"],
    "metamask": ["metamask.io"], "ledger": ["ledger.com"], "trezor": ["trezor.io"],
    "exodus": ["exodus.com"], "binance": ["binance.com"], "coinbase": ["coinbase.com"],
    "moonpay": ["moonpay.com"], "trustwallet": ["trustwallet.com"], "phantom": ["phantom.app"],
    "opensea": ["opensea.io"], "uniswap": ["uniswap.org"], "kucoin": ["kucoin.com"],
    "chase": ["chase.com"], "wellsfargo": ["wellsfargo.com"], "bankofamerica": ["bankofamerica.com"],
    "citibank": ["citi.com", "citibank.com"], "americanexpress": ["americanexpress.com"],
    "steam": ["steampowered.com", "steamcommunity.com"], "roblox": ["roblox.com"],
    "spotify": ["spotify.com"], "outlook": ["outlook.com", "office.com", "live.com"],
    "office365": ["office.com", "microsoft.com"], "onedrive": ["onedrive.com", "live.com"],
    "chatgpt": ["openai.com", "chatgpt.com"], "openai": ["openai.com", "chatgpt.com"],
    "twitter": ["twitter.com", "x.com"], "github": ["github.com"], "zoom": ["zoom.us"],
    "airtel": ["airtel.in", "airtel.com"], "jio": ["jio.com"], "flipkart": ["flipkart.com"],
    "swiggy": ["swiggy.com"], "zomato": ["zomato.com"],
}

PAGE_LOGIN_WORDS = [
    "sign in", "log in", "login", "password", "verify your", "confirm your", "account suspended",
    "unusual activity", "security alert", "update your", "enter your", "wallet", "seed phrase",
    "recovery phrase", "connect wallet", "validate", "otp", "card number", "cvv",
]

_OBFUSCATION_RE = re.compile(r"\b(?:eval|atob|unescape|fromCharCode|document\.write)\s*\(", re.I)
_JS_REDIRECT_RE = re.compile(r"(?:window\.|document\.|top\.|self\.)?location(?:\.href|\.replace|\.assign)?\s*(?:=|\()", re.I)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def split_url(url: str) -> Dict[str, Any]:
    """Robust URL split. Returns host, registered domain, subdomain, tld and the parsed parts."""
    raw = (url or "").strip()
    parsed = urlparse(raw if "://" in raw else f"http://{raw}")
    try:
        port = parsed.port
    except ValueError:
        port = None
    host = (parsed.hostname or "").lower().rstrip(".")
    # A leading "www." says nothing about trust, but the public datasets differ in whether they include it
    if host.startswith("www.") and host.count(".") >= 2:
        host = host[4:]
    ext = _EXTRACT(host)
    registered = ".".join(p for p in (ext.domain, ext.suffix) if p).lower()
    return {
        "raw": raw, "parsed": parsed, "host": host, "port": port,
        "registered": registered, "subdomain": ext.subdomain.lower(),
        "domain_label": ext.domain.lower(), "tld": ext.suffix.lower().split(".")[-1] if ext.suffix else "",
        "suffix": ext.suffix.lower(),
    }


def group_key(url: str) -> str:
    """Grouping key for train/test splits: same site must never land on both sides."""
    parts = split_url(url)
    if parts["registered"] in FREE_HOSTING_SUFFIXES or parts["suffix"] in FREE_HOSTING_SUFFIXES:
        return parts["host"] or parts["registered"] or url
    return parts["registered"] or parts["host"] or url


def _is_free_hosting(parts: Dict[str, Any]) -> bool:
    host = parts["host"]
    return any(host == s or host.endswith("." + s) for s in FREE_HOSTING_SUFFIXES)


def _brand_mismatch(host: str, registered: str) -> int:
    """1 when a known brand name appears in the host but the site is not that brand's own domain."""
    tokens = re.split(r"[^a-z0-9]+", host)
    joined = host.replace("-", "").replace(".", "")
    for brand, official in BRAND_DOMAINS.items():
        if brand in tokens or (len(brand) >= 5 and brand in joined):
            if not any(registered == d or registered.endswith("." + d) for d in official):
                return 1
    return 0


def _max_consonant_run(text: str) -> int:
    best = run = 0
    for ch in text:
        if ch.isalpha() and ch not in "aeiou":
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best


# ---------------------------------------------------------------------------
# Lexical features (URL text only)
# ---------------------------------------------------------------------------

LEXICAL_FEATURES: List[str] = [
    "url_len", "host_len", "path_len", "query_len", "n_dots", "n_hyphens_host", "n_digits_host",
    "digit_ratio_url", "digit_ratio_host", "letter_ratio_url", "n_at", "n_pct", "n_eq", "n_amp",
    "n_slash", "n_qm", "n_underscore", "entropy_url", "entropy_host", "entropy_path",
    "n_subdomains", "path_depth", "n_query_params", "is_ip_host", "has_port", "nonstd_port",
    "is_https", "has_punycode", "tld_id", "tld_len", "tld_abused", "kw_host", "kw_path", "kw_query",
    "brand_mismatch", "brand_in_path", "free_hosting", "is_shortener", "longest_host_token",
    "avg_host_token", "vowel_ratio_label", "consonant_run_label", "label_digit_transitions",
    "has_double_slash_path", "https_token_in_host", "www_not_first", "file_ext_php", "file_ext_html",
    "file_ext_exe", "n_host_labels", "domain_label_len", "subdomain_len", "repeated_char_run",
    "hex_like_path", "base64_like_path", "path_has_email", "ends_with_slash", "has_userinfo",
]


# Features that only describe the HOST. The public benign sets are mostly bare home pages while the phishing feeds are
# mostly deep links, so path/query/length features would teach a dataset artefact, not phishing. The link-text model
# therefore uses host-level signals only; path signals are used by the page model, where benign deep links are collected.
LEXICAL_HOST_FEATURES: List[str] = [
    "host_len", "n_hyphens_host", "n_digits_host", "digit_ratio_host", "entropy_host", "n_subdomains",
    "is_ip_host", "has_port", "nonstd_port", "has_punycode", "tld_id", "tld_len", "tld_abused", "kw_host",
    "brand_mismatch", "free_hosting", "is_shortener", "longest_host_token", "avg_host_token",
    "vowel_ratio_label", "consonant_run_label", "label_digit_transitions", "https_token_in_host",
    "www_not_first", "n_host_labels", "domain_label_len", "subdomain_len", "has_userinfo",
]

# Shortcuts that separate the datasets rather than the classes
BIASED_FEATURES = {"is_https", "ends_with_slash", "final_is_https"}
PAGE_MODEL_LEXICAL_FEATURES: List[str] = [f for f in LEXICAL_FEATURES if f not in BIASED_FEATURES]


def lexical_features(url: str) -> Dict[str, float]:
    parts = split_url(url)
    parsed = parts["parsed"]
    host, path, query = parts["host"], parsed.path or "", parsed.query or ""
    raw = parts["raw"]
    label = parts["domain_label"]
    lowered = raw.lower()

    is_ip = 0
    try:
        import ipaddress
        ipaddress.ip_address(host.strip("[]"))
        is_ip = 1
    except ValueError:
        pass

    host_tokens = [t for t in re.split(r"[.\-]", host) if t]
    path_segments = [s for s in path.split("/") if s]
    ext = path_segments[-1].rsplit(".", 1)[-1].lower() if path_segments and "." in path_segments[-1] else ""
    letters = sum(c.isalpha() for c in label)
    vowels = sum(c in "aeiou" for c in label)
    transitions = sum(
        1 for a, b in zip(label, label[1:]) if (a.isdigit() and b.isalpha()) or (a.isalpha() and b.isdigit())
    )

    f: Dict[str, float] = {
        "url_len": len(raw),
        "host_len": len(host),
        "path_len": len(path),
        "query_len": len(query),
        "n_dots": raw.count("."),
        "n_hyphens_host": host.count("-"),
        "n_digits_host": sum(c.isdigit() for c in host),
        "digit_ratio_url": sum(c.isdigit() for c in raw) / max(1, len(raw)),
        "digit_ratio_host": sum(c.isdigit() for c in host) / max(1, len(host)),
        "letter_ratio_url": sum(c.isalpha() for c in raw) / max(1, len(raw)),
        "n_at": raw.count("@"),
        "n_pct": raw.count("%"),
        "n_eq": raw.count("="),
        "n_amp": raw.count("&"),
        "n_slash": raw.count("/"),
        "n_qm": raw.count("?"),
        "n_underscore": raw.count("_"),
        "entropy_url": shannon_entropy(raw),
        "entropy_host": shannon_entropy(host),
        "entropy_path": shannon_entropy(path),
        "n_subdomains": len([p for p in parts["subdomain"].split(".") if p]),
        "path_depth": len(path_segments),
        "n_query_params": len(parse_qsl(query, keep_blank_values=True)),
        "is_ip_host": is_ip,
        "has_port": int(parts["port"] is not None),
        "nonstd_port": int(parts["port"] not in (None, 80, 443)),
        "is_https": int(parsed.scheme == "https"),
        "has_punycode": int("xn--" in host),
        "tld_id": _TLD_ID.get(parts["tld"], 0),
        "tld_len": len(parts["tld"]),
        "tld_abused": int(parts["tld"] in ABUSED_TLDS),
        "kw_host": sum(k in host for k in SUSPICIOUS_KEYWORDS),
        "kw_path": sum(k in path.lower() for k in SUSPICIOUS_KEYWORDS),
        "kw_query": sum(k in query.lower() for k in SUSPICIOUS_KEYWORDS),
        "brand_mismatch": _brand_mismatch(host, parts["registered"]),
        "brand_in_path": int(any(b in path.lower() for b in BRAND_DOMAINS) and not is_ip),
        "free_hosting": int(_is_free_hosting(parts)),
        "is_shortener": int(parts["registered"] in SHORTENERS),
        "longest_host_token": max((len(t) for t in host_tokens), default=0),
        "avg_host_token": (sum(len(t) for t in host_tokens) / len(host_tokens)) if host_tokens else 0.0,
        "vowel_ratio_label": vowels / letters if letters else 0.0,
        "consonant_run_label": _max_consonant_run(label),
        "label_digit_transitions": transitions,
        "has_double_slash_path": int("//" in path),
        "https_token_in_host": int("https" in host or "http" in host),
        "www_not_first": int("www" in host.split(".")[1:]),
        "file_ext_php": int(ext in ("php", "php3", "asp", "aspx", "jsp", "cgi")),
        "file_ext_html": int(ext in ("html", "htm")),
        "file_ext_exe": int(ext in ("exe", "apk", "zip", "rar", "scr", "msi", "bat", "js", "jar", "dmg")),
        "n_host_labels": len(host.split(".")) if host else 0,
        "domain_label_len": len(label),
        "subdomain_len": len(parts["subdomain"]),
        "repeated_char_run": max((len(m.group(0)) for m in re.finditer(r"(.)\1{2,}", lowered)), default=0),
        "hex_like_path": int(bool(re.search(r"/[0-9a-f]{24,}", lowered))),
        "base64_like_path": int(bool(re.search(r"[A-Za-z0-9+/=_-]{40,}", path + query))),
        "path_has_email": int(bool(re.search(r"[\w.+-]+@[\w-]+\.[\w.]+", path + query))),
        "ends_with_slash": int(raw.endswith("/")),
        "has_userinfo": int(bool(parsed.username or parsed.password)),
    }
    return {name: float(f[name]) for name in LEXICAL_FEATURES}


# ---------------------------------------------------------------------------
# Page features (what the sandbox saw)
# ---------------------------------------------------------------------------

PAGE_FEATURES: List[str] = [
    "page_reachable", "html_len", "n_forms", "n_inputs", "n_password", "n_text_inputs", "n_hidden_inputs",
    "form_action_empty", "form_action_external", "form_post_method", "n_scripts", "n_inline_scripts",
    "n_external_scripts", "n_links", "ratio_external_links", "n_null_links", "n_iframes", "n_hidden_iframes",
    "n_images", "ratio_external_imgs", "has_meta_refresh", "js_redirect", "title_len", "title_login_words",
    "title_brand", "title_brand_mismatch", "body_text_len", "body_login_words", "favicon_external",
    "right_click_blocked", "obfuscation_calls", "is_spa_shell", "n_redirects", "final_host_changed",
    "final_is_https", "domain_age_days", "newly_registered", "sandbox_has_password", "sandbox_external_form",
    "sandbox_exfiltration", "sandbox_hidden_iframes", "sandbox_title_mismatch", "sandbox_brand_impersonation",
    "copyright_brand_mismatch", "n_unique_external_domains",
]

PAGE_MODEL_PAGE_FEATURES: List[str] = [f for f in PAGE_FEATURES if f not in BIASED_FEATURES]

_NAN = float("nan")


def empty_page_features() -> Dict[str, float]:
    """Used when the page could not be fetched. NaN lets the model treat it as 'unknown'."""
    return {name: (0.0 if name == "page_reachable" else _NAN) for name in PAGE_FEATURES}


def _registered(url_or_host: str) -> str:
    return split_url(url_or_host)["registered"]


def page_features(html: str, final_url: str, initial_url: str,
                  sandbox: Optional[Dict[str, Any]] = None) -> Dict[str, float]:
    """Features from the rendered page. `sandbox` is the dict returned by the sandbox engine."""
    from bs4 import BeautifulSoup

    sandbox = sandbox or {}
    if not html:
        feats = empty_page_features()
        feats["domain_age_days"] = _age(sandbox)
        feats["newly_registered"] = float(sandbox.get("newly_registered_domain", 0) or 0)
        return feats

    html = html[:400_000]
    soup = BeautifulSoup(html, "html.parser")
    final_reg = _registered(final_url)
    final_parts = split_url(final_url)
    init_parts = split_url(initial_url)

    inputs = soup.find_all("input")
    pw = [i for i in inputs if (i.get("type") or "").lower() == "password"]
    hidden = [i for i in inputs if (i.get("type") or "").lower() == "hidden"]
    text_inputs = [i for i in inputs if (i.get("type") or "text").lower() in ("text", "email", "tel", "number", "")]

    forms = soup.find_all("form")
    action_empty = action_external = post_method = 0
    for form in forms:
        action = (form.get("action") or "").strip()
        if action in ("", "#", "javascript:void(0)", "javascript:;"):
            action_empty += 1
        else:
            target = _registered(action) if "://" in action or action.startswith("//") else ""
            if target and final_reg and target != final_reg:
                action_external += 1
        if (form.get("method") or "").lower() == "post":
            post_method += 1

    scripts = soup.find_all("script")
    inline = [s for s in scripts if not s.get("src")]
    inline_text = " ".join((s.string or s.get_text() or "") for s in inline)[:200_000]

    links = [a.get("href") or "" for a in soup.find_all("a")]
    external_domains = set()
    ext_links = null_links = 0
    for href in links:
        h = href.strip()
        if h in ("", "#") or h.lower().startswith(("javascript:", "mailto:", "tel:")):
            null_links += 1
            continue
        if "://" in h or h.startswith("//"):
            reg = _registered(h)
            if reg and reg != final_reg:
                ext_links += 1
                external_domains.add(reg)

    imgs = soup.find_all("img")
    ext_imgs = 0
    for img in imgs:
        src = img.get("src") or ""
        if "://" in src or src.startswith("//"):
            reg = _registered(src)
            if reg and reg != final_reg:
                ext_imgs += 1
                external_domains.add(reg)

    iframes = soup.find_all("iframe")
    hidden_iframes = 0
    for fr in iframes:
        style = (fr.get("style") or "").lower().replace(" ", "")
        if "display:none" in style or "visibility:hidden" in style or str(fr.get("width")) in ("0", "1") \
                or str(fr.get("height")) in ("0", "1"):
            hidden_iframes += 1

    title = (soup.title.string or "").strip().lower() if soup.title and soup.title.string else ""
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    body_text = " ".join(soup.get_text(separator=" ").split()).lower()

    meta_refresh = int(any((m.get("http-equiv") or "").lower() == "refresh" for m in soup.find_all("meta")))
    icon_ext = 0
    for link in soup.find_all("link"):
        rel = " ".join(link.get("rel") or []).lower()
        if "icon" in rel:
            href = link.get("href") or ""
            if ("://" in href or href.startswith("//")) and _registered(href) != final_reg:
                icon_ext = 1

    title_brand = 0
    title_brand_mismatch = 0
    for brand, official in BRAND_DOMAINS.items():
        if re.search(rf"\b{re.escape(brand)}\b", title):
            title_brand = 1
            if not any(final_reg == d or final_reg.endswith("." + d) for d in official):
                title_brand_mismatch = 1
                break

    copyright_mismatch = 0
    for m in re.finditer(r"(?:©|&copy;|copyright)\s*(?:\d{4}\s*)?([a-z][a-z0-9 .&-]{2,30})", body_text):
        name = m.group(1).replace(" ", "").replace(".", "")
        for brand, official in BRAND_DOMAINS.items():
            if brand in name and not any(final_reg == d or final_reg.endswith("." + d) for d in official):
                copyright_mismatch = 1

    text_len = len(body_text)
    right_click = int(bool(re.search(r"contextmenu|oncontextmenu|event\.button\s*==\s*2", inline_text, re.I)))

    return {
        "page_reachable": 1.0,
        "html_len": float(len(html)),
        "n_forms": float(len(forms)),
        "n_inputs": float(len(inputs)),
        "n_password": float(len(pw)),
        "n_text_inputs": float(len(text_inputs)),
        "n_hidden_inputs": float(len(hidden)),
        "form_action_empty": float(action_empty),
        "form_action_external": float(action_external),
        "form_post_method": float(post_method),
        "n_scripts": float(len(scripts)),
        "n_inline_scripts": float(len(inline)),
        "n_external_scripts": float(len(scripts) - len(inline)),
        "n_links": float(len(links)),
        "ratio_external_links": ext_links / max(1, len(links)),
        "n_null_links": float(null_links),
        "n_iframes": float(len(iframes)),
        "n_hidden_iframes": float(hidden_iframes),
        "n_images": float(len(imgs)),
        "ratio_external_imgs": ext_imgs / max(1, len(imgs)),
        "has_meta_refresh": float(meta_refresh),
        "js_redirect": float(bool(_JS_REDIRECT_RE.search(inline_text))),
        "title_len": float(len(title)),
        "title_login_words": float(sum(w in title for w in PAGE_LOGIN_WORDS)),
        "title_brand": float(title_brand),
        "title_brand_mismatch": float(title_brand_mismatch),
        "body_text_len": float(text_len),
        "body_login_words": float(sum(w in body_text for w in PAGE_LOGIN_WORDS)),
        "favicon_external": float(icon_ext),
        "right_click_blocked": float(right_click),
        "obfuscation_calls": float(len(_OBFUSCATION_RE.findall(inline_text))),
        "is_spa_shell": float(text_len < 200 and len(scripts) >= 1),
        "n_redirects": float(sandbox.get("sandbox_num_redirects", 0) or 0),
        "final_host_changed": float(final_parts["registered"] != init_parts["registered"]),
        "final_is_https": float(final_url.lower().startswith("https://")),
        "domain_age_days": _age(sandbox),
        "newly_registered": float(sandbox.get("newly_registered_domain", 0) or 0),
        "sandbox_has_password": float(sandbox.get("sandbox_has_password_field", 0) or 0),
        "sandbox_external_form": float(sandbox.get("external_form_action", 0) or 0),
        "sandbox_exfiltration": float(sandbox.get("suspicious_exfiltration", 0) or 0),
        "sandbox_hidden_iframes": float(sandbox.get("sandbox_hidden_iframes", 0) or 0),
        "sandbox_title_mismatch": float(sandbox.get("sandbox_title_mismatch", 0) or 0),
        "sandbox_brand_impersonation": float(sandbox.get("brand_impersonation", 0) or 0),
        "copyright_brand_mismatch": float(copyright_mismatch),
        "n_unique_external_domains": float(len(external_domains)),
    }


def _age(sandbox: Dict[str, Any]) -> float:
    age = sandbox.get("domain_age_days", -1)
    return _NAN if age is None or age < 0 else float(age)


# ---------------------------------------------------------------------------
# Vector assembly
# ---------------------------------------------------------------------------

def vector(names: List[str], values: Dict[str, float]) -> List[float]:
    return [float(values.get(n, _NAN)) for n in names]
