import os
import time
import logging
import re
import threading
from datetime import datetime, timezone
from typing import Dict, Any, Tuple
from urllib.parse import urlparse, urljoin

import requests
import tldextract

from .url_safety import assert_public_url, UnsafeUrlError
from .htmlsafe import make_soup

from .browser_sandbox import BrowserSandbox, analyze_isolated, browser_available

logger = logging.getLogger(__name__)

# Known exfiltration endpoints used by phishers/infostealers
SUSPICIOUS_EXFILTRATION_HOSTS = [
    'api.telegram.org',
    'discord.com',
    'discordapp.com',
    'formspree.io',
    'formcarry.com',
    'emailjs.com',
    'webtooid.com',
    'pastebin.com'
]

# High-value targeted brands and their authorized domain roots
TARGETED_BRANDS = {
    "microsoft": {
        "keywords": ["microsoft", "office 365", "outlook", "onedrive", "sharepoint", "azure"],
        "allowed_domains": ["microsoft.com", "live.com", "office.com", "office365.com", "microsoftonline.com", "windows.net", "sharepoint.com", "aka.ms", "msft.it"]
    },
    "google": {
        "keywords": ["google", "gmail", "google drive", "google workspace", "google forms", "google docs"],
        "allowed_domains": [
            "google.com", "gmail.com", "google.co.in", "accounts.google.com",
            "forms.gle", "docs.google.com", "drive.google.com", "forms.google.com",
            "goo.gl", "g.co", "youtube.com", "youtu.be"
        ]
    },
    "paypal": {
        "keywords": ["paypal", "paypal security"],
        "allowed_domains": ["paypal.com", "paypal.me", "paypal-communication.com"]
    },
    "amazon": {
        "keywords": ["amazon", "amazon prime", "amazon web services"],
        "allowed_domains": ["amazon.com", "amazon.in", "amazon.co.uk", "amzn.to", "aws.amazon.com"]
    },
    "apple": {
        "keywords": ["apple id", "icloud", "apple support"],
        "allowed_domains": ["apple.com", "icloud.com", "apple.co"]
    },
    "netflix": {
        "keywords": ["netflix", "netflix member"],
        "allowed_domains": ["netflix.com"]
    },
    "state_bank_of_india": {
        "keywords": ["state bank of india", "onlinesbi", "sbi yono"],
        "allowed_domains": ["onlinesbi.sbi", "sbi.co.in"]
    },
    "hdfc": {
        "keywords": ["hdfc bank", "netbanking hdfc"],
        "allowed_domains": ["hdfcbank.com"]
    },
    "dhl": {
        "keywords": ["dhl express", "dhl parcel", "dhl tracking"],
        "allowed_domains": ["dhl.com", "dhl.de"]
    },
    "chatgpt": {
        "keywords": ["chatgpt", "openai", "chatgpt plus"],
        "allowed_domains": ["openai.com", "chatgpt.com"]
    },
    "linkedin": {
        "keywords": ["linkedin", "linkedin login", "sign in | linkedin"],
        "allowed_domains": ["linkedin.com", "lnkd.in"]
    }
}

def is_chrome_available() -> bool:
    """Kept for older callers: True when the Playwright browser sandbox can run on this host."""
    return browser_available()


_KW_REGEX_CACHE: Dict[str, "re.Pattern"] = {}


def _keyword_in_text(keyword: str, text: str) -> bool:
    """Whole-word/phrase match ('aws' must not match 'laws')."""
    pat = _KW_REGEX_CACHE.get(keyword)
    if pat is None:
        pat = re.compile(r"(?<![a-z0-9])" + re.escape(keyword.lower()) + r"(?![a-z0-9])")
        _KW_REGEX_CACHE[keyword] = pat
    return pat.search(text or "") is not None


# Real brand names only (generic words like bank/login/secure are not brands)
TITLE_MISMATCH_BRANDS = [
    "paypal", "amazon", "microsoft", "apple", "netflix", "outlook", "linkedin",
    "google", "dhl", "hdfc", "sbi", "chatgpt", "openai",
]


def _is_trusted_url(url: str) -> bool:
    """Brand domain whose own login forms/redirects are trusted (user-content hosts are not)."""
    from .link_threat_pipeline import is_brand_fast_path
    return is_brand_fast_path(url)


def _title_brand_mismatch(page_title: str, final_url: str, has_credential_form: bool) -> bool:
    """Title names a real brand that the host does not contain, on a page with a credential form."""
    if not has_credential_form or not page_title or _is_trusted_url(final_url):
        return False
    host = urlparse(final_url).netloc.lower()
    for brand in TITLE_MISMATCH_BRANDS:
        if _keyword_in_text(brand, page_title) and brand not in host:
            print(f"   [!] Title Mismatch! Title claims '{brand}' but domain is '{host}'")
            return True
    return False


class VirtualSandboxAnalyzer:
    """
    Tier 3: Custom Zero-Day Virtual Sandbox (Headless Browser).
    Spins up an isolated, stealth headless browser environment, navigates to the URL, 
    and inspects DOM, Network, Form destinations, and WHOIS lifecycle.
    """
    def __init__(self):
        # Desktop user agent used only by the HTTP fallback (hosts that cannot run a real browser)
        self.user_agent = ("Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) "
                           "Chrome/124.0.0.0 Mobile Safari/537.36")

    DYNAMIC_HOSTING_PROVIDERS = {
        'vercel.app', 'github.io', 'pages.dev', 'netlify.app', 'herokuapp.com',
        'web.app', 'firebaseapp.com', 'glitch.me', 'onrender.com', 'azurewebsites.net',
        'workers.dev', 'cloudfront.net', 's3.amazonaws.com', 'gitlab.io', 'bitballoon.com',
        'surge.sh', 'replit.app', 'replit.dev', 'ngrok.io', 'localtunnel.me'
    }

    _DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")
    _AGE_CACHE: Dict[str, Tuple[float, Tuple[int, int, int]]] = {}
    _AGE_LOCK = threading.Lock()
    _AGE_TTL_KNOWN = 6 * 3600
    _AGE_TTL_UNKNOWN = 10 * 60

    @staticmethod
    def _age_result(age_days: int) -> Tuple[int, int, int]:
        if age_days < 14:
            print(f"   [!] Zero-Day Scam Domain Detected! Registered {age_days} days ago (< 14 days)")
            return age_days, 1, 90
        if age_days < 30:
            print(f"   [*] Newly Registered Domain Detected! Registered {age_days} days ago (< 30 days)")
            return age_days, 1, 60
        return age_days, 0, 0

    def _query_domain_age(self, url: str) -> Tuple[int, int, int]:
        """
        Domain registration age via RDAP over HTTPS (port 43 WHOIS is blocked on Render).
        Unknown / not found / errors return (-1, 0, 0): never treated as new.
        Returns: (domain_age_days, newly_registered_domain_flag, domain_risk_score)
        """
        unknown = (-1, 0, 0)
        if os.environ.get("TRUSTSHIELD_LAB_MODE") == "1":      # test lab: fake domains must not be looked up on the internet
            return -1, 0, 0
        try:
            ext = tldextract.extract(url)
            reg_domain = ext.registered_domain.lower() if ext.registered_domain else ""
            if not reg_domain or reg_domain in self.DYNAMIC_HOSTING_PROVIDERS:
                return unknown
            if len(reg_domain) > 253 or not self._DOMAIN_RE.match(reg_domain):
                return unknown

            now = time.time()
            with self._AGE_LOCK:
                hit = self._AGE_CACHE.get(reg_domain)
                if hit and hit[0] > now:
                    return hit[1]

            result = unknown
            ttl = self._AGE_TTL_UNKNOWN
            try:
                resp = requests.get(
                    f"https://rdap.org/domain/{reg_domain}",
                    headers={"Accept": "application/rdap+json, application/json"},
                    timeout=3,
                )
                if resp.status_code == 200:
                    events = (resp.json() or {}).get("events", [])
                    for ev in events:
                        if ev.get("eventAction") == "registration" and ev.get("eventDate"):
                            created = datetime.fromisoformat(str(ev["eventDate"]).replace("Z", "+00:00"))
                            if created.tzinfo is None:
                                created = created.replace(tzinfo=timezone.utc)
                            age_days = max(0, (datetime.now(timezone.utc) - created).days)
                            result = self._age_result(age_days)
                            ttl = self._AGE_TTL_KNOWN
                            break
            except Exception as e:
                logger.debug(f"RDAP lookup failed for {reg_domain}: {e}")

            with self._AGE_LOCK:
                self._AGE_CACHE[reg_domain] = (time.time() + ttl, result)
            return result
        except Exception:
            return unknown

    MAX_REDIRECT_HOPS = 5
    MAX_BODY_BYTES = 1_500_000
    REQUEST_BUDGET_SECONDS = 5.0

    def _safe_fetch(self, url: str):
        """
        SSRF-safe fetch: validates the URL and every redirect hop, follows redirects
        manually (max 5), streams the body capped at 1.5 MB within a 5 s budget.
        Returns (final_url, text, hops); text is '' for non-HTML content.
        Raises UnsafeUrlError for unsafe targets.
        """
        current = assert_public_url(url)
        hops = []
        for _ in range(self.MAX_REDIRECT_HOPS + 1):
            deadline = time.monotonic() + self.REQUEST_BUDGET_SECONDS
            resp = requests.get(
                current,
                headers={"User-Agent": self.user_agent},
                timeout=self.REQUEST_BUDGET_SECONDS,
                allow_redirects=False,
                # Deliberately NOT verifying certificates: this fetch exists to inspect untrusted, often broken or
                # self-signed phishing sites, and nothing trusted is sent over it (no cookies, no credentials). With
                # verification on, exactly the suspicious sites we need to analyse would fail to load. The browser
                # sandbox does the same (ignore_https_errors) and records the certificate details as evidence.
                verify=False,
                stream=True,
            )
            try:
                location = resp.headers.get("Location")
                if 300 <= resp.status_code < 400 and location:
                    nxt = urljoin(current, location)
                    assert_public_url(nxt)
                    hops.append(nxt)
                    current = nxt
                    continue

                ctype = (resp.headers.get("Content-Type") or "").lower()
                if ctype and not any(t in ctype for t in ("text/html", "application/xhtml", "text/plain")):
                    return current, "", hops
                body = b""
                for chunk in resp.iter_content(chunk_size=16384):
                    body += chunk
                    if len(body) >= self.MAX_BODY_BYTES or time.monotonic() > deadline:
                        break
                body = body[: self.MAX_BODY_BYTES]
                encoding = getattr(resp, "encoding", None) or "utf-8"
                try:
                    text = body.decode(encoding, errors="replace")
                except LookupError:
                    text = body.decode("utf-8", errors="replace")
                return current, text, hops
            finally:
                try:
                    resp.close()
                except Exception:
                    pass
        raise requests.TooManyRedirects(f"More than {self.MAX_REDIRECT_HOPS} redirects")

    @staticmethod
    def _blocked_features(features: Dict[str, Any]) -> Dict[str, Any]:
        features['sandbox_unreachable'] = 1
        features['sandbox_blocked_unsafe_url'] = 1
        features['sandbox_threat_score'] = 40
        return features

    def _analyze_with_requests(self, url: str, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Lightweight cloud-resilient sandbox: Analyzes HTTP response and DOM elements
        using requests + BeautifulSoup without requiring a heavy Chrome GUI browser.
        Ideal for cloud environments (Render/Heroku) with limited RAM (512MB).
        SSRF-guarded: every URL and redirect hop must resolve to a public address.
        """
        from bs4 import BeautifulSoup

        defaults = {
            "sandbox_has_password_field": 0,
            "external_form_action": 0,
            "suspicious_exfiltration": 0,
            "domain_age_days": -1,
            "newly_registered_domain": 0,
            "domain_risk_score": 0,
            "brand_impersonation": 0,
            "impersonated_brand": None,
            "sandbox_brand_impersonation": 0,
            "sandbox_impersonated_brand": None,
            "detected_target_brand": "",
            "sandbox_num_redirects": 0,
            "sandbox_hidden_iframes": 0,
            "sandbox_title_mismatch": 0,
            "sandbox_unreachable": 0,
            "sandbox_blocked_unsafe_url": 0,
            "sandbox_threat_score": 0
        }
        for k, v in defaults.items():
            features.setdefault(k, v)

        try:
            assert_public_url(url)
        except UnsafeUrlError as e:
            print(f"[-] [CLOUD SANDBOX] URL blocked by SSRF guard: {e}")
            return self._blocked_features(features)

        try:
            print(f"[*] [CLOUD SANDBOX] Detonating URL via Lightweight DOM Analyzer: {url}")
            initial_url = url
            try:
                final_url, html_text, hops = self._safe_fetch(url)
            except UnsafeUrlError as e:
                print(f"[-] [CLOUD SANDBOX] Redirect blocked by SSRF guard: {e}")
                return self._blocked_features(features)

            # Raw page evidence for the ML page-feature extractor (removed before results leave the pipeline)
            features['_html'] = html_text[:400000]
            features['_final_url'] = final_url

            current_ext = tldextract.extract(final_url)
            current_reg_domain = current_ext.registered_domain.lower()
            is_trusted_auth_domain = _is_trusted_url(final_url)

            if hops:
                if not (_is_trusted_url(initial_url) and is_trusted_auth_domain):
                    print(f"   [!] Redirect detected: {initial_url} -> {final_url}")
                    features['sandbox_num_redirects'] = len(hops)

            soup = make_soup(html_text)
            page_title = (soup.title.string or "").strip().lower() if soup.title and soup.title.string else ""

            # Check password fields
            pwds = soup.find_all('input', {'type': lambda t: t and t.lower() == 'password'})
            has_credential_form = len(pwds) > 0 or bool(re.search(r"type=[\"']password[\"']", html_text, re.I))
            if has_credential_form:
                if is_trusted_auth_domain:
                    features['sandbox_has_password_field'] = 0
                else:
                    print("   [!] Credential Harvesting Form Detected!")
                    features['sandbox_has_password_field'] = 1

            # Forms and actions
            forms = soup.find_all('form')
            for form in forms:
                action_attr = form.get('action') or ""
                if action_attr.strip():
                    resolved_action = urljoin(final_url, action_attr).strip()
                    action_ext = tldextract.extract(resolved_action)
                    action_reg_domain = action_ext.registered_domain.lower()

                    if action_reg_domain and current_reg_domain and action_reg_domain != current_reg_domain:
                        if not (is_trusted_auth_domain and _is_trusted_url(resolved_action)):
                            print(f"   [!] External Form Action Detected! {current_reg_domain} -> {action_reg_domain}")
                            features['external_form_action'] = 1

                    is_suspicious_endpoint = any(host in resolved_action.lower() for host in SUSPICIOUS_EXFILTRATION_HOSTS)
                    is_raw_ip = bool(re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", resolved_action))
                    if is_suspicious_endpoint or is_raw_ip:
                        print(f"   [!] Malicious Form Exfiltration Endpoint Detected: {resolved_action}")
                        features['suspicious_exfiltration'] = 1

            # Hidden iframes
            iframes = soup.find_all('iframe')
            hidden_iframes = 0
            for iframe in iframes:
                style = str(iframe.get('style', '')).lower()
                width = str(iframe.get('width', ''))
                height = str(iframe.get('height', ''))
                if 'display:none' in style or 'visibility:hidden' in style or width in ('0', '1') or height in ('0', '1'):
                    hidden_iframes += 1
            features['sandbox_hidden_iframes'] = hidden_iframes

            # Title Mismatch (real brands only, and only with a credential form)
            if _title_brand_mismatch(page_title, final_url, has_credential_form):
                features['sandbox_title_mismatch'] = 1

            # Brand Impersonation Check (word-boundary keyword matching)
            body_text = soup.get_text(separator=' ').lower()
            body_head = body_text[:1000]
            has_login_words = _keyword_in_text('login', body_text) or _keyword_in_text('sign in', body_text)
            for brand, data in TARGETED_BRANDS.items():
                is_allowed = any(current_reg_domain == allowed or current_reg_domain.endswith('.' + allowed) for allowed in data['allowed_domains'])
                if not is_allowed:
                    title_match = any(_keyword_in_text(kw, page_title) for kw in data['keywords'])
                    content_match = any(_keyword_in_text(kw, body_head) for kw in data['keywords'])
                    if title_match or (content_match and has_login_words):
                        print(f"   [!] Brand Impersonation Detected! Claiming '{brand}' on unauthorized domain '{current_reg_domain}'")
                        features['brand_impersonation'] = 1
                        features['impersonated_brand'] = brand
                        features['sandbox_brand_impersonation'] = 1
                        features['sandbox_impersonated_brand'] = brand
                        features['detected_target_brand'] = brand
                        break

            features['sandbox_threat_score'] = self._score(features, is_trusted_auth_domain)
            print(f"[+] [CLOUD SANDBOX] Analysis Complete. Sandbox Score: {features['sandbox_threat_score']}")
            return features

        except Exception as e:
            print(f"[-] [CLOUD SANDBOX] Request error: {e}")
            features['sandbox_unreachable'] = 1
            features['sandbox_threat_score'] = 40
            return features

    @staticmethod
    def _score(features: Dict[str, Any], is_trusted_auth_domain: bool) -> int:
        if is_trusted_auth_domain and not features.get('suspicious_exfiltration', 0):
            return 0
        threat_score = 0
        is_credential_risk = (
            features.get('brand_impersonation', 0) or
            features.get('external_form_action', 0) or
            features.get('suspicious_exfiltration', 0) or
            features.get('newly_registered_domain', 0) or
            features.get('sandbox_title_mismatch', 0)
        )
        if features.get('sandbox_has_password_field', 0) and is_credential_risk:
            threat_score += 45
        if features.get('external_form_action', 0): threat_score += 40
        if features.get('suspicious_exfiltration', 0): threat_score += 55
        if features.get('brand_impersonation', 0): threat_score += 50
        if features.get('newly_registered_domain', 0): threat_score += 35
        if features.get('sandbox_title_mismatch', 0): threat_score += 30
        if features.get('sandbox_num_redirects', 0): threat_score += 20
        if features.get('sandbox_hidden_iframes', 0) > 0: threat_score += 25
        return min(100, threat_score)

    def analyze_link_in_sandbox(self, url: str) -> Dict[str, Any]:
        """
        Collect evidence about a link. With a real browser available this is the full dynamic analysis
        (core_engine/browser_sandbox.py); otherwise a page-source-only HTTP fallback is used (e.g. on Render).
        """
        features: Dict[str, Any] = {
            "engine": "http_fallback", "verification_state": "verified", "unverified_reason": "",
            "sandbox_has_password_field": 0, "external_form_action": 0, "suspicious_exfiltration": 0,
            "domain_age_days": -1, "newly_registered_domain": 0, "domain_risk_score": 0,
            "brand_impersonation": 0, "impersonated_brand": None, "sandbox_brand_impersonation": 0,
            "sandbox_impersonated_brand": None, "detected_target_brand": "", "sandbox_num_redirects": 0,
            "sandbox_hidden_iframes": 0, "sandbox_title_mismatch": 0, "sandbox_unreachable": 0,
            "sandbox_blocked_unsafe_url": 0, "sandbox_threat_score": 0,
        }

        # Domain age (RDAP) runs in parallel with the browser so the two waits overlap
        age: Dict[str, Tuple[int, int, int]] = {}
        age_thread = threading.Thread(target=lambda: age.update(v=self._query_domain_age(url)), daemon=True)
        age_thread.start()

        result: Dict[str, Any]
        if browser_available():
            print(f"[*] [BROWSER SANDBOX] Analysing {url}")
            # Default: each scan runs in its own process with a hard time limit, so a page that hangs the browser
            # can never block a worker. SANDBOX_ISOLATE=0 runs it in-process (used by unit tests).
            if os.environ.get("SANDBOX_ISOLATE", "1") == "1":
                evidence = analyze_isolated(url)
            else:
                evidence = BrowserSandbox().analyze(url)
            if evidence.get("verification_state") == "unverified" and evidence.get("unverified_reason") == "crashed":
                print("[!] Browser crashed; falling back to the HTTP analyzer")
                result = self._analyze_with_requests(url, features)
            else:
                features.update(evidence)
                result = features
        else:
            print("[*] [HTTP SANDBOX] No browser on this host; using the page-source analyzer")
            result = self._analyze_with_requests(url, features)

        age_thread.join(timeout=4)
        age_days, new_flag, risk = age.get("v", (-1, 0, 0))
        result["domain_age_days"], result["newly_registered_domain"], result["domain_risk_score"] = age_days, new_flag, risk
        if result.get("sandbox_unreachable") and result.get("verification_state") == "verified":
            result["verification_state"], result["unverified_reason"] = "unverified", result.get("unverified_reason") or "unreachable"
        return result
