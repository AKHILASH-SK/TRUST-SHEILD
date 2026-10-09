"""
TrustShield browser sandbox v2 (Playwright + Chromium).

Opens a link the way a phone would, then works out dynamically, for ANY website, whether it is trying to collect
credentials, and where that data would go:

  1. load the page as a mobile browser, follow every redirect, close cookie banners
  2. look for a credential surface on the landing page (password / OTP / card / wallet-phrase fields), including
     JavaScript-built forms, modals and embedded frames
  3. if there is none, FIND the way in generically: score every visible clickable element by how much it looks like
     "log in" / "sign up" (text, accessible labels, link target, icons, position - in many languages), click the best
     few and examine whatever appears (new page, popup, modal), up to MAX_DEPTH levels
  4. on an unknown site with a credential form, type FAKE credentials once and record where the submission would go;
     the outgoing request is captured and stopped before it leaves the sandbox
  5. collect identity, legitimacy and wording evidence

It only COLLECTS EVIDENCE (plus a rule-based fallback score). The final verdict is made later by the ML stage and the
decision engine. Every request the browser makes is checked by the SSRF guard, so scripts and redirects inside the
page cannot reach internal addresses. Downloads are cancelled, popups and dialogs are contained.

Evidence keys include the legacy ones the pipeline already uses (sandbox_has_password_field, external_form_action, ...).
"""

import base64
import json
import logging
import os
import re
import secrets
import signal
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import tldextract

from .url_safety import UnsafeUrlError, assert_public_url

logger = logging.getLogger("trustshield.browser_sandbox")
# Closing the browser while a request is still in flight makes Playwright's event loop log a harmless (but very noisy)
# "CancelledError" traceback. The scan result is unaffected, so keep the console readable.
logging.getLogger("asyncio").setLevel(logging.CRITICAL)

try:  # pragma: no cover - environment dependent
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_IMPORTABLE = True
except Exception:  # pragma: no cover
    PLAYWRIGHT_IMPORTABLE = False
    PlaywrightError = Exception  # type: ignore

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

TOTAL_BUDGET_SECONDS = float(os.getenv("SANDBOX_TOTAL_SECONDS", "30"))
MAX_CLICKS = int(os.getenv("SANDBOX_MAX_CLICKS", "3"))
MAX_DEPTH = 2
MAX_REQUESTS = 400
CREDENTIAL_PROBE_ENABLED = os.getenv("SANDBOX_CREDENTIAL_PROBE", "true").lower() == "true"

# Known sign-in providers: a login that hands over to one of these is normal behaviour, not a phishing hop.
IDENTITY_PROVIDER_DOMAINS = {
    "google.com", "gstatic.com", "microsoftonline.com", "live.com", "microsoft.com", "office.com", "apple.com",
    "facebook.com", "github.com", "linkedin.com", "twitter.com", "x.com", "okta.com", "auth0.com", "amazon.com",
    "amazoncognito.com", "paypal.com", "digilocker.gov.in", "sso.gov.in", "yahoo.com", "slack.com", "dropbox.com",
}

# Services that phishing kits use to receive stolen data
EXFIL_HOST_SUFFIXES = (
    "api.telegram.org", "telegram.org", "discord.com", "discordapp.com", "hooks.slack.com", "formspree.io",
    "formcarry.com", "emailjs.com", "webhook.site", "pastebin.com", "requestbin.com", "ngrok.io",
    "ngrok-free.app", "script.google.com", "getform.io", "formsubmit.co", "web3forms.com", "netlify.com/forms",
)

CHALLENGE_TITLE_RE = re.compile(r"just a moment|attention required|checking your browser|verify you are human|"
                                r"are you a robot|access denied|ddos protection|security check|please wait", re.I)
CHALLENGE_FRAME_RE = re.compile(r"captcha|turnstile|challenges\.cloudflare|hcaptcha|recaptcha", re.I)

# Fake values typed into credential forms. The marker lets us prove that a captured request carries them.
PROBE_MARKER = "TsProbe" + secrets.token_hex(4)      # letters and digits only: survives URL/form encoding unchanged
PROBE_VALUES = {
    "password": PROBE_MARKER + "9x", "username": "probe.user.ts", "email": "probe.user.ts@example.com",
    "phone": "9876500000", "otp": "123456", "card": "4242424242424242", "cvv": "123", "expiry": "12/30",
    "pin": "1234", "name": "Test User", "gov_id": "000000000000", "other": "test",
    "wallet_phrase": " ".join(["abandon"] * 11 + ["about"]),
}

# any of these inside a captured request proves our fake data (not the page's own) was being sent
PROBE_MARKERS = (PROBE_MARKER, PROBE_VALUES["wallet_phrase"], PROBE_VALUES["email"], PROBE_VALUES["card"])

WORDING_PATTERNS = {
    "urgency": r"urgent|immediately|within \d+ (?:hours|hrs|minutes)|expires? (?:today|soon)|last chance|act now|final notice|"
               r"24 hours|48 hours|तुरंत|अभी",
    "threat": r"suspend|suspended|blocked|deactivat|terminated|locked|unauthori[sz]ed|unusual (?:activity|sign)|"
              r"security alert|compromised|restricted|ब्लॉक|बंद",
    "credentials": r"enter your (?:password|pin|otp|card|cvv|details)|verify (?:your )?(?:account|identity|details|kyc)|"
                   r"confirm (?:your )?(?:account|identity|details)|update (?:your )?(?:kyc|account|details)|re-?activate|kyc",
    "payment": r"card number|cvv|expiry|net ?banking|upi|bank account|debit card|credit card|payment (?:failed|pending)|refund",
    "prize": r"congratulations|you(?:'ve| have) won|prize|reward|gift card|lucky|free (?:gift|iphone|recharge)|claim now",
    "lure": r"shared (?:a )?(?:document )?with you|document (?:has been )?shared|click (?:on )?[\"']?(?:file|here|view|open)|"
            r"(?:view|open|review|access) (?:the |your )?(?:document|invoice|proposal|statement)|secure (?:document|message)|"
            r"voicemail|payment (?:receipt|advice)|invoice attached|e-?sign",
    "crypto": r"seed phrase|recovery phrase|connect wallet|wallet connect|airdrop|private key|metamask|12[- ]word",
}
_WORDING_RE = {k: re.compile(v, re.I) for k, v in WORDING_PATTERNS.items()}

# ---------------------------------------------------------------------------------------------------------------------
# In-page JavaScript: one structured snapshot of what is on screen. Runs in every frame.
# ---------------------------------------------------------------------------------------------------------------------
COLLECT_JS = r"""
() => {
  const MAXN = 6000;
  const deepAll = (selector) => {
    const out = []; let seen = 0;
    const walk = (root) => {
      let list; try { list = root.querySelectorAll(selector); } catch (e) { return; }
      for (const el of list) { out.push(el); }
      let all; try { all = root.querySelectorAll('*'); } catch (e) { return; }
      for (const el of all) { if (++seen > MAXN) return; if (el.shadowRoot) walk(el.shadowRoot); }
    };
    walk(document); return out;
  };
  const vh = window.innerHeight || 800, vw = window.innerWidth || 400;
  const visible = (el) => {
    if (!el || !el.getBoundingClientRect) return false;
    const r = el.getBoundingClientRect(); if (r.width < 2 || r.height < 2) return false;
    const s = getComputedStyle(el);
    return !(s.display === 'none' || s.visibility === 'hidden' || parseFloat(s.opacity) === 0);
  };
  const text = (el, n) => ((el.innerText || el.textContent || '').trim().replace(/\s+/g, ' ')).slice(0, n || 80);
  const info = (el) => ({
    tag: el.tagName.toLowerCase(), type: (el.getAttribute('type') || '').toLowerCase(),
    name: (el.getAttribute('name') || '').toLowerCase(), id: (el.id || '').toLowerCase(),
    placeholder: (el.getAttribute('placeholder') || '').toLowerCase().slice(0, 80),
    autocomplete: (el.getAttribute('autocomplete') || '').toLowerCase(),
    aria: (el.getAttribute('aria-label') || '').toLowerCase().slice(0, 80),
    label: ((el.labels && el.labels[0] && el.labels[0].innerText) || '').toLowerCase().slice(0, 80),
    maxlength: el.maxLength > 0 ? el.maxLength : 0, visible: visible(el),
    inputmode: (el.getAttribute('inputmode') || '').toLowerCase()
  });
  const forms = [...document.forms].slice(0, 15).map((f) => ({
    action: f.getAttribute('action') || '', method: (f.getAttribute('method') || 'get').toLowerCase(),
    visible: visible(f), inputs: [...f.querySelectorAll('input,textarea,select')].slice(0, 40).map(info),
    submitTexts: [...f.querySelectorAll('button,input[type=submit]')].slice(0, 6).map((b) => text(b, 30)),
  }));
  const loose = deepAll('input,textarea').filter((i) => !i.form).slice(0, 40).map(info);

  // overlays / modals that cover a large part of the screen and hold inputs
  let modalInputs = 0, overlays = 0, cookieBanner = false;
  deepAll('div,section,aside,dialog,form').slice(0, 1500).forEach((el) => {
    const s = getComputedStyle(el);
    if (s.position !== 'fixed' && s.position !== 'sticky' && el.tagName.toLowerCase() !== 'dialog') return;
    if (!visible(el)) return;
    const r = el.getBoundingClientRect();
    const t = (el.innerText || '').toLowerCase();
    if (/cookie|consent|gdpr/.test(t) && r.height < vh * 0.7) cookieBanner = true;
    if (r.width * r.height > 0.25 * vw * vh) { overlays++; modalInputs += el.querySelectorAll('input:not([type=hidden])').length; }
  });

  // login / sign-up entry points, scored from many independent signals (no site-specific rules)
  const POS_LOGIN = /log[\s_-]?in|sign[\s_-]?in|signin|logon|sso\b|my[\s_-]?account|member|customer[\s_-]?(?:login|portal)|net[\s_-]?banking|user[\s_-]?(?:login|id)|portal|ログイン|登录|登入|iniciar ses|connexion|anmelden|entrar|войти|लॉग\s?इन|साइन\s?इन|लॉगिन|உள்நுழை|లాగిన్/i;
  const POS_SIGNUP = /sign[\s_-]?up|register|registration|create[\s_-]?(?:an[\s_-]?)?account|join|get[\s_-]?started|new[\s_-]?user|enrol|रजिस्टर|पंजीकरण|नया\s?खाता|注册|registrar|inscri/i;
  const NEG = /share|follow|subscribe|newsletter|download|install|add[\s_-]?to|cart|buy|delete|remove|donate|facebook\.com|twitter\.com|instagram\.com|linkedin\.com|youtube\.com|whatsapp|mailto:|tel:|javascript:void|logout|log[\s_-]?out|sign[\s_-]?out/i;
  const HREF_POS = /(?:^|[\/_-])(?:log-?in|sign-?in|auth|account|session|sso|register|signup|sign-up|member|portal)(?:[\/_.?#-]|$)/i;
  const candEls = deepAll('a[href],button,[role=button],[role=link],input[type=button],input[type=submit],summary,[onclick]');
  const seenEl = new Set(); const cands = [];
  candEls.slice(0, 1500).forEach((el) => {
    if (seenEl.has(el) || !visible(el)) return; seenEl.add(el);
    const label = [text(el, 60), el.getAttribute('aria-label') || '', el.getAttribute('title') || '', el.getAttribute('value') || '',
      (el.querySelector && el.querySelector('img[alt]') ? el.querySelector('img[alt]').alt : ''),
      (el.querySelector && el.querySelector('svg title') ? el.querySelector('svg title').textContent : '')].join(' | ').toLowerCase();
    const meta = ((el.id || '') + ' ' + (el.className && el.className.baseVal === undefined ? el.className : '') + ' ' + (el.getAttribute('name') || '')).toLowerCase();
    const href = (el.getAttribute('href') || '').toLowerCase();
    const useHref = el.querySelector && el.querySelector('use') ? (el.querySelector('use').getAttribute('href') || el.querySelector('use').getAttribute('xlink:href') || '') : '';
    let score = 0, kind = '';
    const shortText = text(el, 40).length <= 28;
    if (POS_LOGIN.test(label)) { score += shortText ? 3 : 2; kind = 'login'; }
    else if (POS_SIGNUP.test(label)) { score += shortText ? 3 : 2; kind = 'signup'; }
    if (HREF_POS.test(href)) { score += 2; if (!kind) kind = /regist|sign-?up/.test(href) ? 'signup' : 'login'; }
    if (POS_LOGIN.test(meta) || POS_SIGNUP.test(meta)) { score += 1; if (!kind) kind = POS_SIGNUP.test(meta) ? 'signup' : 'login'; }
    if (/user|person|account|profile|avatar/.test(useHref.toLowerCase())) { score += 1; if (!kind) kind = 'login'; }
    const r = el.getBoundingClientRect();
    const inHeader = !!el.closest('header,nav,[role=banner],[role=navigation]') || r.top < vh * 0.22;
    if (inHeader) score += 1;
    if (NEG.test(label) || NEG.test(href)) score -= 4;
    if (score >= 3 && kind) cands.push({ el, score, kind, text: text(el, 40), href: (el.getAttribute('href') || '').slice(0, 200) });
  });
  cands.sort((a, b) => b.score - a.score);
  const candidates = cands.slice(0, 8).map((c, i) => { c.el.setAttribute('data-ts-cand', String(i)); return { idx: i, score: c.score, kind: c.kind, text: c.text, href: c.href }; });

  const TOGGLE = /menu|hamburger|burger|nav-?toggle|navbar-?toggler|drawer|toggle-?nav|☰|≡/i;
  const toggles = [];
  deepAll('button,[role=button],a,div,span,summary').slice(0, 800).forEach((el) => {
    if (!visible(el)) return;
    const lab = (el.getAttribute('aria-label') || '') + ' ' + (el.getAttribute('title') || '') + ' ' +
      ((el.className && el.className.baseVal === undefined) ? el.className : '') + ' ' + (el.id || '') + ' ' + text(el, 6);
    if (TOGGLE.test(lab) && !/search|cart|account|log-?in|sign-?in/i.test(lab)) {
      const r = el.getBoundingClientRect();
      if (r.width < 140 && r.height < 140 && r.top < vh * 0.3) toggles.push(el);
    }
  });
  const menuToggles = toggles.slice(0, 3).map((el, i) => { el.setAttribute('data-ts-menu', String(i)); return { idx: i, text: text(el, 12) }; });

  const links = [...document.querySelectorAll('a[href]')].slice(0, 400).map((a) => ({
    text: text(a, 40).toLowerCase(), href: (a.getAttribute('href') || '').slice(0, 300),
    footer: !!a.closest('footer,[role=contentinfo]')
  }));
  const iframes = [...document.querySelectorAll('iframe')].slice(0, 20).map((f) => {
    const r = f.getBoundingClientRect(); const s = getComputedStyle(f);
    return { src: (f.getAttribute('src') || '').slice(0, 300), w: Math.round(r.width), h: Math.round(r.height),
      hidden: r.width < 3 || r.height < 3 || s.display === 'none' || s.visibility === 'hidden' };
  });
  const metaOf = (sel, attr) => { const m = document.querySelector(sel); return m ? (m.getAttribute(attr) || '') : ''; };
  const scripts = [...document.scripts];
  const inlineJs = scripts.filter((s) => !s.src).map((s) => s.textContent || '').join(' ').slice(0, 60000);
  const logoAlts = [...document.querySelectorAll('img[alt],img[src*=logo],a[class*=logo] img')].slice(0, 8)
    .map((i) => (i.getAttribute('alt') || '').trim().toLowerCase()).filter(Boolean);
  return {
    url: location.href, title: (document.title || '').trim().slice(0, 200), lang: (document.documentElement.lang || '').toLowerCase(),
    text: ((document.body && document.body.innerText) || '').replace(/\s+/g, ' ').trim().slice(0, 9000),
    forms, loose, modalInputs, overlays, cookieBanner, candidates, menuToggles, links, iframes, logoAlts,
    ogSite: metaOf('meta[property="og:site_name"]', 'content'), ogTitle: metaOf('meta[property="og:title"]', 'content'),
    canonical: metaOf('link[rel=canonical]', 'href'), metaRefresh: !!document.querySelector('meta[http-equiv=refresh]'),
    favicon: metaOf('link[rel~=icon]', 'href'), hasJsonLd: !!document.querySelector('script[type="application/ld+json"]'),
    nScripts: scripts.length, nInline: scripts.filter((s) => !s.src).length,
    rightClickBlocked: /contextmenu|oncontextmenu/i.test(inlineJs),
    obfuscation: (inlineJs.match(/\b(?:eval|atob|unescape|fromCharCode)\s*\(/g) || []).length,
    jsRedirect: /(?:window\.|document\.|top\.|self\.)?location(?:\.href|\.replace|\.assign)?\s*(?:=|\()/.test(inlineJs),
    clipboardWrite: /clipboard\.writeText|execCommand\(['"]copy/i.test(inlineJs),
    nImages: document.images.length
  };
}
"""

_PERSON_NAME_HINT = re.compile(r"full.?name|first.?name|last.?name|\bname\b")
_FIELD_RULES: List[Tuple[str, re.Pattern]] = [
    ("password", re.compile(r"(?:^|[^a-z])pass(?:word|wd|code)?\b|pwd|current-password|new-password|passphrase|पासवर्ड")),
    ("wallet_phrase", re.compile(r"seed|recovery.?phrase|mnemonic|secret.?phrase|12.?word|24.?word|private.?key")),
    ("cvv", re.compile(r"cvv|cvc|security.?code|card.?code")),
    ("card", re.compile(r"card.?(?:number|no)|cc-number|ccnum|credit|debit|pan.?number")),
    ("expiry", re.compile(r"expir|exp.?date|cc-exp|valid.?thru|mm.?/.?yy")),
    ("gov_id", re.compile(r"aadhaar|aadhar|\bpan\b|passport|ssn|social.?security|national.?id|voter")),
    ("pin", re.compile(r"\bpin\b|mpin|upi.?pin|atm.?pin")),
    ("otp", re.compile(r"\botp\b|one-time|verification.?code|auth.?code|sms.?code|2fa")),
    ("phone", re.compile(r"phone|mobile|tel\b|msisdn|contact.?number|मोबाइल")),
    ("email", re.compile(r"e-?mail")),
    ("username", re.compile(r"user.?name|user.?id|login|customer.?id|account.?(?:id|number)|member|uid")),
]
_SENSITIVE = {"password", "wallet_phrase", "otp", "cvv", "card", "gov_id", "pin"}


# ---------------------------------------------------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------------------------------------------------
def registered(host_or_url: str) -> str:
    h = host_or_url if "://" not in host_or_url else (urlparse(host_or_url).hostname or "")
    ext = _EXTRACT(h.lower())
    return ".".join(p for p in (ext.domain, ext.suffix) if p)


def classify_field(info: Dict[str, Any]) -> str:
    """What is this input asking for? Decided from its attributes only, so it works on any site."""
    typ = info.get("type", "")
    hay = " ".join(str(info.get(k, "")) for k in ("name", "id", "placeholder", "autocomplete", "aria", "label")).lower()
    if typ == "password":
        return "password"
    if typ in ("hidden", "submit", "button", "checkbox", "radio", "image", "file", "reset"):
        return "other"
    if info.get("autocomplete") in ("one-time-code",):
        return "otp"
    ac = info.get("autocomplete", "")
    if ac.startswith("cc-number"):
        return "card"
    if ac.startswith("cc-csc"):
        return "cvv"
    if ac.startswith("cc-exp"):
        return "expiry"
    if ac in ("current-password", "new-password"):
        return "password"
    if typ == "email":
        return "email"
    if typ == "tel":
        return "phone"
    if info.get("tag") == "textarea" and re.search(r"seed|phrase|mnemonic|recovery|key|word", hay):
        return "wallet_phrase"
    for purpose, rx in _FIELD_RULES:
        if rx.search(hay):
            if purpose == "otp" and info.get("maxlength", 0) not in (0, 4, 5, 6, 7, 8):
                continue
            return purpose
    if info.get("maxlength") in (4, 5, 6, 7, 8) and info.get("inputmode") == "numeric":
        return "otp"
    if _PERSON_NAME_HINT.search(hay):
        return "name"
    return "other"


LOGIN_INTENT_RX = re.compile(r"log[\s_-]?in|sign[\s_-]?in|signin|sso|auth|account|member|portal|continue|next|verify", re.I)
NOT_LOGIN_RX = re.compile(r"newsletter|subscribe|search|contact|message|comment|feedback|coupon", re.I)


def analyse_inputs(inputs: List[Dict[str, Any]], login_intent: bool = False) -> Dict[str, Any]:
    """Only inputs the visitor can actually see count: a hidden login box in the DOM is not a credential surface yet."""
    purposes = [classify_field(i) for i in inputs if i.get("visible")]
    sensitive = [p for p in purposes if p in _SENSITIVE]
    identity = [p for p in purposes if p in ("username", "email", "phone")]
    credential = bool(
        "password" in purposes
        or "wallet_phrase" in purposes
        or ({"card", "cvv"} & set(purposes) and len(purposes) >= 2)
        or ("otp" in purposes and identity)
        or ("gov_id" in purposes and len(purposes) >= 2)
        or ("pin" in purposes and identity)
    )
    # two-step sign-in: only the account name is asked first, the password comes on the next screen
    multi_step = bool(not credential and login_intent and identity and len(purposes) <= 2)
    return {"purposes": purposes, "sensitive": sensitive, "credential": credential or multi_step, "multi_step": multi_step}


def _form_surface(page_state: Dict[str, Any]) -> Dict[str, Any]:
    """Merge every form and loose input across frames into one description of the page's credential surface."""
    best: Dict[str, Any] = {"credential": False, "purposes": [], "sensitive": [], "action_domain": "", "action": "", "via": "", "form": None}
    page_hint = (page_state.get("title", "") + " " + (urlparse(page_state.get("url", "")).path or ""))
    groups: List[Tuple[str, Dict[str, Any], Dict[str, Any]]] = []
    for frame in page_state.get("frames", []):
        for f in frame.get("forms", []):
            hint = page_hint + " " + " ".join(f.get("submitTexts", []))
            intent = bool(LOGIN_INTENT_RX.search(hint)) and not NOT_LOGIN_RX.search(hint)
            groups.append(("form" if frame.get("is_main") else "iframe", f, analyse_inputs(f.get("inputs", []), intent)))
        if frame.get("loose"):
            intent = bool(LOGIN_INTENT_RX.search(page_hint)) and not NOT_LOGIN_RX.search(page_hint)
            groups.append(("script" if frame.get("is_main") else "iframe", {"action": "", "method": "", "inputs": frame["loose"]},
                           analyse_inputs(frame["loose"], intent)))
    for via, form, a in groups:
        if a["credential"] and (not best["credential"] or len(a["sensitive"]) > len(best["sensitive"])):
            action = form.get("action", "")
            best = {"credential": True, "purposes": a["purposes"], "sensitive": a["sensitive"], "multi_step": a["multi_step"],
                    "action": action, "action_domain": registered(action) if "://" in action or action.startswith("//") else "",
                    "via": via, "form": form}
    return best


def host_is_exfil(host: str) -> bool:
    host = (host or "").lower()
    return any(host == s or host.endswith("." + s) or host.endswith(s) for s in EXFIL_HOST_SUFFIXES)


def _is_ip(host: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host or "")) or ":" in (host or "")


def wording_counts(text: str) -> Dict[str, int]:
    return {k: len(rx.findall(text or "")) for k, rx in _WORDING_RE.items()}


BRAND_ALIASES = {
    "americanexpress": ["american express", "amex"], "bankofamerica": ["bank of america"], "wellsfargo": ["wells fargo"],
    "trustwallet": ["trust wallet"], "office365": ["office 365", "microsoft 365"], "onedrive": ["one drive"],
    "paypal": ["pay pal"], "citibank": ["citi bank", "citi"], "hdfc": ["hdfc bank"], "icici": ["icici bank"],
    "sbi": ["state bank of india"], "phonepe": ["phone pe"], "metamask": ["meta mask"], "opensea": ["open sea"],
    "whatsapp": ["whats app"], "linkedin": ["linked in"], "docusign": ["docu sign"],
}


# brands that ordinary sites mention in their body for sign-in buttons, widgets, maps or analytics
WIDGET_BRANDS = {"google", "facebook", "microsoft", "apple", "twitter", "linkedin", "youtube", "instagram", "github",
                 "whatsapp", "telegram", "amazon", "paypal"}


def detect_brand(state: Dict[str, Any], page_registered: str) -> Dict[str, Any]:
    """Which well-known brand does the page claim to be, and does the domain really belong to it?"""
    try:
        from ml.features import BRAND_DOMAINS
    except Exception:  # pragma: no cover
        BRAND_DOMAINS = {}
    strong = " ".join([state.get("title", ""), state.get("ogSite", ""), state.get("ogTitle", "")]).lower()    # what the page calls itself
    logos = " ".join(state.get("logoAlts", [])).lower()                                                      # alt text of images on the page
    body = (state.get("text", "") or "").lower()
    best, best_score, best_head = "", 0, 0
    for brand in BRAND_DOMAINS:
        names = [brand] + BRAND_ALIASES.get(brand, [])
        pat = re.compile(r"\b(?:" + "|".join(re.escape(n) for n in names) + r")\b")
        # An image alt such as "Google" on a "Sign in with Google" button is a sign-in option, not the page's own identity:
        # for widget brands only the page title and site name count.
        head_hits = len(pat.findall(strong)) + (0 if brand in WIDGET_BRANDS else len(pat.findall(logos)))
        body_hits = len(pat.findall(body[:3000])) if len(brand) >= 6 else 0     # short names (ups, axis, chase) are too ambiguous in prose
        # Brands that sites mention all the time as a sign-in option, widget or analytics (Google, Facebook, ...) never
        # count from the body alone, and any other brand needs many more mentions: otherwise a company's own login page
        # that says "Sign in with Google" is mistaken for a fake Google page.
        body_needed = 99 if brand in WIDGET_BRANDS else 8
        if head_hits >= 1 or body_hits >= body_needed:
            score = 3 * head_hits + body_hits
            if score > best_score:
                best, best_score, best_head = brand, score, head_hits
    claimed = best
    owns = None
    if claimed:
        official = BRAND_DOMAINS[claimed]
        owns = any(page_registered == d or page_registered.endswith("." + d) for d in official)
    label = (page_registered.split(".")[0] if page_registered else "").replace("-", "")
    return {"claimed_brand": claimed, "brand_owns_domain": owns, "brand_claim_in_headline": best_head > 0,
            "brand_in_domain_label": bool(claimed and claimed in label and not owns)}


def legitimacy_signals(state: Dict[str, Any], page_registered: str) -> Dict[str, Any]:
    links = state.get("links", [])
    txts = [l.get("text", "") + " " + l.get("href", "").lower() for l in links]
    def has(rx: str) -> bool:
        return any(re.search(rx, t) for t in txts)
    same = 0
    for l in links:
        href = l.get("href", "")
        if not href or href.startswith(("#", "/", "?")) or registered(href) == page_registered:
            same += 1
    return {
        "has_privacy_link": has(r"privacy"), "has_terms_link": has(r"terms|conditions"),
        "has_contact_link": has(r"contact|support|help"), "has_about_link": has(r"about"),
        "footer_links": sum(1 for l in links if l.get("footer")), "n_links": len(links),
        "same_site_link_ratio": round(same / len(links), 3) if links else 0.0,
        "has_cookie_banner": bool(state.get("cookieBanner")), "has_json_ld": bool(state.get("hasJsonLd")),
        "page_language": state.get("lang", ""),
    }


def merge_frames(frames: List[Dict[str, Any]]) -> Dict[str, Any]:
    main = next((f for f in frames if f.get("is_main")), frames[0] if frames else {})
    state = dict(main)
    state["frames"] = frames
    state["iframes_hidden"] = sum(1 for f in main.get("iframes", []) if f.get("hidden"))
    state["modal_inputs"] = sum(f.get("modalInputs", 0) for f in frames)
    return state


# ---------------------------------------------------------------------------------------------------------------------
# the engine
# ---------------------------------------------------------------------------------------------------------------------
_availability: Optional[bool] = None
_availability_lock = threading.Lock()


def browser_available() -> bool:
    """True when Playwright and its Chromium are present. Never true on Render/Heroku (not enough memory)."""
    global _availability
    if os.environ.get("RENDER") or os.environ.get("DYNO") or os.environ.get("FORCE_CLOUD_SANDBOX"):
        return False
    if not PLAYWRIGHT_IMPORTABLE:
        return False
    with _availability_lock:
        if _availability is None:
            try:
                with sync_playwright() as pw:
                    _availability = os.path.exists(pw.chromium.executable_path)
            except Exception as exc:
                logger.info("Playwright/Chromium not available: %s", exc)
                _availability = False
        return _availability


class _Budget:
    def __init__(self, seconds: float):
        self.end = time.monotonic() + seconds

    def left(self) -> float:
        return self.end - time.monotonic()

    def ms(self, cap: float) -> int:
        return int(max(300, min(cap, self.left() * 1000)))


class BrowserSandbox:
    """One scan = one fresh browser context. Create a new instance per scan (it keeps per-scan state)."""

    def __init__(self, probe: bool = CREDENTIAL_PROBE_ENABLED):
        self.probe_enabled = probe
        self.requests: List[Dict[str, Any]] = []
        self.host_ok: Dict[str, bool] = {}
        self.blocked_internal = 0
        self.downloads: List[str] = []
        self.dialogs = 0
        self.popups = 0
        self.probe_active = False
        self.captured_submits: List[Dict[str, Any]] = []
        self.nav_urls: List[str] = []
        self.landing_registered = ""
        self._landing_https = False
        self._closing = False

    # ---- request control -------------------------------------------------------------------------------------
    def _host_allowed(self, url: str) -> bool:
        parsed = urlparse(url)
        key = (parsed.scheme, parsed.hostname or "")
        if parsed.scheme in ("data", "blob", "about"):
            return True
        if key in self.host_ok:
            return self.host_ok[key]
        try:
            assert_public_url(f"{parsed.scheme}://{parsed.hostname}/")
            ok = True
        except UnsafeUrlError:
            ok = False
        self.host_ok[key] = ok
        return ok

    def _route(self, route, request) -> None:
        if self._closing:                     # the scan is over: answer immediately so nothing is left pending
            try:
                route.abort()
            except Exception:
                pass
            return
        try:
            url = request.url
            if not url.startswith(("http://", "https://")):
                route.continue_()
                return
            if len(self.requests) >= MAX_REQUESTS or not self._host_allowed(url):
                self.blocked_internal += 0 if len(self.requests) >= MAX_REQUESTS else 1
                route.abort("blockedbyclient")
                return
            host = urlparse(url).hostname or ""
            method = request.method.upper()
            rec = {"url": url[:300], "host": host, "domain": registered(host), "method": method,
                   "type": request.resource_type, "third_party": bool(self.landing_registered and registered(host) != self.landing_registered)}
            body = ""
            if method in ("POST", "PUT", "PATCH"):
                try:
                    body = request.post_data or ""
                except Exception:
                    body = ""
            from urllib.parse import unquote_plus
            decoded = unquote_plus(body) + " " + unquote_plus(url)
            carries = any(m in decoded for m in PROBE_MARKERS)
            rec["carries_probe"] = carries
            self.requests.append(rec)
            if self.probe_active and (method in ("POST", "PUT", "PATCH") or carries):
                self.captured_submits.append(rec)      # stop it here: the fake data never leaves the sandbox
                route.abort("blockedbyclient")
                return
            if request.resource_type in ("media", "font"):
                route.abort()
                return
            route.continue_()
        except Exception:
            try:
                route.abort()
            except Exception:
                pass

    # ---- page snapshot ----------------------------------------------------------------------------------------------
    def _snapshot(self, page) -> Dict[str, Any]:
        frames: List[Dict[str, Any]] = []
        for fr in page.frames[:8]:
            try:
                data = fr.evaluate(COLLECT_JS)
                data["is_main"] = fr == page.main_frame
                frames.append(data)
            except Exception:
                continue
        return merge_frames(frames) if frames else {}

    def _dismiss_overlays(self, page) -> None:
        try:
            page.evaluate(
                """() => { const rx=/^(accept all|accept|agree|i agree|allow all|got it|ok|okay|continue|close|dismiss|no thanks)$/i;
                  for (const b of document.querySelectorAll('button,a,[role=button]')) {
                    const t=(b.innerText||'').trim(); if (rx.test(t)) { const r=b.getBoundingClientRect();
                    if (r.width>10 && r.height>10 && getComputedStyle(b.closest('[style*=fixed],div,section')||b).position!=='static') { b.click(); return true; } } }
                  return false; }""")
        except Exception:
            pass

    # ---- main entry ---------------------------------------------------------------------------------------------------
    def analyze(self, url: str, budget_seconds: float = TOTAL_BUDGET_SECONDS) -> Dict[str, Any]:
        budget = _Budget(budget_seconds)
        ev = self._empty_evidence()
        try:
            assert_public_url(url)
        except UnsafeUrlError as exc:
            if "does not resolve" in str(exc):
                ev.update(verification_state="unverified", unverified_reason="unreachable")      # dead / taken-down domain
            else:
                ev.update(verification_state="unverified", unverified_reason="blocked_url", sandbox_blocked_unsafe_url=1)
            return self._finish(ev)

        args = ["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu", "--disable-extensions", "--mute-audio",
                "--disable-background-networking", "--disable-popup-blocking=false", "--no-first-run"]
        lab_port = os.environ.get("TRUSTSHIELD_LAB_PORT")
        if lab_port:       # test lab only: every hostname resolves to the local fake-site server
            args.append(f"--host-resolver-rules=MAP * 127.0.0.1:{lab_port}")
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True, args=args)
                context = None
                try:
                    device = dict(pw.devices.get("Pixel 7") or pw.devices.get("Pixel 5") or {})
                    context = browser.new_context(**device, locale="en-IN", timezone_id="Asia/Kolkata",
                                                  ignore_https_errors=True, service_workers="block", accept_downloads=True)
                    context.route("**/*", self._route)
                    context.on("page", lambda p: self._on_new_page(p))
                    page = context.new_page()
                    page.set_default_timeout(6000)
                    self._attach(page)
                    self._run(page, context, url, budget, ev)
                    self._screenshot(page, ev)
                finally:
                    self._closing = True
                    try:
                        if context is not None:
                            context.unroute_all(behavior="ignoreErrors")     # drop pending request handlers before closing
                    except Exception:
                        pass
                    browser.close()
        except Exception as exc:
            logger.warning("browser sandbox crashed on %s: %s", url[:80], exc)
            if ev["verification_state"] != "verified":
                ev.update(verification_state="unverified", unverified_reason="crashed")
        return self._finish(ev)

    # ---- pieces -------------------------------------------------------------------------------------------------------
    def _attach(self, page) -> None:
        page.on("dialog", lambda d: (setattr(self, "dialogs", self.dialogs + 1), d.dismiss()))

        def on_download(dl):
            try:
                self.downloads.append((dl.suggested_filename or "")[:80])
                dl.cancel()
            except Exception:
                pass
        page.on("download", on_download)
        page.on("framenavigated", lambda fr: self.nav_urls.append(fr.url) if fr == page.main_frame else None)

    def _on_new_page(self, page) -> None:
        self.popups += 1
        try:
            self._attach(page)
        except Exception:
            pass

    def _screenshot(self, page, ev) -> None:
        try:
            ev["_screenshot_b64"] = base64.b64encode(page.screenshot(type="jpeg", quality=55, timeout=2500)).decode("ascii")
        except Exception:
            pass

    def _run(self, page, context, url: str, budget: _Budget, ev: Dict[str, Any]) -> None:
        response = None
        try:
            response = page.goto(url, wait_until="domcontentloaded", timeout=budget.ms(12000))
        except Exception as exc:
            msg = str(exc).lower()
            page.set_default_timeout(1500)       # the page is stuck: every follow-up step must fail fast, not wait
            if "timeout" in msg:
                ev.update(verification_state="unverified", unverified_reason="timeout")
            else:
                ev.update(verification_state="unverified", unverified_reason="unreachable")
            if not self._has_page_content(page):
                return
        if response is not None:
            ev["http_status"] = response.status
            self._redirect_chain(response, ev)
            self._tls(response, ev)
        try:
            page.wait_for_load_state("networkidle", timeout=budget.ms(3500))
        except Exception:
            pass
        self.landing_registered = registered(page.url)
        self._landing_https = page.url.startswith("https://")
        self._dismiss_overlays(page)
        page.wait_for_timeout(400)

        landing = self._snapshot(page)
        if not landing:
            ev.update(verification_state="unverified", unverified_reason=ev.get("unverified_reason") or "unreachable")
            return
        ev["_html"] = self._html(page)
        ev["_final_url"] = page.url
        ev["_text"] = landing.get("text", "")
        self._challenge(landing, ev)
        if ev["challenge_page"]:
            ev.update(verification_state="unverified", unverified_reason="bot_protection")
            self._fill_identity(landing, ev)
            return
        ev["verification_state"] = "partial" if ev["unverified_reason"] else "verified"
        self._fill_identity(landing, ev)

        surface = _form_surface(landing)
        examined = [("landing", landing, surface)]
        clicks_done = 0
        active_page = page
        current = landing
        depth = 0
        tried: set = set()
        menu_opened = False
        while not surface["credential"] and clicks_done < MAX_CLICKS and depth < MAX_DEPTH and budget.left() > 5:
            cands = [c for c in current.get("candidates", []) if (c["text"], c["href"]) not in tried]
            if not cands:
                toggles = current.get("menuToggles", [])
                if toggles and not menu_opened:
                    menu_opened = True
                    clicks_done += 1
                    opened = self._click(active_page, context, {"idx": toggles[0]["idx"], "attr": "data-ts-menu"}, budget)
                    if opened is not None:
                        active_page, current = opened
                        surface = _form_surface(current)
                        ev["opened_menu"] = True
                        continue
                break
            cand = cands[0]
            tried.add((cand["text"], cand["href"]))
            clicks_done += 1
            result = self._click(active_page, context, cand, budget)
            if result is None:
                # click did nothing useful; continue with the next candidate on the same page
                continue
            active_page, state = result
            current = state
            surface = _form_surface(state)
            kind = cand["kind"]
            examined.append((f"click:{kind}", state, surface))
            ev["entry_clicks"] = clicks_done
            if registered(active_page.url) != self.landing_registered:
                ev["login_leads_to_other_domain"] = True
                ev["login_target_domain"] = registered(active_page.url)
                if ev["login_target_domain"] in IDENTITY_PROVIDER_DOMAINS:
                    ev["idp_login"] = True
            if active_page.url != page.url or active_page is not page:
                depth += 1

        ev["credential_surface_found"] = bool(surface["credential"])
        if surface["credential"]:
            ev["credential_surface_depth"] = max(0, len(examined) - 1)
            ev["credential_via"] = surface.get("via", "")
            ev["credential_field_types"] = sorted(set(surface.get("purposes", [])))
            ev["sensitive_field_types"] = sorted(set(surface.get("sensitive", [])))
            ev["form_action_domain"] = surface.get("action_domain", "")
            final_state = examined[-1][1]
            final_reg = registered(final_state.get("url", "")) or self.landing_registered
            ev["form_cross_domain"] = bool(surface.get("action_domain") and surface["action_domain"] != final_reg)
            ev["form_action_is_exfil_host"] = host_is_exfil(urlparse(surface.get("action", "")).hostname or "")
            self._apply_state_evidence(final_state, ev)
            if self.probe_enabled and budget.left() > 4 and not ev.get("idp_login"):
                self._probe(active_page, final_state, surface, budget, ev)
        else:
            self._apply_state_evidence(current, ev)

        ev["n_pages_examined"] = len(examined)
        self._network_summary(ev)
        if ev.get("verification_state") != "unverified" and budget.left() <= 0.5:
            ev["verification_state"] = "partial"
            ev["unverified_reason"] = ev["unverified_reason"] or "time_budget"

    # ---- clicking -------------------------------------------------------------------------------------------------------
    def _click(self, page, context, cand: Dict[str, Any], budget: _Budget) -> Optional[Tuple[Any, Dict[str, Any]]]:
        before_url = page.url
        before_pages = set(context.pages)
        try:
            page.locator(f'[{cand.get("attr", "data-ts-cand")}="{cand["idx"]}"]').first.click(timeout=min(2500, budget.ms(2500)), no_wait_after=True, force=False)
        except Exception:
            try:
                page.evaluate("(i) => { const e=document.querySelector('[data-ts-cand=\"'+i+'\"]'); if(e) e.click(); }", cand["idx"])
            except Exception:
                return None
        page.wait_for_timeout(900)
        new_pages = [p for p in context.pages if p not in before_pages]
        target = new_pages[-1] if new_pages else page
        try:
            target.wait_for_load_state("domcontentloaded", timeout=budget.ms(3500))
        except Exception:
            pass
        try:
            target.wait_for_load_state("networkidle", timeout=budget.ms(2000))
        except Exception:
            pass
        if target is page and page.url == before_url:
            page.wait_for_timeout(500)   # in-page change (modal / SPA route): give scripts a moment
        state = self._snapshot(target)
        if not state:
            return None
        return target, state

    # ---- credential probe --------------------------------------------------------------------------------------------------
    def _probe(self, page, state: Dict[str, Any], surface: Dict[str, Any], budget: _Budget, ev: Dict[str, Any]) -> None:
        ev["probe_ran"] = True
        page_domain = registered(page.url) or self.landing_registered
        # type FAKE values into every visible input, chosen by what the field asks for
        try:
            for el in page.locator("input:visible,textarea:visible").all()[:12]:
                try:
                    info = el.evaluate("""e => ({tag:e.tagName.toLowerCase(), type:(e.getAttribute('type')||'').toLowerCase(),
                        name:(e.getAttribute('name')||'').toLowerCase(), id:(e.id||'').toLowerCase(),
                        placeholder:(e.getAttribute('placeholder')||'').toLowerCase(), autocomplete:(e.getAttribute('autocomplete')||'').toLowerCase(),
                        aria:(e.getAttribute('aria-label')||'').toLowerCase(), label:((e.labels&&e.labels[0]&&e.labels[0].innerText)||'').toLowerCase(),
                        maxlength:e.maxLength>0?e.maxLength:0, inputmode:(e.getAttribute('inputmode')||'').toLowerCase()})""")
                    purpose = classify_field(info)
                    if info["type"] in ("hidden", "submit", "button", "checkbox", "radio", "image", "file"):
                        continue
                    el.fill(PROBE_VALUES.get(purpose, "test"), timeout=1200)
                except Exception:
                    continue
        except Exception:
            pass
        self.captured_submits.clear()
        self.probe_active = True
        try:
            submit = page.locator("form button[type=submit]:visible, form input[type=submit]:visible, form button:visible").first
            if submit.count():
                submit.click(timeout=2000, no_wait_after=True)
            else:
                page.keyboard.press("Enter")
        except Exception:
            try:
                page.keyboard.press("Enter")
            except Exception:
                pass
        deadline = time.monotonic() + min(3.5, max(0.5, budget.left() - 0.5))
        while time.monotonic() < deadline and not self.captured_submits:
            page.wait_for_timeout(150)
        self.probe_active = False

        ev["probe_request_seen"] = bool(self.captured_submits)
        for rec in self.captured_submits:
            if not rec.get("carries_probe"):
                continue
            ev["probe_credentials_sent"] = True
            ev["submit_domain"] = rec["domain"]
            ev["submit_host"] = rec["host"]
            ev["submit_cross_domain"] = bool(rec["domain"] and rec["domain"] != page_domain)
            ev["submit_to_messaging_api"] = host_is_exfil(rec["host"])
            ev["submit_to_ip"] = _is_ip(rec["host"])
            ev["submit_insecure"] = rec["url"].startswith("http://") and self._landing_https
            break

    # ---- evidence helpers ------------------------------------------------------------------------------------------------
    def _html(self, page) -> str:
        try:
            return (page.content() or "")[:400_000]
        except Exception:
            return ""

    def _has_page_content(self, page) -> bool:
        try:
            return bool(page.url and page.url != "about:blank" and page.content())
        except Exception:
            return False

    def _redirect_chain(self, response, ev: Dict[str, Any]) -> None:
        chain: List[str] = []
        req = response.request
        while req is not None:
            chain.append(req.url)
            req = req.redirected_from
        chain.reverse()
        hosts = [registered(u) for u in chain + self.nav_urls if u.startswith("http")]
        unique = list(dict.fromkeys(h for h in hosts if h))
        ev["redirect_hops"] = max(0, len(chain) - 1)
        ev["redirect_domains"] = unique[:8]
        ev["redirect_cross_domain"] = len(unique) > 1
        try:
            from ml.features import BRAND_DOMAINS
            famous = {d for ds in BRAND_DOMAINS.values() for d in ds}
        except Exception:  # pragma: no cover
            famous = set()
        ev["redirects_to_popular_site"] = bool(len(unique) > 1 and unique[-1] in famous and unique[0] not in famous)

    def _tls(self, response, ev: Dict[str, Any]) -> None:
        try:
            sd = response.security_details()
        except Exception:
            sd = None
        if sd:
            ev["tls_issuer"] = (sd.get("issuer") or "")[:60]
            valid_from = sd.get("validFrom") or sd.get("valid_from")
            if valid_from:
                ev["tls_age_days"] = max(0, int((time.time() - float(valid_from)) / 86400))
            valid_to = sd.get("validTo") or sd.get("valid_to")
            if valid_to:
                ev["tls_days_left"] = int((float(valid_to) - time.time()) / 86400)

    def _challenge(self, state: Dict[str, Any], ev: Dict[str, Any]) -> None:
        title = state.get("title", "")
        text_len = len(state.get("text", ""))
        frames_src = " ".join(f.get("src", "") for f in state.get("iframes", []))
        blocked_status = ev.get("http_status") in (403, 429, 503)
        if (CHALLENGE_TITLE_RE.search(title) or CHALLENGE_TITLE_RE.search(state.get("text", "")[:300]) and text_len < 1200
                or (CHALLENGE_FRAME_RE.search(frames_src) and text_len < 600)
                or (blocked_status and text_len < 400)):
            ev["challenge_page"] = True

    def _fill_identity(self, state: Dict[str, Any], ev: Dict[str, Any]) -> None:
        ev["page_title"] = state.get("title", "")[:150]
        reg = registered(state.get("url", "")) or self.landing_registered
        ev.update(detect_brand(state, reg))
        ev.update(legitimacy_signals(state, reg))
        ev["wording"] = wording_counts(state.get("text", ""))
        ev["title_support_lure"] = bool(re.search(r"help center|support|appeal|verification|violation|restricted|security check|"
                                                  r"account (?:center|review)|policy", state.get("title", ""), re.I))

    def _apply_state_evidence(self, state: Dict[str, Any], ev: Dict[str, Any]) -> None:
        ev["hidden_iframes"] = max(ev.get("hidden_iframes", 0), state.get("iframes_hidden", 0))
        ev["right_click_blocked"] = ev.get("right_click_blocked", False) or bool(state.get("rightClickBlocked"))
        ev["obfuscated_js"] = max(ev.get("obfuscated_js", 0), int(state.get("obfuscation", 0)))
        ev["clipboard_write"] = ev.get("clipboard_write", False) or bool(state.get("clipboardWrite"))
        ev["is_spa_shell"] = len(state.get("text", "")) < 200 and state.get("nScripts", 0) >= 1
        if state.get("url") and state.get("url") != ev.get("_final_url"):
            ev["_credential_page_url"] = state["url"]

    def _network_summary(self, ev: Dict[str, Any]) -> None:
        tp = {r["domain"] for r in self.requests if r.get("third_party") and r.get("domain")}
        ev["n_requests"] = len(self.requests)
        ev["third_party_domains"] = len(tp)
        ev["third_party_domain_list"] = sorted(tp)[:15]
        ev["exfil_hosts_contacted"] = sorted({r["host"] for r in self.requests if host_is_exfil(r["host"])})[:5]
        ev["blocked_internal_requests"] = self.blocked_internal
        ev["download_attempts"] = self.downloads[:5]
        ev["download_executable"] = any(re.search(r"\.(apk|exe|msi|scr|bat|jar|dmg|iso|zip|rar|ps1|vbs|js)$", d, re.I) for d in self.downloads)
        ev["dialogs"] = self.dialogs
        ev["popups_opened"] = self.popups

    # ---- shape --------------------------------------------------------------------------------------------------------------
    @staticmethod
    def _empty_evidence() -> Dict[str, Any]:
        return {
            "engine": "browser_v2", "verification_state": "verified", "unverified_reason": "", "http_status": 0,
            "challenge_page": False, "credential_surface_found": False, "credential_surface_depth": 0, "credential_via": "",
            "credential_field_types": [], "sensitive_field_types": [], "form_action_domain": "", "form_cross_domain": False,
            "form_action_is_exfil_host": False, "entry_clicks": 0, "opened_menu": False, "login_leads_to_other_domain": False, "login_target_domain": "",
            "idp_login": False, "probe_ran": False, "probe_request_seen": False, "probe_credentials_sent": False,
            "submit_domain": "", "submit_host": "", "submit_cross_domain": False, "submit_to_messaging_api": False,
            "submit_to_ip": False, "submit_insecure": False, "redirect_hops": 0, "redirect_domains": [],
            "redirect_cross_domain": False, "redirects_to_popular_site": False, "n_pages_examined": 1, "claimed_brand": "", "brand_owns_domain": None,
            "brand_in_domain_label": False, "wording": {}, "title_support_lure": False, "hidden_iframes": 0, "right_click_blocked": False,
            "obfuscated_js": 0, "clipboard_write": False, "is_spa_shell": False,
        }

    def _finish(self, ev: Dict[str, Any]) -> Dict[str, Any]:
        """Add the legacy keys the pipeline already consumes, plus a rule-based fallback score."""
        sensitive = set(ev.get("sensitive_field_types", []))
        claimed = ev.get("claimed_brand", "")
        owns = ev.get("brand_owns_domain")
        cross_submit = bool(ev.get("submit_cross_domain") and ev.get("probe_credentials_sent"))
        exfil = bool(ev.get("submit_to_messaging_api") or ev.get("form_action_is_exfil_host")
                     or (ev.get("probe_credentials_sent") and (ev.get("submit_to_ip") or ev.get("submit_insecure"))))
        claim_is_real = bool(ev.get("brand_claim_in_headline", True) or ev.get("brand_in_domain_label"))
        impersonation = bool(claimed and owns is False and claim_is_real
                             and (ev.get("credential_surface_found") or ev.get("brand_in_domain_label")))
        ev.update({
            "sandbox_has_password_field": int("password" in sensitive or bool(sensitive & {"card", "wallet_phrase", "gov_id", "pin"})),
            "external_form_action": int(bool(ev.get("form_cross_domain") or cross_submit)),
            "suspicious_exfiltration": int(exfil),
            "sandbox_hidden_iframes": int(ev.get("hidden_iframes", 0)),
            "sandbox_title_mismatch": int(impersonation and bool(ev.get("page_title"))),
            "brand_impersonation": int(impersonation),
            "impersonated_brand": claimed if impersonation else None,
            "sandbox_brand_impersonation": int(impersonation),
            "sandbox_impersonated_brand": claimed if impersonation else None,
            "detected_target_brand": claimed if impersonation else "",
            "sandbox_num_redirects": int(ev.get("redirect_hops", 0) if ev.get("redirect_cross_domain") else 0),
            "sandbox_unreachable": int(ev.get("verification_state") == "unverified"),
            "sandbox_blocked_unsafe_url": int(ev.get("sandbox_blocked_unsafe_url", 0)),
        })
        ev["sandbox_threat_score"] = evidence_score(ev)
        return ev


def evidence_score(ev: Dict[str, Any]) -> int:
    """Rule-based fallback 0-100 until the ML stage takes over. Risk signals add; legitimacy signals subtract."""
    if ev.get("verification_state") == "unverified":
        return 40 if ev.get("unverified_reason") in ("unreachable", "crashed", "blocked_url") else 0
    risk = 0
    if ev.get("submit_to_messaging_api"):
        risk += 80
    if ev.get("probe_credentials_sent") and ev.get("submit_cross_domain") and not ev.get("idp_login"):
        risk += 55
    if ev.get("form_action_is_exfil_host"):
        risk += 70
    if ev.get("form_cross_domain") and not ev.get("idp_login"):
        risk += 30
    if ev.get("brand_impersonation"):
        risk += 45 if ev.get("credential_surface_found") else 20
    if ev.get("login_leads_to_other_domain") and not ev.get("idp_login") and ev.get("credential_surface_found"):
        risk += 25
    if ev.get("download_executable"):
        risk += 40
    if ev.get("hidden_iframes"):
        risk += 12
    if ev.get("right_click_blocked"):
        risk += 8
    if ev.get("obfuscated_js", 0) >= 2:
        risk += 8
    w = ev.get("wording") or {}
    if ev.get("credential_surface_found") and (w.get("urgency", 0) and w.get("threat", 0)):
        risk += 15
    if w.get("crypto", 0) >= 2:
        risk += 15
    if w.get("lure", 0):
        risk += 25
    if ev.get("redirects_to_popular_site"):
        risk += 40
    legit = 0
    if ev.get("has_privacy_link") and ev.get("has_terms_link"):
        legit += 8
    if ev.get("has_contact_link"):
        legit += 4
    if ev.get("same_site_link_ratio", 0) >= 0.8 and ev.get("n_links", 0) >= 15:
        legit += 6
    if ev.get("credential_surface_found") and not ev.get("form_cross_domain") and not ev.get("submit_cross_domain"):
        legit += 6
    return int(max(0, min(100, risk - legit)))


# ---------------------------------------------------------------------------------------------------------------------
# Hard-timeout isolation
# ---------------------------------------------------------------------------------------------------------------------
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HARD_TIMEOUT_EXTRA_SECONDS = 12


def _kill_tree(proc) -> None:
    """Kill the worker and everything it started (the browser runs in the same process group)."""
    try:
        if os.name == "posix":
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
    try:
        proc.wait(timeout=5)
    except Exception:
        pass


def _unverified(reason: str) -> Dict[str, Any]:
    ev = BrowserSandbox._empty_evidence()
    ev.update(verification_state="unverified", unverified_reason=reason)
    return BrowserSandbox()._finish(ev)


def analyze_isolated(url: str, budget_seconds: float = TOTAL_BUDGET_SECONDS, hard_timeout: Optional[float] = None,
                     worker_cmd: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Same result as BrowserSandbox().analyze(url) but executed in a separate process with a HARD time limit.
    A page that hangs the browser (endless script, debugger trap, frozen renderer) can no longer block the caller:
    after budget + HARD_TIMEOUT_EXTRA_SECONDS the worker and its Chromium are killed and the link is reported as
    unverified ("timeout").
    """
    hard = float(hard_timeout or (budget_seconds + HARD_TIMEOUT_EXTRA_SECONDS))
    fd, out_path = tempfile.mkstemp(suffix=".json", prefix="ts_scan_")
    os.close(fd)
    cmd = list(worker_cmd or [sys.executable, "-m", "core_engine.browser_worker"]) + [url, str(budget_seconds), out_path]
    options: Dict[str, Any] = dict(cwd=BACKEND_DIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=os.environ.copy())
    if os.name == "posix":
        options["start_new_session"] = True
    proc = None
    try:
        proc = subprocess.Popen(cmd, **options)
        try:
            proc.wait(timeout=hard)
        except subprocess.TimeoutExpired:
            logger.warning("browser scan exceeded %.0fs for %s: killed", hard, url[:80])
            _kill_tree(proc)
            return _unverified("timeout")
        with open(out_path, encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict) or "verification_state" not in data:
            raise ValueError("worker returned no evidence")
        return data
    except Exception as exc:
        logger.warning("browser worker failed for %s: %s", url[:80], type(exc).__name__)
        if proc is not None and proc.poll() is None:
            _kill_tree(proc)
        return _unverified("crashed")
    finally:
        try:
            os.remove(out_path)
        except OSError:
            pass

