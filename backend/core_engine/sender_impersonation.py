"""
Sender impersonation: "is B pretending to be C?"

Takes what the email forensics already worked out (SPF / DKIM / DMARC results, the connecting IP) plus a few more facts read
from the message itself (display name, reply-to, the receiving provider's own Authentication-Results, forwarding markers)
and turns them into one plain-language assessment:

    spoofed       the domain's own policy rejects this mail, or every check failed while a well-known brand is claimed
    suspicious    something does not add up (failed checks, a lookalike domain, a brand in the display name)
    authentic     the claimed domain's own checks pass (DMARC aligned)
    unverifiable  the checks could not be run or the domain publishes none: we say so instead of guessing

It never convicts on one weak signal. Forwarded mail and mailing lists legitimately break SPF, so when forwarding markers
are present a "spoofed" result is lowered to "suspicious". Pure logic: no network access (DNS was done earlier), so it is
fast and testable.
"""
import email
import re
from email import policy
from typing import Any, Dict, List, Optional, Tuple

try:                                              # brand -> official domains, shared with the page sandbox
    from ml.features import BRAND_DOMAINS
except Exception:                                 # pragma: no cover
    BRAND_DOMAINS = {}

LEVELS = ("spoofed", "suspicious", "authentic", "unverifiable")

_FORWARD_HEADERS = ("ARC-Seal", "ARC-Message-Signature", "X-Forwarded-For", "X-Forwarded-To", "Resent-From", "Resent-To",
                    "List-Id", "List-Unsubscribe", "X-BeenThere", "X-Mailing-List", "Precedence")


def _registered(domain: str) -> str:
    parts = [p for p in (domain or "").lower().strip(".").split(".") if p]
    if len(parts) <= 2:
        return ".".join(parts)
    # common two-level public suffixes (co.uk, com.au, co.in ...): keep three labels
    if parts[-2] in ("co", "com", "org", "net", "gov", "ac", "edu") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _owns(brand: str, domain: str) -> bool:
    reg = _registered(domain)
    return any(reg == d or reg.endswith("." + d) for d in BRAND_DOMAINS.get(brand, []))


_GENERIC_NAME_WORDS = {"support", "team", "security", "billing", "service", "services", "account", "accounts", "alert", "alerts",
                       "verification", "verify", "help", "helpdesk", "customer", "care", "notification", "notifications",
                       "noreply", "no", "reply", "official", "online", "bank", "banking", "inc", "ltd", "india", "payments",
                       "payment", "update", "updates", "admin", "mail", "email", "the", "from", "center", "centre", "desk",
                       "department", "dept", "fraud", "risk", "prevention", "login", "signin", "sign", "in", "info", "pay"}


def _brand_in(text: str) -> str:
    """
    The well-known brand a display name claims to be, or ''. The name must be the brand plus generic words only
    ("PayPal Security Team"); a person called "Apple Johnson" or a shop called "Amazon Fresh Bakery" is not a claim.
    """
    tokens = [t for t in re.sub(r"[^a-z0-9]+", " ", (text or "").lower()).split() if t]
    for brand in BRAND_DOMAINS:
        if len(brand) < 4:
            continue
        words = brand.split()
        joined = " ".join(tokens)
        if f" {brand} " in f" {joined} ":
            rest = [t for t in tokens if t not in words and t not in _GENERIC_NAME_WORDS]
            if not rest:
                return brand
    return ""


def _lookalike_of(domain: str) -> str:
    """A brand whose name is inside this domain's name although the domain is not the brand's (paypal-secure.com)."""
    reg = _registered(domain)
    label = reg.split(".")[0].replace("-", "").replace("_", "")
    for brand in BRAND_DOMAINS:
        if len(brand) >= 5 and brand in label and not _owns(brand, reg):
            return brand
    return ""


def parse_receiver_report(headers) -> Dict[str, Any]:
    """What the receiving mail provider (Gmail, Outlook ...) recorded in Authentication-Results, if present."""
    results = headers.get_all("Authentication-Results", []) if headers is not None else []
    report: Dict[str, Any] = {"present": bool(results), "by": "", "spf": "", "dkim": "", "dmarc": ""}
    if not results:
        return report
    text = " ".join(str(r) for r in results[:1])
    report["by"] = text.split(";")[0].strip()[:80]
    for key in ("spf", "dkim", "dmarc"):
        m = re.search(r"\b" + key + r"\s*=\s*([a-z]+)", text, re.I)
        if m:
            report[key] = m.group(1).lower()
    return report


def forwarding_signals(headers) -> List[str]:
    return [h for h in _FORWARD_HEADERS if headers is not None and headers.get(h) is not None]


def assess_sender(forensics: Dict[str, Any], raw_message: Optional[bytes] = None) -> Dict[str, Any]:
    """
    forensics: the result of email_forensics.parse_email_file.  raw_message: the original .eml bytes (for the extra headers).
    Returns the assessment; always safe to call (missing pieces just reduce confidence).
    """
    meta = forensics.get("metadata") or {}
    auth = forensics.get("authentication") or {}
    origin = forensics.get("origin_tracing") or {}
    headers = None
    display_name = ""
    if raw_message:
        try:
            headers = email.message_from_bytes(raw_message, policy=policy.default)
            display_name = email.utils.parseaddr(str(headers.get("From", "")))[0]
        except Exception:
            headers = None
    if not display_name:
        display_name = email.utils.parseaddr(str(meta.get("from", "")))[0]

    from_domain = str(meta.get("from_domain") or "").lower()
    spf, dkim, dmarc = (auth.get("spf_state") or "indeterminate", auth.get("dkim_state") or "indeterminate",
                        auth.get("dmarc_state") or "indeterminate")
    policy_set = (auth.get("dmarc_policy") or "").lower()
    sending_ip = origin.get("connecting_ip") or origin.get("originating_ip")

    receiver = parse_receiver_report(headers)
    forwarding = forwarding_signals(headers)
    forwarded = bool(forwarding)

    claimed_brand = _brand_in(display_name)
    if not claimed_brand:
        claimed_brand = next((b for b in BRAND_DOMAINS if _owns(b, from_domain)), "")
    display_brand = _brand_in(display_name)
    display_mismatch = bool(display_brand and from_domain and not _owns(display_brand, from_domain))
    lookalike = _lookalike_of(from_domain) if from_domain else ""
    reply_mismatch = bool(meta.get("reply_to_mismatch"))

    facts: List[str] = []
    level, headline = "unverifiable", "The sender could not be verified."

    if dmarc == "pass":
        level, headline = "authentic", f"This email really comes from {from_domain}: its sender checks pass."
        facts.append(f"{from_domain}'s own policy check (DMARC) passed.")
        if display_mismatch:
            level = "suspicious"
            headline = (f"The sender name says \"{display_brand}\", but the email comes from {from_domain}, "
                        f"which is not {display_brand}'s domain.")
            facts.append("The checks pass for the sender's own domain, not for the brand named in the display name.")
        elif lookalike:
            level = "suspicious"
            headline = f"{from_domain} looks like {lookalike}'s name but is not {lookalike}'s domain."
    elif dmarc == "fail":
        owner_rejects = policy_set in ("reject", "quarantine")
        all_failed = spf == "fail" and dkim != "pass"
        if (owner_rejects or (all_failed and (claimed_brand or display_mismatch))) and not forwarded:
            level = "spoofed"
            headline = (f"This email pretends to come from {from_domain}, but it was sent from "
                        f"{sending_ip or 'an unknown address'}, which {from_domain} has not authorised.")
        else:
            level = "suspicious"
            headline = f"The sender checks for {from_domain} failed, so the sender may not be who it claims."
            if forwarded and (owner_rejects or all_failed):
                facts.append("The message looks forwarded or sent through a mailing list, which can break these checks, "
                             "so it is flagged as suspicious rather than forged.")
        if spf == "fail":
            facts.append(f"SPF failed: {sending_ip or 'the sending address'} is not on {from_domain}'s list of allowed senders.")
        if dkim != "pass":
            facts.append("DKIM: no valid signature from the claimed domain." if dkim in ("fail", "none") else "DKIM could not be verified.")
        if owner_rejects:
            facts.append(f"{from_domain} tells receivers to {policy_set} mail that fails these checks.")
    else:
        # DMARC absent or not evaluable: lean on the other facts, never on silence alone
        if display_mismatch or lookalike:
            level = "suspicious"
            headline = (f"The sender name says \"{display_brand}\", but nothing proves it comes from {display_brand}."
                        if display_mismatch else f"{from_domain} looks like {lookalike}'s name but is not {lookalike}'s domain.")
        elif spf == "fail" and dkim != "pass":
            level = "suspicious"
            headline = f"The sending address is not allowed to send for {from_domain}, and the email has no valid signature."
            facts.append(f"SPF failed for {sending_ip or 'the sending address'}.")
        elif spf == "pass" and dkim == "pass":
            level, headline = "authentic", f"The email's signature and sending address are valid for {from_domain}."
        else:
            facts.append("The domain publishes no complete sender policy, or the checks could not be completed.")

    if display_mismatch:
        facts.append(f"Display name mentions {display_brand}; the address is @{from_domain}.")
    if lookalike and not display_mismatch:
        facts.append(f"The domain name contains \"{lookalike}\" but belongs to someone else.")
    if reply_mismatch:
        facts.append(f"Replies would go to {meta.get('reply_to')}, a different address from the sender.")
        if level == "authentic":
            level = "suspicious"
            headline = "The sender checks pass, but replies are redirected to a different address."
    if receiver["present"]:
        disagree = [k for k, ours in (("spf", spf), ("dkim", dkim), ("dmarc", dmarc))
                    if receiver[k] and ours in ("pass", "fail") and receiver[k] != ours and not (receiver[k] == "none" and ours == "fail")]
        facts.append(f"Your mail provider ({receiver['by'] or 'receiving server'}) recorded: "
                     f"SPF {receiver['spf'] or '?'}, DKIM {receiver['dkim'] or '?'}, DMARC {receiver['dmarc'] or '?'}."
                     + (f" Our own check differs for: {', '.join(disagree)}." if disagree else ""))

    return {
        "level": level,
        "headline": headline,
        "claims": {"display_name": display_name, "address_domain": from_domain, "brand": claimed_brand or None,
                   "reply_to": meta.get("reply_to") or None},
        "reality": {"sending_ip": sending_ip, "originating_ip": origin.get("originating_ip"),
                    "spf": spf, "dkim": dkim, "dmarc": dmarc, "dmarc_policy": policy_set or None},
        "receiver_report": receiver,
        "forwarded": forwarded,
        "forwarding_signals": forwarding,
        "display_name_mismatch": display_mismatch,
        "lookalike_of": lookalike or None,
        "reasons": facts,
    }


def score_contribution(assessment: Dict[str, Any]) -> Tuple[float, str]:
    """(points to add to the email's threat score, short reason). Spoofing alone is serious but never the whole verdict."""
    level = assessment.get("level")
    if level == "spoofed":
        return 40.0, "Sender impersonation: " + assessment.get("headline", "")
    if level == "suspicious":
        return 15.0, "Sender could not be trusted: " + assessment.get("headline", "")
    return 0.0, ""
