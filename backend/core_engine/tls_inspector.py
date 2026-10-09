"""
Certificate inspector: "is the lock real, and does it belong to who it says?"

A padlock only means the connection is encrypted. A phishing site gets a padlock too. What tells a real site from a relay
or a fake is WHO the certificate was issued to, how OLD it is, whether it names this host, and whether a normal browser would
trust the chain. We do one handshake to read the certificate (without trusting it) and a second one to ask whether the chain
verifies the way a browser's would.

Flags are indicators for the analyst. A new free certificate alone proves nothing (every new site has one); the result only
adds weight together with other evidence.
"""
import datetime as dt
import hashlib
import socket
import ssl
from typing import Any, Dict, List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, NameOID

try:
    from .url_safety import UnsafeUrlError, assert_public_url
except Exception:                                  # pragma: no cover
    assert_public_url, UnsafeUrlError = None, ValueError

NEW_CERT_DAYS = 14


def _name(cert_name: x509.Name, oid) -> str:
    try:
        attrs = cert_name.get_attributes_for_oid(oid)
        return attrs[0].value if attrs else ""
    except Exception:
        return ""


def _host_matches(host: str, names: List[str]) -> bool:
    host = host.lower().rstrip(".")
    for n in names:
        n = n.lower().rstrip(".")
        if n == host:
            return True
        if n.startswith("*.") and host.count(".") >= 1 and host.split(".", 1)[1] == n[2:]:
            return True
    return False


def _fetch_certificate(host: str, port: int, timeout: float) -> bytes:
    """The server's leaf certificate (DER), read without trusting it."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            return tls.getpeercert(binary_form=True)


def _chain_trusted(host: str, port: int, timeout: float, cafile: Optional[str]) -> Optional[str]:
    """None when a normal client would trust the chain and the name; otherwise the reason it would not."""
    ctx = ssl.create_default_context(cafile=cafile)
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host):
                return None
    except ssl.SSLCertVerificationError as exc:
        return (exc.verify_message or str(exc))[:120]
    except Exception as exc:
        return f"{type(exc).__name__}"


def assess_certificate(der: bytes, host: str, untrusted_reason: Optional[str], now: Optional[dt.datetime] = None) -> Dict[str, Any]:
    """Judge a certificate (pure function apart from reading the bytes)."""
    now = now or dt.datetime.now(dt.timezone.utc)
    cert = x509.load_der_x509_certificate(der)
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    subject_cn = _name(cert.subject, NameOID.COMMON_NAME)
    issuer_cn = _name(cert.issuer, NameOID.COMMON_NAME)
    issuer_org = _name(cert.issuer, NameOID.ORGANIZATION_NAME)
    try:
        sans = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
    except Exception:
        sans = []
    names = list(dict.fromkeys(sans + ([subject_cn] if subject_cn else [])))
    age_days = max(0, (now - not_before).days)
    self_signed = cert.issuer == cert.subject
    expired = now > not_after
    name_ok = _host_matches(host, names)

    flags: List[str] = []
    if self_signed:
        flags.append("The certificate is self-signed: nobody vouches for it.")
    if expired:
        flags.append("The certificate has expired.")
    if not name_ok:
        flags.append(f"The certificate is not issued for {host} (it names: {', '.join(names[:3]) or 'nothing'}).")
    if untrusted_reason and not self_signed:
        flags.append(f"A normal browser would not trust this connection ({untrusted_reason}).")
    if age_days <= NEW_CERT_DAYS and not (self_signed or expired):
        flags.append(f"The certificate is only {age_days} day(s) old.")

    if self_signed or expired or not name_ok or untrusted_reason:
        level = "untrusted"
        headline = "The padlock cannot be trusted: " + (flags[0] if flags else "the certificate failed verification.")
    elif age_days <= NEW_CERT_DAYS:
        level = "new"
        headline = f"A valid certificate, but a brand-new one ({age_days} day(s) old). New sites, including phishing sites, look like this."
    else:
        level = "ok"
        headline = f"A valid certificate from {issuer_org or issuer_cn or 'a trusted authority'}, {age_days} days old."
    return {"level": level, "headline": headline, "flags": flags, "subject": subject_cn, "issuer": issuer_org or issuer_cn,
            "names": names[:8], "valid_from": not_before.isoformat(), "valid_until": not_after.isoformat(), "age_days": age_days,
            "self_signed": self_signed, "expired": expired, "name_matches": name_ok,
            "sha256_fingerprint": cert.fingerprint(hashes.SHA256()).hex()}


def inspect_certificate(host: str, port: int = 443, timeout: float = 4.0, allow_private: bool = False,
                        cafile: Optional[str] = None) -> Dict[str, Any]:
    """Read and judge the certificate of host:port. Never raises. The host must be public unless allow_private (lab/tests)."""
    host = (host or "").strip().lower().rstrip(".")
    out: Dict[str, Any] = {"host": host, "port": port}
    if not host:
        return {**out, "level": "unknown", "headline": "No host.", "flags": []}
    if not allow_private and assert_public_url is not None:
        try:
            assert_public_url(f"https://{host}:{port}/")
        except Exception:
            return {**out, "level": "unknown", "headline": "This address is not checked (it is not a public internet host).", "flags": []}
    try:
        der = _fetch_certificate(host, port, timeout)
    except Exception as exc:
        return {**out, "level": "unknown", "headline": f"No certificate could be read ({type(exc).__name__}).", "flags": []}
    untrusted = _chain_trusted(host, port, timeout, cafile)
    try:
        return {**out, **assess_certificate(der, host, untrusted)}
    except Exception as exc:
        return {**out, "level": "unknown", "headline": f"The certificate could not be read ({type(exc).__name__}).", "flags": []}
