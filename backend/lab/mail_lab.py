"""
The mail lab: three characters on one laptop.

    C  the real bank (bank.test)     sends from 127.0.0.2, has a published SPF policy, a DKIM key and a DMARC "reject" policy
    B  the attacker                  sends from 127.0.0.3 and claims to be the bank
    A  the victim                    is whoever receives the mail (TrustShield checks it for them)

The checking code is the real production code (email_forensics + sender_impersonation). Only two things are simulated:
the DNS answers (a table instead of the internet) and the sender addresses (127.0.0.x instead of public IPs). Turn the
simulation on with `install()`; it is switched off again with `uninstall()`.
"""
import base64
import dkim
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from email.utils import formatdate, make_msgid

from core_engine import email_forensics

BANK_DOMAIN = "bank.test"
BANK_IP = "127.0.0.2"
ATTACKER_IP = "127.0.0.3"
SELECTOR = "lab"


class LabWorld:
    """Pretend DNS for the lab domains, plus the bank's DKIM key."""

    def __init__(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.private_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                             serialization.NoEncryption())
        public_der = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.records = {
            ("TXT", BANK_DOMAIN): [f"v=spf1 ip4:{BANK_IP} -all"],                                       # only the bank's server may send
            ("TXT", f"_dmarc.{BANK_DOMAIN}"): [f"v=DMARC1; p=reject; adkim=r; aspf=r; rua=mailto:dmarc@{BANK_DOMAIN}"],
            ("TXT", f"{SELECTOR}._domainkey.{BANK_DOMAIN}"): ["v=DKIM1; k=rsa; p=" + base64.b64encode(public_der).decode()],
            ("MX", BANK_DOMAIN): [f"10 mail.{BANK_DOMAIN}"],
            ("A", f"mail.{BANK_DOMAIN}"): [BANK_IP],
        }

    def answer(self, name, rtype):
        """Answers for lab domains; None for everything else (the real DNS is then used)."""
        name = name.rstrip(".").lower()
        if name == BANK_DOMAIN or name.endswith("." + BANK_DOMAIN):
            return self.records.get((rtype, name), [])
        return None

    def install(self):
        email_forensics.DNS_OVERRIDE = self.answer
        email_forensics.LAB_MODE = True
        return self

    @staticmethod
    def uninstall():
        email_forensics.DNS_OVERRIDE = None
        email_forensics.LAB_MODE = False


def build_message(from_header, from_ip, subject="Important notice", body="Please review your account.", reply_to=None,
                  received_by="trustshield-gw", extra_headers=""):
    """An email as it looks after the receiving server has added its Received header for the connecting address."""
    lines = [
        f"Received: from sender ({from_ip}) by {received_by} with ESMTP; {formatdate(localtime=False)}",
        f"From: {from_header}",
        "To: victim@example.test",
        f"Subject: {subject}",
        f"Date: {formatdate(localtime=False)}",
        f"Message-ID: {make_msgid(domain=BANK_DOMAIN)}",
    ]
    if reply_to:
        lines.append(f"Reply-To: {reply_to}")
    if extra_headers:
        lines.append(extra_headers.strip("\r\n"))
    lines += ["MIME-Version: 1.0", "Content-Type: text/plain; charset=utf-8", "", body, ""]
    return "\r\n".join(lines).encode("utf-8")


def sign_as_bank(world: LabWorld, message: bytes) -> bytes:
    """The bank's mail server adds its DKIM signature (the attacker cannot: they do not have the private key)."""
    signature = dkim.sign(message, SELECTOR.encode(), BANK_DOMAIN.encode(), world.private_pem,
                          include_headers=[b"from", b"to", b"subject", b"date", b"message-id"])
    return signature + message


def genuine_bank_email(world: LabWorld) -> bytes:
    return sign_as_bank(world, build_message(f'"Bank Security" <alerts@{BANK_DOMAIN}>', BANK_IP,
                                             subject="Your statement is ready", body="Your monthly statement is available."))


def forged_bank_email(subject="Urgent: verify your account", body="Click https://bank-verify.example/login now"):
    """The attacker's email: it claims to be the bank, but comes from their own server and has no valid signature."""
    return build_message(f'"Bank Security" <alerts@{BANK_DOMAIN}>', ATTACKER_IP, subject=subject, body=body)
