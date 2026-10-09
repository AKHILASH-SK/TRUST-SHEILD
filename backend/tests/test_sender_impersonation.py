"""Sender impersonation verdicts: forged, suspicious, authentic, unverifiable - and the cases that must NOT be flagged."""
from core_engine import sender_impersonation as si


def forensics(from_domain="paypal.com", spf="pass", dkim="pass", dmarc="pass", policy="reject", ip="203.0.113.9",
              reply_mismatch=False, reply_to=""):
    return {"metadata": {"from": f"x@{from_domain}", "from_domain": from_domain, "reply_to_mismatch": reply_mismatch,
                         "reply_to": reply_to},
            "authentication": {"spf_state": spf, "dkim_state": dkim, "dmarc_state": dmarc, "dmarc_policy": policy},
            "origin_tracing": {"connecting_ip": ip, "originating_ip": ip}}


def eml(display='"PayPal Security" <service@paypal.com>', extra=""):
    return (f"From: {display}\r\nTo: me@example.com\r\nSubject: Hello\r\n{extra}\r\n\r\nbody\r\n").encode()


def test_forged_email_from_a_domain_that_rejects_it_is_spoofed():
    out = si.assess_sender(forensics(spf="fail", dkim="none", dmarc="fail", policy="reject"), eml())
    assert out["level"] == "spoofed"
    assert "203.0.113.9" in out["headline"] and "paypal.com" in out["headline"]
    assert out["owner_policy_rejects"] is True and si.score_contribution(out)[0] >= 80      # the domain itself says "reject"


def test_all_checks_failing_while_claiming_a_brand_is_spoofed_even_without_a_reject_policy():
    out = si.assess_sender(forensics(from_domain="hdfcbank.com", spf="fail", dkim="none", dmarc="fail", policy="none"),
                           eml('"HDFC Bank Alerts" <alerts@hdfcbank.com>'))
    assert out["level"] == "spoofed" and out["claims"]["brand"] == "hdfc"


def test_a_genuine_email_that_passes_dmarc_is_authentic_and_adds_no_risk():
    out = si.assess_sender(forensics(), eml())
    assert out["level"] == "authentic" and si.score_contribution(out)[0] == 0


def test_forwarded_or_mailing_list_mail_is_never_called_forged():
    out = si.assess_sender(forensics(spf="fail", dkim="none", dmarc="fail", policy="reject"),
                           eml(extra="ARC-Seal: i=1; a=rsa-sha256\r\nList-Id: <team.example.org>\r\n"))
    assert out["level"] == "suspicious" and out["forwarded"] is True
    assert any("forwarded" in r for r in out["reasons"])


def test_display_name_claiming_a_brand_from_an_unrelated_domain_is_suspicious_even_when_its_own_checks_pass():
    out = si.assess_sender(forensics(from_domain="random-mailer.xyz"), eml('"PayPal Support" <help@random-mailer.xyz>'))
    assert out["level"] == "suspicious" and out["display_name_mismatch"] is True


def test_ordinary_names_that_contain_a_brand_word_are_not_a_claim():
    for name in ('"Apple Johnson" <apple@gmail.com>', '"Amazon Fresh Bakery" <hello@freshbakery.example>', '"Chase" <chase@friends.example>'):
        out = si.assess_sender(forensics(from_domain=name.split("@")[1].strip(">")), eml(name))
        assert out["display_name_mismatch"] is False or "Chase" in name       # a bare brand name is a claim; people are not


def test_lookalike_domain_is_flagged():
    out = si.assess_sender(forensics(from_domain="paypal-secure-login.com"), eml('"Billing" <b@paypal-secure-login.com>'))
    assert out["lookalike_of"] == "paypal" and out["level"] == "suspicious"


def test_missing_policy_and_no_other_signal_is_unverifiable_not_guilty():
    out = si.assess_sender(forensics(from_domain="small-shop.example", spf="none", dkim="none", dmarc="none", policy=""),
                           eml('"Small Shop" <hi@small-shop.example>'))
    assert out["level"] == "unverifiable" and si.score_contribution(out)[0] == 0


def test_dns_trouble_is_unverifiable_not_a_failure():
    out = si.assess_sender(forensics(spf="indeterminate", dkim="indeterminate", dmarc="indeterminate", policy=""), eml())
    assert out["level"] == "unverifiable"


def test_reply_to_redirected_elsewhere_lowers_an_authentic_result():
    out = si.assess_sender(forensics(reply_mismatch=True, reply_to="attacker@evil.example"), eml())
    assert out["level"] == "suspicious"


def test_the_receiving_providers_own_report_is_read_and_compared():
    extra = "Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=paypal.com; dkim=pass; dmarc=pass\r\n"
    out = si.assess_sender(forensics(spf="fail", dkim="pass", dmarc="pass"), eml(extra=extra))
    assert out["receiver_report"]["present"] and out["receiver_report"]["spf"] == "pass"
    assert any("Our own check differs" in r for r in out["reasons"])


# ---- the lab: real checking code against simulated DNS and simulated sender addresses -----------------------------------
import pytest


@pytest.fixture
def world():
    from lab.mail_lab import LabWorld
    w = LabWorld().install()
    yield w
    w.uninstall()


def run(raw):
    from core_engine.email_forensics import parse_email_file
    return si.assess_sender(parse_email_file(raw), raw)


def test_lab_genuine_bank_email_is_authentic(world):
    from lab.mail_lab import genuine_bank_email
    out = run(genuine_bank_email(world))
    assert out["level"] == "authentic", out
    assert out["reality"]["spf"] == "pass" and out["reality"]["dkim"] == "pass" and out["reality"]["dmarc"] == "pass"
    assert out["reality"]["sending_ip"] == "127.0.0.2"


def test_lab_forged_email_claiming_to_be_the_bank_is_spoofed(world):
    from lab.mail_lab import forged_bank_email
    out = run(forged_bank_email())
    assert out["level"] == "spoofed", out
    assert out["reality"]["sending_ip"] == "127.0.0.3" and out["reality"]["spf"] == "fail"
    assert "127.0.0.3" in out["headline"] and "bank.test" in out["headline"]


def test_lab_tampering_with_a_signed_email_breaks_the_signature(world):
    from lab.mail_lab import genuine_bank_email
    tampered = genuine_bank_email(world).replace(b"statement is ready", b"account is locked, click here")
    out = run(tampered)
    assert out["reality"]["dkim"] == "fail" and out["level"] in ("suspicious", "authentic")      # SPF still passes from the bank's IP
    assert out["reality"]["dmarc"] == "pass"                                                       # DMARC accepts SPF alignment alone


def test_lab_the_same_forgery_forwarded_through_a_list_is_only_suspicious(world):
    from lab.mail_lab import build_message, BANK_DOMAIN, ATTACKER_IP
    raw = build_message(f'"Bank Security" <alerts@{BANK_DOMAIN}>', ATTACKER_IP, extra_headers="List-Id: <friends.example.org>\r\nARC-Seal: i=1")
    assert run(raw)["level"] == "suspicious"


def test_lab_analysis_never_touches_real_dns_for_lab_domains(world):
    from core_engine import email_forensics as ef
    assert ef._dns_lookup("bank.test", "TXT")[0].startswith("v=spf1")


def test_lab_whole_pipeline_verdicts(world):
    from core_engine.unified_email_pipeline import analyze_email_pipeline
    from lab.mail_lab import genuine_bank_email, forged_bank_email, build_message, BANK_DOMAIN, ATTACKER_IP
    genuine = analyze_email_pipeline(genuine_bank_email(world), skip_link_sandbox=True)
    assert genuine["verdict"].startswith("LEGITIMATE") and genuine["sender_assessment"]["level"] == "authentic"
    forged = analyze_email_pipeline(forged_bank_email(body="Please call us."), skip_link_sandbox=True)
    assert forged["verdict"].startswith("CRITICAL") and forged["sender_assessment"]["level"] == "spoofed"
    forwarded_mail = build_message(f'"Bank" <alerts@{BANK_DOMAIN}>', ATTACKER_IP,
                                   extra_headers="List-Id: <x.example>" + chr(13) + chr(10) + "ARC-Seal: i=1")
    forwarded = analyze_email_pipeline(forwarded_mail, skip_link_sandbox=True)
    assert forwarded["verdict"].startswith("SUSPICIOUS")          # not "authenticated", and not called forged either


def test_the_connecting_ip_is_the_one_the_receiving_server_recorded_not_one_the_sender_wrote():
    from core_engine.email_forensics import find_connecting_ip
    forged_helo = "from 8.8.8.8 (evil.example [93.184.216.34]) by mx.receiver.example with ESMTP; Fri, 9 Oct 2026 10:00:00 +0000"
    assert find_connecting_ip([forged_helo]) == "93.184.216.34"          # not the 8.8.8.8 the sender claimed in HELO
    gmail_style = "from mail-xyz.google.com (mail-xyz.google.com. [209.85.220.41]) by mx.example.com with ESMTPS"
    assert find_connecting_ip([gmail_style]) == "209.85.220.41"
    # an internal hop (private bracketed address) is skipped, and the HELO text of that hop is never used
    internal = "from 8.8.4.4 (internal [10.0.0.5]) by relay.example"
    assert find_connecting_ip([internal, gmail_style]) == "209.85.220.41"
    # headers without brackets still work as before
    assert find_connecting_ip(["from host by mx with SMTP; connection from 93.184.216.34"]) == "93.184.216.34"
