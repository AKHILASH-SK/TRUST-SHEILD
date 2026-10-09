"""
The mail gateway over a real SMTP connection. Senders connect from different loopback addresses (127.0.0.2, 127.0.0.3 ...)
so the gateway sees different real connecting IPs without any network. The analysis is done in-process (same code the backend runs).
"""
import os
import smtplib
import socket

import pytest

from gateway import smtp_gateway
from gateway.rotation import RotationTracker
from lab.mail_lab import BANK_DOMAIN, BANK_IP, LabWorld, forged_bank_email, genuine_bank_email


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def can_bind(ip):
    s = socket.socket()
    try:
        s.bind((ip, 0))
        return True
    except OSError:
        return False
    finally:
        s.close()


pytestmark = pytest.mark.skipif(not can_bind("127.0.0.3"), reason="this machine cannot bind extra loopback addresses")


@pytest.fixture
def gateway(tmp_path, monkeypatch):
    from core_engine.email_forensics import parse_email_file          # noqa: F401  (import before the lab hooks)
    from core_engine.unified_email_pipeline import analyze_email_pipeline
    world = LabWorld().install()
    monkeypatch.setattr(smtp_gateway.Gateway, "analyze",
                        lambda self, message: analyze_email_pipeline(message, skip_link_sandbox=True))
    monkeypatch.setattr(smtp_gateway.Gateway, "report", lambda self, event: None)
    port = free_port()
    controller, gw = smtp_gateway.start("http://unused.invalid", "127.0.0.1", port, root=str(tmp_path))
    yield world, port, gw, tmp_path
    controller.stop()
    world.uninstall()


def send(port, source_ip, raw, from_addr=f"alerts@{BANK_DOMAIN}"):
    with smtplib.SMTP("127.0.0.1", port, source_address=(source_ip, 0), timeout=60) as smtp:
        return smtp.sendmail(from_addr, ["victim@example.test"], raw)


def read_all(folder):
    return [open(os.path.join(folder, f), "rb").read().decode("utf-8", "replace") for f in sorted(os.listdir(folder))]


def test_the_gateway_sees_the_real_connecting_ip_and_delivers_genuine_mail(gateway):
    world, port, gw, root = gateway
    send(port, BANK_IP, genuine_bank_email(world))
    inbox = read_all(root / "inbox")
    assert len(inbox) == 1 and not os.listdir(root / "quarantine")
    text = inbox[0]
    assert "X-TrustShield-Action: deliver" in text and f"X-TrustShield-Connecting-IP: {BANK_IP}" in text
    assert "X-TrustShield-Sender-Check: authentic" in text
    assert f"([{BANK_IP}]) by trustshield-gateway" in text            # the header the gateway itself wrote


def test_forged_mail_from_another_address_is_quarantined_with_the_attackers_ip_recorded(gateway):
    world, port, gw, root = gateway
    send(port, "127.0.0.3", forged_bank_email())
    quarantined = read_all(root / "quarantine")
    assert len(quarantined) == 1 and not os.listdir(root / "inbox")
    text = quarantined[0]
    assert "X-TrustShield-Action: quarantine" in text and "X-TrustShield-Connecting-IP: 127.0.0.3" in text
    assert "X-TrustShield-Sender-Check: spoofed" in text and "X-TrustShield-Evidence-SHA256:" in text


def test_the_reject_mode_refuses_forged_mail_during_the_smtp_conversation(gateway):
    world, port, gw, root = gateway
    gw.reject_spoofed = True
    with pytest.raises(smtplib.SMTPDataError) as err:
        send(port, "127.0.0.3", forged_bank_email())
    assert err.value.smtp_code == 550


def test_one_claimed_domain_arriving_from_many_addresses_is_flagged_as_rotation(gateway):
    world, port, gw, root = gateway
    for ip in ("127.0.0.3", "127.0.0.4", "127.0.0.5"):
        send(port, ip, forged_bank_email())
    last = read_all(root / "quarantine")[-1]
    assert "X-TrustShield-IP-Rotation:" in last and "3 different unauthorised addresses" in last


def test_header_injection_through_the_helo_name_is_neutralised():
    assert "\r" not in smtp_gateway.header_safe("evil\r\nBcc: someone@example.com") and "\n" not in smtp_gateway.header_safe("a\nb")


def test_rotation_tracker_counts_only_failing_senders_inside_the_window():
    tracker = RotationTracker(window=60, minimum=3)
    for i, ip in enumerate(("10.0.0.1", "10.0.0.2")):
        assert tracker.record("bank.test", ip, failed=True, now=100 + i)["rotating"] is False
    assert tracker.record("bank.test", "10.0.0.2", failed=True, now=102)["distinct_ips"] == 2          # same address again
    assert tracker.record("bank.test", "10.0.0.9", failed=False, now=103)["distinct_ips"] == 2         # passing mail does not count
    assert tracker.record("bank.test", "10.0.0.3", failed=True, now=104)["rotating"] is True
    assert tracker.record("bank.test", "10.0.0.4", failed=True, now=400)["distinct_ips"] == 1          # the old ones aged out
