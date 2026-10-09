"""
The impersonation demo, scene by scene. Needs the lab backend (port 8000) and the mail gateway (port 2525) running:

    cd backend
    powershell -ExecutionPolicy Bypass -File lab\\run_demo.ps1        (starts both, then this)

    python -m lab.scenes [--pause]      --pause waits for Enter between scenes (for presenting)

Characters:  C = the real bank (bank.test, sends from 127.0.0.2)   B = the attacker (sends from 127.0.0.3 and then rotates)
             TrustShield = the gateway in the middle, which sees the REAL address of whoever connects.
"""
import argparse
import hashlib
import logging
import json
import os
import smtplib
import sys
import time

import requests

from lab.mail_lab import ATTACKER_IP, BANK_DOMAIN, BANK_IP, LabWorld, forged_bank_email, genuine_bank_email

API = os.environ.get("TS_API", "http://127.0.0.1:8000")
GATEWAY = ("127.0.0.1", int(os.environ.get("TS_GATEWAY_PORT", "2525")))


def say(text="", color=None):
    codes = {"cyan": "36", "green": "32", "red": "31", "yellow": "33", "dim": "90", "bold": "1"}
    print(f"\033[{codes[color]}m{text}\033[0m" if color else text, flush=True)


def scene(title, pause, story):
    if pause:
        input("\n[Enter] for the next scene ... ")
    say("\n" + "=" * 100, "dim")
    say(title, "bold")
    say(story, "cyan")
    say("-" * 100, "dim")


def send(source_ip, raw):
    """Connect to the gateway FROM a chosen address (127.0.0.x), so the gateway sees a different real sender each time."""
    with smtplib.SMTP(*GATEWAY, source_address=(source_ip, 0), timeout=180) as smtp:
        try:
            smtp.sendmail(f"alerts@{BANK_DOMAIN}", ["victim@example.test"], raw)
            return "accepted"
        except smtplib.SMTPDataError as exc:
            return f"REFUSED at SMTP time: {exc.smtp_code} {exc.smtp_error.decode(errors='replace')}"


def last_event():
    events = requests.get(f"{API}/api/gateway/events", timeout=10).json().get("events", [])
    return events[0] if events else {}


def show_event(event):
    colour = {"quarantine": "red", "warn": "yellow", "deliver": "green"}.get(event.get("action"), None)
    say(f"  gateway saw the connection from : {event.get('connecting_ip')}")
    say(f"  the email claims to be          : {event.get('claimed_domain')}")
    say(f"  SPF / DKIM / DMARC              : {event.get('spf')} / {event.get('dkim')} / {event.get('dmarc')}")
    say(f"  TrustShield says                : {event.get('headline')}")
    say(f"  verdict / action                : {event.get('verdict')} ({event.get('score')})  ->  {str(event.get('action')).upper()}", colour)
    if event.get("rotation"):
        say(f"  IP ROTATION DETECTED            : {event['rotation'].get('message')}", "red")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pause", action="store_true")
    args = ap.parse_args()
    logging.getLogger('werkzeug').setLevel(logging.ERROR)
    world = LabWorld()
    requests.get(f"{API}/api/gateway/events?clear=1", timeout=10)

    scene("SCENE 1  The real bank writes to you (C -> A)", args.pause,
          f"The bank's mail server ({BANK_IP}) is listed in bank.test's SPF record and signs its mail with the bank's secret DKIM key.\n"
          "Nothing is wrong, so TrustShield must let it through.")
    say(f"  sending from {BANK_IP} ... " + send(BANK_IP, genuine_bank_email(world)))
    show_event(last_event())

    scene("SCENE 2  An attacker pretends to be the bank (B pretends to be C)", args.pause,
          f"The attacker sends an email whose From says {BANK_DOMAIN}, but it comes from THEIR machine ({ATTACKER_IP}).\n"
          "Email has no built-in check, so the forged From address is easy. TrustShield sits in the middle and sees the real connecting\n"
          f"address, then asks the bank's DNS: is {ATTACKER_IP} allowed to send for {BANK_DOMAIN}? Is there a valid signature?")
    say(f"  sending from {ATTACKER_IP} ... " + send(ATTACKER_IP, forged_bank_email()))
    forged = last_event()
    show_event(forged)

    scene("SCENE 3  The attacker keeps switching IP address (IP hopping)", args.pause,
          "Blocking one address would be pointless, so the attacker sends the same forgery from a different address each time.\n"
          "TrustShield does not chase the addresses: it notices that ONE claimed sender keeps arriving from MANY unauthorised addresses.")
    for i in range(4, 9):
        ip = f"127.0.0.{i}"
        say(f"  sending from {ip} ... " + send(ip, forged_bank_email(subject=f"Urgent action {i}")))
    show_event(last_event())

    scene("SCENE 4  The attacker's website keeps changing its address (fast-flux)", args.pause,
          "The link in the forged email points to a domain whose DNS answer changes on every question and expires in 30 seconds.\n"
          "TrustShield asks DNS four times and watches the pattern. A normal site gives the same answer.")
    for url in ("https://flux.bank-verify.test/login", "https://steady.shop.test/"):
        out = requests.post(f"{API}/api/infra/check", json={"url": url}, timeout=30).json()
        for d in out.get("domains", []):
            ff = d["fast_flux"]
            say(f"  {d['domain']:<28} {ff['level'].upper():<10} {ff['distinct_ips']} IPs, TTL {ff.get('min_ttl')}s  - {ff['headline']}",
                "red" if ff["level"] == "fast_flux" else "green")

    scene("SCENE 5  A fake page sits between you and the real bank (adversary-in-the-middle)", args.pause,
          "The relay shows the REAL bank's login page, word for word, but on another domain, and passes what you type on to the real bank.\n"
          "You see a normal login while the attacker copies your password. The page looks identical; the DOMAIN is the tell.")
    os.environ["TRUSTSHIELD_LAB_MODE"] = "1"
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tests", "lab"))
    try:
        import lab_server
        from core_engine import browser_sandbox as bs
        from core_engine.link_threat_pipeline import LinkThreatPipeline
        port, stop = lab_server.start()
        os.environ["TRUSTSHIELD_LAB_PORT"] = str(port)
        bs._availability = None
        pipe = LinkThreatPipeline()
        pipe.threat_db.check_indicator = lambda u: False
        for host in ("hdfcbank.com", "hdfcbank-secure-login.com"):
            res = pipe.analyze_url(f"http://{host}/", defer_ai=True)
            sandbox = (res.get("telemetry") or {}).get("sandbox") or {}
            if (res.get("telemetry") or {}).get("status") == "WHITELISTED":
                detail = "the official domain of the bank: trusted at once, no scan needed"
            else:
                detail = (f"the page claims to be '{sandbox.get('claimed_brand')}' but this domain does not belong to it "
                          f"(owned by that brand: {sandbox.get('brand_owns_domain')}), and it asks for a password")
            say(f"  {host:<28} {str(res.get('display_verdict')).upper():<10} {detail}",
                "green" if res.get("display_verdict") == "Safe" else "red")
        stop()
    except Exception as exc:
        say(f"  (relay scene skipped: {type(exc).__name__}: {exc})", "yellow")

    scene("SCENE 6  Proof nothing was changed afterwards (SHA-256)", args.pause,
          "Every analysed email is sealed: its SHA-256 fingerprint is stored with a signature. Change ONE character and the fingerprint\n"
          "becomes completely different, so a tampered report or email cannot pass as the original.")
    original = forged_bank_email()
    altered = original.replace(b"Urgent", b"Urgenx", 1)
    say(f"  original email SHA-256 : {hashlib.sha256(original).hexdigest()}")
    say(f"  one letter changed     : {hashlib.sha256(altered).hexdigest()}", "yellow")
    if forged.get("evidence_sha256"):
        res = requests.post(f"{API}/api/forensics/verify-hash", json={"query": forged["evidence_sha256"]}, timeout=20)
        if res.status_code == 200:
            body = res.json()
            say(f"  vault lookup of the forged email's fingerprint -> {body.get('integrity_verdict')}  (case {body.get('case_id')})", "green")
        else:
            say("  (the case vault needs the database; the fingerprint itself is shown above)", "dim")
    say("\nDone. The portal's 'Mail Gateway' tab shows every message above, live.", "bold")


if __name__ == "__main__":
    main()
