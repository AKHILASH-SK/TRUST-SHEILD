"""
The TrustShield mail gateway ("the person in the middle, on purpose").

Mail is delivered to THIS server instead of straight to the user's inbox. Because the sending machine connects to us
directly, the address we see on the connection is the REAL sender, not Gmail's or anybody's relay. For every message we

    1. record that connecting IP in a Received header (the one header the sender cannot forge: we write it),
    2. run the full analysis through the backend (SPF, DKIM, DMARC, sender impersonation, links, infrastructure, sealed case),
    3. add X-TrustShield-* headers and either deliver it, deliver it with a warning, or quarantine / reject it,
    4. tell the backend what happened (the portal's "Mail Gateway" tab shows it live).

    python -m gateway.smtp_gateway --port 2525 --api http://127.0.0.1:8000 [--reject-spoofed]
"""
import argparse
import asyncio
import email.utils
import json
import os
import re
import threading
import time
import uuid
from typing import Any, Dict, Optional

import requests
from aiosmtpd.controller import Controller

from gateway.rotation import RotationTracker

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mailbox")
MAX_MESSAGE_BYTES = 5 * 1024 * 1024
ANALYSIS_TIMEOUT = 150


def header_safe(value: Any, limit: int = 200) -> str:
    """Header values must never contain line breaks (header injection)."""
    return re.sub(r"[\r\n\x00]+", " ", str(value or ""))[:limit]


class Gateway:
    def __init__(self, api: str, reject_spoofed: bool = False, root: str = ROOT, admin_key: str = ""):
        self.api = api.rstrip("/")
        self.reject_spoofed = reject_spoofed
        self.root = root
        self.admin_key = admin_key
        self.rotation = RotationTracker()
        for folder in ("inbox", "quarantine"):
            os.makedirs(os.path.join(root, folder), exist_ok=True)

    # -- analysis ------------------------------------------------------------------------------------------------------
    def analyze(self, message: bytes) -> Optional[Dict[str, Any]]:
        try:
            resp = requests.post(f"{self.api}/api/forensics/analyze-eml", files={"file": ("mail.eml", message)},
                                 timeout=ANALYSIS_TIMEOUT)
            return resp.json() if resp.status_code == 200 else None
        except Exception as exc:
            print(f"[gateway] analysis service unreachable: {type(exc).__name__}", flush=True)
            return None

    def decide(self, result: Optional[Dict[str, Any]]) -> str:
        """'quarantine' | 'warn' | 'deliver'. If the analysis is unavailable the mail is delivered with a notice, never silently dropped."""
        if not result:
            return "warn"
        sender = (result.get("sender_assessment") or {})
        verdict = str(result.get("verdict") or "").upper()
        if sender.get("level") == "spoofed" or verdict.startswith("CRITICAL"):
            return "quarantine"
        if sender.get("level") == "suspicious" or verdict.startswith("SUSPICIOUS"):
            return "warn"
        return "deliver"

    # -- one message -----------------------------------------------------------------------------------------------------
    def process(self, peer_ip: str, helo: str, mail_from: str, rcpt_to: list, content: bytes) -> Dict[str, Any]:
        msg_id = uuid.uuid4().hex[:10]
        stamp = email.utils.formatdate(localtime=False)
        # The gateway's own Received header, written by us from the real connection: the trustworthy hop.
        received = (f"Received: from {header_safe(helo, 80)} ([{peer_ip}]) by trustshield-gateway with ESMTP id {msg_id}; {stamp}\r\n")
        message = received.encode() + content
        result = self.analyze(message)
        action = self.decide(result)
        sender = (result or {}).get("sender_assessment") or {}
        claimed = (sender.get("claims") or {}).get("address_domain") or ""
        failed = sender.get("level") in ("spoofed", "suspicious")
        rotation = self.rotation.record(claimed, peer_ip, failed)
        if rotation["rotating"] and action == "deliver":
            action = "warn"

        tags = [f"X-TrustShield-Action: {action}",
                f"X-TrustShield-Verdict: {header_safe((result or {}).get('verdict') or 'analysis unavailable')}",
                f"X-TrustShield-Score: {header_safe((result or {}).get('overall_threat_score', ''))}",
                f"X-TrustShield-Sender-Check: {header_safe(sender.get('level') or 'unverified')}: {header_safe(sender.get('headline'))}",
                f"X-TrustShield-Connecting-IP: {peer_ip}",
                f"X-TrustShield-Case: {header_safe((result or {}).get('case_id'))}",
                f"X-TrustShield-Evidence-SHA256: {header_safe((result or {}).get('evidence_hash'))}"]
        if rotation["rotating"]:
            tags.append(f"X-TrustShield-IP-Rotation: {header_safe(rotation['message'])}")
        delivered = ("".join(t + "\r\n" for t in tags)).encode() + message
        folder = "quarantine" if action == "quarantine" else "inbox"
        path = os.path.join(self.root, folder, f"{time.strftime('%H%M%S')}_{msg_id}.eml")
        with open(path, "wb") as fh:
            fh.write(delivered)

        event = {"id": msg_id, "time": time.strftime("%H:%M:%S"), "connecting_ip": peer_ip, "mail_from": header_safe(mail_from, 120),
                 "claimed_domain": claimed, "sender_level": sender.get("level") or "unverified",
                 "headline": sender.get("headline") or "", "verdict": (result or {}).get("verdict") or "analysis unavailable",
                 "score": (result or {}).get("overall_threat_score"), "action": action, "case_id": (result or {}).get("case_id"),
                 "evidence_sha256": (result or {}).get("evidence_hash"), "rotation": rotation if rotation["rotating"] else None,
                 "spf": (sender.get("reality") or {}).get("spf"), "dkim": (sender.get("reality") or {}).get("dkim"),
                 "dmarc": (sender.get("reality") or {}).get("dmarc"), "stored_as": folder}
        with open(os.path.join(self.root, "log.jsonl"), "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event) + "\n")
        self.report(event)
        print(f"[gateway] {event['time']}  from {peer_ip:<12} claims {claimed or '?':<20} -> {action.upper():<10} "
              f"{event['verdict']} ({event['sender_level']})", flush=True)
        return event

    def report(self, event: Dict[str, Any]) -> None:
        try:
            headers = {"X-Admin-Key": self.admin_key} if self.admin_key else {}
            requests.post(f"{self.api}/api/gateway/events", json=event, headers=headers, timeout=5)
        except Exception:
            pass                                                         # the portal feed is optional


class Handler:
    def __init__(self, gateway: Gateway):
        self.gateway = gateway

    async def handle_DATA(self, server, session, envelope):
        if len(envelope.original_content) > MAX_MESSAGE_BYTES:
            return "552 5.3.4 Message too large"
        peer_ip = (session.peer or ("unknown", 0))[0]
        loop = asyncio.get_running_loop()
        event = await loop.run_in_executor(None, self.gateway.process, peer_ip, session.host_name or "unknown",
                                           envelope.mail_from, list(envelope.rcpt_tos), envelope.original_content)
        if event["action"] == "quarantine" and self.gateway.reject_spoofed and event["sender_level"] == "spoofed":
            return "550 5.7.1 Rejected by TrustShield: the sender is not authorised to use this domain"
        return f"250 OK queued as {event['id']} ({event['action']})"


def start(api: str, host: str = "127.0.0.1", port: int = 2525, reject_spoofed: bool = False, root: str = ROOT, admin_key: str = ""):
    """Start the gateway in a background thread; returns (controller, gateway). Stop with controller.stop()."""
    gw = Gateway(api, reject_spoofed=reject_spoofed, root=root, admin_key=admin_key)
    controller = Controller(Handler(gw), hostname=host, port=port, data_size_limit=MAX_MESSAGE_BYTES)
    controller.start()
    return controller, gw


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=2525)
    ap.add_argument("--api", default="http://127.0.0.1:8000")
    ap.add_argument("--reject-spoofed", action="store_true", help="refuse forged mail at SMTP time instead of quarantining it")
    ap.add_argument("--admin-key", default=os.environ.get("ADMIN_API_KEY", ""))
    args = ap.parse_args()
    controller, _gw = start(args.api, args.host, args.port, args.reject_spoofed, admin_key=args.admin_key)
    print(f"[gateway] TrustShield mail gateway listening on {args.host}:{args.port} -> analysing through {args.api}", flush=True)
    print(f"[gateway] delivered mail: {os.path.join(ROOT, 'inbox')}   quarantined: {os.path.join(ROOT, 'quarantine')}", flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        controller.stop()


if __name__ == "__main__":
    main()
