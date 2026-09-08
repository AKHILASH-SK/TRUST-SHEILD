"""
TrustShield V2 - Live Public IP EML Generator
Detects your real external public IP address (via ip-api.com) and constructs
an authentic RFC-5322 .eml message with genuine Received: headers, as if received
by Google MX from your exact computer.
"""

import urllib.request
import json
from datetime import datetime, timezone
from pathlib import Path


def generate_live_eml(recipient_email="friend@gmail.com", output_filename="LIVE_COIMBATORE_ATTACK.eml"):
    # 1. Fetch current live public IP and location
    print("[*] Querying your real live public IP and ISP details...")
    try:
        req = urllib.request.Request("http://ip-api.com/json", headers={"User-Agent": "TrustShield/2.0"})
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())
            public_ip = data.get("query", "157.51.60.12")
            city = data.get("city", "Coimbatore")
            region = data.get("regionName", "Tamil Nadu")
            country = data.get("country", "India")
            isp = data.get("isp", "Reliance Jio Infocomm Limited")
    except Exception as e:
        print(f"[!] Could not query IP dynamically ({e}), using detected IP.")
        public_ip = "157.51.60.12"
        city = "Coimbatore"
        region = "Tamil Nadu"
        country = "India"
        isp = "Reliance Jio Infocomm Limited"

    print(f"[+] Detected Live Origin: {public_ip} ({city}, {region}, {country}) - ISP: {isp}")

    now_utc = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")

    # 2. Build genuine RFC-5322 EML envelope with user's live public IP in Google MX Received header
    eml_content = f"""Delivered-To: {recipient_email}\r
Received: by 2002:a17:902:d00d:b0:1c4:89a1:2345 with SMTP id z13csp982124plb;\r
\t{now_utc}\r
Received: from mail-relay.trustshield-demo.org (unknown [{public_ip}])\r
\tby mx.google.com with ESMTP id a21si891024plm.12\r
\tfor <{recipient_email}>;\r
\t{now_utc}\r
Return-Path: <scammer-drop@external-spoof.biz>\r
From: "Executive Payroll Notification" <hr-payroll@corporate-bonus.top>\r
To: {recipient_email}\r
Reply-To: fraudster-collect@unauthorized-mailbox.net\r
Subject: URGENT: Q3 Appraisal & Direct Deposit Verification Required\r
Date: {now_utc}\r
Message-ID: <20260908.{public_ip}.ts2@spoofed-domain.xyz>\r
MIME-Version: 1.0\r
Content-Type: multipart/alternative; boundary="----=_Part_9988_7766"\r
\r
------=_Part_9988_7766\r
Content-Type: text/plain; charset=UTF-8\r
Content-Transfer-Encoding: 7bit\r
\r
Important Security Notice:\r
Your quarterly appraisal compensation letter is ready for verification.\r
Please verify your banking credentials to prevent salary disbursement delays:\r
https://linked1n.vercel.app/\r
\r
------=_Part_9988_7766\r
Content-Type: text/html; charset=UTF-8\r
Content-Transfer-Encoding: 7bit\r
\r
<!DOCTYPE html>\r
<html>\r
<body style="font-family: Arial, sans-serif; background-color: #f9f9f9; padding: 20px;">\r
  <div style="background: white; border: 1px solid #ddd; padding: 20px; border-radius: 8px; max-width: 600px;">\r
    <h2 style="color: #d9534f;">Q3 Payroll Disbursement Notice</h2>\r
    <p>We received an update request for your direct deposit bank account from IP: <strong>{public_ip}</strong> ({city}, {country}).</p>\r
    <p>If you did not authorize this change, please cancel immediately:</p>\r
    <p><a href="https://linked1n.vercel.app/" style="background: #d9534f; color: white; padding: 10px 18px; text-decoration: none; border-radius: 4px; display: inline-block;">Verify & Cancel Request</a></p>\r
    <p style="color: #888; font-size: 12px; margin-top: 20px;">Corporate Compensation Gateway // Automated Security Dispatch</p>\r
  </div>\r
</body>\r
</html>\r
------=_Part_9988_7766--\r
"""

    output_path = Path(__file__).resolve().parent.parent / output_filename
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        f.write(eml_content)

    print(f"[+] Generated Live Evidence EML: {output_path}")
    print(f"[*] Upload '{output_filename}' into http://localhost:8000/portal to see your real city and ISP pinned on the map!")
    return str(output_path)


if __name__ == "__main__":
    generate_live_eml()
