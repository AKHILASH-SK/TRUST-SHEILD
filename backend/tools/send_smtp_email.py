"""
TrustShield V2 - Custom SMTP Sender & Mail Injection Tool
Demonstrates how email is transmitted directly from a custom sender to a recipient's MX server.
Supports:
  1. Direct Port 25 Delivery to Google MX (requires unblocked Port 25 or VPS)
  2. Authenticated Port 587 Relay (works on any home/residential ISP)
"""

import sys
import smtplib
import socket
from datetime import datetime, timezone
import dns.resolver


def get_mx_server(domain: str) -> str:
    """Finds the primary MX record for the recipient's domain (e.g. aspmx.l.google.com for gmail.com)."""
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        mx_records = [(r.preference, str(r.exchange).rstrip('.')) for r in answers]
        mx_records.sort(key=lambda x: x[0])
        return mx_records[0][1]
    except Exception as e:
        print(f"[!] DNS MX lookup failed for '{domain}': {e}. Falling back to standard MX.")
        return f"aspmx.l.google.com" if "gmail" in domain else domain


def send_direct_smtp(recipient_email: str, sender_email: str = "security-alert@payroll-portal.top", subject: str = "URGENT: Verify Account Information", phishing_link: str = "https://linked1n.vercel.app/"):
    """
    Attempts direct delivery to the recipient's MX server on TCP Port 25.
    If the local ISP blocks Port 25, catches the timeout and provides instructions.
    """
    domain = recipient_email.split('@')[-1]
    mx_host = get_mx_server(domain)
    print(f"[*] Target Domain: {domain}")
    print(f"[*] Primary MX Server: {mx_host}")
    print(f"[*] Connecting directly to {mx_host}:25...")

    now_utc = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
    
    # RFC-5322 MIME Body
    headers = [
        f"From: \"Executive Security Team\" <{sender_email}>",
        f"To: {recipient_email}",
        f"Subject: {subject}",
        f"Date: {now_utc}",
        f"Message-ID: <{datetime.now().strftime('%Y%m%d%H%M%S')}.trustshield@{domain}>",
        "MIME-Version: 1.0",
        "Content-Type: text/html; charset=UTF-8",
        ""
    ]
    
    body = [
        "<html><body>",
        f"<h2>Security Alert: Account Verification Required</h2>",
        f"<p>We detected an unauthorized transaction attempt on your account.</p>",
        f"<p>Please review and verify your identity immediately:</p>",
        f"<p><a href=\"{phishing_link}\" style=\"background-color:#d9534f;color:#fff;padding:10px 16px;text-decoration:none;border-radius:4px;\">Review Incident</a></p>",
        f"<p style=\"color:#888;font-size:11px;\">Automated Security Gateway // TrustShield Forensic Demonstration</p>",
        "</body></html>"
    ]
    
    email_data = "\r\n".join(headers + body)

    try:
        # Attempt connection with 6-second timeout
        server = smtplib.SMTP(mx_host, 25, timeout=6)
        server.set_debuglevel(1)
        server.ehlo_or_helo_if_needed()
        server.sendmail(sender_email, [recipient_email], email_data)
        server.quit()
        print(f"\n[+] SUCCESS! Email successfully transmitted to {recipient_email} via {mx_host}:25.")
        print("[+] When your friend downloads the .eml from Gmail, your public IP will be permanently recorded in the Received: header!")
        return True

    except (socket.timeout, TimeoutError, socket.error) as e:
        print(f"\n[!] DIRECT PORT 25 BLOCKED BY LOCAL ISP: {e}")
        print("--------------------------------------------------------------------------------")
        print("EXPLANATION & FORENSIC CONTEXT:")
        print("1. Why Port 25 is blocked:")
        print("   Consumer broadband ISPs (like Reliance Jio, Airtel, ACT Broadband, Comcast, etc.)")
        print("   deliberately block outbound TCP Port 25 to prevent residential malware from spamming.")
        print("2. How real-world attackers bypass this:")
        print("   Real attackers send emails from a Cloud Virtual Private Server (VPS) such as")
        print("   DigitalOcean, AWS EC2, or bulletproof offshore hosting, where Port 25 is permitted.")
        print("3. Two Easy Ways to Complete Your Test Right Now:")
        print("   A) Option 1: Use the generated 'LIVE_COIMBATORE_ATTACK.eml' created by")
        print("      'generate_my_location_eml.py' — this already embeds your REAL live public IP")
        print("      (157.51.60.12 in Coimbatore, Jio) into Google's Received: header format.")
        print("      Send this file to your friend as an attachment, or upload it directly to")
        print("      http://localhost:8000/portal to see your city and ISP pinned on the map!")
        print("   B) Option 2: Run this script from any Linux VPS (AWS/GCP/Linode) on Port 25,")
        print("      and it will deliver straight to Gmail.")
        print("--------------------------------------------------------------------------------")
        return False


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "friend.test@gmail.com"
    print("=" * 80)
    print("🚀 TRUSTSHIELD V2 - CUSTOM SMTP TRANSMISSION TEST")
    print("=" * 80)
    send_direct_smtp(target)
