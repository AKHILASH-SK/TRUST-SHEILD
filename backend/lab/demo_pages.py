"""
Viewable pages for the demo, so the judges can SEE what the victim sees (and why it fools people):

    bank          the real bank's login page (mock browser window, address bar shows the real domain)
    relay         a copy that looks identical but sits on another domain (this is the adversary-in-the-middle page)
    mail-genuine  the genuine email as an inbox would show it
    mail-forged   the forged email: it looks the same as the genuine one; only the message source shows the real sender address

Everything here is simulated and self-contained (no scripts, no external files, forms go nowhere). The portal shows them in frames next
to TrustShield's verdict. The backend serves them only while demo mode is on or has been used (see /demo/page/<name> in app.py).
"""
from html import escape

PAGES = ("bank", "relay", "mail-genuine", "mail-forged")

_STYLE = """
*{box-sizing:border-box}body{margin:0;font-family:Segoe UI,Arial,sans-serif;background:#eef1f6;color:#0f172a}
.win{margin:10px;border:1px solid #cbd5e1;border-radius:10px;overflow:hidden;background:#fff;box-shadow:0 2px 10px rgba(15,23,42,.08)}
.bar{display:flex;align-items:center;gap:8px;padding:8px 10px;background:#f1f5f9;border-bottom:1px solid #e2e8f0}
.dots span{display:inline-block;width:9px;height:9px;border-radius:50%;background:#cbd5e1;margin-right:3px}
.url{flex:1;background:#fff;border:1px solid #cbd5e1;border-radius:14px;padding:4px 12px;font:12px Consolas,monospace;color:#334155;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.url b{color:#15803d}
.sim{padding:5px 12px;background:#fef3c7;color:#92400e;font-size:11px;border-bottom:1px solid #fde68a}
.bank{padding:22px 26px}.logo{font-weight:800;font-size:22px;color:#004c8f}.logo i{color:#e11d48;font-style:normal}
h2{margin:14px 0 4px;font-size:18px}p{margin:4px 0;color:#475569;font-size:13px}
label{display:block;margin-top:12px;font-size:12px;color:#475569}
.in{margin-top:4px;height:34px;border:1px solid #cbd5e1;border-radius:6px;background:#f8fafc;padding:8px 10px;font-size:13px;color:#94a3b8}
.btn{margin-top:16px;display:inline-block;background:#004c8f;color:#fff;padding:9px 26px;border-radius:6px;font-weight:600;font-size:14px}
.mail{padding:16px 20px;font-size:13px}.mh{border-bottom:1px solid #e2e8f0;padding-bottom:10px;margin-bottom:12px}
.mh div{margin:2px 0;color:#475569}.mh b{color:#0f172a;display:inline-block;width:62px}
.lnk{display:inline-block;margin-top:10px;background:#1d4ed8;color:#fff;padding:8px 18px;border-radius:6px;font-size:13px}
.src{margin-top:16px;border:1px dashed #94a3b8;border-radius:8px;background:#f8fafc;padding:8px 10px;font:11px Consolas,monospace;color:#334155;word-break:break-all}
.src h4{margin:0 0 4px;font:600 11px Segoe UI,Arial;color:#64748b;text-transform:uppercase}
.warn{color:#b91c1c;font-weight:700}.ok{color:#15803d;font-weight:700}
"""


def _page(body: str, title: str) -> str:
    return (f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width'>"
            f"<title>{escape(title)}</title><style>{_STYLE}</style></head><body>{body}</body></html>")


def _window(url_html: str, content: str, note: str = "") -> str:
    return (f"<div class='win'><div class='bar'><span class='dots'><span></span><span></span><span></span></span>"
            f"<div class='url'>{url_html}</div></div><div class='sim'>DEMO PAGE (simulated): {escape(note)}</div>{content}</div>")


def _bank_login() -> str:
    return ("<div class='bank'><div class='logo'>HDFC <i>BANK</i></div><h2>NetBanking Login</h2>"
            "<p>Welcome back. Please sign in to continue.</p>"
            "<label>Customer ID<div class='in'>Customer ID</div></label>"
            "<label>Password<div class='in'>&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;</div></label>"
            "<div class='btn'>Login</div></div>")


def bank_page() -> str:
    url = "<b>&#128274;</b> https://netbanking.<b>hdfcbank.com</b>/login"
    return _page(_window(url, _bank_login(), "the real bank's address"), "Real bank")


def relay_page() -> str:
    # word for word the same content; only the address is different (and a relay forwards what you type to the real bank)
    url = "<b>&#128274;</b> https://<span class='warn'>hdfcbank-secure-login.com</span>/login"
    return _page(_window(url, _bank_login(), "a relay copy on another domain"), "Relay page")


def _mail(sender_ip: str, sender_place: str, authentic: bool) -> str:
    verdict = ("<span class='ok'>SPF pass, DKIM pass, DMARC pass</span>" if authentic
               else "<span class='warn'>SPF fail, DKIM fail, DMARC fail (the bank's policy says reject)</span>")
    header = ("<div class='mh'><div><b>From</b>Bank Security &lt;alerts@bank.test&gt;</div><div><b>To</b>victim@example.test</div>"
              "<div><b>Subject</b>Your account: action required</div></div>")
    body = ("<p>Dear customer, we noticed unusual activity on your account. Please verify your details to keep your account active.</p>"
            "<div class='lnk'>Verify my account</div>")
    source = (f"<div class='src'><h4>Message source (what the receiving server recorded)</h4>"
              f"Received: from host ([{escape(sender_ip)}]) by trustshield-gateway<br>"
              f"Connecting address: <b>{escape(sender_ip)}</b> &middot; {escape(sender_place)}<br>Sender checks: {verdict}</div>")
    return f"<div class='mail'>{header}{body}{source}</div>"


def mail_page(authentic: bool) -> str:
    content = (_mail("127.0.0.2", "Mumbai, India (the bank's own server)", True) if authentic
               else _mail("127.0.0.3", "Bucharest, Romania (cheap VPS hosting)", False))
    bar = "<b>&#9993;</b> Inbox &rsaquo; " + ("Bank Security (genuine)" if authentic else "Bank Security (forged)")
    return _page(_window(bar, content, "the same email looks identical either way; only the source differs"),
                 "Genuine email" if authentic else "Forged email")


def render(name: str):
    if name == "bank":
        return bank_page()
    if name == "relay":
        return relay_page()
    if name == "mail-genuine":
        return mail_page(True)
    if name == "mail-forged":
        return mail_page(False)
    return None
