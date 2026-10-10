# TrustShield: impersonation, IP rotation and the mail gateway — guide for you and the judges

This is the "backtrack and understand" document. Read sections 1–3 first (story and demo), then 4–6 (how it is built), then 7 (judge questions).

---

## 1. The problem in one paragraph

Attackers win by making something fake look like something you trust: a forged **sender** ("From: your bank"), a fake **page** that relays your login to the real bank
(**adversary-in-the-middle**), a **network** that quietly tampers with what your phone receives, and **infrastructure that keeps moving** (new IP every few minutes).
The jury's picture — "B pretends to have C's IP to talk to A" — is IP/sender **spoofing** and **person-in-the-middle** (MITM, also called on-path or adversary-in-the-middle, MITRE ATT&CK T1557).

What we can honestly do: **catch the impersonation, see the real connecting address, and recognise rotating infrastructure.**
What nobody can do: find the attacker's real location behind VPNs/Tor/hacked machines. We track the *infrastructure they use*, not the person.

## 2. What we built (one line each)

| # | Piece | What it answers | Where |
|---|---|---|---|
| 1 | **Sender impersonation check** | "Is this email pretending to be someone it isn't?" (SPF + DKIM + DMARC + display name + lookalike + forwarding) | `backend/core_engine/sender_impersonation.py` |
| 2 | **Mail gateway (SMTP)** | "TrustShield in the middle, on purpose": sees the **real connecting IP**, judges the mail, delivers / warns / quarantines / rejects | `backend/gateway/smtp_gateway.py` |
| 3 | **IP-rotation detector** | "Same claimed sender arriving from many unauthorised addresses" | `backend/gateway/rotation.py` |
| 4 | **Fast-flux detector** | "This domain keeps changing the addresses it points to" | `backend/core_engine/fast_flux.py` |
| 5 | **Certificate inspector** | "Is the padlock real, whose is it, how old?" | `backend/core_engine/tls_inspector.py` |
| 6 | **Relay-page detection** | A pixel-perfect copy of a real bank on another domain | existing sandbox brand check + lab scene |
| 7 | **Network safety check (phone)** | "Is this Wi-Fi tampering with my traffic?" (DNS, certificates, rewritten pages) | `app/.../network/NetworkIntegrity.kt`, Security & Privacy screen |
| 8 | **Sealing with SHA-256** | "Nothing was changed after analysis" | existing `evidence_seal` + vault, used by the gateway |
| 9 | **Lab + demo** | A safe, local simulation of all of the above | `backend/lab/` |
| 10 | **Portal** | "Attacker infrastructure" card, **Mail Gateway** tab (live) | `frontend/` |

Also fixed on the way (real security issue): the connecting IP is now taken from the address **the receiving server recorded in brackets**, never from text the sender wrote in
the HELO name. Before, an attacker could plant a fake IP there.

## 3. Run the demo (one command)

```
cd backend
powershell -ExecutionPolicy Bypass -File lab\run_demo.ps1          # add -Pause to wait for Enter between scenes
```
It opens the **lab backend** (port 8000) and the **mail gateway** (port 2525) in two windows and plays six scenes. Open `http://localhost:8000/portal/` → **Mail Gateway** tab to watch live.
Afterwards close those two windows and start the normal backend (`python app.py`). **Lab mode treats private addresses as real senders — never use it for normal scanning.**

| Scene | What happens | What to say |
|---|---|---|
| 1 | Real bank mail from 127.0.0.2: SPF pass, DKIM pass, DMARC pass → **delivered** | "We must not flag the real thing." |
| 2 | Attacker mail claiming the bank from 127.0.0.3: SPF/DKIM/DMARC fail, bank's own policy says *reject* → **forged sender, quarantined**, real IP named | "Because the mail connects to us directly, we see the true address." |
| 3 | Same forgery from 5 more addresses → **IP rotation detected** | "Blocking one IP is pointless. We notice one claimed sender from many unauthorised addresses and block the pattern." |
| 4 | `flux.bank-verify.test` changes address every question (TTL 30 s) → **fast-flux**; `steady.shop.test` → normal | "We watch the domain's behaviour, not one IP." |
| 5 | A relay copy of the bank's login on another domain → **Dangerous**; the real bank → **Safe** | "Looks identical. The domain is the tell." |
| 6 | SHA-256 of the email vs one letter changed; vault lookup → **SEAL VALID** | "Evidence can't be changed silently." |

Portal extras: upload `backend/lab/samples/2_forged_bank_email.eml` on the dashboard → Email Analysis tab shows the **"Who is pretending to be whom"** card and the **"Attacker infrastructure"** card.

## 4. How it works (follow the code)

> **Important (changed after the first real-email test):** the sender-impersonation check and its portal card were removed from the normal SOC portal, because they could flag genuine emails (for example a real BookMyShow mail whose Reply-To uses the parent domain). The check now runs **only in demo mode** (the lab demo and the mail gateway); real emails are scored exactly as before. Demo mode switches itself off after 10 minutes and must not be left on during real analysis.

### 4.1 Sender impersonation (`sender_impersonation.py`)
Input: what `email_forensics.parse_email_file` already computed (SPF/DKIM/DMARC states, connecting IP) + a few headers.
Output `level`:
- **spoofed** — DMARC fails **and** (the domain's own policy is *reject/quarantine*, **or** every check failed while a known brand is claimed), and the mail does not look forwarded.
- **suspicious** — failed checks without proof, a brand in the *display name* from an unrelated domain, a lookalike domain (`paypal-secure-login.com`), reply-to redirected, or forwarded mail that fails.
- **authentic** — DMARC passes (aligned), or SPF **and** DKIM pass.
- **unverifiable** — DNS trouble or no published policy. **We say so; we never guess.**

False-positive guards: forwarded mail / mailing lists (ARC, List-Id, Resent-…) are never called "forged"; a person called "Apple Johnson" is not a brand (the display name must be the brand + generic words such as "Security Team").
Score: a forged sender whose domain says *reject* adds 80 (critical); weaker forms add less. Mail with failed checks is never labelled "authenticated".

### 4.2 The mail gateway (`smtp_gateway.py`)
1. A sender connects to port 2525. `aiosmtpd` gives us the **peer address** — the real connecting IP.
2. We write our own `Received: from <helo> ([<real ip>]) by trustshield-gateway` header (the one the sender cannot forge).
3. The message goes to the backend `/api/forensics/analyze-eml` (full analysis, sealed case).
4. Decision: forged → **quarantine** (or **reject at SMTP time** with `--reject-spoofed`); suspicious → **deliver with warning headers**; else deliver. Headers added: `X-TrustShield-Verdict / Sender-Check / Connecting-IP / Case / Evidence-SHA256 / IP-Rotation`.
5. If analysis is down, mail is delivered with a notice — **never silently dropped**.
6. Header values are stripped of line breaks (header-injection guard).
Real deployment: public IP, MX record pointing at it, TLS, port 25 open (a cheap VPS; **no AWS needed**).

### 4.3 IP rotation (`rotation.py`)
Counts **distinct failing addresses per claimed domain in a 10-minute window** (3 or more = rotation). Only messages whose sender checks failed count, so a real sender's own addresses never trigger it.

### 4.4 Fast-flux (`fast_flux.py`)
Ask DNS the same question 4 times and look at: distinct IPs (≥5), TTL (≤300 s), spread over unrelated /16 networks (≥3), and whether the set changed. **All together** = fast-flux; two of three = "possible".
CDNs (many IPs but long TTL, same set) are not flagged; trusted domains/hosting platforms are never examined. It is an **indicator**, never a conviction (worth +15 on an email, only on top of other findings).
The lab DNS server (`lab/fastflux_dns.py`, UDP on 127.0.0.1:5353) plays the attacker's rotating DNS (this is where UDP appears: DNS is UDP, mail is TCP).

### 4.4b Certificate check (`tls_inspector.py`)
One handshake to read the certificate *without trusting it*, one to ask "would a normal browser trust this chain?". Flags: self-signed, expired, wrong name, untrusted chain, brand-new. A new free certificate alone proves nothing — it only adds weight with other evidence.

### 4.5 Network safety check on the phone (`NetworkIntegrity.kt`)
Android won't let an app read the ARP table, so we detect the **effects**: (1) DNS answer for google.com/wikipedia.org/cloudflare.com pointing to a private address while trusted DNS-over-HTTPS says public;
(2) certificate rejected, or issued by a non-public authority (a warning: workplace proxies do this too); (3) the connectivity-check page (`generate_204`) comes back changed (fake sign-in/redirect).
The worst finding sets the headline (Safe / Warning / Danger / Could not check). The decision logic is pure Kotlin with unit tests.

### 4.6 SHA-256 / sealing
Each analysed email gets `evidence_sha256` (fingerprint of the original bytes). The case is sealed with a keyed signature (HMAC with the server secret); `/api/forensics/verify-hash` re-checks it (`SEAL VALID` / `TAMPERED`).

### 4.7 Who sends, who receives, and where is the sender? (the gateway in plain words)
- **Who sends:** any mail server (or a script) that wants to deliver a message. In the demo it is a small Python script posing as the bank's server (127.0.0.2) or the attacker (127.0.0.3 ...).
- **To whom:** the person named in the envelope (`RCPT TO`), e.g. `victim@example.test`. In real life the recipient's domain publishes an **MX record** ("deliver my mail to this server"). If that MX points at TrustShield, every sender's server connects to us first.
- **What we do with it:** judge it, then **deliver** (to `gateway/mailbox/inbox`), **warn**, or **quarantine** (`gateway/mailbox/quarantine`). *Today the "inbox" is a folder. Forwarding onward to the user's real mailbox server is the next step for a real deployment and is not built.*
- **Where is the sender?** The gateway sees the **real connecting IP**. We look that IP up (existing geolocation: ipwho.is / ip-api) and show **city, country, network name, and a "hosting/VPS" or "proxy/VPN" flag**.
  It appears in the gateway console line, in the Mail Gateway tab (a **Location** column and a **world map**), in the `X-TrustShield-Location` header, and in the portal's **Geolocation** tab for an uploaded email.
- **Important:** that location is the **sending server**, not the person. If the sender used **Gmail**, the connecting IP is Google's data centre (Gmail does not reveal the user's own IP). If the attacker runs their **own SMTP server**, or a cheap VPS, you see *that* machine. If they use a VPN/Tor/hacked machine, you see that. City accuracy is approximate.
- **In the lab**, the 127.0.0.x addresses have **simulated** locations (Mumbai = the bank, Bucharest/Lagos/Sao Paulo/Jakarta/Frankfurt/Singapore = the attacker's rotating servers), clearly labelled "(simulated)".

### 4.8 Offline mode: the model on the phone
When the phone cannot reach the TrustShield server (no internet), the Link Gate and the notification alerts no longer fall back to guesswork. They run **the same link-text model the server uses, on the phone**:
- The 350-tree LightGBM model, its calibration table and thresholds are exported by `python -m ml.export_for_android` into `app/src/main/assets/ondevice/` (about 1.3 MB) and evaluated by small Kotlin code (`app/.../ondevice/`). No internet and no cloud call is involved.
- It only judges the **text of the link** (28 host features). The page model needs the sandbox browser, so it cannot run offline, and every offline answer says *"Checked on this phone only; the page was not inspected"*.
- **Proof it is identical to the server's model:** `LexicalParityTest` feeds ~1,000 links (phishing feeds, popular sites, hosted projects, and awkward cases such as IPs, ports, punycode, `.com.mu`) through both the Python and the Kotlin code and demands identical features and probabilities.
- **Cut-offs (measured on 3,000 phishing and 3,000 legitimate links the model had never seen):** score >= 0.9892 -> **Dangerous** (48% of phishing, 0.0% of legitimate sites; but on free hosting like vercel.app or blogspot it is only *Unverified*, the hosting lesson); score >= 0.5 -> **Unverified** (75% of phishing, 3.3% of legitimate); below that -> **"Looks normal"** (never a clean *Safe*, because about a quarter of phishing links look ordinary from the text alone).
- Tested on a real phone with mobile data off and the backend stopped: phishing-looking links (paypal-secure-login.top, hdfc-netbanking-verify.xyz, amazon-prize-claim.click, login-microsoft-account.cfd) were **Dangerous**; the fake Roblox links and the hosted Facebook look-alike were **Unverified**; ordinary sites and Google/GitHub links **looked normal**.
- After retraining the server's models, run `python -m ml.export_for_android` again, then `.\gradlew testDebugUnitTest --tests "com.example.trustshield.LexicalParityTest"` to confirm the phone still matches.

## 5. Files added/changed

```
backend/core_engine/sender_impersonation.py   who is pretending to be whom
backend/core_engine/fast_flux.py              rotating DNS detector
backend/core_engine/tls_inspector.py          certificate inspector
backend/core_engine/infrastructure.py         runs fast-flux + certificate for an email's links (time-boxed)
backend/core_engine/email_forensics.py        connecting IP fix + lab hooks (DNS_OVERRIDE, LAB_MODE)
backend/core_engine/unified_email_pipeline.py  sender_assessment + infrastructure in the email result and score
backend/gateway/{smtp_gateway,rotation}.py    the SMTP gateway
backend/app.py                                /api/gateway/events (lab/admin), /api/infra/check, lab start-up
backend/lab/{mail_lab,fastflux_dns,scenes,make_samples}.py, run_demo.ps1   the safe lab
frontend/{index.html,app.js}                  portal cards + Mail Gateway tab
app/.../network/NetworkIntegrity.kt, activities/SecurityPrivacyActivity.kt, layout activity_network_check.xml
tests: test_sender_impersonation, test_fast_flux, test_tls_inspector, test_mail_gateway, NetworkIntegrityTest.kt
```
Whole backend suite: 427 passed. Android unit tests for the network check pass.

## 6. Honest limits (say these before they ask)
- The lab uses **made-up DNS records** for `bank.test` and `127.0.0.x` sender addresses. The checking code is the real production code; in real life it reads real DNS records and real connection addresses.
- Real DKIM/DMARC alignment needs a real domain; forwarded mail can fail SPF legitimately — we lower the verdict instead of convicting.
- Fast-flux needs several lookups and is an indicator. We cannot identify the attacker's person or true location.
- The phone check sees effects, not ARP packets. A workplace proxy shows as a **warning**, not an attack.
- The mail gateway is demonstrated on a laptop; production needs a public IP, MX record, TLS and port 25.
- The Mail Gateway tab is available in lab mode or with the admin key.

## 7. Questions the jury may ask — short answers

**What is a person-in-the-middle (MITM)?** An attacker secretly relays (and may change) communication between two parties who think they talk directly. Also called on-path or adversary-in-the-middle.

**How can B "use C's IP"?** Two ways. On the *same network*, **ARP spoofing**: B tells A "C's IP address is mine", so A sends C's traffic to B. And **IP spoofing**: forging the source address in packets — easy for one-way floods, hard for real conversations (replies go to the real owner). In **email** nothing checks the From address, so B can simply claim to be C.

**How do you stop it?** By layer: email → SPF/DKIM/DMARC + our gateway; web → brand-on-wrong-domain + certificate checks; network → DNS/certificate/page-tampering checks on the phone; moving infrastructure → fast-flux and IP-rotation detection.

**Can you find the attacker's IP?** We see the IP that **connected to us** (real, because the gateway is the receiver). The attacker may use a VPN, Tor or hacked machines, so that is *infrastructure*, not the person. We block the **pattern**.

**SPF / DKIM / DMARC?** SPF: the domain publishes which IPs may send for it. DKIM: the sending server signs the mail with a private key; anyone checks it with the public key in DNS. DMARC: the domain says what to do when those fail and requires the checked domain to match the visible From.

**Do you need AWS?** No. Any server with a public IP, a domain with an MX record pointing to it, TLS and port 25. Home ISPs and AWS block port 25 by default.

**SMTP: TCP or UDP?** TCP (port 25 between servers, 587/465 for users). UDP is used by DNS and QUIC.

**What is a hash? SHA-256 vs SHA-512?** A fixed-size fingerprint of any data; change one letter and it is completely different; it cannot be reversed. SHA-256 gives 256 bits, SHA-512 gives 512 bits (a bit faster on 64-bit CPUs); both are strong. We use SHA-256 to fingerprint evidence.

**Hash vs encryption vs signature?** Hash = fingerprint (one-way). Encryption = reversible with a key (HTTPS/TLS). Signature/HMAC = proves who produced something and that it is unchanged (our case seal is an HMAC with the server's secret key; DKIM uses RSA + SHA-256).

**Passwords?** Never plain SHA. We use **bcrypt** (deliberately slow, salted) for PINs.

**Why not convict on one signal?** Forwarding, new certificates, CDNs and workplace proxies all look "odd". Every detector can only *add weight* to concrete evidence, and "cannot verify" is an allowed answer.
