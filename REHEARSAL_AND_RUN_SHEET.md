# TrustShield — run sheet (copy-paste, no experience needed)

Everything below is safe: none of these steps changes code or data. If anything looks wrong, stop and note the red text.

## A. Is everything healthy? (1 minute)

Open **PowerShell** and paste:

```
cd C:\Users\akhil\AndroidStudioProjects\TrustShield\backend
powershell -ExecutionPolicy Bypass -File tools\run_all_checks.ps1 -Quick
```

You should end with a green **ALL CHECKS PASSED**. (Without `-Quick` it takes about 5 minutes and tests everything.)
Red **FAILED** = scroll up, find the line with `FAILED` or `FAIL`, and send it to Akhilash.
*Run it before the demo, not in the middle of it (it keeps the machine busy for about a minute).*

## B. Start the normal backend

```
cd C:\Users\akhil\AndroidStudioProjects\TrustShield\backend
python app.py
```
Leave that window open. Wait about 40 seconds. Open `http://localhost:8000/api/health` in a browser: it should say OK.
The SOC portal is at `http://localhost:8000/portal/`.

## C. The impersonation demo (the "man in the middle" story, about 3 minutes)

**The backend is never restarted or closed by the demo.** Keep it running from section B (so you can show the SOC portal first), then:
```
cd C:\Users\akhil\AndroidStudioProjects\TrustShield\backend
powershell -ExecutionPolicy Bypass -File lab\run_demo.ps1 -Pause
```
- If the backend is already running, the demo uses it as it is. If it isn't running, the demo starts it in its own window and leaves it open.
- The mail gateway is started in its own window only if it isn't running already. Then six scenes play in this window; press **Enter** for the next one.
- The demo switches the running backend into *demo mode* for 30 minutes (simulated bank, rotating DNS, 127.0.0.x senders). It switches itself off again. To switch it off at once: `python -m lab.scenes --off`.
- Open `http://localhost:8000/portal/`, click **Mail Gateway**. The four pages (real bank, relay copy, genuine and forged email) are at the top **before scene 1 starts**, with each verdict showing "not checked yet"; the badges fill in as the scenes run, and **the results stay on screen afterwards**. If you opened the portal before an update, it reloads itself on this tab (or press Ctrl+F5).
- With `-Pause`, the first Enter is "Before we start": use it to explain the four pages ("they look identical to the victim") before any scene runs.
- *One-time note:* if the backend window was opened BEFORE the latest update, close that window once and start it again (`python app.py`). After that you never need to restart it for the demo.
- To show the lab emails in Email Analysis, upload the files from `backend\lab\samples` within the 30 minutes after the demo.

| Scene | What you see | One sentence to say |
|---|---|---|
| 1 | Real bank mail, green, DELIVER | "The real bank passes: we don't cry wolf." |
| 2 | Forged mail, red, QUARANTINE, the attacker's real address and location | "Because mail comes straight to our gateway, we see who really connected." |
| 3 | Five more addresses, red banner "IP ROTATION DETECTED" | "The attacker keeps switching IP, so we block the pattern, not one address." |
| 4 | `flux...` = FAST_FLUX, `steady...` = NORMAL | "A normal site gives the same answer; theirs changes every few seconds." |
| 5 | Fake bank page = DANGEROUS, real bank = SAFE | "Looks identical. The address is the tell." |
| 6 | Two long codes, then SEAL VALID | "Change one letter and the fingerprint changes. Evidence can't be edited silently." |

In the portal, upload `backend\lab\samples\2_forged_bank_email.eml` (dashboard → **Browse .eml**), then open **Email Analysis** (cards: *Who is pretending to be whom*, *Attacker infrastructure*) and **Geolocation** (a map pin in Romania).

## D. The phone

1. Phone on the same Wi-Fi/hotspot as the laptop, and the app pointing at the laptop's current IP (ask Akhil if links fail to scan).
2. Tap a normal link in WhatsApp: the Link Gate scans it. A Google Doc or Sheet link should say **Safe** at once.
3. In the app: **Profile → Security & Privacy → Check this network**. On ordinary Wi-Fi it should show green ("No sign of tampering").

## E. If something goes wrong

| Problem | What to do |
|---|---|
| Portal shows nothing / "OFFLINE" | The backend isn't running: section B. |
| Mail Gateway tab says "LAB ONLY" | You started the normal backend. That tab works only in the demo (section C). |
| Demo says port already in use | Close all python/PowerShell windows from earlier, then run section C again. |
| A scan takes long | Normal: a brand-new link takes 7–20 seconds the first time; the same link a second time is about 1 second. |
| App can't reach the laptop | The laptop's IP changed (hotspot). Tell Akhil; the app needs the new address. |
| The map is grey | Wait a few seconds or refresh (Ctrl+F5); it needs internet for the map tiles. |

## F. Three honest sentences if the judges push

- "We find the **sending server's** IP and location, not the person: VPNs, Tor and Gmail hide that."
- "The lab uses made-up DNS and simulated locations; the checking code is the real code."
- "When we can't be sure, we say **Unverified** instead of accusing a legitimate site."

More detail: `IMPERSONATION_AND_GATEWAY_GUIDE.md` (same folder).
