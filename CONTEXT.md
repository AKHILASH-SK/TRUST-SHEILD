# TrustShield

Real-time phishing prevention for individuals, and forensic investigation for organizations.

## Language

**Consumer**:
An ordinary phone user who receives links through WhatsApp, SMS and other third-party apps. Served by the mobile app.

**Organization**:
An institution or company that handles a lot of email. Served by the web portal and the browser extension.

**Link**:
Any URL that reaches a person through a message or email, before they open it.

**Verdict**:
The final classification of a **Link** (safe, suspicious or dangerous) with a risk score.

**Notification Interception**:
Catching a **Link** from an incoming notification before the person taps it. Needs the person to grant notification access.

**Link Gate** *(working name)*:
The planned middleware step that catches a **Link** at the moment the person taps it, runs it through the pipeline, and only then lets the browser open it. Covers people who have not granted notification access.

**Email Forensic Case**:
The investigation record built from a received email: header audit, relay hops, sender and infrastructure intelligence, and a sealed evidence report. Meant for **Organizations**.

**Fast-Path Whitelist**:
A list of top-tier, well-known domains whose **Links** skip the sandbox and are judged **safe** immediately, so only new or unknown **Links** pay the cost of deeper analysis.

**Pipeline**:
The ordered checks that produce a **Verdict**: rules, threat database, **Fast-Path Whitelist**, reputation lookup, sandbox detonation, then the ML classifier.

**Own-Risk Override**:
When a **Link** is not safe, the person may still choose to open it. The choice is recorded.

**Detection**:
One **Link** that TrustShield intercepted or gated, together with its **Verdict**, the reasons, and the app it came from.

**Consumer Portal** *(working name)*:
The website where a **Consumer** reviews and searches every **Detection** across all their third-party apps, and audits what was found in each one.

**Organization Console** *(working name)*:
The website where an **Organization's** IT staff check whether a **Link** or email is legitimate and review what their people were exposed to.

**Forensic Workbench** *(working name)*:
The website where investigators trace the origin of an attack and manage cases by case ID. Currently the existing forensic portal.

## Flagged ambiguities

- Whether messages from WhatsApp and similar apps get a forensic case, or only emails do, is still open.
- Whether the Organization Console and the Forensic Workbench are one site with roles or two separate sites is still open.
