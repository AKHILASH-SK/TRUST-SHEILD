/**
 * TrustShield - Real-Time Endpoint In-Page Webmail Guard (content.js)
 * Automatically extracts email context and injects a floating shield HUD into Gmail / Outlook.
 */

const BACKEND_LOCAL_URL = "http://127.0.0.1:8000/api/extension/analyze";
const BACKEND_CLOUD_URL = "https://trust-sheild.onrender.com/api/extension/analyze";
const PORTAL_LOCAL_URL = "http://127.0.0.1:8000/portal/";
const PORTAL_CLOUD_URL = "https://trust-sheild.onrender.com/portal/";

function extractEmailData() {
  let subject = "";
  let sender = "";
  let body = "";
  let links = [];

  try {
    // 1. Gmail Extraction
    const gmailSubject = document.querySelector('h2.hP');
    if (gmailSubject) subject = gmailSubject.innerText.trim();

    const gmailSender = document.querySelector('.gD');
    if (gmailSender) {
      sender = gmailSender.getAttribute('email') || gmailSender.innerText.trim();
    }

    const gmailBody = document.querySelector('.a3s.aiL') || document.querySelector('.nH.hx');
    if (gmailBody) {
      body = gmailBody.innerText.trim();
      const anchorTags = gmailBody.querySelectorAll('a[href]');
      anchorTags.forEach(a => {
        const h = a.href || a.getAttribute('href');
        if (h && (h.startsWith('http://') || h.startsWith('https://'))) {
          links.push(h.trim());
        }
      });
    }

    // 2. Outlook / Microsoft 365 Web Extraction
    if (!body) {
      const outlookSubject = document.querySelector('[role="heading"][aria-level="2"]') || document.querySelector('.Q35U3');
      if (outlookSubject) subject = outlookSubject.innerText.trim();

      const outlookSender = document.querySelector('span[title*="@"]') || document.querySelector('.L7_bB');
      if (outlookSender) {
        sender = outlookSender.getAttribute('title') || outlookSender.innerText.trim();
      }

      const outlookBody = document.querySelector('[aria-label="Message body"]') || document.querySelector('.allowTextSelection');
      if (outlookBody) {
        body = outlookBody.innerText.trim();
        const anchorTags = outlookBody.querySelectorAll('a[href]');
        anchorTags.forEach(a => {
          const h = a.href || a.getAttribute('href');
          if (h && (h.startsWith('http://') || h.startsWith('https://'))) {
            links.push(h.trim());
          }
        });
      }
    }

    // 3. Yahoo Mail Extraction
    if (!body) {
      const yahooSubject = document.querySelector('[data-test-id="message-view-subject"]');
      if (yahooSubject) subject = yahooSubject.innerText.trim();

      const yahooSender = document.querySelector('[data-test-id="message-sender"]');
      if (yahooSender) sender = yahooSender.innerText.trim();

      const yahooBody = document.querySelector('.msg-body');
      if (yahooBody) {
        body = yahooBody.innerText.trim();
        const anchorTags = yahooBody.querySelectorAll('a[href]');
        anchorTags.forEach(a => {
          const h = a.href || a.getAttribute('href');
          if (h && (h.startsWith('http://') || h.startsWith('https://'))) {
            links.push(h.trim());
          }
        });
      }
    }

    // 4. Fallback: User Selected Text or Active Page Container
    if (!body) {
      const selection = window.getSelection().toString().trim();
      if (selection) {
        body = selection;
        subject = subject || "Selected Text from Webmail";
      } else {
        const mainContainer = document.querySelector('article') || document.querySelector('main') || document.body;
        body = mainContainer.innerText.substring(0, 5000).trim();
        const anchorTags = (mainContainer || document).querySelectorAll('a[href]');
        anchorTags.forEach(a => {
          const h = a.href || a.getAttribute('href');
          if (h && (h.startsWith('http://') || h.startsWith('https://'))) {
            links.push(h.trim());
          }
        });
      }
    }

    // Regex extraction from body text as well
    const urlRegex = /https?:\/\/[^\s<>"'\)]+/g;
    const matched = body.match(urlRegex) || [];
    matched.forEach(u => {
      const clean = u.replace(/[\s,;:?!\.\>\)\]]+$/, '');
      if (clean) links.push(clean);
    });

  } catch (e) {
    console.error("Error extracting email data", e);
  }

  // Deduplicate links
  const uniqueLinks = Array.from(new Set(links)).filter(u => u && !u.startsWith('mailto:') && !u.startsWith('javascript:'));

  return {
    subject: subject || document.title || "Webmail Incident",
    sender: sender || "sender@unknown-origin.net",
    body: body || "No content extracted",
    links: uniqueLinks
  };
}

// Listen for messages from the popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "extractEmail") {
    const data = extractEmailData();
    sendResponse(data);
  }
  return true;
});

// =========================================================================
// IN-PAGE FLOATING SHIELD WIDGET
// =========================================================================

function initFloatingGuardWidget() {
  if (document.getElementById('ts-guard-host')) return;

  const host = document.createElement('div');
  host.id = 'ts-guard-host';
  host.style.position = 'fixed';
  host.style.bottom = '24px';
  host.style.right = '24px';
  host.style.zIndex = '2147483647';
  host.style.fontFamily = 'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';

  const shadow = host.attachShadow({ mode: 'open' });

  const style = document.createElement('style');
  style.textContent = `
    * { box-sizing: border-box; margin: 0; padding: 0; }
    
    .ts-pill {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 10px 16px;
      background: rgba(15, 23, 42, 0.94);
      backdrop-filter: blur(12px);
      border: 1px solid rgba(255, 255, 255, 0.15);
      border-radius: 9999px;
      color: #ffffff;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3), 0 8px 10px -6px rgba(0, 0, 0, 0.3);
      transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
      user-select: none;
    }
    .ts-pill:hover {
      transform: translateY(-2px);
      box-shadow: 0 15px 30px -5px rgba(37, 99, 235, 0.35), 0 0 0 1px #3b82f6;
      background: rgba(15, 23, 42, 0.98);
    }
    .ts-pill-icon {
      width: 18px;
      height: 18px;
      fill: #10b981;
      filter: drop-shadow(0 0 6px rgba(16, 185, 129, 0.6));
      animation: pulse 2s infinite;
    }
    .ts-badge {
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 9px;
      font-family: monospace;
      font-weight: 700;
      background: rgba(16, 185, 129, 0.2);
      color: #34d399;
      border: 1px solid rgba(16, 185, 129, 0.3);
    }
    
    @keyframes pulse {
      0%, 100% { transform: scale(1); opacity: 1; }
      50% { transform: scale(1.1); opacity: 0.85; }
    }

    /* Expanded Modal Card */
    .ts-card {
      position: absolute;
      bottom: 50px;
      right: 0;
      width: 360px;
      background: #0f172a;
      color: #f8fafc;
      border: 1px solid rgba(255, 255, 255, 0.15);
      border-radius: 16px;
      padding: 18px;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.6), 0 0 0 1px rgba(255, 255, 255, 0.1);
      backdrop-filter: blur(16px);
      opacity: 0;
      transform: translateY(12px) scale(0.96);
      pointer-events: none;
      transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
    }
    .ts-card.active {
      opacity: 1;
      transform: translateY(0) scale(1);
      pointer-events: auto;
    }

    .ts-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      border-bottom: 1px solid rgba(255, 255, 255, 0.1);
      padding-bottom: 12px;
      margin-bottom: 14px;
    }
    .ts-title-wrap {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .ts-title {
      font-size: 14px;
      font-weight: 700;
      color: #ffffff;
      letter-spacing: -0.01em;
    }
    .ts-close-btn {
      background: transparent;
      border: none;
      color: #94a3b8;
      cursor: pointer;
      font-size: 18px;
      line-height: 1;
      padding: 2px 6px;
      border-radius: 4px;
      transition: all 0.15s ease;
    }
    .ts-close-btn:hover {
      color: #ffffff;
      background: rgba(255, 255, 255, 0.1);
    }

    .ts-target-preview {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 8px;
      padding: 10px 12px;
      font-size: 11px;
      margin-bottom: 14px;
      color: #cbd5e1;
    }
    .ts-target-preview strong {
      color: #ffffff;
      font-weight: 600;
    }

    .ts-action-btn {
      width: 100%;
      padding: 11px 16px;
      border: none;
      border-radius: 10px;
      font-size: 13px;
      font-weight: 700;
      color: #ffffff;
      background: linear-gradient(135deg, #2563eb, #1d4ed8);
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      box-shadow: 0 4px 12px rgba(37, 99, 235, 0.4);
      transition: all 0.2s ease;
    }
    .ts-action-btn:hover {
      background: linear-gradient(135deg, #3b82f6, #2563eb);
      transform: translateY(-1px);
      box-shadow: 0 6px 16px rgba(37, 99, 235, 0.5);
    }
    .ts-action-btn:disabled {
      opacity: 0.6;
      cursor: not-allowed;
      transform: none;
    }

    /* Result View */
    .ts-result-box {
      margin-top: 14px;
      border-radius: 12px;
      padding: 14px;
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid rgba(255, 255, 255, 0.1);
      display: none;
      animation: fadeIn 0.3s ease-out;
    }
    .ts-result-box.visible {
      display: block;
    }

    .ts-verdict-banner {
      padding: 8px 12px;
      border-radius: 8px;
      font-size: 12px;
      font-weight: 800;
      text-align: center;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      margin-bottom: 10px;
    }
    .ts-verdict-danger {
      background: rgba(239, 68, 68, 0.2);
      color: #fca5a5;
      border: 1px solid rgba(239, 68, 68, 0.4);
    }
    .ts-verdict-safe {
      background: rgba(16, 185, 129, 0.2);
      color: #6ee7b7;
      border: 1px solid rgba(16, 185, 129, 0.4);
    }

    .ts-score-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 8px 0;
      border-bottom: 1px solid rgba(255, 255, 255, 0.08);
      font-size: 12px;
    }
    .ts-score-val {
      font-family: monospace;
      font-size: 15px;
      font-weight: 800;
    }
    .ts-score-danger { color: #ef4444; }
    .ts-score-safe { color: #10b981; }

    .ts-portal-link-btn {
      margin-top: 12px;
      width: 100%;
      padding: 9px 14px;
      background: rgba(255, 255, 255, 0.08);
      hover: background: rgba(255, 255, 255, 0.15);
      border: 1px solid rgba(255, 255, 255, 0.2);
      border-radius: 8px;
      color: #38bdf8;
      font-size: 12px;
      font-weight: 700;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      transition: all 0.2s ease;
      text-decoration: none;
    }
    .ts-portal-link-btn:hover {
      background: #0284c7;
      color: #ffffff;
      border-color: #0284c7;
      transform: translateY(-1px);
    }

    .ts-spinner {
      width: 16px;
      height: 16px;
      border: 2px solid rgba(255,255,255,0.3);
      border-top-color: #ffffff;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    @keyframes fadeIn { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }
  `;

  const container = document.createElement('div');
  container.innerHTML = `
    <!-- Floating Pill Button -->
    <div class="ts-pill" id="tsPillBtn" title="TrustShield Autonomous Phishing Guard">
      <svg class="ts-pill-icon" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      <span>TrustShield Guard</span>
      <span class="ts-badge">SEC. 63 BSA</span>
    </div>

    <!-- Floating HUD Panel -->
    <div class="ts-card" id="tsCard">
      <div class="ts-header">
        <div class="ts-title-wrap">
          <svg style="width:16px;height:16px;fill:#10b981;" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          <span class="ts-title">TrustShield Endpoint Guard</span>
        </div>
        <button class="ts-close-btn" id="tsCloseBtn">&times;</button>
      </div>

      <div class="ts-target-preview" id="tsTargetPreview">
        <div><strong>Sender:</strong> <span id="tsPreviewSender">Inspecting active email...</span></div>
        <div style="margin-top:3px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"><strong>Subject:</strong> <span id="tsPreviewSubject">...</span></div>
      </div>

      <button class="ts-action-btn" id="tsAnalyzeBtn">
        <svg style="width:14px;height:14px;fill:currentColor;" viewBox="0 0 24 24"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>
        <span id="tsBtnText">Analyze Active Email</span>
      </button>

      <!-- Live Result View -->
      <div class="ts-result-box" id="tsResultBox">
        <div class="ts-verdict-banner ts-verdict-danger" id="tsVerdictBanner">CRITICAL THREAT DETECTED</div>
        
        <div class="ts-score-row">
          <span>Threat Risk Score</span>
          <span class="ts-score-val ts-score-danger" id="tsScoreVal">100 / 100</span>
        </div>

        <div class="ts-score-row">
          <span>Attribution Type</span>
          <span style="font-size:11px;font-weight:700;color:#cbd5e1;" id="tsAttrType">MALICIOUS_PAYLOAD</span>
        </div>

        <div style="font-size:11px;color:#94a3b8;margin-top:8px;line-height:1.4;" id="tsKeyFinding">
          Detonated 1 payload URL. Credential interceptor and brand impersonation detected.
        </div>

        <button class="ts-portal-link-btn" id="tsOpenPortalBtn">
          <span>🔍 Open Full SOC Forensic Dossier &rarr;</span>
        </button>
      </div>
    </div>
  `;

  shadow.appendChild(style);
  shadow.appendChild(container);
  document.body.appendChild(host);

  // Bind Events inside Shadow DOM
  const pillBtn = shadow.getElementById('tsPillBtn');
  const card = shadow.getElementById('tsCard');
  const closeBtn = shadow.getElementById('tsCloseBtn');
  const analyzeBtn = shadow.getElementById('tsAnalyzeBtn');
  const btnText = shadow.getElementById('tsBtnText');
  const resultBox = shadow.getElementById('tsResultBox');
  const previewSender = shadow.getElementById('tsPreviewSender');
  const previewSubject = shadow.getElementById('tsPreviewSubject');
  const verdictBanner = shadow.getElementById('tsVerdictBanner');
  const scoreVal = shadow.getElementById('tsScoreVal');
  const attrType = shadow.getElementById('tsAttrType');
  const keyFinding = shadow.getElementById('tsKeyFinding');
  const openPortalBtn = shadow.getElementById('tsOpenPortalBtn');

  let currentDossier = null;
  let currentRawEml = null;
  let currentCaseId = null;

  function refreshEmailPreview() {
    const data = extractEmailData();
    if (previewSender) previewSender.innerText = data.sender || "Open an email to inspect";
    if (previewSubject) previewSubject.innerText = data.subject || "No subject";
  }

  pillBtn.addEventListener('click', () => {
    refreshEmailPreview();
    card.classList.toggle('active');
  });

  closeBtn.addEventListener('click', () => {
    card.classList.remove('active');
  });

  analyzeBtn.addEventListener('click', async () => {
    const emailData = extractEmailData();
    analyzeBtn.disabled = true;
    btnText.innerHTML = `<span class="ts-spinner"></span> Scanning & Detonating...`;

    try {
      let response;
      try {
        response = await fetch(BACKEND_LOCAL_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(emailData)
        });
      } catch (_) {
        response = await fetch(BACKEND_CLOUD_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(emailData)
        });
      }

      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const res = await response.json();

      currentDossier = res.full_dossier || res.details || res;
      currentRawEml = res.raw_eml || "";
      currentCaseId = res.case_id || "";

      const score = parseFloat(res.final_threat_score || 0);
      const verdict = res.verdict || "ANALYZED";
      const attribution = res.threat_attribution?.type || res.text_verdict || "ANOMALOUS_INDICATORS";

      if (scoreVal) {
        scoreVal.innerText = `${score.toFixed(1)} / 100`;
        scoreVal.className = `ts-score-val ${score >= 80 ? 'ts-score-danger' : 'ts-score-safe'}`;
      }

      if (verdictBanner) {
        verdictBanner.innerText = verdict;
        verdictBanner.className = `ts-verdict-banner ${score >= 80 ? 'ts-verdict-danger' : 'ts-verdict-safe'}`;
      }

      if (attrType) attrType.innerText = attribution;

      if (keyFinding) {
        const linkCount = res.links_found || 0;
        keyFinding.innerText = `Scanned ${linkCount} link(s). Analysis completed across multi-modal neural classifier and stealth headless sandbox.`;
      }

      resultBox.classList.add('visible');

    } catch (err) {
      alert(`TrustShield Scan Error: ${err.message}\nMake sure TrustShield backend is running on port 8000.`);
      console.error(err);
    } finally {
      analyzeBtn.disabled = false;
      btnText.innerText = "Re-Analyze Active Email";
    }
  });

  openPortalBtn.addEventListener('click', () => {
    if (currentDossier) {
      try {
        localStorage.setItem('trustshield_incoming_incident', JSON.stringify({
          dossier: currentDossier,
          raw_eml: currentRawEml,
          case_id: currentCaseId
        }));
      } catch (e) {
        console.warn('LocalStorage quota:', e);
      }
    }
    const redirectUrl = currentCaseId 
      ? `${PORTAL_LOCAL_URL}?case_id=${encodeURIComponent(currentCaseId)}`
      : PORTAL_LOCAL_URL;
    window.open(redirectUrl, '_blank');
  });
}

// Auto-inject on page load
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initFloatingGuardWidget);
} else {
  initFloatingGuardWidget();
}
