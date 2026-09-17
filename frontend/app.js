/**
 * TrustShield V2 - SOC Analyst Forensic Intelligence Portal
 * Autonomous Telemetry & Interactive Progress Controller
 */

// Global API Base resolution
var API_BASE = (window.location.port === '8000' && window.location.protocol.startsWith('http'))
  ? ''
  : 'http://localhost:8000';

var currentReport = null;
var rawEmlContent = '';
var mapInstance = null;
var mapMarkersGroup = null;
var mapPolyline = null;
var progressTimerInterval = null;
var stageTimeouts = [];

// Synthetic Sample Phishing .eml for 1-Click Evaluation
var SAMPLE_PHISHING_EML = `Delivered-To: victim.executive@company.com\r
Received: from mx.internal.company.com (mx.internal.company.com [10.0.2.15])\r
\tby mailbox.company.com (Postfix) with ESMTP id 4X9F8D01;\r
\tMon, 7 Sep 2026 14:35:12 +0000 (UTC)\r
Received: from edge-relay.company.com (edge-relay.company.com [192.168.1.1])\r
\tby mx.internal.company.com with ESMTP id 3B8C1A22;\r
\tMon, 7 Sep 2026 14:35:10 +0000 (UTC)\r
Received: from mail.spoofed-sender.xyz (unknown [185.220.101.5])\r
\tby edge-relay.company.com (Postfix) with ESMTPS id 1A2B3C4D;\r
\tMon, 7 Sep 2026 14:35:05 +0000 (UTC)\r
Received: from attacker-laptop (unknown [10.0.0.5])\r
\tby mail.spoofed-sender.xyz (Postfix) with ESMTPA id 99887766;\r
\tMon, 7 Sep 2026 14:34:58 +0000 (UTC)\r
Return-Path: <spoofed-account@spoofed-sender.xyz>\r
From: "Executive Security Alert" <security@paypal-verification.top>\r
To: victim.executive@company.com\r
Subject: URGENT: Unauthorized Wire Transfer Detected - Verify Identity\r
Date: Mon, 7 Sep 2026 14:34:55 +0000\r
Message-ID: <20260907143455.ABC123XYZ@spoofed-sender.xyz>\r
Reply-To: phisher-drop@external-scam.biz\r
MIME-Version: 1.0\r
Content-Type: multipart/alternative; boundary="----=_Part_12345_67890"\r
\r
------=_Part_12345_67890\r
Content-Type: text/plain; charset=UTF-8\r
Content-Transfer-Encoding: 7bit\r
\r
Urgent Notice:\r
We detected an unauthorized login attempt from an unrecognized device.\r
Please cancel this transaction immediately by visiting https://linked1n.vercel.app/\r
Alternatively review your case here: https://portal-resolve.top/ticket?id=99281\r
\r
------=_Part_12345_67890\r
Content-Type: text/html; charset=UTF-8\r
Content-Transfer-Encoding: 7bit\r
\r
<!DOCTYPE html>\r
<html>\r
<body>\r
  <h2>Security Notification</h2>\r
  <p>An unauthorized wire transfer of $14,850.00 was requested from foreign IP <strong>185.220.101.5</strong>.</p>\r
  <p>If you did not authorize this, cancel immediately:</p>\r
  <p><a href="https://linked1n.vercel.app/" style="color:red; font-weight:bold;">Click Here to Cancel Transfer</a></p>\r
  <p>Support Reference: <a href="https://portal-resolve.top/ticket?id=99281">Resolution Portal</a></p>\r
</body>\r
</html>\r
------=_Part_12345_67890--\r
`;

// Export globals for inline HTML event attributes
window.triggerFileInput = function(e) {
  if (e) {
    if (e.target && e.target.id === 'emlFileInput') return;
    e.preventDefault();
    e.stopPropagation();
  }
  const fileInput = document.getElementById('emlFileInput');
  if (fileInput) {
    fileInput.value = '';
    fileInput.click();
  }
};

window.handleFileSelect = function(e) {
  if (e && e.target && e.target.files && e.target.files.length > 0) {
    processEmlFile(e.target.files[0]);
  }
};

window.loadSamplePhishingDemo = function(e) {
  if (e) {
    e.preventDefault();
    e.stopPropagation();
  }
  const blob = new Blob([SAMPLE_PHISHING_EML], { type: 'message/rfc822' });
  const sampleFile = new File([blob], 'URGENT_WIRE_TRANSFER_ATTACK.eml', { type: 'message/rfc822' });
  processEmlFile(sampleFile);
};

window.downloadSampleEml = function(e) {
  if (e) {
    e.preventDefault();
    e.stopPropagation();
  }
  const blob = new Blob([SAMPLE_PHISHING_EML], { type: 'message/rfc822' });
  const downloadUrl = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = downloadUrl;
  a.download = 'URGENT_WIRE_TRANSFER_ATTACK.eml';
  document.body.appendChild(a);
  a.click();
  window.URL.revokeObjectURL(downloadUrl);
  a.remove();
};

window.exportDossierPdf = exportDossierPdf;
window.resetDashboard = resetDashboard;
window.copyEvidenceHash = copyEvidenceHash;
window.openRawHeadersModal = openRawHeadersModal;
window.closeRawHeadersModal = closeRawHeadersModal;
window.copyRawHeaders = copyRawHeaders;
window.openAttackStudioModal = openAttackStudioModal;
window.closeAttackStudioModal = closeAttackStudioModal;
window.downloadStudioLiveEml = downloadStudioLiveEml;
window.executeLiveStudioInjection = executeLiveStudioInjection;

var cachedLiveTelemetry = {
  ip: '157.51.60.12',
  city: 'Coimbatore',
  region: 'Tamil Nadu',
  country: 'India',
  isp: 'Reliance Jio Infocomm Limited',
  asn: 'AS55836'
};

async function queryLiveMachineTelemetry() {
  try {
    const res = await fetch('http://ip-api.com/json', { cache: 'no-store' }).catch(() => null);
    if (res && res.ok) {
      const data = await res.json();
      if (data && data.status === 'success') {
        cachedLiveTelemetry = {
          ip: data.query || '157.51.60.12',
          city: data.city || 'Coimbatore',
          region: data.regionName || 'Tamil Nadu',
          country: data.country || 'India',
          isp: data.isp || 'Reliance Jio Infocomm Limited',
          asn: data.as || 'AS55836'
        };
      }
    }
  } catch (e) {
    console.debug('Live telemetry probe:', e);
  }

  const ipEl = document.getElementById('studioLiveIp');
  const cityEl = document.getElementById('studioLiveCity');
  const ispEl = document.getElementById('studioLiveIsp');
  const asnEl = document.getElementById('studioLiveAsn');

  if (ipEl) ipEl.innerText = cachedLiveTelemetry.ip;
  if (cityEl) cityEl.innerText = `${cachedLiveTelemetry.city}, ${cachedLiveTelemetry.region}, ${cachedLiveTelemetry.country}`;
  if (ispEl) ispEl.innerText = cachedLiveTelemetry.isp;
  if (asnEl) asnEl.innerText = cachedLiveTelemetry.asn;
}

function openAttackStudioModal(e) {
  if (e) e.preventDefault();
  const modal = document.getElementById('attackStudioModal');
  if (modal) {
    modal.classList.remove('hidden');
    queryLiveMachineTelemetry();
  }
}

function closeAttackStudioModal(e) {
  if (e) e.preventDefault();
  const modal = document.getElementById('attackStudioModal');
  if (modal) modal.classList.add('hidden');
}

function buildLiveStudioEml() {
  const from = document.getElementById('studioFrom')?.value || '"Executive Security Alert" <security@paypal-verification.top>';
  const returnPath = document.getElementById('studioReturnPath')?.value || 'scammer-drop@external-spoof.biz';
  const to = document.getElementById('studioTo')?.value || 'victim.executive@company.com';
  const replyTo = document.getElementById('studioReplyTo')?.value || 'fraudster-collect@unauthorized-mailbox.net';
  const subject = document.getElementById('studioSubject')?.value || 'URGENT: Unauthorized Wire Transfer Detected - Verify Identity';
  const url = document.getElementById('studioUrl')?.value || 'https://linked1n.vercel.app/';

  const nowUtc = new Date().toUTCString();
  const ip = cachedLiveTelemetry.ip || '157.51.60.12';
  const city = cachedLiveTelemetry.city || 'Coimbatore';
  const country = cachedLiveTelemetry.country || 'India';

  return `Delivered-To: ${to}\r
Received: by 2002:a17:902:d00d:b0:1c4:89a1:2345 with SMTP id z13csp982124plb;\r
\t${nowUtc}\r
Received: from mail-relay.trustshield-demo.org (unknown [${ip}])\r
\tby mx.google.com with ESMTP id a21si891024plm.12\r
\tfor <${to}>;\r
\t${nowUtc}\r
Return-Path: <${returnPath}>\r
From: ${from}\r
To: ${to}\r
Reply-To: ${replyTo}\r
Subject: ${subject}\r
Date: ${nowUtc}\r
Message-ID: <${Date.now()}.${ip}@trustshield-demo.org>\r
MIME-Version: 1.0\r
Content-Type: multipart/alternative; boundary="----=_Part_LiveStudio_9988"\r
\r
------=_Part_LiveStudio_9988\r
Content-Type: text/plain; charset=UTF-8\r
Content-Transfer-Encoding: 7bit\r
\r
Urgent Notice:\r
We detected an unauthorized transaction attempt originating from IP: ${ip} (${city}, ${country}).\r
Please cancel this transaction immediately by visiting: ${url}\r
\r
------=_Part_LiveStudio_9988\r
Content-Type: text/html; charset=UTF-8\r
Content-Transfer-Encoding: 7bit\r
\r
<!DOCTYPE html>\r
<html>\r
<body style="font-family: Arial, sans-serif; background-color: #f9f9f9; padding: 20px;">\r
  <div style="background: white; border: 1px solid #ddd; padding: 20px; border-radius: 8px; max-width: 600px;">\r
    <h2 style="color: #d9534f;">Security Alert: Account Verification Required</h2>\r
    <p>An unauthorized transaction was requested from network IP <strong>${ip}</strong> (${city}, ${country}).</p>\r
    <p>If you did not authorize this, cancel immediately:</p>\r
    <p><a href="${url}" style="background-color: #d9534f; color: white; padding: 10px 18px; text-decoration: none; border-radius: 4px; display: inline-block;">Verify & Cancel Request</a></p>\r
    <p style="color: #888; font-size: 11px; margin-top: 20px;">Automated Security Gateway // TrustShield Forensic Demonstration</p>\r
  </div>\r
</body>\r
</html>\r
------=_Part_LiveStudio_9988--\r
`;
}

function downloadStudioLiveEml(e) {
  if (e) e.preventDefault();
  const emlContent = buildLiveStudioEml();
  const blob = new Blob([emlContent], { type: 'message/rfc822' });
  const downloadUrl = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = downloadUrl;
  const ipClean = (cachedLiveTelemetry.ip || 'LIVE').replace(/\./g, '_');
  const cityClean = (cachedLiveTelemetry.city || 'ORIGIN').replace(/\s+/g, '_');
  a.download = `LIVE_ATTACK_${cityClean}_${ipClean}.eml`;
  document.body.appendChild(a);
  a.click();
  window.URL.revokeObjectURL(downloadUrl);
  a.remove();
}

function executeLiveStudioInjection(e) {
  if (e) e.preventDefault();
  closeAttackStudioModal();
  const emlContent = buildLiveStudioEml();
  const blob = new Blob([emlContent], { type: 'message/rfc822' });
  const ipClean = (cachedLiveTelemetry.ip || 'LIVE').replace(/\./g, '_');
  const cityClean = (cachedLiveTelemetry.city || 'ORIGIN').replace(/\s+/g, '_');
  const liveFile = new File([blob], `LIVE_ATTACK_${cityClean}_${ipClean}.eml`, { type: 'message/rfc822' });
  processEmlFile(liveFile);
}

// Setup Drag & Drop on startup
document.addEventListener('DOMContentLoaded', () => {
  setupDragAndDrop();
});

function setupDragAndDrop() {
  const dropZone = document.getElementById('dropZone');
  if (!dropZone) return;

  window.addEventListener('dragover', (e) => e.preventDefault());
  window.addEventListener('drop', (e) => e.preventDefault());

  ['dragenter', 'dragover'].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.add('border-cyan-400', 'bg-cyan-950/25');
    });
  });

  ['dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.remove('border-cyan-400', 'bg-cyan-950/25');
    });
  });

  dropZone.addEventListener('drop', (e) => {
    const dt = e.dataTransfer;
    if (dt && dt.files && dt.files.length > 0) {
      processEmlFile(dt.files[0]);
    }
  });
}

function copyEvidenceHash(e) {
  if (e) e.stopPropagation();
  const hashText = document.getElementById('sha256Digest')?.innerText;
  if (hashText && hashText !== 'Calculating...') {
    navigator.clipboard.writeText(hashText);
    const copyBtn = document.getElementById('copyHashBtn');
    if (copyBtn) {
      copyBtn.innerHTML = `<span class="text-emerald-400 font-semibold font-mono">✓ Copied</span>`;
      setTimeout(() => {
        copyBtn.innerHTML = `
          <svg class="w-3 h-3 inline-block mr-1" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect width="14" height="14" x="8" y="8" rx="2" ry="2"/>
            <path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>
          </svg>
          <span>Copy SHA-256</span>
        `;
      }, 2000);
    }
  }
}

function openRawHeadersModal(e) {
  if (e) e.preventDefault();
  const modal = document.getElementById('rawHeadersModal');
  const modalBody = document.getElementById('rawHeadersText');
  if (modal && modalBody) {
    modalBody.innerText = rawEmlContent || 'Raw headers not available for this session.';
    modal.classList.remove('hidden');
  }
}

function closeRawHeadersModal(e) {
  if (e) e.preventDefault();
  const modal = document.getElementById('rawHeadersModal');
  if (modal) modal.classList.add('hidden');
}

function copyRawHeaders(e) {
  if (e) e.preventDefault();
  const modalBody = document.getElementById('rawHeadersText');
  if (modalBody && modalBody.innerText) {
    navigator.clipboard.writeText(modalBody.innerText);
    const btn = e.target.closest('button');
    if (btn) {
      const orig = btn.innerHTML;
      btn.innerHTML = `<span class="text-emerald-400">✓ Copied</span>`;
      setTimeout(() => { btn.innerHTML = orig; }, 1800);
    }
  }
}

function resetDashboard(e) {
  if (e) e.preventDefault();
  currentReport = null;
  rawEmlContent = '';

  const uploadSec = document.getElementById('uploadSection');
  const trackerSec = document.getElementById('progressTrackerSection');
  const verdictSec = document.getElementById('executiveVerdict');
  const gridSec = document.getElementById('dashboardGrid');

  if (uploadSec) uploadSec.classList.remove('hidden');
  if (trackerSec) trackerSec.classList.add('hidden');
  if (verdictSec) verdictSec.classList.add('hidden');
  if (gridSec) gridSec.classList.add('hidden');

  if (uploadSec) uploadSec.scrollIntoView({ behavior: 'smooth' });
}

// =========================================================================
// INTERACTIVE MULTI-STAGE FORENSIC PROGRESS TRACKER ENGINE
// =========================================================================

function getUtcTimestamp() {
  const now = new Date();
  return now.toISOString().substring(11, 23);
}

function appendTerminalLog(category, message, level = 'info') {
  const container = document.getElementById('terminalLogContainer');
  if (!container) return;

  const colorMap = {
    info: 'text-cyan-300',
    crypto: 'text-emerald-400',
    warn: 'text-amber-400 font-semibold',
    alert: 'text-red-400 font-bold',
    success: 'text-emerald-300 font-bold',
    net: 'text-indigo-300',
    dim: 'text-slate-500'
  };

  const badgeColor = {
    info: 'bg-cyan-950 text-cyan-400 border-cyan-800',
    crypto: 'bg-emerald-950 text-emerald-400 border-emerald-800',
    warn: 'bg-amber-950 text-amber-400 border-amber-800',
    alert: 'bg-red-950 text-red-400 border-red-800',
    success: 'bg-emerald-950 text-emerald-300 border-emerald-700',
    net: 'bg-indigo-950 text-indigo-400 border-indigo-800',
    dim: 'bg-slate-900 text-slate-500 border-slate-800'
  };

  const line = document.createElement('div');
  line.className = 'flex items-start space-x-2 py-0.5';
  line.innerHTML = `
    <span class="text-slate-600 select-none text-[10px]">[${getUtcTimestamp()}]</span>
    <span class="px-1 py-0.2 rounded border text-[9px] font-bold ${badgeColor[level] || badgeColor.info}">${category}</span>
    <span class="${colorMap[level] || 'text-slate-300'} flex-1 break-words">${message}</span>
  `;

  container.appendChild(line);
  container.scrollTop = container.scrollHeight;
}

function updateStageCard(stageNum, status, label) {
  const card = document.getElementById(`stageCard${stageNum}`);
  const badge = document.getElementById(`stageBadge${stageNum}`);
  const desc = document.getElementById(`stageDesc${stageNum}`);

  if (!card) return;

  if (desc && label) desc.innerText = label;

  if (status === 'active') {
    card.className = 'p-2.5 rounded-lg bg-cyan-950/40 border border-cyan-500 shadow-md shadow-cyan-500/20 flex flex-col justify-between transition-all duration-300';
    if (badge) badge.className = 'w-2 h-2 rounded-full bg-cyan-400 animate-ping';
  } else if (status === 'completed') {
    card.className = 'p-2.5 rounded-lg bg-emerald-950/30 border border-emerald-700/60 flex flex-col justify-between transition-all duration-300';
    if (badge) badge.className = 'w-2 h-2 rounded-full bg-emerald-400';
  } else {
    // queued
    card.className = 'p-2.5 rounded-lg bg-slate-950/80 border border-slate-800 flex flex-col justify-between transition-all duration-300';
    if (badge) badge.className = 'w-2 h-2 rounded-full bg-slate-700';
  }
}

function startProgressAnimation(fileName, fileSize) {
  const trackerSec = document.getElementById('progressTrackerSection');
  const uploadSec = document.getElementById('uploadSection');
  const verdictSec = document.getElementById('executiveVerdict');
  const gridSec = document.getElementById('dashboardGrid');

  if (trackerSec) trackerSec.classList.remove('hidden');
  if (uploadSec) uploadSec.classList.add('hidden');
  if (verdictSec) verdictSec.classList.add('hidden');
  if (gridSec) gridSec.classList.add('hidden');

  trackerSec.scrollIntoView({ behavior: 'smooth' });

  // Clear previous timers
  if (progressTimerInterval) clearInterval(progressTimerInterval);
  stageTimeouts.forEach(t => clearTimeout(t));
  stageTimeouts = [];

  // Reset progress bar & timer
  const bar = document.getElementById('progressBarFill');
  const percentText = document.getElementById('progressPercent');
  const elapsedText = document.getElementById('elapsedTimer');
  const substatus = document.getElementById('progressSubstatus');
  const logContainer = document.getElementById('terminalLogContainer');

  if (bar) bar.style.width = '5%';
  if (percentText) percentText.innerText = '5%';
  if (elapsedText) elapsedText.innerText = '0.00s';
  if (logContainer) logContainer.innerHTML = '';

  for (let i = 1; i <= 6; i++) {
    updateStageCard(i, 'queued');
  }

  const startTime = performance.now();
  progressTimerInterval = setInterval(() => {
    const elapsed = (performance.now() - startTime) / 1000;
    if (elapsedText) elapsedText.innerText = `${elapsed.toFixed(2)}s`;
  }, 50);

  // Initial Log Lines
  appendTerminalLog('INIT', `Initialized TrustShield Autonomous Forensic Kernel v2.4`, 'info');
  appendTerminalLog('INGEST', `Ingesting raw MIME envelope: '${fileName}' (${(fileSize / 1024).toFixed(1)} KB)`, 'info');

  // Stage 1: Active
  updateStageCard(1, 'active', 'Calculating SHA-256...');
  if (substatus) substatus.innerText = 'Generating Section 65B cryptographic evidence digest...';
  if (bar) bar.style.width = '16%';
  if (percentText) percentText.innerText = '16%';

  stageTimeouts.push(setTimeout(() => {
    updateStageCard(1, 'completed', '✓ SHA-256 Sealed');
    appendTerminalLog('CRYPTO', `SHA-256 Chain of Custody hash stamped (Sec 65B compliant)`, 'crypto');
    
    // Stage 2: Active
    updateStageCard(2, 'active', 'Parsing RFC-5322...');
    if (substatus) substatus.innerText = 'Dissecting email headers and validating identity alignment...';
    if (bar) bar.style.width = '33%';
    if (percentText) percentText.innerText = '33%';
    appendTerminalLog('RFC5322', `Extracting boundary parts, Return-Path, and Reply-To headers`, 'info');
  }, 220));

  stageTimeouts.push(setTimeout(() => {
    updateStageCard(2, 'completed', '✓ Identity Audited');
    appendTerminalLog('SPOOF', `Checked Display Name vs Envelope Return-Path`, 'info');

    // Stage 3: Active
    updateStageCard(3, 'active', 'Auditing SPF/DKIM...');
    if (substatus) substatus.innerText = 'Verifying cryptographic DKIM keys and SPF/DMARC policies...';
    if (bar) bar.style.width = '50%';
    if (percentText) percentText.innerText = '50%';
    appendTerminalLog('DNS', `Querying DNS TXT records for SPF and DMARC enforcement`, 'info');
  }, 650));

  stageTimeouts.push(setTimeout(() => {
    updateStageCard(3, 'completed', '✓ DNS Protocols Audited');
    appendTerminalLog('DNS', `Checked MX server records & domain reputation`, 'crypto');

    // Stage 4: Active
    updateStageCard(4, 'active', 'Tracing Server Hops...');
    if (substatus) substatus.innerText = 'Resolving relay hop IP addresses and geolocation route...';
    if (bar) bar.style.width = '68%';
    if (percentText) percentText.innerText = '68%';
    appendTerminalLog('GEO', `Geolocating origin node and relay hops across autonomous systems`, 'net');
  }, 1150));

  stageTimeouts.push(setTimeout(() => {
    updateStageCard(4, 'completed', '✓ Route Traced');
    appendTerminalLog('GEO', `Origin node IP identified. Checking Tor exit and VPN proxies`, 'net');

    // Stage 5: Active
    updateStageCard(5, 'active', 'Detonating Links...');
    if (substatus) substatus.innerText = 'Detonating hyperlinks in isolated stealth Chromium sandbox...';
    if (bar) bar.style.width = '84%';
    if (percentText) percentText.innerText = '84%';
    appendTerminalLog('SANDBOX', `Detonating hyperlinks in isolated stealth Chromium container...`, 'warn');
  }, 1750));
}

function completeProgressAnimation(report, elapsedSeconds) {
  // Clear any pending synthetic stage timeouts
  stageTimeouts.forEach(t => clearTimeout(t));
  stageTimeouts = [];

  const bar = document.getElementById('progressBarFill');
  const percentText = document.getElementById('progressPercent');
  const substatus = document.getElementById('progressSubstatus');

  // Mark all stages as completed
  for (let i = 1; i <= 6; i++) {
    updateStageCard(i, 'completed', '✓ Complete');
  }

  if (bar) bar.style.width = '100%';
  if (percentText) percentText.innerText = '100%';
  if (substatus) substatus.innerText = 'Forensic evaluation complete. Rendering incident dossier...';

  // Log final forensic findings into terminal
  const score = Math.round(parseFloat(report.overall_threat_score || 0));
  const verdict = report.verdict || 'ANALYSIS COMPLETE';

  if (score >= 80) {
    appendTerminalLog('ALERT', `Critical Threat Signature Confirmed: Risk Score ${score}/100`, 'alert');
  } else if (score >= 50) {
    appendTerminalLog('WARN', `Suspicious Indicators Flagged: Risk Score ${score}/100`, 'warn');
  } else {
    appendTerminalLog('CLEAN', `Message Verified Authenticated: Risk Score ${score}/100`, 'success');
  }

  appendTerminalLog('FUSION', `Meta-Classifier Verdict: [${verdict}] in ${elapsedSeconds.toFixed(2)}s`, 'success');
  appendTerminalLog('DOSSIER', `Section 65B Electronic Dossier assembled. Displaying SOC dashboard.`, 'crypto');

  if (progressTimerInterval) clearInterval(progressTimerInterval);

  // Transition smoothly to the dashboard after brief completion pause
  setTimeout(() => {
    const trackerSec = document.getElementById('progressTrackerSection');
    const verdictSec = document.getElementById('executiveVerdict');
    const gridSec = document.getElementById('dashboardGrid');

    if (trackerSec) trackerSec.classList.add('hidden');
    if (verdictSec) verdictSec.classList.remove('hidden');
    if (gridSec) gridSec.classList.remove('hidden');

    renderDashboard(report);

    if (verdictSec) verdictSec.scrollIntoView({ behavior: 'smooth' });
  }, 450);
}

// =========================================================================
// MAIN INGESTION & PIPELINE FETCH CALL
// =========================================================================

async function processEmlFile(file) {
  if (!file) return;

  const startTime = performance.now();
  startProgressAnimation(file.name, file.size);

  // Read file as text for raw headers modal
  const reader = new FileReader();
  reader.onload = (e) => {
    rawEmlContent = e.target.result;
  };
  reader.readAsText(file);

  const formData = new FormData();
  formData.append('file', file);

  try {
    const response = await fetch(`${API_BASE}/api/forensics/analyze-eml`, {
      method: 'POST',
      body: formData
    });

    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      throw new Error(errData.error || `HTTP ${response.status}: Forensic analysis request failed`);
    }

    const data = await response.json();
    currentReport = data;

    const elapsedSeconds = (performance.now() - startTime) / 1000;
    completeProgressAnimation(data, elapsedSeconds);

  } catch (error) {
    if (progressTimerInterval) clearInterval(progressTimerInterval);
    appendTerminalLog('ERROR', `Pipeline Execution Fault: ${error.message}`, 'alert');
    alert(`Forensic Ingestion Error:\n${error.message}\n\nPlease ensure backend is running at ${API_BASE || 'http://localhost:8000'}`);
    console.error('Forensic Analysis Error:', error);
  }
}

// =========================================================================
// DASHBOARD RENDERING CONTROLLERS
// =========================================================================

function renderDashboard(data) {
  renderVerdict(data);
  renderMetadataAndAuth(data);
  renderLeafletMap(data.origin_intelligence);
  renderNarrativeAndLinks(data);
}

function renderVerdict(data) {
  const score = parseFloat(data.overall_threat_score || 0.0);
  const scoreNumber = document.getElementById('scoreNumber');
  const scoreCircle = document.getElementById('scoreCircle');
  const verdictCard = document.getElementById('verdictCard');
  const verdictBadge = document.getElementById('verdictBadge');
  const attributionBadge = document.getElementById('attributionBadge');
  const verdictHeadline = document.getElementById('verdictHeadline');
  const attributionDetails = document.getElementById('attributionDetails');

  if (scoreNumber) scoreNumber.innerText = Math.round(score);

  const circumference = 263.89;
  const offset = circumference - (score / 100) * circumference;
  if (scoreCircle) scoreCircle.style.strokeDashoffset = offset;

  const attr = data.threat_attribution || {};
  if (attributionBadge) attributionBadge.innerText = attr.type || 'UNKNOWN';
  if (attributionDetails) attributionDetails.innerText = attr.details || 'Evaluation completed across all forensic telemetry engines.';

  if (score >= 80.0) {
    if (scoreCircle) scoreCircle.setAttribute('stroke', '#ef4444');
    if (verdictCard) verdictCard.className = 'rounded-xl border border-red-800/80 p-5 bg-[#0e1424] shadow-2xl glow-red transition-all';
    if (verdictBadge) {
      verdictBadge.className = 'px-2.5 py-0.5 rounded text-[11px] font-bold font-mono tracking-wide uppercase bg-red-950 text-red-400 border border-red-700/80';
      verdictBadge.innerText = data.verdict || 'CRITICAL FRAUD / PHISHING';
    }
    if (verdictHeadline) verdictHeadline.innerText = 'High-Impact Cyber Attack & Identity Spoofing';
  } else if (score >= 50.0) {
    if (scoreCircle) scoreCircle.setAttribute('stroke', '#f59e0b');
    if (verdictCard) verdictCard.className = 'rounded-xl border border-amber-800/80 p-5 bg-[#0e1424] shadow-2xl glow-amber transition-all';
    if (verdictBadge) {
      verdictBadge.className = 'px-2.5 py-0.5 rounded text-[11px] font-bold font-mono tracking-wide uppercase bg-amber-950 text-amber-400 border border-amber-700/80';
      verdictBadge.innerText = data.verdict || 'SUSPICIOUS / UNVERIFIED ORIGIN';
    }
    if (verdictHeadline) verdictHeadline.innerText = 'Suspicious Infrastructure & Anomalous Identity';
  } else {
    if (scoreCircle) scoreCircle.setAttribute('stroke', '#10b981');
    if (verdictCard) verdictCard.className = 'rounded-xl border border-emerald-800/80 p-5 bg-[#0e1424] shadow-2xl glow-emerald transition-all';
    if (verdictBadge) {
      verdictBadge.className = 'px-2.5 py-0.5 rounded text-[11px] font-bold font-mono tracking-wide uppercase bg-emerald-950 text-emerald-400 border border-emerald-700/80';
      verdictBadge.innerText = data.verdict || 'LEGITIMATE / AUTHENTICATED';
    }
    if (verdictHeadline) verdictHeadline.innerText = 'Technical Envelope Verified Legitimate';
  }
}

function renderMetadataAndAuth(data) {
  const meta = data.metadata || {};
  const auth = data.authentication || {};
  const mx = data.sender_domain_intelligence || {};

  // BEC Warning
  const becBox = document.getElementById('becAlertBox');
  if (becBox) {
    if (meta.reply_to_mismatch) {
      becBox.classList.remove('hidden');
      const becDetail = document.getElementById('becDetailText');
      if (becDetail) {
        becDetail.innerText = `Header From: <${meta.from || 'Unknown'}>  !=  Reply-To: <${meta.reply_to || 'None'}>`;
      }
    } else {
      becBox.classList.add('hidden');
    }
  }

  // Chain of custody hash
  const shaEl = document.getElementById('sha256Digest');
  if (shaEl) shaEl.innerText = data.evidence_hash_sha256 || 'N/A';

  // Envelope fields
  const setText = (id, txt) => {
    const el = document.getElementById(id);
    if (el) el.innerText = txt || 'N/A';
  };

  setText('metaSubject', meta.subject || '(No Subject)');
  setText('metaFrom', meta.from || 'Unknown Sender');
  setText('metaFromDomain', meta.from_domain || meta.sender_domain || 'Unknown');
  setText('metaReturnPath', meta.return_path || 'None');
  setText('metaTo', meta.to || 'Unknown');
  setText('metaDate', meta.date || 'Unknown');

  const originIntel = data.origin_intelligence || {};
  setText('metaHops', `${originIntel.total_hops || 0} intermediate relay hops`);

  // Protocol Badges (SPF, DKIM, DMARC, MX)
  const setProtocol = (badgeId, detailsId, passed, detailsText, passLabel = 'PASS', failLabel = 'FAIL') => {
    const badge = document.getElementById(badgeId);
    const det = document.getElementById(detailsId);
    if (badge) {
      if (passed) {
        badge.className = 'px-2 py-0.5 rounded text-[9px] font-bold font-mono uppercase bg-emerald-950 text-emerald-400 border border-emerald-700/60';
        badge.innerText = passLabel;
      } else {
        badge.className = 'px-2 py-0.5 rounded text-[9px] font-bold font-mono uppercase bg-red-950 text-red-400 border border-red-700/60';
        badge.innerText = failLabel;
      }
    }
    if (det) det.innerText = detailsText || '';
  };

  setProtocol('spfBadge', 'spfDetails', auth.spf_pass, auth.spf_details || (auth.spf_pass ? 'SPF Record authorizes sender IP' : 'Origin IP unauthorized in SPF record'));
  setProtocol('dkimBadge', 'dkimDetails', auth.dkim_pass, auth.dkim_details || (auth.dkim_pass ? 'Valid cryptographic signature' : 'No valid DKIM signature found'));
  setProtocol('dmarcBadge', 'dmarcDetails', auth.dmarc_pass, auth.dmarc_details || (auth.dmarc_pass ? 'DMARC alignment verified' : 'DMARC policy failed'));

  const hasMx = mx.has_mx_records;
  const mxCount = (mx.mx_records || []).length;
  setProtocol('mxBadge', 'mxDetails', hasMx, hasMx ? `${mxCount} valid MX exchanger records` : 'No MX records (Burner/Disposable domain)', 'VALID MX', 'NO MX');
}

function renderNarrativeAndLinks(data) {
  // Parse 3-bullet narrative
  const rawSummary = data.incident_summary || '';
  let threatSum = 'Threat evaluation completed.';
  let evidenceSum = 'All authentication protocols passed.';
  let actionSum = 'No action needed.';

  const lines = rawSummary.split('\n');
  lines.forEach(line => {
    const clean = line.trim();
    if (clean.startsWith('• Threat Summary:')) {
      threatSum = clean.replace('• Threat Summary:', '').trim();
    } else if (clean.startsWith('• Key Forensic Evidence:')) {
      evidenceSum = clean.replace('• Key Forensic Evidence:', '').trim();
    } else if (clean.startsWith('• Recommended Action:')) {
      actionSum = clean.replace('• Recommended Action:', '').trim();
    }
  });

  const sumEl = document.getElementById('narrativeThreatSummary');
  const evEl = document.getElementById('narrativeEvidence');
  const actEl = document.getElementById('narrativeAction');

  if (sumEl) sumEl.innerText = threatSum;
  if (evEl) evEl.innerText = evidenceSum;
  if (actEl) actEl.innerText = actionSum;

  // Hyperlinks & Payloads table
  const links = data.link_investigation || [];
  const linkBadge = document.getElementById('linkCountBadge');
  if (linkBadge) linkBadge.innerText = `${links.length} Link${links.length === 1 ? '' : 's'}`;

  const container = document.getElementById('linksContainer');
  if (!container) return;
  container.innerHTML = '';

  if (links.length === 0) {
    container.innerHTML = `<div class="p-3 text-center text-slate-500 font-mono text-[10px]">No embedded hyperlinks identified in payload.</div>`;
    return;
  }

  links.forEach(link => {
    const score = parseFloat(link.threat_score || 0);
    const tel = link.telemetry || {};
    
    let scoreBadgeColor = 'bg-emerald-950 text-emerald-400 border-emerald-700/60';
    if (score >= 80) scoreBadgeColor = 'bg-red-950 text-red-400 border-red-700/80';
    else if (score >= 50) scoreBadgeColor = 'bg-amber-950 text-amber-400 border-amber-700/80';

    const flags = [];
    if (tel.brand_impersonation) flags.push(`Brand: ${tel.detected_brand || 'Impersonation'}`);
    if (tel.sandbox_has_password) flags.push('Password Input');
    if (tel.external_form_action) flags.push('External Form Action');
    if (tel.suspicious_exfiltration) flags.push('Data Exfiltration');
    if (tel.domain_age_days >= 0 && tel.domain_age_days < 14) flags.push(`Zero-Day Domain (${tel.domain_age_days}d)`);
    if (tel.title_mismatch) flags.push('Title Mismatch');

    const flagHtml = flags.map(f => `<span class="px-1.5 py-0.5 rounded bg-red-950/80 border border-red-800/60 text-red-300 text-[9px] font-mono">${f}</span>`).join(' ');

    const card = document.createElement('div');
    card.className = 'p-2.5 rounded bg-slate-950/80 border border-slate-800 space-y-1.5 text-xs';
    card.innerHTML = `
      <div class="flex items-center justify-between">
        <span class="font-mono text-[11px] text-cyan-300 font-bold truncate max-w-[220px]" title="${link.url}">${link.url}</span>
        <span class="px-2 py-0.5 rounded font-mono text-[10px] font-bold ${scoreBadgeColor}">${Math.round(score)}/100</span>
      </div>
      <div class="flex flex-wrap gap-1">
        ${flagHtml || '<span class="text-slate-500 font-mono text-[9px]">Clean structural heuristics</span>'}
      </div>
    `;
    container.appendChild(card);
  });
}

function renderLeafletMap(originIntel) {
  if (!originIntel) return;

  const originIp = originIntel.originating_ip || 'Unknown';
  const originCountry = originIntel.origin_country || 'Unknown';
  const originIsp = originIntel.origin_isp || 'Unknown ISP';
  const isAnon = originIntel.is_anonymized_node || originIntel.is_proxy;

  const ipEl = document.getElementById('originIpText');
  const countryEl = document.getElementById('originCountryBadge');
  const ispEl = document.getElementById('originIspText');
  const flagEl = document.getElementById('originProxyFlag');

  if (ipEl) ipEl.innerText = originIp;
  if (countryEl) countryEl.innerText = originCountry;
  if (ispEl) ispEl.innerText = originIsp;

  if (flagEl) {
    if (isAnon) {
      flagEl.innerHTML = `
        <span class="px-2 py-0.5 rounded text-[9px] font-mono font-bold uppercase bg-red-950 text-red-400 border border-red-700/60">TOR / PROXY</span>
        <span class="block text-[9px] text-slate-400 font-mono truncate max-w-[140px]">${originIsp}</span>
      `;
    } else {
      flagEl.innerHTML = `
        <span class="px-2 py-0.5 rounded text-[9px] font-mono font-bold uppercase bg-emerald-950 text-emerald-400 border border-emerald-700/60">CLEAN ORIGIN</span>
        <span class="block text-[9px] text-slate-400 font-mono truncate max-w-[140px]">${originIsp}</span>
      `;
    }
  }

  // Hops container list
  const hops = originIntel.route_map || [];
  const hopsContainer = document.getElementById('hopsContainer');
  if (hopsContainer) {
    hopsContainer.innerHTML = '';
    if (hops.length === 0) {
      hopsContainer.innerHTML = `<div class="p-2 text-center text-slate-500 font-mono text-[10px]">No public relay hops extracted.</div>`;
    } else {
      hops.forEach((hop, idx) => {
        const isOrigin = (idx === 0);
        const item = document.createElement('div');
        item.className = 'p-1.5 rounded bg-slate-950/70 border border-slate-800/80 flex items-center justify-between text-[10px] font-mono';
        item.innerHTML = `
          <div class="flex items-center space-x-2">
            <span class="w-4 h-4 rounded-full ${isOrigin ? 'bg-red-500/20 text-red-400 border border-red-500/50' : 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/50'} flex items-center justify-center font-bold text-[9px]">
              ${hop.hop || (idx + 1)}
            </span>
            <span class="text-slate-200 font-bold">${hop.ip || 'Unknown IP'}</span>
          </div>
          <span class="text-slate-400">${hop.country || 'Unknown'} (${hop.city || 'Relay'})</span>
        `;
        hopsContainer.appendChild(item);
      });
    }
  }

  // Initialize or update Leaflet Map
  const mapDiv = document.getElementById('map');
  if (!mapDiv || typeof L === 'undefined') return;

  if (!mapInstance) {
    mapInstance = L.map('map', {
      zoomControl: true,
      attributionControl: false,
      scrollWheelZoom: false
    }).setView([20, 0], 2);

    // Standard OpenStreetMap with CSS inversion
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      maxZoom: 18
    }).addTo(mapInstance);

    mapMarkersGroup = L.layerGroup().addTo(mapInstance);
  } else {
    mapMarkersGroup.clearLayers();
    if (mapPolyline) {
      mapInstance.removeLayer(mapPolyline);
      mapPolyline = null;
    }
  }

  // Plot valid coordinates
  const validCoords = [];
  hops.forEach((hop, idx) => {
    const lat = parseFloat(hop.lat);
    const lon = parseFloat(hop.lon);
    if (!isNaN(lat) && !isNaN(lon) && (lat !== 0 || lon !== 0)) {
      validCoords.push([lat, lon]);
      const isOrigin = (idx === 0);

      const icon = L.divIcon({
        className: 'custom-leaflet-marker',
        html: `<div class="${isOrigin ? 'pulse-marker-origin' : 'pulse-marker-hop'}"></div>`,
        iconSize: isOrigin ? [16, 16] : [10, 10],
        iconAnchor: isOrigin ? [8, 8] : [5, 5]
      });

      const marker = L.marker([lat, lon], { icon }).addTo(mapMarkersGroup);
      marker.bindPopup(`
        <strong style="color:${isOrigin ? '#ef4444' : '#06b6d4'}">Hop #${hop.hop || (idx + 1)} ${isOrigin ? '(ORIGIN)' : ''}</strong><br/>
        IP: ${hop.ip || 'Unknown'}<br/>
        Location: ${hop.city || 'Unknown'}, ${hop.country || 'Unknown'}<br/>
        ISP: ${hop.isp || 'Unknown'}
      `);
    }
  });

  if (validCoords.length > 1) {
    mapPolyline = L.polyline(validCoords, {
      color: '#06b6d4',
      weight: 2,
      opacity: 0.8,
      dashArray: '4, 6'
    }).addTo(mapInstance);
  }

  if (validCoords.length > 0) {
    mapInstance.fitBounds(validCoords, { padding: [30, 30], maxZoom: 6 });
  } else {
    mapInstance.setView([20, 0], 2);
  }

  setTimeout(() => {
    mapInstance.invalidateSize();
  }, 200);
}

// =========================================================================
// PDF EXPORT CONTROLLER
// =========================================================================

async function exportDossierPdf(e) {
  if (e) e.preventDefault();
  if (!currentReport) {
    alert('No forensic report loaded to export.');
    return;
  }

  const btn = document.getElementById('exportPdfBtn');
  const origHtml = btn ? btn.innerHTML : '';

  try {
    if (btn) {
      btn.disabled = true;
      btn.innerHTML = `
        <svg class="w-3.5 h-3.5 animate-spin mr-1.5 inline" viewBox="0 0 24 24" fill="none" stroke="currentColor">
          <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-opacity="0.25" fill="none"/>
          <path d="M12 2a10 10 0 0 1 10 10" stroke="currentColor" stroke-width="2"/>
        </svg>
        <span>Generating PDF...</span>
      `;
    }

    const response = await fetch(`${API_BASE}/api/forensics/export-pdf`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(currentReport)
    });

    if (!response.ok) {
      throw new Error(`PDF generation failed (HTTP ${response.status})`);
    }

    const blob = await response.blob();
    const downloadUrl = window.URL.createObjectURL(blob);
    const hash = (currentReport.evidence_hash_sha256 || 'dossier').substring(0, 10);
    const a = document.createElement('a');
    a.href = downloadUrl;
    a.download = `TrustShield_Forensic_Dossier_${hash}.pdf`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(downloadUrl);
    a.remove();

  } catch (err) {
    console.error('PDF Export Error:', err);
    alert(`Failed to export PDF dossier:\n${err.message}`);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = origHtml;
    }
  }
}
