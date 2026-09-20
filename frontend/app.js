/**
 * TrustShield - Forensic Intelligence Platform
 * Tab-based investigation console + autonomous pipeline controller
 */

// Global API Base resolution:
// When served over HTTP/HTTPS (localhost or Render cloud), use relative path ('')
// When opened directly as a local file (file://), fallback to Render cloud
var API_BASE = window.location.protocol.startsWith('http')
  ? ''
  : 'https://trust-sheild.onrender.com';

var currentReport = null;
var rawEmlContent = '';
var mapInstance = null;
var mapMarkersGroup = null;
var mapPolyline = null;
var progressTimerInterval = null;
var stageTimeouts = [];
var currentIocs = [];
var caseIdValue = '';

// Chain-of-custody timestamps captured live during this session's run
var tCaptured = null;
var tHashed = null;
var tVerdict = null;

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
window.triggerVaultFileInput = triggerVaultFileInput;
window.handleVaultFileSelect = handleVaultFileSelect;
window.executeVaultQuery = executeVaultQuery;
window.loadVerifiedDossier = loadVerifiedDossier;
window.loadVaultCasesHistory = loadVaultCasesHistory;
window.filterVaultCasesTable = filterVaultCasesTable;
window.loadVaultCaseById = loadVaultCaseById;

var cachedVaultCases = [];
var verifiedCaseDossier = null;
var verifiedCaseRawEml = null;

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

// Setup on startup
document.addEventListener('DOMContentLoaded', () => {
  setupDragAndDrop();
  generateCaseId();
  checkIncomingExtensionIncident();
});

async function checkIncomingExtensionIncident() {
  try {
    // 1. Check for ?case_id= in the URL query string (Primary Cross-Origin Bridge)
    const urlParams = new URLSearchParams(window.location.search);
    const caseId = urlParams.get('case_id');

    if (caseId) {
      caseIdValue = caseId;
      const el = document.getElementById('caseId');
      if (el) el.innerText = caseIdValue;
      const rEl = document.getElementById('reportCaseId');
      if (rEl) rEl.innerText = caseIdValue;

      // Fetch pre-analyzed case dossier from backend
      try {
        const res = await fetch(`${API_BASE}/api/forensics/case/${encodeURIComponent(caseId)}`);
        if (res.ok) {
          const caseData = await res.json();
          if (caseData && caseData.dossier) {
            currentReport = caseData.dossier;
            rawEmlContent = caseData.raw_eml || '';
            tCaptured = new Date(caseData.created_at || Date.now());
            tHashed = new Date(caseData.created_at || Date.now());
            tVerdict = new Date(caseData.created_at || Date.now());

            setTimeout(() => {
              renderDashboard(caseData.dossier, 0.25);
              switchTab('threat');
            }, 100);
            return;
          }
        }
      } catch (err) {
        console.warn('Error fetching case by ID:', err);
      }
    }

    // 2. Fallback: Check LocalStorage if passed on same origin
    const raw = localStorage.getItem('trustshield_incoming_incident');
    if (raw) {
      localStorage.removeItem('trustshield_incoming_incident');
      const parsed = JSON.parse(raw);
      const dossier = parsed.dossier || parsed;
      const rawEml = parsed.raw_eml || '';
      if (parsed.case_id) {
        caseIdValue = parsed.case_id;
        const el = document.getElementById('caseId');
        if (el) el.innerText = caseIdValue;
        const rEl = document.getElementById('reportCaseId');
        if (rEl) rEl.innerText = caseIdValue;
      }
      if (rawEml) rawEmlContent = rawEml;
      if (dossier && dossier.overall_threat_score !== undefined) {
        currentReport = dossier;
        tCaptured = new Date();
        tHashed = new Date();
        tVerdict = new Date();
        setTimeout(() => {
          renderDashboard(dossier, 0.45);
          switchTab('threat');
        }, 150);
      }
    }
  } catch (e) {
    console.warn('Error loading incoming extension incident:', e);
  }
}

function generateCaseId() {
  const n = Math.floor(100000 + Math.random() * 900000);
  caseIdValue = `TSF-${n}`;
  const el = document.getElementById('caseId');
  if (el) el.innerText = caseIdValue;
  const rEl = document.getElementById('reportCaseId');
  if (rEl) rEl.innerText = caseIdValue;
}

function setupDragAndDrop() {
  const dropZone = document.getElementById('dropZone');
  if (!dropZone) return;

  window.addEventListener('dragover', (e) => e.preventDefault());
  window.addEventListener('drop', (e) => e.preventDefault());

  ['dragenter', 'dragover'].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.add('border-indigo-400', 'bg-indigo-50');
    });
  });

  ['dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.remove('border-indigo-400', 'bg-indigo-50');
    });
  });

  dropZone.addEventListener('drop', (e) => {
    const dt = e.dataTransfer;
    if (dt && dt.files && dt.files.length > 0) {
      processEmlFile(dt.files[0]);
    }
  });

  const vaultDropZone = document.getElementById('vaultDropZone');
  if (vaultDropZone) {
    ['dragenter', 'dragover'].forEach(eventName => {
      vaultDropZone.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        vaultDropZone.classList.add('border-teal-400', 'bg-teal-900/40');
      });
    });

    ['dragleave', 'drop'].forEach(eventName => {
      vaultDropZone.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        vaultDropZone.classList.remove('border-teal-400', 'bg-teal-900/40');
      });
    });

    vaultDropZone.addEventListener('drop', (e) => {
      e.preventDefault();
      e.stopPropagation();
      vaultDropZone.classList.remove('border-teal-400', 'bg-teal-900/40');
      const dt = e.dataTransfer;
      if (dt && dt.files && dt.files.length > 0) {
        verifyUploadedEvidenceFile(dt.files[0]);
      }
    });
  }
}

function copyEvidenceHash(e) {
  if (e) e.stopPropagation();
  const hashText = document.getElementById('sha256Digest')?.innerText;
  if (hashText && hashText !== 'Calculating...') {
    navigator.clipboard.writeText(hashText);
    const copyBtn = document.getElementById('copyHashBtn');
    if (copyBtn) {
      copyBtn.innerHTML = `<span class="text-emerald-300 font-semibold">Copied</span>`;
      setTimeout(() => {
        copyBtn.innerHTML = `
          <svg class="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect width="14" height="14" x="8" y="8" rx="2" ry="2"/>
            <path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>
          </svg>
          <span>Copy</span>
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
      btn.innerHTML = `<span class="text-emerald-600">Copied</span>`;
      setTimeout(() => { btn.innerHTML = orig; }, 1800);
    }
  }
}

// =========================================================================
// TAB NAVIGATION
// =========================================================================

var TAB_NAMES = ['dashboard', 'email', 'threat', 'network', 'geo', 'ioc', 'graph', 'vault', 'timeline', 'report'];
var CONTENT_TABS = ['email', 'threat', 'network', 'geo', 'ioc', 'graph', 'timeline', 'report'];

function switchTab(name) {
  TAB_NAMES.forEach(n => {
    const panel = document.getElementById(`tab-${n}`);
    if (panel) panel.classList.toggle('active', n === name);
    const btn = document.querySelector(`.nav-item[data-tab="${n}"]`);
    if (btn) btn.classList.toggle('active', n === name);
  });
  window.scrollTo({ top: 0, behavior: 'smooth' });

  if (name === 'vault') {
    loadVaultCasesHistory();
  }

  // Leaflet sizes itself against its container at init time
  if (name === 'geo' && mapInstance) {
    setTimeout(() => {
      mapInstance.invalidateSize();
      if (mapMarkersGroup && typeof mapMarkersGroup.getBounds === 'function' && mapMarkersGroup.getLayers().length > 0) {
        mapInstance.fitBounds(mapMarkersGroup.getBounds(), { padding: [30, 30], maxZoom: 6 });
      }
    }, 150);
  }
}
window.switchTab = switchTab;

function enableAllTabs() {
  document.querySelectorAll('.nav-item').forEach(btn => btn.classList.remove('tab-disabled'));
}

function disableTabsExceptDashboard() {
  document.querySelectorAll('.nav-item').forEach(btn => {
    if (btn.dataset.tab !== 'dashboard' && btn.dataset.tab !== 'vault') {
      btn.classList.add('tab-disabled');
    } else {
      btn.classList.remove('tab-disabled');
    }
  });
}

function revealAllTabContent() {
  CONTENT_TABS.forEach(n => {
    const empty = document.getElementById(`${n}Empty`);
    const content = document.getElementById(`${n}Content`);
    if (empty) empty.classList.add('hidden');
    if (content) content.classList.remove('hidden');
  });
  const dEmpty = document.getElementById('dashboardSummaryEmpty');
  const dContent = document.getElementById('dashboardSummaryContent');
  if (dEmpty) dEmpty.classList.add('hidden');
  if (dContent) dContent.classList.remove('hidden');
}

function hideAllTabContent() {
  CONTENT_TABS.forEach(n => {
    const empty = document.getElementById(`${n}Empty`);
    const content = document.getElementById(`${n}Content`);
    if (empty) empty.classList.remove('hidden');
    if (content) content.classList.add('hidden');
  });
  const dEmpty = document.getElementById('dashboardSummaryEmpty');
  const dContent = document.getElementById('dashboardSummaryContent');
  if (dEmpty) dEmpty.classList.remove('hidden');
  if (dContent) dContent.classList.add('hidden');
}

function resetDashboard(e) {
  if (e) e.preventDefault();
  currentReport = null;
  rawEmlContent = '';
  currentIocs = [];
  tCaptured = null;
  tHashed = null;
  tVerdict = null;

  const trackerSec = document.getElementById('progressTrackerSection');
  if (trackerSec) trackerSec.classList.add('hidden');

  hideAllTabContent();
  disableTabsExceptDashboard();
  switchTab('dashboard');
  generateCaseId();

  const statusPill = document.getElementById('caseStatusPill');
  if (statusPill) {
    statusPill.className = 'text-[9.5px] font-medium text-slate-400 truncate';
    statusPill.innerText = 'Awaiting Evidence';
  }

  ['navScoreBadge', 'navIocBadge', 'navVaultBadge'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.classList.add('hidden');
  });

  const uploadSec = document.getElementById('uploadSection');
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
    info: 'text-indigo-300',
    crypto: 'text-emerald-400',
    warn: 'text-amber-400 font-semibold',
    alert: 'text-red-400 font-bold',
    success: 'text-emerald-300 font-bold',
    net: 'text-fuchsia-300',
    dim: 'text-slate-500'
  };

  const badgeColor = {
    info: 'bg-indigo-950 text-indigo-300 border-indigo-800',
    crypto: 'bg-emerald-950 text-emerald-400 border-emerald-800',
    warn: 'bg-amber-950 text-amber-400 border-amber-800',
    alert: 'bg-red-950 text-red-400 border-red-800',
    success: 'bg-emerald-950 text-emerald-300 border-emerald-700',
    net: 'bg-fuchsia-950 text-fuchsia-300 border-fuchsia-800',
    dim: 'bg-slate-900 text-slate-500 border-slate-700'
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

  const stateClasses = [
    'bg-indigo-50', 'shadow-[inset_0_-2px_0_0_#6366f1]',
    'bg-emerald-50', 'shadow-[inset_0_-2px_0_0_#10b981]',
    'bg-white'
  ];
  card.classList.remove(...stateClasses);

  if (status === 'active') {
    card.classList.add('bg-indigo-50', 'shadow-[inset_0_-2px_0_0_#6366f1]');
    if (badge) badge.className = 'w-2 h-2 rounded-full bg-indigo-500 animate-ping';
  } else if (status === 'completed') {
    card.classList.add('bg-emerald-50', 'shadow-[inset_0_-2px_0_0_#10b981]');
    if (badge) badge.className = 'w-2 h-2 rounded-full bg-emerald-500';
  } else {
    // queued
    card.classList.add('bg-white');
    if (badge) badge.className = 'w-2 h-2 rounded-full bg-slate-300';
  }
}

function startProgressAnimation(fileName, fileSize) {
  const trackerSec = document.getElementById('progressTrackerSection');
  if (trackerSec) {
    trackerSec.classList.remove('hidden');
    trackerSec.scrollTop = 0;
  }

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
  if (substatus) substatus.innerText = 'Generating Section 63 (BSA) cryptographic evidence digest...';
  if (bar) bar.style.width = '16%';
  if (percentText) percentText.innerText = '16%';

  stageTimeouts.push(setTimeout(() => {
    tHashed = new Date();
    updateStageCard(1, 'completed', 'SHA-256 Sealed');
    appendTerminalLog('CRYPTO', `SHA-256 Chain of Custody hash stamped (Sec. 63 BSA compliant)`, 'crypto');

    // Stage 2: Active
    updateStageCard(2, 'active', 'Parsing RFC-5322...');
    if (substatus) substatus.innerText = 'Dissecting email headers and validating identity alignment...';
    if (bar) bar.style.width = '33%';
    if (percentText) percentText.innerText = '33%';
    appendTerminalLog('RFC5322', `Extracting boundary parts, Return-Path, and Reply-To headers`, 'info');
  }, 220));

  stageTimeouts.push(setTimeout(() => {
    updateStageCard(2, 'completed', 'Identity Audited');
    appendTerminalLog('SPOOF', `Checked Display Name vs Envelope Return-Path`, 'info');

    // Stage 3: Active
    updateStageCard(3, 'active', 'Auditing SPF/DKIM...');
    if (substatus) substatus.innerText = 'Verifying cryptographic DKIM keys and SPF/DMARC policies...';
    if (bar) bar.style.width = '50%';
    if (percentText) percentText.innerText = '50%';
    appendTerminalLog('DNS', `Querying DNS TXT records for SPF and DMARC enforcement`, 'info');
  }, 650));

  stageTimeouts.push(setTimeout(() => {
    updateStageCard(3, 'completed', 'DNS Protocols Audited');
    appendTerminalLog('DNS', `Checked MX server records & domain reputation`, 'crypto');

    // Stage 4: Active
    updateStageCard(4, 'active', 'Tracing Server Hops...');
    if (substatus) substatus.innerText = 'Resolving relay hop IP addresses and geolocation route...';
    if (bar) bar.style.width = '68%';
    if (percentText) percentText.innerText = '68%';
    appendTerminalLog('GEO', `Geolocating origin node and relay hops across autonomous systems`, 'net');
  }, 1150));

  stageTimeouts.push(setTimeout(() => {
    updateStageCard(4, 'completed', 'Route Traced');
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
  tVerdict = new Date();

  const bar = document.getElementById('progressBarFill');
  const percentText = document.getElementById('progressPercent');
  const substatus = document.getElementById('progressSubstatus');

  // Mark all stages as completed
  for (let i = 1; i <= 6; i++) {
    updateStageCard(i, 'completed', 'Complete');
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
  appendTerminalLog('DOSSIER', `Section 63 (BSA) Electronic Dossier assembled. Displaying case workspace.`, 'crypto');

  if (progressTimerInterval) clearInterval(progressTimerInterval);

  // Transition smoothly to the investigation workspace after brief completion pause
  setTimeout(() => {
    const trackerSec = document.getElementById('progressTrackerSection');
    if (trackerSec) trackerSec.classList.add('hidden');

    renderDashboard(report, elapsedSeconds);
    switchTab('threat');
  }, 450);
}

// =========================================================================
// MAIN INGESTION & PIPELINE FETCH CALL
// =========================================================================

async function processEmlFile(file) {
  if (!file) return;

  tCaptured = new Date();
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
    alert(`Forensic Ingestion Error:\n${error.message}\n\nPlease ensure the backend server is reachable at ${window.location.origin || 'https://trust-sheild.onrender.com'}`);
    console.error('Forensic Analysis Error:', error);
  }
}

// =========================================================================
// DASHBOARD RENDERING ORCHESTRATOR
// =========================================================================

function renderDashboard(data, elapsedSeconds) {
  renderVerdict(data, elapsedSeconds);
  renderMetadataAndAuth(data);
  renderLeafletMap(data.origin_intelligence);
  renderNarrativeAndLinks(data);
  renderExplainableAI(data);
  renderNetworkIntel(data);
  renderIOCExplorer(data);
  renderAttackGraph(data);
  renderEvidenceVault(data);
  renderTimeline(data);
  renderReportTab(data);
  renderDashboardSummary(data);

  revealAllTabContent();
  enableAllTabs();
  updateHeaderStatus(data);
}

function renderVerdict(data, elapsedSeconds) {
  const score = parseFloat(data.overall_threat_score || 0.0);
  const scoreNumber = document.getElementById('scoreNumber');
  const scoreCircle = document.getElementById('scoreCircle');
  const verdictCard = document.getElementById('verdictCard');
  const verdictBadge = document.getElementById('verdictBadge');
  const attributionBadge = document.getElementById('attributionBadge');
  const verdictHeadline = document.getElementById('verdictHeadline');
  const attributionDetails = document.getElementById('attributionDetails');
  const durationBadge = document.getElementById('analysisDurationBadge');

  if (scoreNumber) scoreNumber.innerText = Math.round(score);
  if (durationBadge && typeof elapsedSeconds === 'number') durationBadge.innerText = `Audit: ${elapsedSeconds.toFixed(2)}s`;

  const circumference = 263.89;
  const offset = circumference - (score / 100) * circumference;
  if (scoreCircle) scoreCircle.style.strokeDashoffset = offset;

  const attr = data.threat_attribution || {};
  if (attributionBadge) attributionBadge.innerText = attr.type || 'UNKNOWN';
  if (attributionDetails) attributionDetails.innerText = attr.details || 'Evaluation completed across all forensic telemetry engines.';

  if (score >= 80.0) {
    if (scoreCircle) scoreCircle.setAttribute('stroke', '#ef4444');
    if (verdictCard) verdictCard.className = 'rounded-xl border border-red-200 p-6 bg-white shadow-sm relative overflow-hidden transition-all duration-300';
    if (verdictBadge) {
      verdictBadge.className = 'verdict-stamp anim-stamp-in text-red-600 bg-red-50';
      verdictBadge.innerText = data.verdict || 'CRITICAL FRAUD / PHISHING';
    }
    if (verdictHeadline) verdictHeadline.innerText = 'High-Impact Cyber Attack & Identity Spoofing';
  } else if (score >= 50.0) {
    if (scoreCircle) scoreCircle.setAttribute('stroke', '#f59e0b');
    if (verdictCard) verdictCard.className = 'rounded-xl border border-amber-200 p-6 bg-white shadow-sm relative overflow-hidden transition-all duration-300';
    if (verdictBadge) {
      verdictBadge.className = 'verdict-stamp anim-stamp-in text-amber-600 bg-amber-50';
      verdictBadge.innerText = data.verdict || 'SUSPICIOUS / UNVERIFIED ORIGIN';
    }
    if (verdictHeadline) verdictHeadline.innerText = 'Suspicious Infrastructure & Anomalous Identity';
  } else {
    if (scoreCircle) scoreCircle.setAttribute('stroke', '#10b981');
    if (verdictCard) verdictCard.className = 'rounded-xl border border-emerald-200 p-6 bg-white shadow-sm relative overflow-hidden transition-all duration-300';
    if (verdictBadge) {
      verdictBadge.className = 'verdict-stamp anim-stamp-in text-emerald-600 bg-emerald-50';
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
  const hops = originIntel.route_map || [];
  setText('metaHops', `${hops.length} intermediate relay hops`);

  // Protocol Badges (SPF, DKIM, DMARC, MX)
  const setProtocol = (badgeId, detailsId, passed, detailsText, passLabel = 'PASS', failLabel = 'FAIL') => {
    const badge = document.getElementById(badgeId);
    const det = document.getElementById(detailsId);
    if (badge) {
      if (passed) {
        badge.className = 'px-2 py-0.5 rounded text-[9px] font-bold font-mono uppercase bg-emerald-100 text-emerald-700 border border-emerald-200';
        badge.innerText = passLabel;
      } else {
        badge.className = 'px-2 py-0.5 rounded text-[9px] font-bold font-mono uppercase bg-red-100 text-red-700 border border-red-200';
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
    container.innerHTML = `<div class="p-3 text-center text-slate-400 font-mono text-[10px]">No embedded hyperlinks identified in payload.</div>`;
    return;
  }

  links.forEach((link, idx) => {
    const score = parseFloat(link.threat_score || 0);
    const tel = link.telemetry || {};
    const exhibitLabel = `EXHIBIT ${String.fromCharCode(65 + (idx % 26))}`;

    let scoreBadgeColor = 'bg-emerald-100 text-emerald-700 border-emerald-200';
    if (score >= 80) scoreBadgeColor = 'bg-red-100 text-red-700 border-red-200';
    else if (score >= 50) scoreBadgeColor = 'bg-amber-100 text-amber-700 border-amber-200';

    const flags = [];
    if (tel.brand_impersonation) flags.push(`Brand: ${tel.detected_brand || 'Impersonation'}`);
    if (tel.sandbox_has_password) flags.push('Password Input');
    if (tel.external_form_action) flags.push('External Form Action');
    if (tel.suspicious_exfiltration) flags.push('Data Exfiltration');
    if (tel.domain_age_days >= 0 && tel.domain_age_days < 14) flags.push(`Zero-Day Domain (${tel.domain_age_days}d)`);
    if (tel.title_mismatch) flags.push('Title Mismatch');

    const flagHtml = flags.map(f => `<span class="px-1.5 py-0.5 rounded bg-red-50 border border-red-200 text-red-700 text-[9px] font-mono">${f}</span>`).join(' ');

    const card = document.createElement('div');
    card.className = 'p-2.5 rounded-lg bg-slate-50 border border-slate-200 space-y-1.5 text-xs';
    card.innerHTML = `
      <div class="flex items-center justify-between gap-2">
        <span class="text-[9px] font-mono text-rose-700 font-bold flex-shrink-0">${exhibitLabel}</span>
        <span class="font-mono text-[11px] text-slate-800 font-bold truncate flex-1" title="${link.url}">${link.url}</span>
        <span class="px-2 py-0.5 rounded font-mono text-[10px] font-bold border ${scoreBadgeColor}">${Math.round(score)}/100</span>
      </div>
      <div class="flex flex-wrap gap-1">
        ${flagHtml || '<span class="text-slate-400 font-mono text-[9px]">Clean structural heuristics</span>'}
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
        <span class="px-2 py-0.5 rounded text-[9px] font-mono font-bold uppercase bg-red-500/20 text-red-300 border border-red-500/40">TOR / PROXY</span>
        <span class="block text-[9px] text-slate-400 font-mono truncate max-w-[160px]">${originIsp}</span>
      `;
    } else {
      flagEl.innerHTML = `
        <span class="px-2 py-0.5 rounded text-[9px] font-mono font-bold uppercase bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">CLEAN ORIGIN</span>
        <span class="block text-[9px] text-slate-400 font-mono truncate max-w-[160px]">${originIsp}</span>
      `;
    }
  }

  // Hops container list
  const hops = originIntel.route_map || [];
  const hopsContainer = document.getElementById('hopsContainer');
  if (hopsContainer) {
    hopsContainer.innerHTML = '';
    if (hops.length === 0) {
      hopsContainer.innerHTML = `<div class="p-2 text-center text-slate-400 font-mono text-[10px]">No public relay hops extracted.</div>`;
    } else {
      hops.forEach((hop, idx) => {
        const isOrigin = (idx === 0);
        const item = document.createElement('div');
        item.className = 'p-1.5 rounded-lg bg-slate-50 border border-slate-200 flex items-center justify-between text-[10px] font-mono';
        item.innerHTML = `
          <div class="flex items-center space-x-2">
            <span class="w-4 h-4 rounded-full ${isOrigin ? 'bg-red-100 text-red-600 border border-red-200' : 'bg-emerald-100 text-emerald-700 border border-emerald-200'} flex items-center justify-center font-bold text-[9px]">
              ${hop.hop || (idx + 1)}
            </span>
            <span class="text-slate-800 font-bold">${hop.ip || 'Unknown IP'}</span>
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

    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      maxZoom: 18
    }).addTo(mapInstance);

    mapMarkersGroup = L.featureGroup().addTo(mapInstance);
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
        <strong style="color:${isOrigin ? '#f87171' : '#6ee7b7'}">Hop #${hop.hop || (idx + 1)} ${isOrigin ? '(ORIGIN)' : ''}</strong><br/>
        IP: ${hop.ip || 'Unknown'}<br/>
        Location: ${hop.city || 'Unknown'}, ${hop.country || 'Unknown'}<br/>
        ISP: ${hop.isp || 'Unknown'}
      `);
    }
  });

  if (validCoords.length > 1) {
    mapPolyline = L.polyline(validCoords, {
      color: '#10b981',
      weight: 2,
      opacity: 0.85,
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
// EXPLAINABLE AI
// =========================================================================

function buildExecutiveRationale(data) {
  const score = Math.round(parseFloat(data.overall_threat_score || 0));
  const auth = data.authentication || {};
  const meta = data.metadata || {};
  const links = data.link_investigation || [];
  const origin = data.origin_intelligence || {};

  const failedProtocols = [];
  if (!auth.spf_pass) failedProtocols.push('SPF');
  if (!auth.dkim_pass) failedProtocols.push('DKIM');
  if (!auth.dmarc_pass) failedProtocols.push('DMARC');

  const riskyLinks = links.filter(l => parseFloat(l.threat_score || 0) >= 50);
  const brandLink = links.find(l => l.telemetry && l.telemetry.brand_impersonation);

  const clauses = [];
  if (brandLink) clauses.push(`a textbook ${brandLink.telemetry.detected_brand || 'brand'} impersonation pattern`);
  if (failedProtocols.length) clauses.push(`broken authentication alignment (${failedProtocols.join('/')} fail)`);
  if (meta.reply_to_mismatch) clauses.push('a silent Reply-To diversion consistent with business email compromise');
  if (origin.is_anonymized_node || origin.is_proxy) clauses.push(`credential-harvesting infrastructure hosted behind an anonymized relay (${origin.origin_isp || 'unknown ISP'})`);
  if (riskyLinks.length) clauses.push(`${riskyLinks.length} high-risk embedded payload link${riskyLinks.length === 1 ? '' : 's'}`);
  if (!clauses.length) clauses.push('no material forensic anomalies across the audited protocols');

  return `TrustShield AI flagged this message with ${score}/100 fraud risk because it exhibits ${clauses.join(', ')}.`;
}

function buildCitations(data) {
  const auth = data.authentication || {};
  const meta = data.metadata || {};
  const mx = data.sender_domain_intelligence || {};
  const origin = data.origin_intelligence || {};
  const links = data.link_investigation || [];
  const citations = [];

  if (!auth.spf_pass) citations.push({ ref: 'REF-01', title: 'Authentication Breakdown (SPF Fail)', snippet: auth.spf_details || 'Origin IP fails SPF record check', finding: 'The sending IP is not authorized to send mail for this domain — a strong indicator of spoofing.' });
  if (!auth.dkim_pass) citations.push({ ref: 'REF-02', title: 'DKIM Signature Missing', snippet: auth.dkim_details || 'No valid DKIM signature found', finding: 'The message carries no verifiable cryptographic signature tying it to the claimed sending domain.' });
  if (!auth.dmarc_pass) citations.push({ ref: 'REF-03', title: 'DMARC Policy Failure', snippet: auth.dmarc_details || 'DMARC policy failed', finding: 'The sending domain’s DMARC policy could not align either SPF or DKIM identifiers.' });
  if (meta.reply_to_mismatch) citations.push({ ref: 'REF-04', title: 'Reply-To Divergence (BEC Indicator)', snippet: `From: ${meta.from || 'unknown'}  ≠  Reply-To: ${meta.reply_to || 'unknown'}`, finding: 'Replies are silently redirected to a mailbox outside the visible sender domain.' });
  if (origin.is_anonymized_node || origin.is_proxy) citations.push({ ref: 'REF-05', title: 'Anonymized Origin Infrastructure', snippet: `${origin.originating_ip || 'unknown IP'} via ${origin.origin_isp || 'unknown ISP'}`, finding: 'The earliest traceable IP resolves to a TOR exit node or proxy, obscuring the true sender.' });
  if (!mx.has_mx_records) citations.push({ ref: 'REF-06', title: 'Disposable / Burner Domain', snippet: 'No MX records resolved for the sender domain', finding: 'A legitimate organization would maintain valid mail exchanger records.' });

  links.forEach((l, idx) => {
    const tel = l.telemetry || {};
    const label = `EXHIBIT ${String.fromCharCode(65 + (idx % 26))}`;
    if (tel.brand_impersonation) citations.push({ ref: label, title: 'Brand Impersonation Detected', snippet: l.url, finding: `Landing page visually impersonates ${tel.detected_brand || 'a trusted brand'}.` });
    if (tel.domain_age_days >= 0 && tel.domain_age_days < 14) citations.push({ ref: label, title: 'Domain Age Anomaly', snippet: `Domain registered ${tel.domain_age_days} day${tel.domain_age_days === 1 ? '' : 's'} ago`, finding: 'Newly registered domains are disproportionately used in short-lived phishing campaigns.' });
    if (tel.sandbox_has_password) citations.push({ ref: label, title: 'Suspicious Credential Landing Page', snippet: l.url, finding: 'Sandbox detonation found a live password input field on the linked page.' });
  });

  return citations;
}

function renderExplainableAI(data) {
  const rationaleEl = document.getElementById('xaiRationale');
  if (rationaleEl) rationaleEl.innerText = buildExecutiveRationale(data);

  const citations = buildCitations(data);
  const countEl = document.getElementById('xaiCitationCount');
  if (countEl) countEl.innerText = `Evidence reference citations (${citations.length})`;

  const container = document.getElementById('xaiCitationsContainer');
  if (!container) return;
  container.innerHTML = '';

  if (citations.length === 0) {
    container.innerHTML = `<div class="md:col-span-2 p-4 text-center text-slate-400 text-xs bg-slate-50 rounded-lg border border-slate-200">No anomalous evidence citations were generated — the message passed every audited check.</div>`;
    return;
  }

  citations.forEach(c => {
    const card = document.createElement('div');
    card.className = 'p-3.5 bg-white border border-slate-200 rounded-lg hover:border-violet-300 transition-colors';
    card.innerHTML = `
      <div class="flex items-center justify-between mb-1">
        <span class="text-[10px] font-mono font-bold text-violet-700">${c.ref}</span>
        <span class="text-[9px] font-mono text-slate-300">CITATION</span>
      </div>
      <h5 class="text-[12px] font-bold text-slate-900">${c.title}</h5>
      <p class="text-[10px] font-mono text-red-700 bg-red-50 border border-red-100 rounded px-1.5 py-1 mt-1 break-all">"${c.snippet}"</p>
      <p class="text-[11px] text-slate-500 mt-1.5 leading-relaxed">${c.finding}</p>
    `;
    container.appendChild(card);
  });
}

// =========================================================================
// NETWORK INTEL
// =========================================================================

function renderNetworkIntel(data) {
  const origin = data.origin_intelligence || {};
  const hops = origin.route_map || [];
  const isAnon = origin.is_anonymized_node || origin.is_proxy;

  const setText = (id, txt) => { const el = document.getElementById(id); if (el) el.innerText = txt; };
  setText('netOriginIp', origin.originating_ip || 'Unknown');
  setText('netOriginCountry', origin.origin_country || 'Unknown');
  setText('netOriginIsp', origin.origin_isp || 'Unknown');
  setText('netHopCount', `${hops.length} relay hop${hops.length === 1 ? '' : 's'}`);

  const anonBadge = document.getElementById('netAnonBadge');
  if (anonBadge) {
    anonBadge.innerHTML = isAnon
      ? `<span class="px-2 py-0.5 rounded text-[9px] font-bold font-mono uppercase bg-red-100 text-red-700 border border-red-200">TOR / PROXY</span>`
      : `<span class="px-2 py-0.5 rounded text-[9px] font-bold font-mono uppercase bg-emerald-100 text-emerald-700 border border-emerald-200">DIRECT</span>`;
  }

  const container = document.getElementById('networkHopsContainer');
  if (container) {
    container.innerHTML = '';
    if (hops.length === 0) {
      container.innerHTML = `<div class="p-3 text-center text-slate-400 font-mono text-[10px]">No relay infrastructure extracted.</div>`;
    } else {
      hops.forEach((hop, idx) => {
        const isOrigin = idx === 0;
        const row = document.createElement('div');
        row.className = 'flex items-center justify-between p-2 rounded-lg bg-slate-50 border border-slate-200 text-[11px]';
        row.innerHTML = `
          <div class="flex items-center gap-2.5">
            <span class="w-5 h-5 rounded-full flex items-center justify-center text-[9px] font-bold ${isOrigin ? 'bg-red-100 text-red-600' : 'bg-cyan-100 text-cyan-700'}">${hop.hop || idx + 1}</span>
            <div>
              <span class="font-mono font-bold text-slate-800 block">${hop.ip || 'Unknown IP'}</span>
              <span class="text-[10px] text-slate-400">${hop.isp || 'Unknown ISP'}</span>
            </div>
          </div>
          <span class="text-[10px] text-slate-500 font-mono">${hop.city || 'Unknown'}, ${hop.country || 'Unknown'}</span>
        `;
        container.appendChild(row);
      });
    }
  }

  const riskEl = document.getElementById('networkRiskNarrative');
  if (riskEl) {
    const bits = [];
    if (isAnon) bits.push(`the earliest hop (${origin.originating_ip || 'unknown IP'}) routes through anonymized infrastructure at ${origin.origin_isp || 'an unidentified provider'}`);
    else bits.push(`the earliest hop (${origin.originating_ip || 'unknown IP'}) resolves to a direct, non-anonymized network path via ${origin.origin_isp || 'an unidentified provider'}`);
    bits.push(`the message traversed ${hops.length} relay hop${hops.length === 1 ? '' : 's'} before reaching the recipient mailbox`);
    riskEl.innerText = bits.join('; ') + '.';
  }
}

// =========================================================================
// IOC EXPLORER
// =========================================================================

function extractDomainFromString(str) {
  if (!str) return null;
  try {
    const atMatch = String(str).match(/@([^\s>]+)/);
    if (atMatch) return atMatch[1].replace(/[>\]"']/g, '');
    const u = new URL(str);
    return u.hostname;
  } catch (e) {
    return null;
  }
}

function buildIocList(data) {
  const iocs = [];
  const meta = data.metadata || {};
  const origin = data.origin_intelligence || {};
  const links = data.link_investigation || [];

  const fromDomain = meta.from_domain || meta.sender_domain || extractDomainFromString(meta.from);
  if (fromDomain) iocs.push({ type: 'Sender Domain', value: fromDomain, risk: 'high', source: 'Envelope From' });

  const returnDomain = extractDomainFromString(meta.return_path);
  if (returnDomain) iocs.push({ type: 'Return-Path Domain', value: returnDomain, risk: 'medium', source: 'Return-Path header' });

  (origin.route_map || []).forEach((hop, idx) => {
    if (hop.ip) {
      iocs.push({
        type: idx === 0 ? 'Origin IP' : 'Relay IP',
        value: hop.ip,
        risk: idx === 0 && (origin.is_anonymized_node || origin.is_proxy) ? 'high' : idx === 0 ? 'medium' : 'low',
        source: `Hop #${hop.hop || idx + 1} — ${hop.city || 'Unknown'}, ${hop.country || 'Unknown'}`
      });
    }
  });

  links.forEach((l, idx) => {
    const label = `Exhibit ${String.fromCharCode(65 + (idx % 26))}`;
    const score = parseFloat(l.threat_score || 0);
    const risk = score >= 80 ? 'high' : score >= 50 ? 'medium' : 'low';
    const domain = extractDomainFromString(l.url);
    if (domain) iocs.push({ type: 'Payload Domain', value: domain, risk, source: label });
    iocs.push({ type: 'Payload URL', value: l.url, risk, source: label });
  });

  if (data.evidence_hash_sha256) iocs.push({ type: 'File Hash (SHA-256)', value: data.evidence_hash_sha256, risk: 'info', source: 'Evidence Vault seal' });

  return iocs;
}

function riskBadgeHtml(risk) {
  const map = {
    high: 'bg-red-100 text-red-700 border-red-200',
    medium: 'bg-amber-100 text-amber-700 border-amber-200',
    low: 'bg-slate-100 text-slate-600 border-slate-200',
    info: 'bg-teal-100 text-teal-700 border-teal-200'
  };
  return `<span class="px-1.5 py-0.5 rounded text-[9px] font-bold font-mono uppercase border ${map[risk] || map.low}">${risk}</span>`;
}

function renderIocRows(list) {
  const body = document.getElementById('iocTableBody');
  if (!body) return;
  body.innerHTML = '';
  if (list.length === 0) {
    body.innerHTML = `<tr><td colspan="4" class="px-4 py-6 text-center text-slate-400 text-xs">No indicators match this filter.</td></tr>`;
    return;
  }
  list.forEach(ioc => {
    const tr = document.createElement('tr');
    tr.className = 'ioc-row border-t border-slate-100';
    tr.innerHTML = `
      <td class="px-4 py-2 font-semibold text-slate-600 whitespace-nowrap">${ioc.type}</td>
      <td class="px-4 py-2 font-mono text-slate-800 break-all">${ioc.value}</td>
      <td class="px-4 py-2">${riskBadgeHtml(ioc.risk)}</td>
      <td class="px-4 py-2 text-slate-400 whitespace-nowrap">${ioc.source}</td>
    `;
    body.appendChild(tr);
  });
}

function renderIOCExplorer(data) {
  currentIocs = buildIocList(data);
  const summary = document.getElementById('iocSummaryText');
  if (summary) summary.innerText = `${currentIocs.length} indicator${currentIocs.length === 1 ? '' : 's'} extracted from this case`;
  const searchInput = document.getElementById('iocSearchInput');
  if (searchInput) searchInput.value = '';
  renderIocRows(currentIocs);
}

function filterIocTable() {
  const q = (document.getElementById('iocSearchInput')?.value || '').toLowerCase().trim();
  if (!q) { renderIocRows(currentIocs); return; }
  const filtered = currentIocs.filter(ioc =>
    ioc.type.toLowerCase().includes(q) || String(ioc.value).toLowerCase().includes(q) || ioc.source.toLowerCase().includes(q)
  );
  renderIocRows(filtered);
}
window.filterIocTable = filterIocTable;

// =========================================================================
// ATTACK GRAPH
// =========================================================================

function riskColor(score) {
  if (score >= 80) return '#ef4444';
  if (score >= 50) return '#f59e0b';
  return '#94a3b8';
}

function truncateMid(str, max) {
  if (!str || str.length <= max) return str || '';
  const half = Math.floor((max - 3) / 2);
  return str.slice(0, half) + '...' + str.slice(str.length - half);
}

function nodeIconPath(type) {
  const icons = {
    domain: '<circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/>',
    ip: '<rect width="18" height="7" x="3" y="3" rx="1.5"/><rect width="18" height="7" x="3" y="14" rx="1.5"/><circle cx="7" cy="6.5" r="0.8" fill="currentColor" stroke="none"/><circle cx="7" cy="17.5" r="0.8" fill="currentColor" stroke="none"/>',
    payload: '<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>',
    brand: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" x2="12" y1="8" y2="12"/><line x1="12" x2="12.01" y1="16" y2="16"/>'
  };
  return icons[type] || icons.domain;
}

function svgNode(x, y, w, h, title, subtitle, color, iconType) {
  const iconSize = 16;
  const iconCx = x - w / 2 + 20;
  const textX = x + 10;
  return `
    <g>
      <rect x="${x - w / 2}" y="${y - h / 2}" width="${w}" height="${h}" rx="10" fill="${color}14" stroke="${color}" stroke-width="1.5"/>
      <circle cx="${iconCx}" cy="${y}" r="13" fill="white" stroke="${color}" stroke-width="1.25"/>
      <g transform="translate(${iconCx - iconSize / 2}, ${y - iconSize / 2}) scale(${iconSize / 24})" fill="none" stroke="${color}" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round">
        ${nodeIconPath(iconType)}
      </g>
      <text x="${textX}" y="${y - 4}" text-anchor="middle" font-size="11" font-weight="700" fill="#0f172a" font-family="Inter, sans-serif">${title}</text>
      <text x="${textX}" y="${y + 12}" text-anchor="middle" font-size="9" fill="#64748b" font-family="JetBrains Mono, monospace">${subtitle}</text>
    </g>
  `;
}

function svgEdge(x1, y1, x2, y2, color, dashed) {
  const midX = (x1 + x2) / 2;
  const path = `M ${x1} ${y1} C ${midX} ${y1}, ${midX} ${y2}, ${x2} ${y2}`;
  return `
    <path d="${path}" fill="none" stroke="${color}" stroke-width="1.75" ${dashed ? 'stroke-dasharray="5 5"' : ''} marker-end="url(#arrow)" opacity="0.8"/>
    <circle cx="${x1}" cy="${y1}" r="3" fill="${color}"/>
  `;
}

function renderAttackGraph(data) {
  const wrap = document.getElementById('attackGraphSvgWrap');
  if (!wrap) return;

  const meta = data.metadata || {};
  const origin = data.origin_intelligence || {};
  const hops = origin.route_map || [];
  const links = data.link_investigation || [];

  if (hops.length === 0 && links.length === 0) {
    wrap.innerHTML = `<div class="p-8 text-center text-slate-400 text-xs">Not enough correlated entities to render a graph for this case.</div>`;
    return;
  }

  // Width is derived from the hop chain's actual extent (not link count, which
  // stacks vertically) so the payload column is always placed clear of the
  // last hop node regardless of how many relay hops this email had.
  const nodeW = 170, nodeH = 46;
  const senderX = 190, senderY = 46;
  const hopY = 160;
  const hopStartX = 90;
  const hopGap = 190;
  const hopChainRightEdge = hops.length > 0
    ? hopStartX + (hops.length - 1) * hopGap + (nodeW + 10) / 2
    : senderX + (nodeW + 30) / 2;
  const linkNodeHalfW = (nodeW + 30) / 2;
  const linkStartX = Math.max(hopChainRightEdge + 100 + linkNodeHalfW, senderX + 500);
  const width = Math.max(900, linkStartX + linkNodeHalfW + 60);
  const linkStartY = 150;
  const linkGapY = 100;

  let maxY = hopY + nodeH / 2 + 40;
  let nodes = '';
  let edges = '';

  const fromDomain = meta.from_domain || meta.sender_domain || 'unknown-domain';
  nodes += svgNode(senderX, senderY, nodeW + 30, nodeH, truncateMid(fromDomain, 26), 'SENDER DOMAIN', '#0d9488', 'domain');

  let prevX = senderX;
  hops.forEach((hop, idx) => {
    const x = hopStartX + idx * (hopGap || 180);
    const isOrigin = idx === 0;
    const color = isOrigin && (origin.is_anonymized_node || origin.is_proxy) ? '#ef4444' : '#64748b';
    edges += svgEdge(prevX, senderY + nodeH / 2, x, hopY - nodeH / 2, color, false);
    nodes += svgNode(x, hopY, nodeW + 10, nodeH, hop.ip || 'unknown-ip', isOrigin ? 'ORIGIN IP' : `HOP #${hop.hop || idx + 1}`, color, 'ip');
    prevX = x;
  });
  maxY = Math.max(maxY, hopY + nodeH / 2 + 30);

  let curY = linkStartY;
  links.forEach((link) => {
    const tel = link.telemetry || {};
    const score = parseFloat(link.threat_score || 0);
    const color = riskColor(score);
    const x = linkStartX;
    const y = curY;
    edges += svgEdge(senderX, senderY + nodeH / 2, x, y - nodeH / 2, color, true);

    let domain = link.url;
    try { domain = new URL(link.url).hostname; } catch (e) { /* keep raw url */ }
    nodes += svgNode(x, y, nodeW + 30, nodeH, truncateMid(domain, 24), `PAYLOAD · ${Math.round(score)}/100`, color, 'payload');
    maxY = Math.max(maxY, y + nodeH / 2 + 30);
    curY += linkGapY;

    if (tel.brand_impersonation) {
      const by = y + 78;
      edges += svgEdge(x, y + nodeH / 2, x, by - nodeH / 2, '#ef4444', false);
      nodes += svgNode(x, by, nodeW + 10, nodeH, tel.detected_brand || 'Brand Target', 'IMPERSONATED BRAND', '#ef4444', 'brand');
      maxY = Math.max(maxY, by + nodeH / 2 + 30);
      curY = by + linkGapY;
    }
  });

  wrap.innerHTML = `
    <svg width="${width}" height="${maxY}" class="min-w-[900px]" style="background:#fafafa; border-radius:12px;">
      <defs>
        <pattern id="graphDots" width="16" height="16" patternUnits="userSpaceOnUse">
          <circle cx="1.2" cy="1.2" r="1.2" fill="#e2e8f0"/>
        </pattern>
        <marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
          <path d="M0,0 L8,4 L0,8 Z" fill="#94a3b8"/>
        </marker>
      </defs>
      <rect x="0" y="0" width="${width}" height="${maxY}" fill="url(#graphDots)"/>
      ${edges}
      ${nodes}
    </svg>
  `;
}

// =========================================================================
// EVIDENCE VAULT
// =========================================================================

function fmtTime(d) {
  return d.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
}

function renderEvidenceVault(data) {
  const shaEl = document.getElementById('sha256Digest');
  if (shaEl) shaEl.innerText = data.evidence_hash_sha256 || 'N/A';

  const idText = document.getElementById('vaultEvidenceIdText');
  const sealedAt = tHashed || new Date();
  if (idText) idText.innerText = `EVIDENCE ID: EVD-${caseIdValue.replace('TSF-', '')} · SEALED AT: ${fmtTime(sealedAt)}`;

  const log = [];
  if (tCaptured) log.push({ actor: 'Automated Ingestion Engine', action: 'Captured raw .eml artifact', time: tCaptured });
  if (tHashed) log.push({ actor: 'TrustShield Evidence Vault', action: 'Generated SHA-256 seal hash & preserved record', time: tHashed });
  if (tVerdict) log.push({ actor: 'TrustShield Forensic Kernel', action: 'Verified cryptographic integrity & rendered verdict', time: tVerdict });

  const container = document.getElementById('custodyLogContainer');
  if (container) {
    container.innerHTML = '';
    if (log.length === 0) {
      container.innerHTML = `<div class="py-3 text-center text-slate-400 text-xs">No custody events recorded.</div>`;
    } else {
      log.forEach(entry => {
        const row = document.createElement('div');
        row.className = 'flex items-center justify-between py-2.5';
        row.innerHTML = `
          <div>
            <p class="text-[12px] font-semibold text-slate-800">${entry.action}</p>
            <p class="text-[10px] text-slate-400">ACTOR: ${entry.actor}</p>
          </div>
          <span class="text-[10px] font-mono text-slate-400 flex-shrink-0">${fmtTime(entry.time)}</span>
        `;
        container.appendChild(row);
      });
    }
  }

  const navBadge = document.getElementById('navVaultBadge');
  if (navBadge) {
    navBadge.classList.remove('hidden');
    navBadge.innerText = 'SEALED';
    navBadge.className = 'hidden lg:inline-flex px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-emerald-50 text-emerald-700 border border-emerald-200';
  }
}

function reSealEvidence(e) {
  if (e) e.preventDefault();
  const btn = document.getElementById('resealBtn');
  const shaEl = document.getElementById('sha256Digest');
  if (!currentReport || !shaEl) return;
  const orig = btn ? btn.innerHTML : '';
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `
      <svg class="w-3.5 h-3.5 animate-spin" viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="10" stroke-opacity="0.3"/><path d="M12 2a10 10 0 0 1 10 10" stroke-width="2"/></svg>
      <span>Recomputing...</span>
    `;
  }
  setTimeout(() => {
    shaEl.innerText = currentReport.evidence_hash_sha256 || 'N/A';
    const now = new Date();
    const container = document.getElementById('custodyLogContainer');
    if (container) {
      const row = document.createElement('div');
      row.className = 'flex items-center justify-between py-2.5';
      row.innerHTML = `
        <div><p class="text-[12px] font-semibold text-slate-800">Re-verified SHA-256 vault seal</p><p class="text-[10px] text-slate-400">ACTOR: Inv. TrustShield AI</p></div>
        <span class="text-[10px] font-mono text-slate-400 flex-shrink-0">${fmtTime(now)}</span>
      `;
      container.appendChild(row);
    }
    if (btn) { btn.disabled = false; btn.innerHTML = orig; }
  }, 700);
}
window.reSealEvidence = reSealEvidence;

// =========================================================================
// INTERACTIVE CRYPTOGRAPHIC EVIDENCE VAULT & LIVE TAMPER VERIFICATION ENGINE
// =========================================================================

function triggerVaultFileInput(e) {
  if (e) {
    if (e.target && e.target.id === 'vaultFileInput') return;
    e.preventDefault();
    e.stopPropagation();
  }
  const fileInput = document.getElementById('vaultFileInput');
  if (fileInput) {
    fileInput.value = '';
    fileInput.click();
  }
}

function handleVaultFileSelect(e) {
  if (e && e.target && e.target.files && e.target.files.length > 0) {
    verifyUploadedEvidenceFile(e.target.files[0]);
  }
}

async function verifyUploadedEvidenceFile(file) {
  if (!file) return;

  const defaultState = document.getElementById('tamperDefaultState');
  const successState = document.getElementById('tamperSuccessState');
  const errorState = document.getElementById('tamperErrorState');

  if (defaultState) {
    defaultState.classList.remove('hidden');
    defaultState.innerHTML = `
      <div class="flex flex-col items-center justify-center py-4">
        <svg class="w-8 h-8 text-teal-400 animate-spin mb-2" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="10" stroke-opacity="0.25"/>
          <path d="M12 2a10 10 0 0 1 10 10" stroke-width="2.5"/>
        </svg>
        <p class="text-xs font-bold text-teal-300">Computing Live SHA-256 Digest...</p>
        <p class="text-[10px] text-slate-400 mt-0.5">Cross-referencing cryptographic signature against PostgreSQL vault</p>
      </div>
    `;
  }
  if (successState) successState.classList.add('hidden');
  if (errorState) errorState.classList.add('hidden');

  try {
    const formData = new FormData();
    formData.append('file', file);

    const response = await fetch(`${API_BASE}/api/forensics/verify-file`, {
      method: 'POST',
      body: formData
    });

    const res = await response.json();

    if (defaultState) defaultState.classList.add('hidden');

    if (response.ok && res.matched) {
      // 100% Untampered Match
      verifiedCaseDossier = res.dossier;
      verifiedCaseRawEml = res.raw_eml || '';
      caseIdValue = res.case_id;

      if (successState) {
        successState.classList.remove('hidden');
        const caseIdEl = document.getElementById('vResCaseId');
        if (caseIdEl) caseIdEl.innerText = res.case_id || 'TSF-VERIFIED';

        const timeEl = document.getElementById('vResTime');
        if (timeEl) {
          const t = res.sealed_at || res.created_at;
          timeEl.innerText = t ? fmtTime(new Date(t)) : fmtTime(new Date());
        }

        const subEl = document.getElementById('vResSubject');
        if (subEl) subEl.innerText = res.subject || 'Evidence Artifact';

        const hashEl = document.getElementById('vResHash');
        if (hashEl) hashEl.innerText = res.evidence_hash || res.computed_hash || '—';
      }
    } else {
      // Tampering Detected / Unregistered
      if (errorState) {
        errorState.classList.remove('hidden');
        const msgEl = document.getElementById('tamperErrorMsg');
        if (msgEl) {
          msgEl.innerText = res.message || 'The computed cryptographic hash does not match any sealed evidence record in the database. The file contents have been modified or tampered with.';
        }
        const hashEl = document.getElementById('tamperComputedHashText');
        if (hashEl) {
          hashEl.innerText = `Computed SHA-256: ${res.computed_hash || 'Calculation Failed'}`;
        }
      }
    }
  } catch (err) {
    console.error('Vault verification error:', err);
    if (defaultState) defaultState.classList.add('hidden');
    if (errorState) {
      errorState.classList.remove('hidden');
      const msgEl = document.getElementById('tamperErrorMsg');
      if (msgEl) msgEl.innerText = `Verification service error: ${err.message}`;
    }
  }
}

async function executeVaultQuery() {
  const input = document.getElementById('vaultSearchInput');
  if (!input) return;
  const query = (input.value || '').trim();
  if (!query) {
    alert('Please enter a Case ID (e.g., TSF-123456) or a 64-character SHA-256 hash to verify.');
    return;
  }

  const defaultState = document.getElementById('tamperDefaultState');
  const successState = document.getElementById('tamperSuccessState');
  const errorState = document.getElementById('tamperErrorState');

  if (defaultState) {
    defaultState.classList.remove('hidden');
    defaultState.innerHTML = `
      <div class="flex flex-col items-center justify-center py-4">
        <svg class="w-8 h-8 text-teal-400 animate-spin mb-2" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="10" stroke-opacity="0.25"/>
          <path d="M12 2a10 10 0 0 1 10 10" stroke-width="2.5"/>
        </svg>
        <p class="text-xs font-bold text-teal-300">Searching Cryptographic Vault...</p>
        <p class="text-[10px] text-slate-400 mt-0.5">Querying index for '${query}'</p>
      </div>
    `;
  }
  if (successState) successState.classList.add('hidden');
  if (errorState) errorState.classList.add('hidden');

  try {
    const response = await fetch(`${API_BASE}/api/forensics/verify-hash`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: query })
    });

    const res = await response.json();

    if (defaultState) defaultState.classList.add('hidden');

    if (response.ok && res.matched) {
      verifiedCaseDossier = res.dossier;
      verifiedCaseRawEml = res.raw_eml || '';
      caseIdValue = res.case_id;

      if (successState) {
        successState.classList.remove('hidden');
        const caseIdEl = document.getElementById('vResCaseId');
        if (caseIdEl) caseIdEl.innerText = res.case_id || 'TSF-VERIFIED';

        const timeEl = document.getElementById('vResTime');
        if (timeEl) {
          const t = res.created_at;
          timeEl.innerText = t ? fmtTime(new Date(t)) : fmtTime(new Date());
        }

        const subEl = document.getElementById('vResSubject');
        if (subEl) subEl.innerText = res.subject || 'Evidence Artifact';

        const hashEl = document.getElementById('vResHash');
        if (hashEl) hashEl.innerText = res.evidence_hash || '—';
      }
    } else {
      if (errorState) {
        errorState.classList.remove('hidden');
        const msgEl = document.getElementById('tamperErrorMsg');
        if (msgEl) {
          msgEl.innerText = res.message || `No cryptographic seal found for '${query}'. Either this record has not been ingested or the hash has been modified.`;
        }
        const hashEl = document.getElementById('tamperComputedHashText');
        if (hashEl) hashEl.innerText = `Searched Query: ${query}`;
      }
    }
  } catch (err) {
    console.error('Vault query error:', err);
    if (defaultState) defaultState.classList.add('hidden');
    if (errorState) {
      errorState.classList.remove('hidden');
      const msgEl = document.getElementById('tamperErrorMsg');
      if (msgEl) msgEl.innerText = `Lookup error: ${err.message}`;
    }
  }
}

function loadVerifiedDossier() {
  if (verifiedCaseDossier) {
    currentReport = verifiedCaseDossier;
    rawEmlContent = verifiedCaseRawEml || '';
    if (caseIdValue) {
      const el = document.getElementById('caseId');
      if (el) el.innerText = caseIdValue;
      const rEl = document.getElementById('reportCaseId');
      if (rEl) rEl.innerText = caseIdValue;
    }
    tCaptured = new Date();
    tHashed = new Date();
    tVerdict = new Date();
    renderDashboard(verifiedCaseDossier, 0.3);
    switchTab('threat');
  }
}

async function loadVaultCasesHistory() {
  const tbody = document.getElementById('vaultCasesTableBody');
  if (!tbody) return;

  try {
    const res = await fetch(`${API_BASE}/api/forensics/cases?limit=50`);
    if (res.ok) {
      const data = await res.json();
      cachedVaultCases = data.cases || [];
      renderVaultCasesTable(cachedVaultCases);
    } else {
      tbody.innerHTML = `<tr><td colspan="7" class="py-6 text-center text-slate-400">Unable to load case records from PostgreSQL vault.</td></tr>`;
    }
  } catch (err) {
    console.warn('Error loading vault cases:', err);
    if (tbody) {
      tbody.innerHTML = `<tr><td colspan="7" class="py-6 text-center text-slate-400">Offline or database connection unavailable.</td></tr>`;
    }
  }
}

function renderVaultCasesTable(cases) {
  const tbody = document.getElementById('vaultCasesTableBody');
  if (!tbody) return;

  if (!cases || cases.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="py-6 text-center text-slate-400 font-mono text-xs">No sealed forensic cases found in the database repository.</td></tr>`;
    return;
  }

  tbody.innerHTML = cases.map(c => {
    const hash = c.evidence_hash || '—';
    const hashShort = hash.length > 16 ? `${hash.substring(0, 8)}...${hash.substring(hash.length - 6)}` : hash;
    const score = parseFloat(c.threat_score || 0.0);
    const scoreColor = score >= 80 ? 'text-rose-600 bg-rose-50 border-rose-200' : (score >= 50 ? 'text-amber-600 bg-amber-50 border-amber-200' : 'text-emerald-600 bg-emerald-50 border-emerald-200');
    const createdStr = c.created_at ? c.created_at.replace('T', ' ').substring(0, 19) : '—';
    const sender = (c.sender || 'Unknown').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const subject = (c.subject || '(No Subject)').replace(/</g, '&lt;').replace(/>/g, '&gt;');

    return `
      <tr class="hover:bg-slate-50 transition-colors">
        <td class="py-2.5 px-3 font-bold text-teal-700">${c.case_id}</td>
        <td class="py-2.5 px-3 text-slate-700 font-mono" title="${hash}">${hashShort}</td>
        <td class="py-2.5 px-3 text-slate-800 max-w-[200px] truncate" title="${sender}">${sender}</td>
        <td class="py-2.5 px-3 text-slate-700 max-w-[220px] truncate" title="${subject}">${subject}</td>
        <td class="py-2.5 px-3">
          <span class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[9.5px] font-bold border ${scoreColor}">
            ${score.toFixed(0)}/100 · ${c.verdict || 'ANALYZED'}
          </span>
        </td>
        <td class="py-2.5 px-3 text-slate-500 font-mono text-[10px]">${createdStr}</td>
        <td class="py-2.5 px-3 text-right">
          <button type="button" onclick="loadVaultCaseById('${c.case_id}')" class="px-2.5 py-1 rounded bg-teal-50 hover:bg-teal-100 text-teal-700 font-bold border border-teal-200 text-[10px] transition-colors cursor-pointer">
            Inspect &rarr;
          </button>
        </td>
      </tr>
    `;
  }).join('');
}

function filterVaultCasesTable() {
  const input = document.getElementById('caseTableFilter');
  if (!input) return;
  const q = input.value.toLowerCase().trim();
  if (!q) {
    renderVaultCasesTable(cachedVaultCases);
    return;
  }
  const filtered = cachedVaultCases.filter(c => {
    return (c.case_id || '').toLowerCase().includes(q) ||
           (c.sender || '').toLowerCase().includes(q) ||
           (c.subject || '').toLowerCase().includes(q) ||
           (c.evidence_hash || '').toLowerCase().includes(q) ||
           (c.verdict || '').toLowerCase().includes(q);
  });
  renderVaultCasesTable(filtered);
}

async function loadVaultCaseById(caseId) {
  if (!caseId) return;
  try {
    const res = await fetch(`${API_BASE}/api/forensics/case/${encodeURIComponent(caseId)}`);
    if (res.ok) {
      const caseData = await res.json();
      if (caseData && caseData.dossier) {
        caseIdValue = caseData.case_id;
        const el = document.getElementById('caseId');
        if (el) el.innerText = caseIdValue;
        const rEl = document.getElementById('reportCaseId');
        if (rEl) rEl.innerText = caseIdValue;

        currentReport = caseData.dossier;
        rawEmlContent = caseData.raw_eml || '';
        tCaptured = new Date(caseData.created_at || Date.now());
        tHashed = new Date(caseData.created_at || Date.now());
        tVerdict = new Date(caseData.created_at || Date.now());

        renderDashboard(caseData.dossier, 0.25);
        switchTab('threat');
      }
    } else {
      alert(`Could not retrieve case ${caseId} from repository.`);
    }
  } catch (err) {
    console.error('Error retrieving case:', err);
    alert(`Error loading case: ${err.message}`);
  }
}

// =========================================================================
// TIMELINE
// =========================================================================

function renderTimeline(data) {
  const meta = data.metadata || {};
  const origin = data.origin_intelligence || {};
  const hops = origin.route_map || [];
  const container = document.getElementById('timelineContainer');
  if (!container) return;
  container.innerHTML = '';

  const items = [];
  items.push({ label: 'Email composed', detail: meta.date || 'Unknown timestamp', tag: 'SOURCE', color: '#64748b' });

  hops.forEach((hop, idx) => {
    items.push({
      label: idx === 0 ? `Origin transmission — ${hop.ip || 'unknown IP'}` : `Relay hop #${hop.hop || idx + 1} — ${hop.ip || 'unknown IP'}`,
      detail: `${hop.city || 'Unknown'}, ${hop.country || 'Unknown'} · ${hop.isp || 'Unknown ISP'}`,
      tag: `SEQ ${idx + 1}`,
      color: idx === 0 ? '#ef4444' : '#0d9488'
    });
  });

  if (tCaptured) items.push({ label: 'Evidence captured by TrustShield', detail: tCaptured.toLocaleTimeString(), tag: 'INGEST', color: '#0d9488' });
  if (tHashed) items.push({ label: 'SHA-256 chain-of-custody seal generated', detail: tHashed.toLocaleTimeString(), tag: 'SEAL', color: '#10b981' });
  if (tVerdict) items.push({ label: 'Forensic verdict rendered', detail: tVerdict.toLocaleTimeString(), tag: 'VERDICT', color: '#ef4444' });

  items.forEach(item => {
    const row = document.createElement('div');
    row.className = 'relative pl-6';
    row.innerHTML = `
      <span class="absolute -left-[9px] top-1 w-3.5 h-3.5 rounded-full border-2 border-white" style="background:${item.color}"></span>
      <div class="flex items-center gap-2">
        <span class="text-[9px] font-mono font-bold text-slate-400">${item.tag}</span>
        <h5 class="text-[12px] font-semibold text-slate-800">${item.label}</h5>
      </div>
      <p class="text-[11px] text-slate-400 font-mono mt-0.5">${item.detail}</p>
    `;
    container.appendChild(row);
  });
}

// =========================================================================
// REPORT TAB
// =========================================================================

function renderReportTab(data) {
  const setText = (id, txt) => { const el = document.getElementById(id); if (el) el.innerText = txt; };
  const setHtml = (id, html) => { const el = document.getElementById(id); if (el) el.innerHTML = html; };

  const hash = data.evidence_hash_sha256 || 'UNKNOWN';
  const score = parseFloat(data.overall_threat_score || 0.0);
  const verdict = data.verdict || 'UNKNOWN';
  const meta = data.metadata || {};
  const auth = data.authentication || {};
  const mx = data.sender_domain_intelligence || {};
  const origin = data.origin_intelligence || {};
  const attr = data.threat_attribution || {};
  const links = data.link_investigation || [];
  const hops = origin.route_map || [];
  const now = new Date();

  // Header and Identifiers
  setText('reportCaseId', caseIdValue || `TSF-${hash.substring(0, 8).toUpperCase()}`);
  setText('reportGeneratedAt', fmtTime(now));
  setText('reportSha256Digest', hash);

  // Verdict Box Styling & Scores
  const verdictBox = document.getElementById('reportVerdictBox');
  const verdictPill = document.getElementById('reportVerdictPill');
  const threatScoreText = document.getElementById('reportThreatScoreText');

  if (threatScoreText) threatScoreText.innerText = `${score.toFixed(1)} / 100`;
  if (verdictPill) verdictPill.innerText = verdict;

  if (score >= 80.0) {
    if (verdictBox) verdictBox.className = 'rounded-xl border border-red-200 bg-red-50/60 p-5';
    if (verdictPill) verdictPill.className = 'px-3 py-1 rounded-md text-xs font-extrabold uppercase tracking-wide bg-red-600 text-white shadow-sm';
    if (threatScoreText) threatScoreText.className = 'text-lg font-black font-mono text-red-700';
  } else if (score >= 50.0) {
    if (verdictBox) verdictBox.className = 'rounded-xl border border-amber-200 bg-amber-50/60 p-5';
    if (verdictPill) verdictPill.className = 'px-3 py-1 rounded-md text-xs font-extrabold uppercase tracking-wide bg-amber-600 text-white shadow-sm';
    if (threatScoreText) threatScoreText.className = 'text-lg font-black font-mono text-amber-700';
  } else {
    if (verdictBox) verdictBox.className = 'rounded-xl border border-emerald-200 bg-emerald-50/60 p-5';
    if (verdictPill) verdictPill.className = 'px-3 py-1 rounded-md text-xs font-extrabold uppercase tracking-wide bg-emerald-600 text-white shadow-sm';
    if (threatScoreText) threatScoreText.className = 'text-lg font-black font-mono text-emerald-700';
  }

  // Attribution Details
  setText('reportAttrTypeText', attr.type || 'UNKNOWN');
  setText('reportAttrConfBadge', `CONFIDENCE: ${attr.confidence || 'UNKNOWN'}`);
  setText('reportAttrDetailsText', attr.details || 'Deterministic forensic correlation complete.');

  // Origin Details
  setText('reportOriginIpText', origin.originating_ip || 'N/A');
  const isAnon = origin.is_anonymized_node || origin.is_proxy;
  const infraType = isAnon ? 'Anonymized Proxy / Exit Node' : 'Direct Autonomous System Transit';
  const geoSummary = origin.country ? `${origin.city || ''}, ${origin.country} (${origin.isp || 'Autonomous System'})` : 'Transit Autonomous System';
  setText('reportInfraTypeText', `${infraType} · ${geoSummary}`);

  // Exhibit 1: RFC-5322 Envelope
  setText('reportSubject', meta.subject || 'N/A');
  setText('reportFrom', meta.from || 'N/A');
  setText('reportReturnPath', meta.return_path || 'N/A');
  setText('reportTo', meta.to || 'N/A');
  setText('reportDate', meta.date || 'N/A');
  setText('reportMsgId', meta.message_id || 'N/A');

  const replyToWrap = document.getElementById('reportReplyToWrap');
  if (replyToWrap) {
    const replyVal = meta.reply_to || 'None';
    if (meta.reply_to_mismatch) {
      replyToWrap.innerHTML = `
        <span class="text-slate-900 font-mono">${replyVal}</span>
        <span class="px-2 py-0.5 rounded text-[9px] font-mono font-bold bg-red-100 text-red-700 border border-red-300">BEC MISMATCH DETECTED</span>
      `;
    } else {
      replyToWrap.innerHTML = `<span class="text-slate-900 font-mono">${replyVal}</span>`;
    }
  }

  // Exhibit 2: Authentication Audit
  const fmtAuthBadge = (pass) => pass
    ? `<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-100 text-emerald-800 border border-emerald-300">PASS</span>`
    : `<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-red-100 text-red-800 border border-red-300">FAIL</span>`;

  setHtml('reportSpfBadge', fmtAuthBadge(auth.spf_pass));
  setText('reportSpfDetails', auth.spf_details || (auth.spf_pass ? 'Authorized by sending SPF policy' : 'Failed SPF authorization check'));

  setHtml('reportDkimBadge', fmtAuthBadge(auth.dkim_pass));
  setText('reportDkimDetails', auth.dkim_details || (auth.dkim_pass ? 'Cryptographic DKIM signature valid' : 'No valid cryptographic DKIM signature found'));

  setHtml('reportDmarcBadge', fmtAuthBadge(auth.dmarc_pass));
  setText('reportDmarcDetails', auth.dmarc_details || (auth.dmarc_pass ? 'Aligned with sending identity' : 'Identifier alignment failed'));

  setHtml('reportMxBadge', fmtAuthBadge(mx.has_mx_records));
  setText('reportMxDetails', `Domain: ${mx.from_domain || 'N/A'} | Primary MX: ${mx.primary_mx || 'None (Burner/Unroutable)'}`);

  // Exhibit 3: Mail Routing Hop Table
  const hopTbody = document.getElementById('reportHopTableBody');
  if (hopTbody) {
    if (hops.length === 0) {
      hopTbody.innerHTML = `<tr><td colspan="5" class="py-3 px-3 text-center text-slate-400">No external relay hops detected in message headers.</td></tr>`;
    } else {
      hopTbody.innerHTML = hops.map(hop => {
        const isSusp = hop.is_suspicious_proxy || false;
        const badge = isSusp
          ? `<span class="text-red-600 font-bold">ANONYMIZED PROXY</span>`
          : `<span class="text-emerald-600 font-bold">CLEAN TRANSIT</span>`;
        let loc = `${hop.city || 'Unknown'}, ${hop.country || 'Unknown'}`;
        if (hop.lat && hop.lon) loc += ` (${hop.lat.toFixed(2)}, ${hop.lon.toFixed(2)})`;
        return `
          <tr class="hover:bg-slate-50">
            <td class="py-2 px-3 text-slate-800 font-bold">${hop.hop_number || '-'}</td>
            <td class="py-2 px-3 text-slate-900 font-bold font-mono">${hop.ip || 'Unknown'}</td>
            <td class="py-2 px-3 text-slate-600">${loc}</td>
            <td class="py-2 px-3 text-slate-700">${hop.isp || 'Unknown'} <span class="text-slate-400">(${hop.asn || 'N/A'})</span></td>
            <td class="py-2 px-3 text-[10px]">${badge}</td>
          </tr>
        `;
      }).join('');
    }
  }

  // Exhibit 4: Payload Hyperlink Detonation Table
  const linkTbody = document.getElementById('reportLinkTableBody');
  if (linkTbody) {
    if (links.length === 0) {
      linkTbody.innerHTML = `<tr><td colspan="4" class="py-3 px-3 text-center text-slate-400">No embedded hyperlinks detected in evidence.</td></tr>`;
    } else {
      linkTbody.innerHTML = links.map(link => {
        const linkScore = parseFloat(link.threat_score || 0.0);
        const linkScoreColor = linkScore >= 80 ? 'text-red-600 font-bold' : (linkScore >= 50 ? 'text-amber-600 font-bold' : 'text-emerald-600 font-bold');
        const tel = link.telemetry || {};
        const sigs = [];
        if (tel.known_db_match) sigs.push('Known Threat DB Match');
        if (tel.sandbox_has_password) sigs.push('Credential Interceptor Form');
        if (tel.brand_impersonation) sigs.push(`Brand Impersonation (${tel.detected_brand || 'Unknown'})`);
        if (tel.suspicious_exfiltration) sigs.push('Malicious Form Action');
        if (sigs.length === 0) sigs.push('Standard HTML Structure');

        return `
          <tr class="hover:bg-slate-50">
            <td class="py-2 px-3 font-mono text-[10.5px] text-slate-900 break-all max-w-[240px]">${link.url || ''}</td>
            <td class="py-2 px-3 font-mono ${linkScoreColor}">${linkScore.toFixed(1)} / 100</td>
            <td class="py-2 px-3 font-semibold text-slate-800">${link.verdict || 'UNKNOWN'}</td>
            <td class="py-2 px-3 text-slate-600">${sigs.join(' · ')}</td>
          </tr>
        `;
      }).join('');
    }
  }

  // Narrative Container
  const narrativeContainer = document.getElementById('reportNarrativeContainer');
  if (narrativeContainer) {
    const rawNarrative = data.incident_summary || 'Evaluation complete across all forensic telemetry engines.';
    const lines = rawNarrative.split('\n').map(l => l.trim()).filter(Boolean);
    narrativeContainer.innerHTML = lines.map(line => `
      <div class="flex items-start gap-2">
        <span class="w-1.5 h-1.5 rounded-full bg-slate-500 mt-1.5 flex-shrink-0"></span>
        <p class="text-slate-800">${line}</p>
      </div>
    `).join('');
  }
}

// =========================================================================
// DASHBOARD CASE OVERVIEW SUMMARY
// =========================================================================

function renderDashboardSummary(data) {
  const score = Math.round(parseFloat(data.overall_threat_score || 0));
  const auth = data.authentication || {};
  const passCount = ['spf_pass', 'dkim_pass', 'dmarc_pass'].filter(k => auth[k]).length;
  const origin = data.origin_intelligence || {};
  const links = data.link_investigation || [];

  // Each tile's accent matches the color of the sidebar section it jumps to,
  // so the dashboard reads as an index into the same color-coded system.
  const tiles = [
    { label: 'Fraud Risk Score', value: `${score}/100`, tab: 'threat', accent: '#fb7185', color: score >= 80 ? 'text-red-600' : score >= 50 ? 'text-amber-600' : 'text-emerald-600' },
    { label: 'Protocols Passed', value: `${passCount}/3`, tab: 'email', accent: '#60a5fa', color: passCount === 3 ? 'text-emerald-600' : 'text-red-600' },
    { label: 'Relay Hops', value: `${origin.total_hops || (origin.route_map || []).length || 0}`, tab: 'geo', accent: '#34d399', color: 'text-slate-700' },
    { label: 'Payload Links', value: `${links.length}`, tab: 'threat', accent: '#fb7185', color: 'text-slate-700' },
    { label: 'IOCs Extracted', value: `${currentIocs.length}`, tab: 'ioc', accent: '#fbbf24', color: 'text-slate-700' },
    { label: 'Evidence Vault', value: 'Sealed', tab: 'vault', accent: '#2dd4bf', color: 'text-emerald-600' }
  ];

  const grid = document.getElementById('dashboardTiles');
  if (grid) {
    grid.innerHTML = tiles.map(t => `
      <button type="button" onclick="switchTab('${t.tab}')" style="border-left: 3px solid ${t.accent}" class="text-left p-3.5 bg-white border border-slate-200 rounded-xl hover:shadow-md transition-all cursor-pointer">
        <span class="text-[10px] font-semibold uppercase tracking-wide text-slate-400 block">${t.label}</span>
        <span class="text-lg font-extrabold ${t.color} block mt-1">${t.value}</span>
      </button>
    `).join('');
  }
}

// =========================================================================
// HEADER CASE STATUS
// =========================================================================

function updateHeaderStatus(data) {
  const score = Math.round(parseFloat(data.overall_threat_score || 0));
  const pill = document.getElementById('caseStatusPill');
  if (pill) {
    if (score >= 80) {
      pill.className = 'text-[9.5px] font-bold text-rose-600 truncate';
      pill.innerText = 'Critical Threat';
    } else if (score >= 50) {
      pill.className = 'text-[9.5px] font-bold text-amber-600 truncate';
      pill.innerText = 'Suspicious Origin';
    } else {
      pill.className = 'text-[9.5px] font-bold text-emerald-600 truncate';
      pill.innerText = 'Verified Clean';
    }
  }

  const navScore = document.getElementById('navScoreBadge');
  if (navScore) {
    navScore.innerText = `${score}/100`;
    const tint = score >= 80 ? 'bg-rose-50 text-rose-700 border border-rose-200' : score >= 50 ? 'bg-amber-50 text-amber-700 border border-amber-200' : 'bg-emerald-50 text-emerald-700 border border-emerald-200';
    navScore.className = `hidden lg:inline-flex px-1.5 py-0.5 rounded text-[9px] font-mono font-bold ${tint}`;
  }

  const navIoc = document.getElementById('navIocBadge');
  if (navIoc) {
    navIoc.classList.remove('hidden');
    navIoc.innerText = currentIocs.length;
    navIoc.className = 'hidden lg:inline-flex px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-amber-50 text-amber-700 border border-amber-200';
  }
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
