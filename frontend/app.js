/**
 * TrustShield V2 - SOC Analyst Forensic Intelligence Portal
 * Unified Frontend Controller
 * Digital Forensics Workstation & RFC-5322 Telemetry Engine
 * Modern Light-Mode SaaS Architecture
 */

// Global API Base resolution
var API_BASE = (window.location.port === '8000' && window.location.protocol.startsWith('http'))
  ? ''
  : 'http://localhost:8000';

var currentReport = null;
var currentFileMeta = null;
var mapInstance = null;
var mapMarkersGroup = null;
var mapPolyline = null;
var statusInterval = null;

// Synthetic Sample Phishing .eml for offline / direct browser evaluation fallback
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
Please cancel this transaction immediately by visiting https://example.com/phish\r
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
  <p><a href="https://example.com/phish" style="color:red; font-weight:bold;">Click Here to Cancel Transfer</a></p>\r
  <p>Support Reference: <a href="https://portal-resolve.top/ticket?id=99281">Resolution Portal</a></p>\r
</body>\r
</html>\r
------=_Part_12345_67890--\r
`;

// Global Trigger Functions for HTML Event Handlers
window.triggerFileInput = function (e) {
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

window.handleFileSelect = function (e) {
  if (e && e.target && e.target.files && e.target.files.length > 0) {
    const file = e.target.files[0];
    e.target.value = ''; // Reset input value immediately so re-selecting same or new file fires onchange
    processEmlFile(file);
  }
};

/**
 * Executes a live pre-configured scenario (phishing, bec, or legitimate)
 */
window.loadDemoScenario = async function (scenario) {
  showLoading(true, `Loading pre-configured ${scenario.toUpperCase()} evidence scenario...`);

  try {
    const toggleEl = document.getElementById('fastDemoToggle');
    const isFastDemo = toggleEl ? toggleEl.checked : true;
    const queryParams = isFastDemo ? '?demo_mode=true&skip_sandbox=true' : '';

    const response = await fetch(`${API_BASE}/api/forensics/demo/${scenario}${queryParams}`);
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: Failed to load demo scenario '${scenario}'`);
    }

    const data = await response.json();
    currentReport = data;
    currentFileMeta = {
      name: `${scenario.toUpperCase()}_SCENARIO.eml`,
      size: 14200,
      isDemo: true
    };
    updateProcessedFileCard(currentFileMeta, data);
    renderDashboard(data);
  } catch (error) {
    console.error('Demo Scenario Load Error:', error);
    if (scenario === 'phishing') {
      // Offline fallback using synthetic EML
      const blob = new Blob([SAMPLE_PHISHING_EML], { type: 'message/rfc822' });
      const sampleFile = new File([blob], 'URGENT_WIRE_TRANSFER_ATTACK.eml', { type: 'message/rfc822' });
      processEmlFile(sampleFile, { demoMode: true });
    } else {
      alert(`Demo Scenario Error:\n${error.message}\n\nPlease verify backend is running at ${API_BASE || 'http://localhost:8000'}`);
    }
  } finally {
    showLoading(false);
  }
};

/**
 * Downloads a sample .eml file for manual user testing
 */
window.downloadSampleScenario = async function (scenario) {
  const filenames = {
    phishing: 'URGENT_WIRE_TRANSFER_ATTACK.eml',
    bec: 'EXECUTIVE_WIRE_REQUEST_BEC.eml',
    legitimate: 'MAINTENANCE_ANNOUNCEMENT_CLEAN.eml'
  };
  const filename = filenames[scenario] || `${scenario}.eml`;

  try {
    const response = await fetch(`${API_BASE}/api/forensics/sample-eml?type=${scenario}`);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const blob = await response.blob();
    triggerBlobDownload(blob, filename);
  } catch (err) {
    console.warn('Falling back to local synthetic blob download for scenario:', scenario);
    const blob = new Blob([SAMPLE_PHISHING_EML], { type: 'message/rfc822' });
    triggerBlobDownload(blob, filename);
  }
};

function triggerBlobDownload(blob, filename) {
  const downloadUrl = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = downloadUrl;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  window.URL.revokeObjectURL(downloadUrl);
  a.remove();
}

// Backward compatibility triggers
window.loadSamplePhishingDemo = function (e) {
  if (e) { e.preventDefault(); e.stopPropagation(); }
  loadDemoScenario('phishing');
};

window.downloadSampleEml = function (e) {
  if (e) { e.preventDefault(); e.stopPropagation(); }
  downloadSampleScenario('phishing');
};

window.exportDossierPdf = exportDossierPdf;
window.resetDashboard = resetDashboard;
window.removeCurrentFile = removeCurrentFile;
window.copyEvidenceHash = copyEvidenceHash;

function copyEvidenceHash(e) {
  if (e) e.stopPropagation();
  const hashText = document.getElementById('sha256Digest').innerText;
  if (hashText && hashText !== '--' && hashText !== 'Calculating...') {
    navigator.clipboard.writeText(hashText);
    const copyBtn = document.getElementById('copyHashBtn');
    if (copyBtn) {
      copyBtn.innerHTML = `<span class="text-emerald-600 font-semibold font-mono">✓ Copied</span>`;
      setTimeout(() => {
        copyBtn.innerHTML = `<span>Copy</span>`;
      }, 2000);
    }
  }
}

window.copyLinkToClipboard = function(urlText, btnId) {
  navigator.clipboard.writeText(urlText);
  const btn = document.getElementById(btnId);
  if (btn) {
    const orig = btn.innerText;
    btn.innerText = 'Copied!';
    btn.classList.add('text-emerald-600');
    setTimeout(() => {
      btn.innerText = orig;
      btn.classList.remove('text-emerald-600');
    }, 1500);
  }
};

// Drag & Drop Setup
function setupDragAndDrop() {
  const dropZone = document.getElementById('dropZone');
  if (!dropZone) return;

  window.addEventListener('dragover', (e) => e.preventDefault());
  window.addEventListener('drop', (e) => e.preventDefault());

  ['dragenter', 'dragover'].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.add('border-slate-500', 'bg-slate-100');
    });
  });

  ['dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.remove('border-slate-500', 'bg-slate-100');
    });
  });

  dropZone.addEventListener('drop', (e) => {
    const dt = e.dataTransfer;
    if (dt && dt.files && dt.files.length > 0) {
      processEmlFile(dt.files[0]);
    }
  });
}

// Ingests file and calls backend
async function processEmlFile(file, options = {}) {
  if (!file) return;
  // Clear any existing report state immediately to avoid displaying stale data
  currentReport = null;
  currentFileMeta = {
    name: file.name || 'uploaded_evidence.eml',
    size: file.size || 0,
    lastModified: file.lastModified || Date.now()
  };
  showLoading(true, 'Initiating live forensic ingestion & RFC-5322 normalization...');

  const formData = new FormData();
  formData.append('file', file);

  try {
    const toggleEl = document.getElementById('fastDemoToggle');
    const isFastDemo = options.demoMode !== undefined 
      ? options.demoMode 
      : (toggleEl ? toggleEl.checked : true);
    // CRITICAL: Live uploads must NEVER pass demo_mode=true
    const queryParams = isFastDemo ? '?skip_sandbox=true&demo_mode=false' : '?demo_mode=false';

    const response = await fetch(`${API_BASE}/api/forensics/analyze-eml${queryParams}`, {
      method: 'POST',
      body: formData
    });

    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      throw new Error(errData.error || `HTTP ${response.status}: Analysis request failed`);
    }

    const data = await response.json();
    currentReport = data;
    updateProcessedFileCard(currentFileMeta, data);
    renderDashboard(data);
  } catch (error) {
    alert(`Forensic Ingestion Error:\n${error.message}\n\nPlease ensure backend is running at ${API_BASE || 'http://localhost:8000'}`);
    console.error('Forensic Analysis Error:', error);
  } finally {
    showLoading(false);
  }
}

function showLoading(isLoading, initialText) {
  const loadingState = document.getElementById('loadingState');
  const statusText = document.getElementById('loadingStatusText');
  if (!loadingState) return;

  if (isLoading) {
    loadingState.classList.remove('hidden');
    
    const steps = [
      'Computing SHA-256 Chain of Custody & MIME normalization...',
      'Extracting RFC-5322 Received headers & mapping chronological relays...',
      'Auditing cryptographic SPF, DKIM, and DMARC alignment...',
      'Running deterministic URL heuristics (brand spoofing, TLD risk, typosquatting)...',
      'Detonating embedded payloads and verifying domain reachability...',
      'Correlating email urgency cues & synthesising final legal attribution matrix...'
    ];
    let stepIdx = 0;
    if (statusText) statusText.innerText = initialText || steps[0];
    
    if (statusInterval) clearInterval(statusInterval);
    statusInterval = setInterval(() => {
      stepIdx = (stepIdx + 1) % steps.length;
      if (statusText) statusText.innerText = steps[stepIdx];
    }, 1200);

  } else {
    loadingState.classList.add('hidden');
    if (statusInterval) clearInterval(statusInterval);
  }
}

/**
 * Multi-View Workspace Navigation
 * Toggles focused views: dashboard, analyze, investigation, forensics, trace, links, assessment, reports, demo
 */
window.switchView = function (viewName) {
  const views = [
    'dashboard',
    'analyze',
    'investigation',
    'forensics',
    'trace',
    'links',
    'assessment',
    'reports',
    'demo'
  ];

  if (!views.includes(viewName)) return;

  // 1. Toggle visibility of workspace views
  views.forEach(v => {
    const el = document.getElementById(`view-${v}`);
    if (el) {
      if (v === viewName) {
        el.classList.remove('hidden');
      } else {
        el.classList.add('hidden');
      }
    }
  });

  // 2. Update active style on sidebar navigation buttons
  views.forEach(v => {
    const navBtn = document.getElementById(`nav-${v}`);
    if (navBtn) {
      if (v === viewName) {
        navBtn.classList.remove('text-slate-400');
        navBtn.classList.add('nav-active', 'text-white', 'bg-slate-800');
      } else {
        navBtn.classList.remove('nav-active', 'text-white', 'bg-slate-800');
        navBtn.classList.add('text-slate-400');
      }
    }
  });

  // 3. Ensure Leaflet recalculates canvas dimensions when switching to trace view
  if (viewName === 'trace' && mapInstance) {
    setTimeout(() => {
      try {
        mapInstance.invalidateSize();
      } catch (err) {
        console.warn('Map resize refresh notice:', err);
      }
    }, 150);
  }

  // 4. Clean animation and smooth scroll to top for easy access
  window.scrollTo({ top: 0, behavior: 'smooth' });
  const activeViewEl = document.getElementById(`view-${viewName}`);
  if (activeViewEl) {
    // Re-trigger entrance animation
    activeViewEl.style.animation = 'none';
    void activeViewEl.offsetHeight;
    activeViewEl.style.animation = '';
    
    // Smoothly scroll active view into viewport at the top
    activeViewEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
};

/**
 * Main dashboard orchestration function
 */
function renderDashboard(data) {
  // Ensure legacy container IDs remain unhidden for compatibility
  const execSection = document.getElementById('executiveVerdict');
  const keyEvidenceSection = document.getElementById('keyEvidenceSection');
  const dashGrid = document.getElementById('dashboardGrid');
  const bottomGrid = document.getElementById('bottomSectionsGrid');

  if (execSection) execSection.classList.remove('hidden');
  if (keyEvidenceSection) keyEvidenceSection.classList.remove('hidden');
  if (dashGrid) dashGrid.classList.remove('hidden');
  if (bottomGrid) bottomGrid.classList.remove('hidden');

  // Render individual sections
  renderVerdict(data);
  renderKeyEvidence(data);
  renderMetadataAndAuth(data);
  renderLeafletMap(data.origin_intelligence);
  renderLinks(data.link_investigation);
  renderLegalAndNarrative(data);

  // Update active investigation state on dashboard view and sidebar badge
  const meta = data.metadata || {};
  const subjectEl = document.getElementById('dashActiveSubject');
  const verdictEl = document.getElementById('dashActiveVerdict');
  const activeCaseCard = document.getElementById('dashboardActiveCaseCard');
  const navBadge = document.getElementById('navCaseBadge');
  
  if (subjectEl) subjectEl.innerText = meta.subject || 'Investigation Evidence';
  if (verdictEl) {
    const verdict = data.verdict || (data.overall_threat_score >= 80 ? 'CRITICAL THREAT' : (data.overall_threat_score >= 50 ? 'SUSPICIOUS' : 'CLEAN'));
    verdictEl.innerText = verdict;
    if (data.overall_threat_score >= 80) {
      verdictEl.className = 'ml-2 px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-rose-100 text-rose-800';
    } else if (data.overall_threat_score >= 50) {
      verdictEl.className = 'ml-2 px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-amber-100 text-amber-800';
    } else {
      verdictEl.className = 'ml-2 px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-emerald-100 text-emerald-800';
    }
  }
  if (activeCaseCard) activeCaseCard.classList.remove('hidden');
  if (navBadge) navBadge.classList.remove('hidden');

  // Automatically transition the view to the primary Investigation Overview screen
  switchView('investigation');
}

/**
 * SECTION A: Incident Overview & Executive Verdict
 */
function renderVerdict(data) {
  const score = parseFloat(data.overall_threat_score || 0.0);
  const scoreNumber = document.getElementById('scoreNumber');
  const scoreCircle = document.getElementById('scoreCircle');
  const verdictCard = document.getElementById('verdictCard');
  const verdictBadge = document.getElementById('verdictBadge');
  const attributionBadge = document.getElementById('attributionBadge');
  const confidenceBadge = document.getElementById('confidenceBadge');
  const verdictHeadline = document.getElementById('verdictHeadline');
  const attributionDetails = document.getElementById('attributionDetails');
  const modeLabel = document.getElementById('analysisModeLabel');

  if (scoreNumber) scoreNumber.innerText = Math.round(score);

  const circumference = 263.89;
  const offset = circumference - (score / 100) * circumference;
  if (scoreCircle) scoreCircle.style.strokeDashoffset = offset;

  const attr = data.threat_attribution || {};
  if (attributionBadge) attributionBadge.innerText = attr.type || 'UNKNOWN';
  if (attributionDetails) attributionDetails.innerText = attr.details || 'Evaluation completed across all telemetry engines.';

  const confidence = (data.confidence || attr.confidence || 'MODERATE').toUpperCase();
  if (confidenceBadge) {
    confidenceBadge.innerText = `CONFIDENCE: ${confidence}`;
    if (confidence === 'HIGH') {
      confidenceBadge.className = 'px-2.5 py-1 rounded-lg text-xs font-mono font-bold uppercase bg-slate-900 text-white';
    } else {
      confidenceBadge.className = 'px-2.5 py-1 rounded-lg text-xs font-mono font-semibold uppercase bg-slate-100 text-slate-700 border border-slate-200';
    }
  }

  if (modeLabel) {
    const isDemo = data.analysis_type === 'DEMO_SCENARIO' || data.evidence_source === 'SYNTHETIC_DEMO';
    if (isDemo) {
      modeLabel.innerHTML = `<span class="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-amber-50 text-amber-800 border border-amber-300">🎮 DEMO SCENARIO</span>`;
    } else {
      modeLabel.innerHTML = `<span class="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-emerald-50 text-emerald-800 border border-emerald-300">🛡️ LIVE EMAIL ANALYSIS</span>`;
    }
  }

  // Visual Theme by Score / Verdict (Clean Light-Mode Styling)
  const verdict = data.verdict || '';
  if (score >= 80.0 || verdict.includes('CRITICAL') || verdict.includes('PHISHING')) {
    if (scoreCircle) scoreCircle.setAttribute('stroke', '#ef4444');
    if (verdictCard) verdictCard.className = 'card-soft rounded-3xl p-6 sm:p-8 space-y-6 bg-white border border-rose-200 shadow-sm transition-all';
    if (verdictBadge) {
      verdictBadge.className = 'px-3 py-1 rounded-lg text-xs font-bold font-mono tracking-wide uppercase bg-rose-50 text-rose-700 border border-rose-200';
      verdictBadge.innerText = verdict || 'CRITICAL FRAUD / PHISHING';
    }
    if (verdictHeadline) verdictHeadline.innerText = 'Severe Cyber Attack & Deceptive Payload Detected';
  } else if (score >= 50.0 || verdict.includes('BEC') || verdict.includes('SUSPICIOUS')) {
    if (scoreCircle) scoreCircle.setAttribute('stroke', '#f59e0b');
    if (verdictCard) verdictCard.className = 'card-soft rounded-3xl p-6 sm:p-8 space-y-6 bg-white border border-amber-200 shadow-sm transition-all';
    if (verdictBadge) {
      verdictBadge.className = 'px-3 py-1 rounded-lg text-xs font-bold font-mono tracking-wide uppercase bg-amber-50 text-amber-700 border border-amber-200';
      verdictBadge.innerText = verdict || 'HIGH-RISK BEC / SPOOFING';
    }
    if (verdictHeadline) verdictHeadline.innerText = 'High-Risk Identity Spoofing / Suspicious Origin';
  } else {
    if (scoreCircle) scoreCircle.setAttribute('stroke', '#10b981');
    if (verdictCard) verdictCard.className = 'card-soft rounded-3xl p-6 sm:p-8 space-y-6 bg-white border border-emerald-200 shadow-sm transition-all';
    if (verdictBadge) {
      verdictBadge.className = 'px-3 py-1 rounded-lg text-xs font-bold font-mono tracking-wide uppercase bg-emerald-50 text-emerald-700 border border-emerald-200';
      verdictBadge.innerText = verdict || 'LEGITIMATE / AUTHENTICATED';
    }
    if (verdictHeadline) verdictHeadline.innerText = 'Email Authenticated & Clean';
  }

  // Key Identifiers Grid in Section A
  const meta = data.metadata || {};
  const originIntel = data.origin_intelligence || {};
  
  const setEl = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.innerText = val || '--';
  };

  setEl('overviewFrom', meta.from || 'Unknown Sender');
  setEl('overviewTo', meta.to || 'Undisclosed');
  setEl('overviewDate', meta.date || 'Unknown Date');
  setEl('overviewOriginIp', originIntel.originating_ip || 'No Public Origin');
  setEl('overviewHops', `${originIntel.total_hops || 0} relays`);

  // Recommended Action Box (Light Modern Styling)
  const actionBox = document.getElementById('recommendedActionBox');
  const actionText = document.getElementById('recommendedActionText');
  const actionIcon = document.getElementById('actionIcon');

  const actionMsg = data.recommended_action || (
    score >= 80.0
      ? 'QUARANTINE IMMEDIATELY. Block sender domain and originating IP across edge gateways. Alert recipient and SOC team.'
      : (score >= 50.0
          ? 'ALERT RECIPIENT. Suspected executive impersonation or deceptive link. Mandate verbal out-of-band verification before taking action.'
          : 'ALLOW. Message passed technical envelope, cryptographic authentication, and hyperlink security audits.')
  );

  if (actionText) actionText.innerText = actionMsg;
  if (actionBox) {
    if (score >= 80.0) {
      actionBox.className = 'p-4 rounded-2xl bg-rose-50 border border-rose-200 flex items-start space-x-3.5';
      if (actionText) actionText.className = 'text-xs text-rose-800 mt-1 leading-relaxed font-medium';
      if (actionIcon) actionIcon.innerHTML = `<svg class="w-5 h-5 text-rose-600" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`;
    } else if (score >= 50.0) {
      actionBox.className = 'p-4 rounded-2xl bg-amber-50 border border-amber-200 flex items-start space-x-3.5';
      if (actionText) actionText.className = 'text-xs text-amber-800 mt-1 leading-relaxed font-medium';
      if (actionIcon) actionIcon.innerHTML = `<svg class="w-5 h-5 text-amber-600" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
    } else {
      actionBox.className = 'p-4 rounded-2xl bg-emerald-50 border border-emerald-200 flex items-start space-x-3.5';
      if (actionText) actionText.className = 'text-xs text-emerald-800 mt-1 leading-relaxed font-medium';
      if (actionIcon) actionIcon.innerHTML = `<svg class="w-5 h-5 text-emerald-600" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>`;
    }
  }
}

/**
 * SECTION B: Why It Was Flagged (Key Evidence)
 */
function renderKeyEvidence(data) {
  const container = document.getElementById('keyEvidenceList');
  const badge = document.getElementById('evidenceCountBadge');
  if (!container) return;

  container.innerHTML = '';
  
  // Render Layered Evidence Telemetry Matrix if available
  if (data.layered_evidence) {
    const auth = data.layered_evidence.authentication || {};
    const link = data.layered_evidence.link_threat || {};
    const content = data.layered_evidence.content_social_engineering || {};
    const infra = data.layered_evidence.infrastructure_origin || {};

    const getStatusPill = (status, goodValues = ['PASS', 'CLEAN', 'LOW', 'STANDARD']) => {
      if (goodValues.includes(status)) {
        return `<span class="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-emerald-50 text-emerald-700 border border-emerald-200">${status}</span>`;
      } else if (['FAIL', 'CRITICAL', 'HIGH', 'ANONYMIZED_INFRASTRUCTURE'].includes(status)) {
        return `<span class="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-rose-50 text-rose-700 border border-rose-200">${status}</span>`;
      } else {
        return `<span class="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-amber-50 text-amber-700 border border-amber-200">${status}</span>`;
      }
    };

    const matrixEl = document.createElement('div');
    matrixEl.className = 'grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 p-3.5 rounded-2xl bg-slate-50/80 border border-slate-200 mb-3';
    matrixEl.innerHTML = `
      <div class="space-y-1">
        <div class="flex items-center justify-between">
          <span class="text-[10px] font-bold font-mono uppercase text-slate-500">1. Sender Auth</span>
          ${getStatusPill(auth.status, ['PASS'])}
        </div>
        <p class="text-[11px] text-slate-700 leading-snug">${auth.details || 'SPF / DKIM / DMARC'}</p>
      </div>

      <div class="space-y-1">
        <div class="flex items-center justify-between">
          <span class="text-[10px] font-bold font-mono uppercase text-slate-500">2. Link / Payload Risk</span>
          ${getStatusPill(link.status, ['CLEAN'])}
        </div>
        <p class="text-[11px] text-slate-700 leading-snug">${link.details || 'Hyperlink telemetry'}</p>
      </div>

      <div class="space-y-1">
        <div class="flex items-center justify-between">
          <span class="text-[10px] font-bold font-mono uppercase text-slate-500">3. Content Signals</span>
          ${getStatusPill(content.status, ['LOW'])}
        </div>
        <p class="text-[11px] text-slate-700 leading-snug">${content.details || 'Urgency / Compensation'}</p>
      </div>

      <div class="space-y-1">
        <div class="flex items-center justify-between">
          <span class="text-[10px] font-bold font-mono uppercase text-slate-500">4. Origin Infrastructure</span>
          ${getStatusPill(infra.status, ['STANDARD'])}
        </div>
        <p class="text-[11px] text-slate-700 leading-snug">${infra.details || 'MTA transit path'}</p>
      </div>
    `;
    container.appendChild(matrixEl);
  }

  // Combine all indicators from data
  const indicators = data.threat_indicators_detected || data.primary_evidence || [];
  
  if (badge) {
    badge.innerText = `${indicators.length} Threat Indicator(s)`;
    badge.className = indicators.length > 0 
      ? 'px-2.5 py-0.5 rounded-full text-[11px] font-mono font-semibold bg-rose-50 text-rose-700 border border-rose-200'
      : 'px-2.5 py-0.5 rounded-full text-[11px] font-mono font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200';
  }

  if (indicators.length === 0) {
    // Clean email state
    const cleanEl = document.createElement('div');
    cleanEl.className = 'p-4 rounded-2xl bg-emerald-50 border border-emerald-200 flex items-start space-x-3.5';
    cleanEl.innerHTML = `
      <svg class="w-5 h-5 text-emerald-600 flex-shrink-0 mt-0.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        <path d="m9 12 2 2 4-4"/>
      </svg>
      <div>
        <h4 class="text-xs font-bold font-mono uppercase text-emerald-900">All Forensic Checks Passed</h4>
        <p class="text-xs text-emerald-800 mt-1 leading-relaxed">
          All forensic checks passed: SPF/DKIM/DMARC authenticated, no suspicious links or redirects detected, and sender infrastructure is verified and trusted.
        </p>
      </div>
    `;
    container.appendChild(cleanEl);
    return;
  }

  indicators.forEach((indicatorText, idx) => {
    let category = 'THREAT INDICATOR';
    let iconColor = 'text-rose-600';
    let tagClass = 'bg-rose-50 text-rose-700 border border-rose-200';

    const lower = indicatorText.toLowerCase();
    if (lower.includes('lookalike') || lower.includes('typo') || lower.includes('phish')) {
      category = 'DECEPTIVE URL / LOOKALIKE';
      iconColor = 'text-rose-600';
      tagClass = 'bg-rose-100 text-rose-800 border border-rose-300';
    } else if (lower.includes('bec') || lower.includes('reply-to')) {
      category = 'BEC IDENTITY SPOOFING';
      tagClass = 'bg-rose-100 text-rose-800 border border-rose-300';
    } else if (lower.includes('spf') || lower.includes('dkim') || lower.includes('dmarc')) {
      category = 'CRYPTOGRAPHIC AUTH';
      iconColor = 'text-amber-600';
      tagClass = 'bg-amber-50 text-amber-800 border border-amber-200';
    } else if (lower.includes('unresolv') || lower.includes('dead') || lower.includes('dns')) {
      category = 'DEAD / UNRESOLVED DOMAIN';
      iconColor = 'text-rose-600';
      tagClass = 'bg-rose-50 text-rose-700 border border-rose-200';
    } else if (lower.includes('link') || lower.includes('url') || lower.includes('entropy') || lower.includes('tld')) {
      category = 'HYPERLINK PAYLOAD';
      iconColor = 'text-amber-600';
      tagClass = 'bg-amber-50 text-amber-800 border border-amber-200';
    } else if (lower.includes('urgency') || lower.includes('social engineering') || lower.includes('job offer') || lower.includes('compensation')) {
      category = 'SOCIAL ENGINEERING';
      iconColor = 'text-amber-600';
      tagClass = 'bg-amber-50 text-amber-800 border border-amber-200';
    } else if (lower.includes('mta') || lower.includes('tor') || lower.includes('proxy')) {
      category = 'ORIGIN INFRASTRUCTURE';
      iconColor = 'text-purple-600';
      tagClass = 'bg-purple-50 text-purple-800 border border-purple-200';
    }

    const item = document.createElement('div');
    item.className = 'p-3.5 rounded-2xl bg-slate-50 border border-slate-200/80 flex items-start space-x-3 text-xs';
    item.innerHTML = `
      <div class="flex-shrink-0 mt-0.5 ${iconColor}">
        <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="10"/>
          <line x1="12" y1="8" x2="12" y2="12"/>
          <line x1="12" y1="16" x2="12.01" y2="16"/>
        </svg>
      </div>
      <div class="flex-1">
        <div class="flex items-center space-x-2">
          <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase font-mono ${tagClass}">
            ${category}
          </span>
          <span class="text-[10px] text-slate-400 font-mono">Trigger #${idx + 1}</span>
        </div>
        <p class="text-slate-800 mt-1 leading-relaxed font-medium">
          ${indicatorText}
        </p>
      </div>
    `;
    container.appendChild(item);
  });
}

/**
 * SECTION C: Email Forensics & Protocol Alignment
 */
function renderMetadataAndAuth(data) {
  const meta = data.metadata || {};
  const auth = data.authentication || {};
  const mx = data.sender_domain_intelligence || {};

  // BEC Alert Box
  const becBox = document.getElementById('becAlertBox');
  if (becBox) {
    if (meta.reply_to_mismatch) {
      becBox.classList.remove('hidden');
      const becDetail = document.getElementById('becDetailText');
      if (becDetail) becDetail.innerText = `Visible From: ${meta.from || 'N/A'}\nActual Reply-To: ${meta.reply_to || 'N/A'}`;
    } else {
      becBox.classList.add('hidden');
    }
  }

  const setElText = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.innerText = val || '--';
  };

  setElText('metaSubject', meta.subject || 'No Subject');
  setElText('metaFrom', meta.from || 'Unknown Sender');
  setElText('metaFromDomain', meta.from_domain || 'Unknown Domain');
  setElText('metaReturnPath', meta.return_path || 'None');
  setElText('metaTo', meta.to || 'Undisclosed Recipients');
  setElText('metaDate', meta.date || 'Unknown Date');
  setElText('metaHops', `${data.origin_intelligence?.total_hops || 0} intermediate relays`);

  // Alignment checks
  const setAlignmentBadge = (id, isAligned) => {
    const el = document.getElementById(id);
    if (!el) return;
    if (isAligned) {
      el.className = 'px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-emerald-50 text-emerald-700 border border-emerald-200';
      el.innerText = '✓ ALIGNED';
    } else {
      el.className = 'px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-rose-50 text-rose-700 border border-rose-200';
      el.innerText = '🚨 MISMATCH';
    }
  };

  const fromDomain = (meta.from_domain || '').toLowerCase();
  const returnPath = (meta.return_path || '').toLowerCase();
  const returnPathAligned = fromDomain && returnPath.includes(fromDomain);
  setAlignmentBadge('alignmentReturnPathBadge', returnPathAligned);
  setAlignmentBadge('alignmentReplyToBadge', !meta.reply_to_mismatch);

  // Authentication Badges (SPF, DKIM, DMARC, MX)
  const setBadge = (elId, status, passText = 'PASS', failText = 'FAIL') => {
    const el = document.getElementById(elId);
    if (!el) return;
    if (status) {
      el.className = 'px-2.5 py-1 rounded-lg text-[10px] font-bold font-mono uppercase bg-emerald-50 text-emerald-700 border border-emerald-200';
      el.innerText = passText;
    } else {
      el.className = 'px-2.5 py-1 rounded-lg text-[10px] font-bold font-mono uppercase bg-rose-50 text-rose-700 border border-rose-200';
      el.innerText = failText;
    }
  };

  setBadge('spfBadge', auth.spf_pass);
  setElText('spfDetails', auth.spf_details || 'Sender Policy Framework evaluation');

  setBadge('dkimBadge', auth.dkim_pass);
  setElText('dkimDetails', auth.dkim_details || 'Cryptographic public key verification');

  setBadge('dmarcBadge', auth.dmarc_pass);
  setElText('dmarcDetails', auth.dmarc_details || 'Domain alignment and policy enforcement');

  setBadge('mxBadge', mx.has_mx_records, 'VALID MX', 'NO MX');
  setElText('mxDetails', mx.has_mx_records 
    ? `Primary MX: ${mx.primary_mx || 'Configured'}`
    : `Domain '${mx.from_domain}' lacks mail exchanger records`);
}

/**
 * SECTION D: Transmission Trace & Leaflet Map
 */
function renderLeafletMap(originIntel) {
  if (!originIntel) return;

  const routeMap = originIntel.route_map || [];
  const originIp = originIntel.originating_ip || 'Unknown';
  const originCountry = originIntel.origin_country || 'Unknown';
  const originIsp = originIntel.origin_isp || 'Unknown';
  const isAnonymized = originIntel.is_anonymized_node;

  const setElText = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.innerText = val;
  };

  setElText('originIpText', originIp);
  setElText('originCountryBadge', originCountry);
  setElText('originIspText', originIsp);

  const originProxyFlag = document.getElementById('originProxyFlag');
  if (originProxyFlag) {
    if (isAnonymized) {
      originProxyFlag.innerHTML = `
        <span class="px-2.5 py-0.5 rounded-lg text-xs font-mono font-bold uppercase bg-rose-50 text-rose-700 border border-rose-200">TOR / VPN EXIT NODE</span>
        <span class="block text-[11px] text-slate-500 font-mono truncate max-w-[180px]">${originIsp}</span>
      `;
    } else {
      originProxyFlag.innerHTML = `
        <span class="px-2.5 py-0.5 rounded-lg text-xs font-mono font-bold uppercase bg-emerald-50 text-emerald-700 border border-emerald-200">STANDARD TRANSIT</span>
        <span class="block text-[11px] text-slate-500 font-mono truncate max-w-[180px]">${originIsp}</span>
      `;
    }
  }

  // Render Leaflet Map (Light Tiles)
  if (typeof L !== 'undefined') {
    const mapEl = document.getElementById('map');
    if (mapEl) {
      if (!mapInstance) {
        mapInstance = L.map('map', {
          zoomControl: true,
          attributionControl: false
        }).setView([20, 0], 2);

        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
          maxZoom: 19,
          attribution: '&copy; OpenStreetMap'
        }).addTo(mapInstance);

        mapMarkersGroup = L.featureGroup().addTo(mapInstance);
      } else {
        mapMarkersGroup.clearLayers();
        if (mapPolyline) mapInstance.removeLayer(mapPolyline);
      }

      setTimeout(() => {
        if (mapInstance) mapInstance.invalidateSize();
      }, 250);
    }
  }

  const coordinates = [];
  const hopsContainer = document.getElementById('hopsContainer');
  if (hopsContainer) hopsContainer.innerHTML = '';

  routeMap.forEach((hop) => {
    const hasCoords = (hop.lat && hop.lon && (hop.lat !== 0 || hop.lon !== 0));
    const isOrigin = (hop.ip === originIp || hop.is_suspicious_proxy);
    const hopBadgeClass = isOrigin
      ? 'border-rose-200 bg-rose-50/70 text-rose-900'
      : (hop.ip.startsWith('10.') || hop.ip.startsWith('192.168.') || hop.ip.startsWith('172.') 
          ? 'border-slate-100 bg-slate-50 text-slate-500' 
          : 'border-slate-200 bg-white text-slate-700');

    if (hopsContainer) {
      const hopItem = document.createElement('div');
      hopItem.className = `p-2.5 rounded-xl border ${hopBadgeClass} text-xs font-mono flex items-center justify-between shadow-xs`;
      hopItem.innerHTML = `
        <div class="flex items-center space-x-2 truncate">
          <span class="px-1.5 py-0.5 rounded bg-slate-100 text-[10px] font-bold text-slate-600">Hop #${hop.hop_number}</span>
          <span class="font-bold text-slate-800">${hop.ip}</span>
          <span class="text-slate-400 text-[10px] truncate">(${hop.city || 'LAN'}, ${hop.country || 'RFC-1918'})</span>
        </div>
        <div class="flex-shrink-0 text-right">
          ${hop.is_suspicious_proxy 
            ? '<span class="text-[10px] px-2 py-0.5 rounded-md bg-rose-100 text-rose-700 font-bold">TOR / PROXY</span>' 
            : (isOrigin ? '<span class="text-[10px] px-2 py-0.5 rounded-md bg-slate-900 text-white font-bold">ORIGIN MTA</span>' : '<span class="text-[10px] text-slate-400">RELAY</span>')}
        </div>
      `;
      hopsContainer.appendChild(hopItem);
    }

    if (hasCoords && mapMarkersGroup && typeof L !== 'undefined') {
      coordinates.push([hop.lat, hop.lon]);

      const iconClass = isOrigin ? 'pulse-marker-origin' : 'pulse-marker-hop';
      const customIcon = L.divIcon({
        className: 'custom-div-icon',
        html: `<div class="${iconClass}"></div>`,
        iconSize: [16, 16],
        iconAnchor: [8, 8]
      });

      const popupHtml = `
        <div class="font-mono">
          <div class="text-xs font-bold ${isOrigin ? 'text-rose-600' : 'text-slate-900'} border-b border-slate-200 pb-1 mb-1">
            HOP #${hop.hop_number}: ${hop.ip}
          </div>
          <div><strong>Location:</strong> ${hop.city}, ${hop.country}</div>
          <div><strong>ISP:</strong> ${hop.isp} (${hop.asn})</div>
          <div class="mt-1">
            ${hop.is_suspicious_proxy 
              ? '<span class="px-1.5 py-0.5 rounded bg-rose-100 text-rose-700 text-[9px] font-bold uppercase">🚨 Tor / VPN Node</span>' 
              : '<span class="text-emerald-600 text-[9px] font-bold">✓ Verified Transit Node</span>'}
          </div>
        </div>
      `;

      const marker = L.marker([hop.lat, hop.lon], { icon: customIcon }).bindPopup(popupHtml);
      mapMarkersGroup.addLayer(marker);
    }
  });

  if (coordinates.length > 1 && mapInstance && typeof L !== 'undefined') {
    mapPolyline = L.polyline(coordinates, {
      color: '#0f172a',
      weight: 2.5,
      opacity: 0.8,
      dashArray: '6, 6',
      lineCap: 'round'
    }).addTo(mapInstance);

    mapInstance.fitBounds(mapPolyline.getBounds(), { padding: [30, 30] });
  } else if (coordinates.length === 1 && mapInstance) {
    mapInstance.setView(coordinates[0], 5);
  }
}

/**
 * SECTION E: Hyperlink & Payload Investigation
 */
function renderLinks(links = []) {
  const linksContainer = document.getElementById('linksContainer');
  const countBadge = document.getElementById('linkCountBadge');
  if (countBadge) countBadge.innerText = `${links.length} Link(s)`;
  if (!linksContainer) return;

  linksContainer.innerHTML = '';

  if (links.length === 0) {
    linksContainer.innerHTML = `
      <div class="p-6 rounded-2xl bg-slate-50 border border-slate-200 text-center text-xs text-slate-400 font-mono">
        No embedded links detected in email body
      </div>
    `;
    return;
  }

  links.forEach((link, idx) => {
    const score = parseFloat(link.threat_score || 0.0);
    const telemetry = link.telemetry || {};
    const isUnreachable = telemetry.is_unreachable === true;
    
    // Critical: Never mark an unreachable/dead link as clean!
    let verdictLabel = link.verdict || link.classification || 'CLEAN';
    let badgeClass = 'bg-emerald-50 text-emerald-700 border-emerald-200';

    if (score >= 80.0 || verdictLabel.includes('CRITICAL') || verdictLabel.includes('PHISHING')) {
      badgeClass = 'bg-rose-50 text-rose-700 border-rose-200';
    } else if (score >= 50.0 || isUnreachable || verdictLabel.includes('UNRESOLVED') || verdictLabel.includes('SUSPICIOUS')) {
      badgeClass = 'bg-amber-50 text-amber-700 border-amber-200';
      if (isUnreachable && !verdictLabel.includes('PHISHING')) {
        verdictLabel = 'SUSPICIOUS / UNRESOLVED DOMAIN';
      }
    }

    // Extract destination domain
    let domainStr = 'N/A';
    try {
      domainStr = new URL(link.url).hostname;
    } catch (_) {
      domainStr = link.url.split('/')[2] || link.url;
    }

    // Indicator tags
    const indicators = link.indicators || telemetry.threat_indicators_detected || telemetry.heuristic_flags || [];
    let indicatorsHtml = '';
    if (indicators.length > 0) {
      indicatorsHtml = `
        <div class="space-y-1 pt-2 border-t border-slate-100">
          <span class="text-[10px] uppercase font-bold text-slate-400 block font-mono">Detected Indicators:</span>
          <div class="flex flex-wrap gap-1.5">
            ${indicators.map(ind => {
              return `<span class="px-2 py-0.5 rounded-md text-[10px] bg-slate-100 text-slate-700 font-mono font-medium">${ind}</span>`;
            }).join('')}
          </div>
        </div>
      `;
    }

    const card = document.createElement('div');
    card.className = 'p-4 rounded-2xl bg-slate-50 border border-slate-200/80 space-y-2.5 text-xs';
    
    const copyBtnId = `copyLinkBtn_${idx}`;
    card.innerHTML = `
      <div class="flex items-center justify-between">
        <span class="px-2.5 py-0.5 rounded-md text-[10px] font-bold font-mono border uppercase ${badgeClass}">
          ${Math.round(score)}/100 • ${verdictLabel}
        </span>
        <span class="text-[11px] text-slate-500 font-mono">Domain: <strong class="text-slate-800">${domainStr}</strong></span>
      </div>
      
      <div class="flex items-center justify-between bg-white p-2.5 rounded-xl border border-slate-200 shadow-xs">
        <span class="text-[11px] text-slate-800 break-all select-all font-mono">${link.url}</span>
        <button type="button" id="${copyBtnId}" onclick="copyLinkToClipboard('${link.url.replace(/'/g, "\\'")}', '${copyBtnId}')" class="ml-2 text-[10px] px-2.5 py-1 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-700 font-semibold cursor-pointer flex-shrink-0 transition-colors">
          Copy
        </button>
      </div>

      ${indicatorsHtml}

      <div class="text-[11px] text-slate-500 leading-normal">
        ${link.summary ? link.summary.split('\n')[0] : 'Payload evaluated in forensic pipeline.'}
      </div>
    `;
    linksContainer.appendChild(card);
  });
}

/**
 * SECTION F: Investigative Assessment & Legal Dossier
 */
function renderLegalAndNarrative(data) {
  const originIntel = data.origin_intelligence || {};
  const attr = data.threat_attribution || {};

  // Probable Source Infrastructure
  const sourceInfraEl = document.getElementById('sourceInfraText');
  if (sourceInfraEl) {
    if (originIntel.is_anonymized_node) {
      sourceInfraEl.innerText = `Tor Exit Node / Anonymized VPN Proxy (${originIntel.origin_isp || 'Unknown ASN'})`;
    } else if (originIntel.originating_ip) {
      sourceInfraEl.innerText = `Commercial Hosting / Transit Network (${originIntel.origin_isp || 'Standard IP'})`;
    } else {
      sourceInfraEl.innerText = 'Authenticated Corporate Exchange / Direct Transit Infrastructure';
    }
  }

  // Attribution Confidence & Rationale
  const confBadge = document.getElementById('attributionConfidenceBadge');
  const confRationale = document.getElementById('attributionRationale');
  const confLevel = (data.confidence || attr.confidence || 'MODERATE').toUpperCase();

  if (confBadge) {
    confBadge.innerText = `${confLevel} CONFIDENCE`;
    if (confLevel === 'HIGH') {
      confBadge.className = 'px-2.5 py-0.5 rounded text-[10px] font-bold font-mono uppercase bg-slate-900 text-white';
    } else {
      confBadge.className = 'px-2.5 py-0.5 rounded text-[10px] font-bold font-mono uppercase bg-slate-200 text-slate-700';
    }
  }

  if (confRationale) {
    confRationale.innerText = attr.details || 'Attribution confidence weighted from cryptographic protocol alignment, network hop telemetry, and deterministic payload indicators.';
  }

  // Incident Narrative
  const narrativeContainer = document.getElementById('narrativeContent');
  if (narrativeContainer) {
    narrativeContainer.innerText = data.incident_summary || 'No forensic narrative available.';
  }

  // SHA-256 Digest
  const shaEl = document.getElementById('sha256Digest');
  if (shaEl) {
    shaEl.innerText = data.evidence_hash_sha256 || 'N/A';
  }
}

/**
 * Exports Court-Admissible PDF Dossier
 */
async function exportDossierPdf(e) {
  if (e) e.stopPropagation();
  if (!currentReport) {
    alert('No active forensic report to export. Ingest an .eml file or run a demo scenario first.');
    return;
  }

  const btn = document.getElementById('exportPdfBtn');
  const originalHtml = btn ? btn.innerHTML : '';
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<svg class="w-4 h-4 animate-spin inline-block mr-1.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg><span>Compiling PDF...</span>`;
  }

  try {
    const response = await fetch(`${API_BASE}/api/forensics/export-pdf`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(currentReport)
    });

    if (!response.ok) {
      throw new Error(`PDF Export failed with HTTP status ${response.status}`);
    }

    const blob = await response.blob();
    const blobUrl = window.URL.createObjectURL(blob);
    
    const hashPrefix = (currentReport.evidence_hash_sha256 || 'dossier').substring(0, 10);
    const downloadLink = document.createElement('a');
    downloadLink.href = blobUrl;
    downloadLink.download = `TrustShield_Forensic_Dossier_${hashPrefix}.pdf`;
    document.body.appendChild(downloadLink);
    downloadLink.click();
    
    window.URL.revokeObjectURL(blobUrl);
    downloadLink.remove();

  } catch (error) {
    alert(`Failed to export forensic dossier PDF:\n${error.message}`);
    console.error('PDF Export Error:', error);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = originalHtml;
    }
  }
}

function formatBytes(bytes, decimals = 1) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

function updateProcessedFileCard(fileMeta, data) {
  const card = document.getElementById('processedFileCard');
  if (!card) return;
  
  const nameEl = document.getElementById('loadedFileName');
  const sizeEl = document.getElementById('loadedFileSize');
  const statusEl = document.getElementById('loadedFileStatus');
  const verdictEl = document.getElementById('loadedFileVerdict');

  if (nameEl) nameEl.innerText = fileMeta.name || 'evidence.eml';
  if (sizeEl) sizeEl.innerText = fileMeta.size ? formatBytes(fileMeta.size) : 'Ready';

  const score = parseFloat(data.overall_threat_score || 0.0);
  const verdict = data.verdict || '';

  if (statusEl) {
    if (score >= 80.0 || verdict.includes('CRITICAL') || verdict.includes('PHISHING')) {
      statusEl.className = 'px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-100 text-rose-800 uppercase';
      statusEl.innerText = 'CRITICAL THREAT';
    } else if (score >= 50.0 || verdict.includes('BEC') || verdict.includes('SUSPICIOUS')) {
      statusEl.className = 'px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-100 text-amber-800 uppercase';
      statusEl.innerText = 'SUSPICIOUS / BEC';
    } else {
      statusEl.className = 'px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-100 text-emerald-800 uppercase';
      statusEl.innerText = 'VERIFIED / CLEAN';
    }
  }

  if (verdictEl) {
    verdictEl.innerText = `Threat Score: ${Math.round(score)}/100 • ${verdict || 'Analysis Complete'}`;
  }

  card.classList.remove('hidden');
}

function resetInvestigationOverview() {
  const scoreNumber = document.getElementById('scoreNumber');
  if (scoreNumber) {
    scoreNumber.innerText = '--';
    scoreNumber.className = 'text-3xl font-black font-mono tracking-tighter text-slate-400';
  }

  const scoreCircle = document.getElementById('scoreCircle');
  if (scoreCircle) {
    scoreCircle.style.strokeDashoffset = '263.89';
    scoreCircle.setAttribute('stroke', '#cbd5e1');
  }

  const verdictCard = document.getElementById('verdictCard');
  if (verdictCard) {
    verdictCard.className = 'card-soft rounded-3xl p-6 sm:p-8 space-y-6 bg-white border border-slate-200 transition-all';
  }

  const verdictBadge = document.getElementById('verdictBadge');
  if (verdictBadge) {
    verdictBadge.className = 'px-3 py-1 rounded-lg text-xs font-bold font-mono tracking-wide uppercase bg-slate-100 text-slate-600 border border-slate-200';
    verdictBadge.innerText = 'NO EVIDENCE LOADED';
  }

  const attributionBadge = document.getElementById('attributionBadge');
  if (attributionBadge) {
    attributionBadge.className = 'px-2.5 py-1 rounded-lg text-xs font-mono font-semibold uppercase bg-slate-100 text-slate-600 border border-slate-200';
    attributionBadge.innerText = '--';
  }

  const confidenceBadge = document.getElementById('confidenceBadge');
  if (confidenceBadge) {
    confidenceBadge.className = 'px-2.5 py-1 rounded-lg text-xs font-mono font-semibold uppercase bg-slate-100 text-slate-600 border border-slate-200';
    confidenceBadge.innerText = 'CONFIDENCE: --';
  }

  const verdictHeadline = document.getElementById('verdictHeadline');
  if (verdictHeadline) {
    verdictHeadline.innerText = 'Awaiting Email Ingestion';
  }

  const attributionDetails = document.getElementById('attributionDetails');
  if (attributionDetails) {
    attributionDetails.innerText = 'Upload an RFC-5322 (.eml or .msg) file to run automated forensics, origin geolocation, and link sandboxing.';
  }

  const modeLabel = document.getElementById('analysisModeLabel');
  if (modeLabel) {
    modeLabel.innerText = 'STANDBY';
  }

  const actionBox = document.getElementById('recommendedActionBox');
  if (actionBox) {
    actionBox.className = 'p-4 rounded-2xl bg-slate-50 border border-slate-200 flex items-start space-x-3.5';
  }
  const actionText = document.getElementById('recommendedActionText');
  if (actionText) {
    actionText.className = 'text-xs text-slate-500 mt-1 leading-relaxed font-medium';
    actionText.innerText = 'Upload an email evidence file (.eml / .msg) in the Ingestion workspace to start automated SOC evaluation.';
  }

  const ids = ['overviewFrom', 'overviewTo', 'overviewDate', 'overviewOriginIp', 'overviewHops'];
  ids.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.innerText = '--';
  });

  const evidenceList = document.getElementById('keyEvidenceList');
  if (evidenceList) {
    evidenceList.innerHTML = `<div class="p-6 rounded-2xl bg-slate-50 border border-slate-100 text-center text-slate-400 text-xs font-medium">No forensic triggers recorded yet. Awaiting evidence file ingestion.</div>`;
  }
  const countBadge = document.getElementById('evidenceCountBadge');
  if (countBadge) countBadge.innerText = '0 Indicators';
}

function resetAllTelemetryViews() {
  // Reset Technical Message Envelope (Section C)
  const becBox = document.getElementById('becAlertBox');
  if (becBox) becBox.classList.add('hidden');

  const metaIds = ['metaSubject', 'metaFrom', 'metaFromDomain', 'metaReturnPath', 'metaTo', 'metaDate', 'metaHops'];
  metaIds.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.innerText = '--';
  });

  const alignPath = document.getElementById('alignmentReturnPathBadge');
  if (alignPath) {
    alignPath.innerText = '--';
    alignPath.className = 'px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-slate-100 text-slate-600';
  }
  const alignReply = document.getElementById('alignmentReplyToBadge');
  if (alignReply) {
    alignReply.innerText = '--';
    alignReply.className = 'px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-slate-100 text-slate-600';
  }

  // Reset Leaflet Map (Section D)
  if (mapMarkersGroup) {
    try { mapMarkersGroup.clearLayers(); } catch (_) {}
  }
  if (mapPolyline && mapInstance) {
    try {
      mapInstance.removeLayer(mapPolyline);
      mapPolyline = null;
    } catch (_) {}
  }
  if (mapInstance) {
    try { mapInstance.setView([20, 0], 2); } catch (_) {}
  }
  const countryBadge = document.getElementById('originCountryBadge');
  if (countryBadge) countryBadge.innerText = 'Unknown';
  const ipEl = document.getElementById('originIpText');
  if (ipEl) ipEl.innerText = '--';
  const geoEl = document.getElementById('originGeoText');
  if (geoEl) geoEl.innerText = '--';
  const ispEl = document.getElementById('originIspText');
  if (ispEl) ispEl.innerText = '--';
  const hopsTable = document.getElementById('transitHopsTable');
  if (hopsTable) hopsTable.innerHTML = '<tr><td colspan="5" class="py-4 text-center text-xs text-slate-400 font-mono">No transit telemetry loaded</td></tr>';

  // Reset Links (Section E)
  const linkBadge = document.getElementById('linkCountBadge');
  if (linkBadge) linkBadge.innerText = '0 Links';
  const linksContainer = document.getElementById('linksContainer');
  if (linksContainer) {
    linksContainer.innerHTML = '<div class="p-6 rounded-2xl bg-slate-50 border border-slate-200 text-center text-xs text-slate-400 font-mono">No embedded links detected in email body</div>';
  }

  // Reset Legal & Reports (Section F & Reports)
  const sourceInfra = document.getElementById('sourceInfraText');
  if (sourceInfra) sourceInfra.innerText = '--';
  const confBadge = document.getElementById('attributionConfidenceBadge');
  if (confBadge) confBadge.innerText = 'CONFIDENCE: --';
  const confRationale = document.getElementById('attributionRationale');
  if (confRationale) confRationale.innerText = '--';
  const narrative = document.getElementById('narrativeContent');
  if (narrative) narrative.innerText = 'No forensic narrative available.';
  const sha = document.getElementById('sha256Digest');
  if (sha) sha.innerText = '--';
}

function removeCurrentFile(e) {
  if (e) {
    if (e.preventDefault) e.preventDefault();
    if (e.stopPropagation) e.stopPropagation();
  }
  currentReport = null;
  currentFileMeta = null;

  const fileInput = document.getElementById('emlFileInput');
  if (fileInput) fileInput.value = '';

  const processedCard = document.getElementById('processedFileCard');
  if (processedCard) processedCard.classList.add('hidden');

  const activeCaseCard = document.getElementById('dashboardActiveCaseCard');
  if (activeCaseCard) activeCaseCard.classList.add('hidden');
  const navBadge = document.getElementById('navCaseBadge');
  if (navBadge) navBadge.classList.add('hidden');

  const subjectEl = document.getElementById('dashActiveSubject');
  if (subjectEl) subjectEl.innerText = '--';
  const verdictEl = document.getElementById('dashActiveVerdict');
  if (verdictEl) verdictEl.innerText = '--';

  resetInvestigationOverview();
  resetAllTelemetryViews();

  switchView('analyze');
}

function resetDashboard(e) {
  removeCurrentFile(e);
}

// Initial setup on DOM ready
function initWorkspace() {
  setupDragAndDrop();
  resetInvestigationOverview();
  resetAllTelemetryViews();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initWorkspace);
} else {
  initWorkspace();
}

// Floating return-to-top handler for smooth navigation
window.addEventListener('scroll', () => {
  const btn = document.getElementById('backToTopBtn');
  if (btn) {
    if (window.scrollY > 280) {
      btn.classList.remove('opacity-0', 'pointer-events-none');
      btn.classList.add('opacity-100');
    } else {
      btn.classList.add('opacity-0', 'pointer-events-none');
      btn.classList.remove('opacity-100');
    }
  }
}, { passive: true });
