/**
 * TrustShield V2 - SOC Analyst Forensic Intelligence Portal
 * Unified Frontend Controller
 */

// Global API Base resolution
var API_BASE = (window.location.port === '8000' && window.location.protocol.startsWith('http'))
  ? ''
  : 'http://localhost:8000';

var currentReport = null;
var mapInstance = null;
var mapMarkersGroup = null;
var mapPolyline = null;
var statusInterval = null;

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

function copyEvidenceHash(e) {
  if (e) e.stopPropagation();
  const hashText = document.getElementById('sha256Digest').innerText;
  if (hashText && hashText !== 'Calculating...') {
    navigator.clipboard.writeText(hashText);
    const copyBtn = document.getElementById('copyHashBtn');
    copyBtn.innerHTML = `<span class="text-emerald-400 font-semibold">✓ Copied</span>`;
    setTimeout(() => {
      copyBtn.innerHTML = `
        <svg class="w-3 h-3 inline-block mr-1" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <rect width="14" height="14" x="8" y="8" rx="2" ry="2"/>
          <path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>
        </svg>
        <span>Copy</span>
      `;
    }, 2000);
  }
}

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
      dropZone.classList.add('border-cyan-400', 'bg-cyan-950/30');
    });
  });

  ['dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.remove('border-cyan-400', 'bg-cyan-950/30');
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
async function processEmlFile(file) {
  if (!file) return;
  showLoading(true);

  const formData = new FormData();
  formData.append('file', file);

  try {
    const response = await fetch(`${API_BASE}/api/forensics/analyze-eml`, {
      method: 'POST',
      body: formData
    });

    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      throw new Error(errData.error || `HTTP ${response.status}: Analysis request failed`);
    }

    const data = await response.json();
    currentReport = data;

    renderDashboard(data);
    showLoading(false);

  } catch (error) {
    showLoading(false);
    alert(`Forensic Ingestion Error:\n${error.message}\n\nPlease ensure backend is running at ${API_BASE || 'http://localhost:8000'}`);
    console.error('Forensic Analysis Error:', error);
  }
}

function showLoading(isLoading) {
  const loadingState = document.getElementById('loadingState');
  const statusText = document.getElementById('loadingStatusText');
  if (!loadingState) return;

  if (isLoading) {
    loadingState.classList.remove('hidden');
    
    const steps = [
      'Computing SHA-256 Chain of Custody...',
      'Tracing Received: Hops & Filtering RFC-1918 Private Subnets...',
      'Querying SPF, DKIM, DMARC & MX Infrastructure...',
      'Detonating Hyperlinks in Headless Chrome Sandbox...',
      'Classifying Threat Actor Attribution Matrix...'
    ];
    let stepIdx = 0;
    if (statusText) statusText.innerText = steps[0];
    
    if (statusInterval) clearInterval(statusInterval);
    statusInterval = setInterval(() => {
      stepIdx = (stepIdx + 1) % steps.length;
      if (statusText) statusText.innerText = steps[stepIdx];
    }, 1500);

  } else {
    loadingState.classList.add('hidden');
    if (statusInterval) clearInterval(statusInterval);
  }
}

function renderDashboard(data) {
  const execSection = document.getElementById('executiveVerdict');
  const dashGrid = document.getElementById('dashboardGrid');
  if (execSection) execSection.classList.remove('hidden');
  if (dashGrid) dashGrid.classList.remove('hidden');

  renderVerdict(data);
  renderMetadataAndAuth(data);
  renderLeafletMap(data.origin_intelligence);
  renderNarrativeAndLinks(data);

  if (execSection) execSection.scrollIntoView({ behavior: 'smooth' });
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
  if (attributionDetails) attributionDetails.innerText = attr.details || 'Evaluation completed across all telemetry engines.';

  if (score >= 80.0) {
    if (scoreCircle) scoreCircle.setAttribute('stroke', '#ef4444');
    if (verdictCard) verdictCard.className = 'rounded-2xl border border-red-800/80 p-6 sm:p-8 bg-gradient-to-br from-red-950/40 via-slate-900 to-slate-950 shadow-2xl glow-red transition-all';
    if (verdictBadge) {
      verdictBadge.className = 'px-3 py-1 rounded-md text-xs font-bold font-mono tracking-wide uppercase bg-red-950/90 text-red-400 border border-red-700/80';
      verdictBadge.innerText = data.verdict || 'CRITICAL FRAUD / PHISHING';
    }
    if (verdictHeadline) verdictHeadline.innerText = 'Critical Cyber Attack & Identity Spoofing';
  } else if (score >= 50.0) {
    if (scoreCircle) scoreCircle.setAttribute('stroke', '#f59e0b');
    if (verdictCard) verdictCard.className = 'rounded-2xl border border-amber-800/80 p-6 sm:p-8 bg-gradient-to-br from-amber-950/40 via-slate-900 to-slate-950 shadow-2xl glow-amber transition-all';
    if (verdictBadge) {
      verdictBadge.className = 'px-3 py-1 rounded-md text-xs font-bold font-mono tracking-wide uppercase bg-amber-950/90 text-amber-400 border border-amber-700/80';
      verdictBadge.innerText = data.verdict || 'SUSPICIOUS / UNVERIFIED ORIGIN';
    }
    if (verdictHeadline) verdictHeadline.innerText = 'Suspicious Infrastructure & Unverified Identity';
  } else {
    if (scoreCircle) scoreCircle.setAttribute('stroke', '#10b981');
    if (verdictCard) verdictCard.className = 'rounded-2xl border border-emerald-800/80 p-6 sm:p-8 bg-gradient-to-br from-emerald-950/40 via-slate-900 to-slate-950 shadow-2xl glow-emerald transition-all';
    if (verdictBadge) {
      verdictBadge.className = 'px-3 py-1 rounded-md text-xs font-bold font-mono tracking-wide uppercase bg-emerald-950/90 text-emerald-400 border border-emerald-700/80';
      verdictBadge.innerText = data.verdict || 'LEGITIMATE / AUTHENTICATED';
    }
    if (verdictHeadline) verdictHeadline.innerText = 'Technical Envelope Verified Clean';
  }
}

function renderMetadataAndAuth(data) {
  const meta = data.metadata || {};
  const auth = data.authentication || {};
  const mx = data.sender_domain_intelligence || {};

  const becBox = document.getElementById('becAlertBox');
  if (becBox) {
    if (meta.reply_to_mismatch) {
      becBox.classList.remove('hidden');
      const becDetail = document.getElementById('becDetailText');
      if (becDetail) becDetail.innerText = `From: ${meta.from || 'N/A'}\nReply-To: ${meta.reply_to || 'N/A'}`;
    } else {
      becBox.classList.add('hidden');
    }
  }

  const setElText = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.innerText = val;
  };

  setElText('metaSubject', meta.subject || 'No Subject');
  setElText('metaFrom', meta.from || 'Unknown Sender');
  setElText('metaFromDomain', meta.from_domain || 'Unknown Domain');
  setElText('metaReturnPath', meta.return_path || 'None');
  setElText('metaTo', meta.to || 'Undisclosed Recipients');
  setElText('metaDate', meta.date || 'Unknown Date');
  setElText('metaHops', `${data.origin_intelligence?.total_hops || 0} intermediate hops`);

  const setBadge = (elId, status, passText = 'PASS', failText = 'FAIL') => {
    const el = document.getElementById(elId);
    if (!el) return;
    if (status) {
      el.className = 'px-2.5 py-1 rounded text-[10px] font-bold font-mono uppercase bg-emerald-950 text-emerald-400 border border-emerald-700/60';
      el.innerText = passText;
    } else {
      el.className = 'px-2.5 py-1 rounded text-[10px] font-bold font-mono uppercase bg-red-950 text-red-400 border border-red-700/60';
      el.innerText = failText;
    }
  };

  setBadge('spfBadge', auth.spf_pass);
  setElText('spfDetails', auth.spf_details || 'Sender Policy Framework evaluation');

  setBadge('dkimBadge', auth.dkim_pass);
  setElText('dkimDetails', auth.dkim_details || 'Cryptographic public key verification');

  setBadge('dmarcBadge', auth.dmarc_pass);
  setElText('dmarcDetails', auth.dmarc_details || 'Domain alignment and policy enforcement');

  setBadge('mxBadge', mx.has_mx_records, 'VALID MX', 'NO MX (BURNER)');
  setElText('mxDetails', mx.has_mx_records 
    ? `Primary MX: ${mx.primary_mx || 'Configured'}`
    : `Domain '${mx.from_domain}' lacks mail exchanger infrastructure`);
}

function renderLeafletMap(originIntel) {
  if (!originIntel) return;
  if (typeof L === 'undefined') {
    console.warn('Leaflet not loaded');
    return;
  }

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
    if (originIntel.is_proxy) {
      originProxyFlag.innerHTML = `
        <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-red-950 text-red-400 border border-red-700/50">TOR / PROXY</span>
        <span class="block text-[10px] text-slate-400 font-mono truncate max-w-[150px]">${originIsp}</span>
      `;
    } else if (originIntel.is_hosting) {
      originProxyFlag.innerHTML = `
        <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-cyan-950 text-cyan-400 border border-cyan-700/50">CLOUD / MTA RELAY</span>
        <span class="block text-[10px] text-slate-400 font-mono truncate max-w-[150px]">${originIsp}</span>
      `;
    } else {
      originProxyFlag.innerHTML = `
        <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-emerald-950 text-emerald-400 border border-emerald-700/50">STANDARD TRANSIT</span>
        <span class="block text-[10px] text-slate-400 font-mono truncate max-w-[150px]">${originIsp}</span>
      `;
    }
  }

  const mapEl = document.getElementById('map');
  if (!mapEl) return;

  if (!mapInstance) {
    mapInstance = L.map('map', {
      zoomControl: true,
      attributionControl: false
    }).setView([20, 0], 2);

    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      maxZoom: 19,
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright" target="_blank" class="text-cyan-500">OpenStreetMap</a>'
    }).addTo(mapInstance);

    mapMarkersGroup = L.featureGroup().addTo(mapInstance);
  } else {
    mapMarkersGroup.clearLayers();
    if (mapPolyline) mapInstance.removeLayer(mapPolyline);
  }

  setTimeout(() => {
    if (mapInstance) mapInstance.invalidateSize();
  }, 250);

  const coordinates = [];
  const hopsContainer = document.getElementById('hopsContainer');
  if (hopsContainer) hopsContainer.innerHTML = '';

  routeMap.forEach((hop) => {
    const hasCoords = (hop.lat && hop.lon && (hop.lat !== 0 || hop.lon !== 0));
    const isOrigin = (hop.ip === originIp || hop.is_suspicious_proxy);
    const hopBadgeClass = isOrigin
      ? 'border-red-600/70 bg-red-950/40 text-red-300'
      : (hop.ip.startsWith('10.') || hop.ip.startsWith('192.168.') 
          ? 'border-slate-700 bg-slate-950/40 text-slate-400' 
          : 'border-cyan-800/60 bg-cyan-950/40 text-cyan-300');

    if (hopsContainer) {
      const hopItem = document.createElement('div');
      hopItem.className = `p-2 rounded-lg border ${hopBadgeClass} text-xs font-mono flex items-center justify-between`;
      hopItem.innerHTML = `
        <div class="flex items-center space-x-2 truncate">
          <span class="px-1.5 py-0.5 rounded bg-black/40 text-[10px] font-bold">#${hop.hop_number}</span>
          <span class="font-bold">${hop.ip}</span>
          <span class="text-slate-500 text-[10px] truncate">(${hop.city || 'LAN'}, ${hop.country || 'RFC-1918'})</span>
        </div>
        <div class="flex-shrink-0 text-right">
          ${hop.is_suspicious_proxy 
            ? '<span class="text-[9px] px-1.5 py-0.5 rounded bg-red-950 text-red-400 border border-red-800 font-bold">TOR / VPN</span>' 
            : '<span class="text-[9px] text-slate-500">RELAY</span>'}
        </div>
      `;
      hopsContainer.appendChild(hopItem);
    }

    if (hasCoords && mapMarkersGroup) {
      coordinates.push([hop.lat, hop.lon]);

      const iconClass = isOrigin ? 'pulse-marker-origin' : 'pulse-marker-hop';
      const customIcon = L.divIcon({
        className: 'custom-div-icon',
        html: `<div class="${iconClass}"></div>`,
        iconSize: [20, 20],
        iconAnchor: [10, 10]
      });

      const popupHtml = `
        <div class="font-mono">
          <div class="text-xs font-bold ${isOrigin ? 'text-red-400' : 'text-cyan-400'} border-b border-slate-700 pb-1 mb-1">
            HOP #${hop.hop_number}: ${hop.ip}
          </div>
          <div><strong>Location:</strong> ${hop.city}, ${hop.country}</div>
          <div><strong>ISP:</strong> ${hop.isp} (${hop.asn})</div>
          <div class="mt-1">
            ${hop.is_suspicious_proxy 
              ? '<span class="px-1.5 py-0.5 rounded bg-red-950 text-red-400 border border-red-700 text-[9px] font-bold uppercase">🚨 Tor / VPN Proxy Detected</span>' 
              : '<span class="text-emerald-400 text-[9px]">✓ Verified Transit Node</span>'}
          </div>
        </div>
      `;

      const marker = L.marker([hop.lat, hop.lon], { icon: customIcon }).bindPopup(popupHtml);
      mapMarkersGroup.addLayer(marker);
    }
  });

  if (coordinates.length > 1 && mapInstance) {
    mapPolyline = L.polyline(coordinates, {
      color: '#ef4444',
      weight: 2.5,
      opacity: 0.8,
      dashArray: '6, 8',
      lineCap: 'round'
    }).addTo(mapInstance);

    mapInstance.fitBounds(mapPolyline.getBounds(), { padding: [40, 40] });
  } else if (coordinates.length === 1 && mapInstance) {
    mapInstance.setView(coordinates[0], 5);
  }
}

function renderNarrativeAndLinks(data) {
  const narrativeContainer = document.getElementById('narrativeContent');
  if (narrativeContainer) narrativeContainer.innerText = data.incident_summary || 'No forensic narrative available.';

  const links = data.link_investigation || [];
  const linksContainer = document.getElementById('linksContainer');
  const countBadge = document.getElementById('linkCountBadge');
  if (countBadge) countBadge.innerText = `${links.length} Link(s)`;
  
  if (linksContainer) {
    linksContainer.innerHTML = '';

    if (links.length === 0) {
      linksContainer.innerHTML = `
        <div class="p-4 rounded-lg bg-slate-950/60 border border-slate-800 text-center text-xs text-slate-500 font-mono">
          No embedded links detected in email payload
        </div>
      `;
    } else {
      links.forEach(link => {
        const score = parseFloat(link.threat_score || 0.0);
        const isCritical = score >= 80.0;
        const isSuspicious = score >= 50.0 && score < 80.0;
        
        const badgeClass = isCritical
          ? 'bg-red-950 text-red-400 border-red-700'
          : (isSuspicious ? 'bg-amber-950 text-amber-400 border-amber-700' : 'bg-emerald-950 text-emerald-400 border-emerald-700');

        const card = document.createElement('div');
        card.className = `p-3 rounded-lg bg-slate-950/80 border ${isCritical ? 'border-red-900/60' : 'border-slate-800'} space-y-2 text-xs font-mono`;
        card.innerHTML = `
          <div class="flex items-center justify-between">
            <span class="px-2 py-0.5 rounded text-[10px] font-bold border uppercase ${badgeClass}">
              ${Math.round(score)}/100 • ${link.verdict || 'UNKNOWN'}
            </span>
            <span class="text-[10px] text-slate-500">${link.telemetry?.hard_override_triggered ? '🚨 Threat DB Match' : 'Sandbox Audit'}</span>
          </div>
          <div class="text-[11px] text-slate-300 break-all bg-black/40 p-1.5 rounded border border-slate-800/80">
            ${link.url}
          </div>
          <div class="text-[10px] text-slate-400 truncate">
            ${link.summary ? link.summary.split('\n')[0] : 'Payload evaluated in headless sandbox.'}
          </div>
        `;
        linksContainer.appendChild(card);
      });
    }
  }

  const shaEl = document.getElementById('sha256Digest');
  if (shaEl) shaEl.innerText = data.evidence_hash_sha256 || 'N/A';
}

async function exportDossierPdf(e) {
  if (e) e.stopPropagation();
  if (!currentReport) {
    alert('No active forensic report to export.');
    return;
  }

  const btn = document.getElementById('exportPdfBtn');
  const originalHtml = btn ? btn.innerHTML : '';
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<svg class="w-4 h-4 animate-spin inline-block mr-1" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg><span>Compiling PDF Dossier...</span>`;
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

function resetDashboard(e) {
  if (e) e.stopPropagation();
  currentReport = null;
  const fileInput = document.getElementById('emlFileInput');
  if (fileInput) fileInput.value = '';
  const execSection = document.getElementById('executiveVerdict');
  const dashGrid = document.getElementById('dashboardGrid');
  if (execSection) execSection.classList.add('hidden');
  if (dashGrid) dashGrid.classList.add('hidden');
  const uploadSec = document.getElementById('uploadSection');
  if (uploadSec) uploadSec.scrollIntoView({ behavior: 'smooth' });
}

// Initial setup on load
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', setupDragAndDrop);
} else {
  setupDragAndDrop();
}
