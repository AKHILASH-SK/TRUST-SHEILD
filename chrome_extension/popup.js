document.addEventListener('DOMContentLoaded', async () => {
  const analyzeBtn = document.getElementById('analyze-btn');
  const loadingDiv = document.getElementById('loading');
  const resultsDiv = document.getElementById('results');
  const errorMsg = document.getElementById('error-msg');
  const targetSender = document.getElementById('target-sender');
  const targetSubject = document.getElementById('target-subject');
  const openPortalBtn = document.getElementById('open-portal-btn');

  const LOCAL_API_URL = "http://127.0.0.1:8000/api/extension/analyze";
  const CLOUD_API_URL = "https://trust-sheild.onrender.com/api/extension/analyze";
  const PORTAL_URL = "http://127.0.0.1:8000/portal/";

  let lastDossier = null;
  let lastRawEml = null;

  // 1. Initial active tab inspection
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.id) {
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        files: ['content.js']
      });

      chrome.tabs.sendMessage(tab.id, { action: "extractEmail" }, (emailData) => {
        if (!chrome.runtime.lastError && emailData) {
          if (targetSender) targetSender.innerText = emailData.sender || "Webmail message detected";
          if (targetSubject) targetSubject.innerText = emailData.subject || "No subject header";
        }
      });
    }
  } catch (e) {
    console.debug("Initial tab probe:", e);
  }

  // 2. Analyze Button Click
  analyzeBtn.addEventListener('click', async () => {
    analyzeBtn.disabled = true;
    loadingDiv.classList.remove('hidden');
    resultsDiv.classList.add('hidden');
    errorMsg.classList.add('hidden');

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab || !tab.id) {
        showError("No active browser tab found.");
        return;
      }
      
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        files: ['content.js']
      });

      chrome.tabs.sendMessage(tab.id, { action: "extractEmail" }, async (emailData) => {
        if (chrome.runtime.lastError || !emailData) {
          showError("Could not extract email content from this page. Open an email in Gmail or Outlook.");
          return;
        }

        try {
          let response;
          try {
            response = await fetch(LOCAL_API_URL, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(emailData)
            });
          } catch (localErr) {
            console.warn("Local backend unreachable, trying cloud endpoint...", localErr);
            response = await fetch(CLOUD_API_URL, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(emailData)
            });
          }

          if (!response || !response.ok) {
            throw new Error(`Server returned status ${response ? response.status : 'offline'}`);
          }

          const result = await response.json();
          lastDossier = result.full_dossier || result.details || result;
          lastRawEml = result.raw_eml || "";
          displayResults(result, emailData);
        } catch (apiError) {
          showError("Backend analysis error. Please ensure TrustShield backend is running on port 8000.");
          console.error(apiError);
        }
      });
    } catch (e) {
      showError("Unable to inspect this tab (system or protected page).");
      console.error(e);
    }
  });

  // 3. Display Results
  function displayResults(result, emailData) {
    loadingDiv.classList.add('hidden');
    resultsDiv.classList.remove('hidden');

    const verdictBanner = document.getElementById('verdict-banner');
    const verdictText = document.getElementById('verdict-text');
    const verdictIcon = document.getElementById('verdict-icon');
    const threatScore = document.getElementById('threat-score');
    const resAttribution = document.getElementById('res-attribution');
    
    document.getElementById('res-sender').innerText = emailData.sender || "Unknown";
    document.getElementById('res-nlp').innerText = result.text_verdict || "Intent Analyzed";
    document.getElementById('res-links').innerText = result.links_found ? `${result.links_found} Link(s) Detonated` : "No links found";

    const score = parseFloat(result.final_threat_score || 0);
    threatScore.innerText = `${score.toFixed(1)} / 100`;

    const attrType = result.threat_attribution?.type || result.text_verdict || "THREAT_ANALYSIS_COMPLETE";
    if (resAttribution) resAttribution.innerText = attrType;

    verdictBanner.classList.remove('verdict-safe', 'verdict-suspicious', 'verdict-phishing');
    
    if (score >= 80 || result.verdict === "CRITICAL FRAUD / PHISHING") {
      verdictBanner.classList.add('verdict-phishing');
      verdictIcon.innerText = "🚨";
      verdictText.innerText = "CRITICAL PHISHING DETECTED";
      threatScore.style.color = "#ef4444";
    } else if (score >= 50 || result.verdict === "SUSPICIOUS") {
      verdictBanner.classList.add('verdict-suspicious');
      verdictIcon.innerText = "⚠️";
      verdictText.innerText = "SUSPICIOUS EMAIL";
      threatScore.style.color = "#f59e0b";
    } else {
      verdictBanner.classList.add('verdict-safe');
      verdictIcon.innerText = "✅";
      verdictText.innerText = "AUTHENTICATED & SAFE";
      threatScore.style.color = "#10b981";
    }

    analyzeBtn.disabled = false;
  }

  function showError(msg) {
    loadingDiv.classList.add('hidden');
    analyzeBtn.disabled = false;
    errorMsg.innerText = msg;
    errorMsg.classList.remove('hidden');
  }

  // 4. Open SOC Portal Button Click
  if (openPortalBtn) {
    openPortalBtn.addEventListener('click', () => {
      chrome.tabs.create({ url: PORTAL_URL }, (newTab) => {
        if (newTab && newTab.id && lastDossier) {
          // Listen for tab completion to inject incident payload
          chrome.tabs.onUpdated.addListener(function listener(tabId, info) {
            if (tabId === newTab.id && info.status === 'complete') {
              chrome.tabs.onUpdated.removeListener(listener);
              chrome.scripting.executeScript({
                target: { tabId: newTab.id },
                func: (dossier, rawEml) => {
                  try {
                    localStorage.setItem('trustshield_incoming_incident', JSON.stringify({
                      dossier: dossier,
                      raw_eml: rawEml
                    }));
                    if (typeof window.checkIncomingExtensionIncident === 'function') {
                      window.checkIncomingExtensionIncident();
                    }
                  } catch (err) {
                    console.warn(err);
                  }
                },
                args: [lastDossier, lastRawEml]
              });
            }
          });
        }
      });
    });
  }
});
