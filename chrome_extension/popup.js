document.addEventListener('DOMContentLoaded', () => {
  const analyzeBtn = document.getElementById('analyze-btn');
  const loadingDiv = document.getElementById('loading');
  const resultsDiv = document.getElementById('results');
  const errorMsg = document.getElementById('error-msg');

  // Change this to your Render URL before publishing (e.g., https://trustshield.onrender.com/api/extension/analyze)
  const API_URL = "http://127.0.0.1:8000/api/extension/analyze";

  analyzeBtn.addEventListener('click', async () => {
    analyzeBtn.disabled = true;
    loadingDiv.classList.remove('hidden');
    resultsDiv.classList.add('hidden');
    errorMsg.classList.add('hidden');

    try {
      // Get the current active tab
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      
      // Inject the content script if not already there
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        files: ['content.js']
      });

      // Request email data from content script
      chrome.tabs.sendMessage(tab.id, { action: "extractEmail" }, async (emailData) => {
        if (chrome.runtime.lastError || !emailData) {
          showError("Could not extract email content. Make sure you are on a webmail page.");
          return;
        }

        try {
          // Send data to TrustShield Backend
          const response = await fetch(API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(emailData)
          });

          if (!response.ok) {
            throw new Error(`Server returned ${response.status}`);
          }

          const result = await response.json();
          displayResults(result, emailData);
        } catch (apiError) {
          showError("Backend connection failed. Make sure your server is running!");
          console.error(apiError);
        }
      });
    } catch (e) {
      showError("An unexpected error occurred.");
      console.error(e);
    }
  });

  function displayResults(result, emailData) {
    loadingDiv.classList.add('hidden');
    resultsDiv.classList.remove('hidden');

    // Update UI elements
    const verdictBanner = document.getElementById('verdict-banner');
    const verdictText = document.getElementById('verdict-text');
    const threatScore = document.getElementById('threat-score');
    
    document.getElementById('res-sender').innerText = emailData.sender;
    document.getElementById('res-nlp').innerText = result.text_verdict || "Analyzed";
    document.getElementById('res-links').innerText = result.links_found ? result.links_found + " Links Scanned" : "No links found";

    // Set Verdict colors
    const score = result.final_threat_score || 0;
    threatScore.innerText = `${score}/100`;

    verdictBanner.classList.remove('verdict-safe', 'verdict-suspicious', 'verdict-phishing');
    
    if (result.verdict === "CRITICAL FRAUD / PHISHING" || score >= 80) {
      verdictBanner.classList.add('verdict-phishing');
      verdictText.innerText = "🚨 DANGER: PHISHING DETECTED";
    } else if (result.verdict === "SUSPICIOUS" || score >= 50) {
      verdictBanner.classList.add('verdict-suspicious');
      verdictText.innerText = "⚠️ SUSPICIOUS EMAIL";
    } else {
      verdictBanner.classList.add('verdict-safe');
      verdictText.innerText = "✅ SAFE EMAIL";
    }

    analyzeBtn.disabled = false;
  }

  function showError(msg) {
    loadingDiv.classList.add('hidden');
    analyzeBtn.disabled = false;
    errorMsg.innerText = msg;
    errorMsg.classList.remove('hidden');
  }
});
