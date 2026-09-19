function extractEmailData() {
  let subject = "";
  let sender = "";
  let body = "";

  try {
    // Attempt to extract Gmail specific fields
    const subjectEl = document.querySelector('h2.hP');
    if (subjectEl) subject = subjectEl.innerText;

    const senderEl = document.querySelector('.gD');
    if (senderEl) {
      sender = senderEl.getAttribute('email') || senderEl.innerText;
    }

    const bodyEl = document.querySelector('.a3s.aiL');
    if (bodyEl) {
      body = bodyEl.innerText;
    } else {
      // Fallback: grab all text in the main message container
      const backupBody = document.querySelector('.nH.hx');
      if (backupBody) body = backupBody.innerText;
    }
  } catch (e) {
    console.error("Error extracting email data", e);
  }

  // If we couldn't find Gmail specific elements, just grab page text and selection
  if (!body) {
    body = window.getSelection().toString() || document.body.innerText.substring(0, 5000);
  }

  return {
    subject: subject || "Unknown Subject",
    sender: sender || "Unknown Sender",
    body: body || "No content found"
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
