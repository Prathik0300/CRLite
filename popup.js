function updateUI(data) {
  const domainEl = document.getElementById("domain");
  const badgeEl = document.getElementById("statusBadge");

  const domain = data.lastChecked || "None";
  const status = data.certStatus || "Unknown";

  domainEl.textContent = domain;

  badgeEl.textContent = status;
  badgeEl.className = "badge"; // Reset existing styles

  if (status === "Revoked") {
    badgeEl.classList.add("revoked");
  } else if (status === "Not Revoked") {
    badgeEl.classList.add("not-revoked");
  } else {
    badgeEl.classList.add("unknown");
  }
}

chrome.storage.local.get(["certInfo"], (data) => {
  if (data.certInfo) {
    const cert = data.certInfo;
    document.getElementById("certDetails").innerText = `
Subject: ${cert.subject.CN}
Issuer: ${cert.issuer.CN}
Serial: ${cert.serialNumber}
Valid From: ${cert.valid_from}
Valid To: ${cert.valid_to}
    `;
  }
});

// Initial load
chrome.storage.local.get(["lastChecked", "certStatus"], (data) => {
  updateUI(data);
});

// Refresh button
document.getElementById("refresh").addEventListener("click", () => {
  chrome.storage.local.get(["lastChecked", "certStatus"], (data) => {
    updateUI(data);
  });
});
