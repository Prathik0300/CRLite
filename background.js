// Configurable API base; can be changed via options page
const DEFAULT_API_BASE = "https://YOUR-RENDER-APP.onrender.com"; // replace with your Render URL

async function getApiBase() {
  const { apiBase } = await chrome.storage.local.get(["apiBase"]);
  return apiBase || DEFAULT_API_BASE;
}

// Set defaults on install: enable revoked blocking by default
chrome.runtime.onInstalled.addListener(async () => {
  const { blockRevoked } = await chrome.storage.local.get(["blockRevoked"]);
  if (blockRevoked === undefined) {
    await chrome.storage.local.set({ blockRevoked: true });
  }
});

// Handle each tab update: fetch cert info and block only if expired
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (
    changeInfo.status !== "complete" ||
    !tab.url ||
    tab.url.startsWith("chrome://") ||
    tab.url.startsWith("chrome-extension://")
  )
    return;

  const url = new URL(tab.url);
  const domain = url.hostname.replace(/^www\./, "");

  (async () => {
    let certStatus = "Unknown";
    try {
      const base = await getApiBase();
      const { blockRevoked } = await chrome.storage.local.get(["blockRevoked"]);
      const enableRevoked = blockRevoked !== false; // default ON when undefined
      const res = await fetch(
        `${base}/cert?domain=${encodeURIComponent(domain)}`
      );
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const cert = await res.json();

      const isExpired =
        cert?.isExpired === true ||
        (cert?.valid_to ? new Date(cert.valid_to) < new Date() : false);
      const isRevoked = cert?.isRevoked === true;
      const isUntrusted = cert?.isTrusted === false;
      const shouldBlock = enableRevoked
        ? isExpired || isRevoked || isUntrusted
        : isExpired;
      certStatus = shouldBlock ? "Revoked" : "Not Revoked";

      chrome.storage.local.set({ certInfo: cert });
    } catch (e) {
      console.error(" Failed to retrieve cert info:", e);
      certStatus = "Unknown";
    }

    console.log(`🛡️ ${domain} ➝ ${certStatus}`);

    chrome.storage.local.set({
      lastChecked: domain,
      certStatus: certStatus,
    });

    if (certStatus === "Revoked") {
      const blockedUrl =
        chrome.runtime.getURL("blocked.html") + `?domain=${domain}`;
      chrome.tabs.update(tabId, { url: blockedUrl });
    }
  })();
});
