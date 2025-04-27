importScripts("bloom.js"); // SHA-256 based
let filters = null;

// Load Bloom filters from cascadeFilters.json
fetch(chrome.runtime.getURL("cascadeFilters.json"))
  .then((res) => res.json())
  .then((data) => {
    filters = data;
    console.log("✔️ Bloom filters loaded");
  })
  .catch((err) => console.error("❌ Error loading filters:", err));

// Intercept every main-frame request
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (!filters) return;

    const url = new URL(details.url);

    // ⛔ Ignore extension or chrome-internal URLs
    if (
      url.protocol === "chrome-extension:" ||
      url.hostname.endsWith("chrome.com") ||
      url.hostname.includes("chromewebdata")
    ) {
      return;
    }

    const domain = url.hostname.replace(/^www\./, "");
    const serial = btoa(domain);

    return (async () => {
      const status = await checkCascade(serial, filters);

      console.log(`🛡️ Checked ${domain}: ${status}`);

      chrome.storage.local.set({
        lastChecked: domain,
        certStatus: status,
      });

      if (status === "Revoked") {
        console.log("YES IT IS REVOKED!!!");
        return {
          redirectUrl:
            chrome.runtime.getURL("blocked.html") + `?domain=${domain}`,
        };
      }

      return {};
    })();
  },
  { urls: ["<all_urls>"], types: ["main_frame"] }
);

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (
    changeInfo.status !== "complete" ||
    !tab.url ||
    tab.url.startsWith("chrome://") ||
    tab.url.startsWith("chrome-extension://") ||
    !filters
  )
    return;

  const url = new URL(tab.url);
  const domain = url.hostname.replace(/^www\./, "");
  const serial = btoa(domain);

  (async () => {
    const status = await checkCascade(serial, filters);

    if (status === "Revoked") {
      console.warn(`🚫 Redirecting to blocked.html for ${domain}`);

      const blockedUrl =
        chrome.runtime.getURL("blocked.html") + `?domain=${domain}`;

      chrome.scripting.executeScript({
        target: { tabId },
        func: (url) => {
          window.location.href = url;
        },
        args: [blockedUrl],
      });
    }
  })();
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (
    changeInfo.status !== "complete" ||
    !tab.url ||
    tab.url.startsWith("chrome://") ||
    tab.url.startsWith("chrome-extension://") ||
    !filters
  )
    return;

  const url = new URL(tab.url);
  const domain = url.hostname.replace(/^www\./, "");

  (async () => {
    const certInfo = await fetchCertificate(domain);

    if (certInfo) {
      console.log("✅ Cert for", domain, certInfo);
      chrome.storage.local.set({
        certInfo: certInfo,
      });
    }
  })();
});

async function fetchCertificate(domain) {
  try {
    const response = await fetch(`http://localhost:3000/cert?domain=${domain}`);
    const data = await response.json();
    console.log("🔍 Certificate Info:", data);
    return data;
  } catch (error) {
    console.error("❌ Failed to fetch certificate:", error);
    return null;
  }
}
