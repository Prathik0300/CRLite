importScripts("bloom.js"); // SHA-256 + BloomFilter helpers

let staticFilters = null;
let dynamicRevokedFilter = new BloomFilter(256, 4);
let dynamicWhitelistFilter = new BloomFilter(256, 4);

const BLOOM_REFRESH_INTERVAL = 10 * 60 * 1000;

// Load static cascadeFilters
fetch(chrome.runtime.getURL("cascadeFilters.json"))
  .then((res) => res.json())
  .then((data) => {
    staticFilters = data;
    console.log("✔️ Static cascadeFilters loaded");
  })
  .catch((err) => console.error("❌ Error loading cascade filters:", err));

// Fetch revoked domains from server
async function fetchRevokedList() {
  try {
    const res = await fetch("http://127.0.0.1:3000/revokedList");
    const list = await res.json();
    await chrome.storage.local.set({ revokedList: list });
    console.log("✅ Revoked domain list loaded:", list);
  } catch (err) {
    console.error("❌ Failed to fetch revoked list:", err);
  }
}

fetchRevokedList();
setInterval(fetchRevokedList, BLOOM_REFRESH_INTERVAL);

// Handle each tab update
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
    const certInfo = await fetchCertificate(domain);
    if (!certInfo || !certInfo.serialNumber) return;

    const serial = certInfo.serialNumber;
    const { revokedList } = await chrome.storage.local.get(["revokedList"]);

    if (revokedList?.includes(domain)) {
      await dynamicRevokedFilter.add(serial);
      console.warn(`🚫 ${domain} is revoked → adding to revoked filter`);
    } else {
      await dynamicWhitelistFilter.add(serial);
      console.log(`✅ ${domain} added to whitelist`);
    }

    const certStatus = await checkRevocation(serial);
    console.log(`🛡️ ${domain} ➝ ${certStatus}`);

    chrome.storage.local.set({
      lastChecked: domain,
      certStatus: certStatus,
      certInfo: certInfo,
    });

    if (certStatus === "Revoked") {
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

// Fetch certificate
async function fetchCertificate(domain) {
  try {
    const res = await fetch(`http://127.0.0.1:3000/cert?domain=${domain}`);
    return await res.json();
  } catch (e) {
    console.error(`❌ Failed to fetch cert for ${domain}:`, e.message);
    return null;
  }
}

// Revocation check
async function checkRevocation(serial) {
  if (!serial) return "Unknown";

  if (await dynamicWhitelistFilter.has(serial)) {
    return "Not Revoked";
  }
  if (await dynamicRevokedFilter.has(serial)) {
    return "Revoked";
  }

  if (staticFilters?.levels) {
    let maybeRevoked = false;

    for (const level of staticFilters.levels) {
      const hit = await checkBloomFilter(
        level.bitArray,
        level.size,
        level.hashCount,
        serial
      );
      if (level.type === "blacklist" && hit) maybeRevoked = true;
      if (level.type === "whitelist" && maybeRevoked && hit)
        return "Not Revoked";
    }

    return maybeRevoked ? "Revoked" : "Not Revoked";
  }

  return "Unknown";
}

// Bloom hash checker
async function checkBloomFilter(bitArray, size, hashCount, key) {
  for (let i = 0; i < hashCount; i++) {
    const hash = await sha256Hash(key, i);
    const index = hash % size;
    if (bitArray[index] === 0) return false;
  }
  return true;
}
