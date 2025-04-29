importScripts("bloom.js");

let staticFilters = null; // Static cascadeFilters loaded at startup
let dynamicFilter = null; // In-memory dynamic Bloom filter
const BLOOM_REFRESH_INTERVAL = 10 * 60 * 1000; // Refresh every 10 min

// Load Static cascadeFilters.json
fetch(chrome.runtime.getURL("cascadeFilters.json"))
  .then((res) => res.json())
  .then((data) => {
    staticFilters = data;
    console.log("✔️ Static cascadeFilters loaded");
  })
  .catch((err) => console.error("❌ Error loading static filters:", err));

// Initialize empty dynamic Bloom filter
dynamicFilter = new BloomFilter(1000, 4);

// Periodic function to refresh revoked domains list
async function fetchRevokedList() {
  try {
    const res = await fetch("http://localhost:3000/revokedList");
    const domains = await res.json();
    chrome.storage.local.set({ revokedList: domains });
    console.log("✅ Fetched dynamic revoked domain list:", domains);
  } catch (err) {
    console.error("❌ Failed to fetch dynamic revoked list:", err);
  }
}

// Initial load + periodic refresh
fetchRevokedList();
setInterval(fetchRevokedList, BLOOM_REFRESH_INTERVAL);

// On visiting a site
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

    if (certInfo) {
      console.log("🔍 Cert fetched for", domain, certInfo);

      chrome.storage.local.set({
        lastChecked: domain,
        certStatus: "Checking...",
        certInfo: certInfo,
      });

      // Check if domain is dynamically revoked
      const { revokedList } = await chrome.storage.local.get(["revokedList"]);

      if (revokedList && revokedList.includes(domain)) {
        console.warn(`🚫 ${domain} is dynamically revoked!`);

        if (certInfo.serialNumber) {
          dynamicFilter.add(certInfo.serialNumber);
          console.log(
            "➕ Added serial to dynamic Bloom filter:",
            certInfo.serialNumber
          );
        }
      }

      const isRevoked = await checkRevocation(certInfo.serialNumber);

      if (isRevoked) {
        console.error(`❌ ${domain} certificate is revoked!`);

        chrome.storage.local.set({
          certStatus: "Revoked",
        });

        const blockedUrl =
          chrome.runtime.getURL("blocked.html") + `?domain=${domain}`;

        chrome.scripting.executeScript({
          target: { tabId },
          func: (url) => {
            window.location.href = url;
          },
          args: [blockedUrl],
        });
      } else {
        console.log(`✅ ${domain} certificate is safe.`);

        chrome.storage.local.set({
          certStatus: "Not Revoked",
        });
      }
    }
  })();
});

// Fetch cert from server
async function fetchCertificate(domain) {
  try {
    const res = await fetch(`http://localhost:3000/cert?domain=${domain}`);
    const data = await res.json();
    return data;
  } catch (error) {
    console.error("❌ Failed fetching cert:", error);
    return null;
  }
}

// Check revocation status
async function checkRevocation(serialNumber) {
  if (!serialNumber) return false;

  // Check dynamic Bloom filter first
  if (dynamicFilter && dynamicFilter.has(serialNumber)) {
    return true;
  }

  // Check static cascadeFilters if available
  if (staticFilters) {
    for (const level of staticFilters.levels) {
      if (
        await checkBloomFilter(
          level.bitArray,
          level.size,
          level.hashCount,
          serialNumber
        )
      ) {
        return true;
      }
    }
  }

  return false;
}

// Check a serial against a Bloom filter level
async function checkBloomFilter(bitArray, size, hashCount, key) {
  for (let i = 0; i < hashCount; i++) {
    const hash = await sha256Hash(key, i);
    const index = hash % size;
    if (bitArray[index] === 0) return false;
  }
  return true;
}

// SHA-256 based hashing (already in bloom.js)
