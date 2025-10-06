document.addEventListener("DOMContentLoaded", async () => {
  const input = document.getElementById("apiBase");
  const blockRevokedEl = document.getElementById("blockRevoked");
  const { apiBase, blockRevoked } = await chrome.storage.local.get([
    "apiBase",
    "blockRevoked",
  ]);
  input.value = apiBase || "https://crlite.onrender.com";
  blockRevokedEl.checked = blockRevoked !== false; // default to ON when undefined

  document.getElementById("save").addEventListener("click", async () => {
    const value = input.value.trim();
    await chrome.storage.local.set({
      apiBase: value,
      blockRevoked: blockRevokedEl.checked,
    });
    alert("Saved.");
  });
});
