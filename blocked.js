document.addEventListener("DOMContentLoaded", () => {
  const params = new URLSearchParams(window.location.search);
  const domain = params.get("domain");

  console.log("🔍 Query param received:", domain);

  const messageEl = document.getElementById("message");

  if (domain) {
    messageEl.textContent = `Access to ${domain} has been blocked because its certificate is marked as revoked.`;
  } else {
    messageEl.textContent =
      "Access to this site has been blocked, but the domain is unknown.";
  }
});
