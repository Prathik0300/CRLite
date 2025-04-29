const express = require("express");
const cors = require("cors");
const tls = require("tls");

const app = express();
app.use(cors());
app.use(express.json());

// Simulated dynamically revoked domains
const dynamicRevokedDomains = [
  "github.com",
  "uic.blackboard.com",
  "expired.badssl.com",
];

// ✅ GET /revokedList — List of revoked domains
app.get("/revokedList", (req, res) => {
  res.json(dynamicRevokedDomains);
});

// ✅ GET /cert?domain=... — Fetch TLS certificate info
app.get("/cert", (req, res) => {
  const domain = req.query.domain;
  if (!domain) return res.status(400).json({ error: "Missing domain" });

  const socket = tls.connect(443, domain, { servername: domain }, () => {
    const cert = socket.getPeerCertificate(true);
    socket.end();

    let validTo = cert.valid_to;
    if (dynamicRevokedDomains.includes(domain)) {
      // Fake an expired certificate date (7 days ago)
      const pastDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
      validTo = pastDate.toUTCString();
      console.log(`🔧 Faking expired valid_to for ${domain}:`, validTo);
    }

    res.json({
      serialNumber: cert.serialNumber,
      subject: cert.subject,
      issuer: cert.issuer,
      valid_from: cert.valid_from,
      valid_to: validTo,
    });
  });

  socket.on("error", (err) => {
    res.status(500).json({ error: err.message });
  });
});

// Start server
const port = 3000;
app.listen(port, () => {
  console.log(`✅ CRLite server running at http://localhost:${port}`);
});
