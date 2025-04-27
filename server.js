const tls = require("tls");
const fs = require("fs");
const express = require("express");
const app = express();
const port = 3000; // or any free port

app.use(express.json());

// Allow CORS (important for extension to call it)
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  next();
});

app.get("/cert", (req, res) => {
  const domain = req.query.domain;

  if (!domain) {
    return res.status(400).json({ error: "Domain query param required" });
  }

  const socket = tls.connect(443, domain, { servername: domain }, () => {
    const cert = socket.getPeerCertificate(true);

    if (!cert || Object.keys(cert).length === 0) {
      return res.status(500).json({ error: "No certificate found" });
    }

    res.json({
      subject: cert.subject,
      issuer: cert.issuer,
      serialNumber: cert.serialNumber,
      valid_from: cert.valid_from,
      valid_to: cert.valid_to,
    });

    socket.end();
  });

  socket.on("error", (err) => {
    res.status(500).json({ error: err.message });
  });
});

app.listen(port, () => {
  console.log(
    `✅ Certificate fetch server running on http://localhost:${port}`
  );
});
