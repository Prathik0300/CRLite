const express = require("express");
const cors = require("cors");
const { BloomFilter } = require("bloom-filters");
const tls = require("tls");

const app = express();
app.use(cors());
app.use(express.json());

const bloom = new BloomFilter(1000, 4);

// Static revoked domains for simulation
const staticRevokedDomains = ["openai.com", "google.com"];
const dynamicRevokedDomains = ["github.com", "uic.blackboard.com"];

// Populate baseline Bloom filter
async function populateStatic() {
  for (const domain of staticRevokedDomains) {
    try {
      await addCertSerialToBloom(domain, bloom);
    } catch (err) {
      console.error(`Error fetching ${domain}:`, err.message);
    }
  }
}

async function addCertSerialToBloom(domain, bloom) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(443, domain, { servername: domain }, () => {
      const cert = socket.getPeerCertificate(true);
      if (cert.serialNumber) {
        bloom.add(cert.serialNumber);
      }
      socket.end();
      resolve();
    });
    socket.on("error", reject);
  });
}

populateStatic();

app.get("/filter", (req, res) => {
  res.json(bloom.saveAsJSON());
});

app.get("/cert", (req, res) => {
  const domain = req.query.domain;
  if (!domain) {
    return res.status(400).json({ error: "Missing domain" });
  }

  const socket = tls.connect(443, domain, { servername: domain }, () => {
    const cert = socket.getPeerCertificate(true);
    socket.end();

    let valid_to = cert.valid_to;
    console.log({ valid_to, domain });
    // ✅ If domain is dynamically revoked, manipulate valid_to
    if (dynamicRevokedDomains.includes(domain)) {
      console.log("inside ");
      const pastDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000); // 7 days ago
      valid_to = pastDate.toUTCString();
      console.log(`🔧 Faking valid_to for revoked domain ${domain}:`, valid_to);
    }

    res.json({
      serialNumber: cert.serialNumber,
      subject: cert.subject,
      issuer: cert.issuer,
      valid_from: cert.valid_from,
      valid_to: valid_to,
    });
  });

  socket.on("error", (err) => {
    res.status(500).json({ error: err.message });
  });
});

// ✅ New API for revoked list
app.get("/revokedList", (req, res) => {
  res.json(dynamicRevokedDomains);
});

const port = 3000;
app.listen(port, () => {
  console.log(`✅ Server running at http://localhost:${port}`);
});
