const express = require("express");
const cors = require("cors");
const tls = require("tls");
const ocsp = require("ocsp");
const https = require("https");
const http = require("http");

const app = express();
app.use(cors());
app.use(express.json());

app.get("/cert", (req, res) => {
  const domain = req.query.domain;
  if (!domain) return res.status(400).json({ error: "Missing domain" });

  const socket = tls.connect(
    443,
    domain,
    { servername: domain, rejectUnauthorized: false },
    () => {
      const cert = socket.getPeerCertificate(true);
      socket.end();

      const validTo = cert.valid_to;
      const validToDate = new Date(validTo);
      const now = new Date();
      const isValidDate = !Number.isNaN(validToDate.getTime());
      const isExpired = isValidDate ? validToDate < now : null;

      // Attempt OCSP revocation check (optional)
      const toPEM = (raw) => {
        if (!raw) return null;
        const b64 = raw.toString("base64");
        const lines = b64.match(/.{1,64}/g) || [];
        return `-----BEGIN CERTIFICATE-----\n${lines.join(
          "\n"
        )}\n-----END CERTIFICATE-----\n`;
      };

      const leafPEM = toPEM(cert.raw);

      const respond = (isRevoked, isTrusted, trustError) => {
        res.json({
          serialNumber: cert.serialNumber,
          subject: cert.subject,
          issuer: cert.issuer,
          valid_from: cert.valid_from,
          valid_to: validTo,
          isExpired: isExpired,
          isRevoked: isRevoked,
          isTrusted: isTrusted,
          trustError: trustError || null,
        });
      };

      const fetchIssuerAsPEM = (url) =>
        new Promise((resolve, reject) => {
          try {
            const client = url.startsWith("https:") ? https : http;
            client
              .get(url, (r) => {
                if (
                  r.statusCode &&
                  r.statusCode >= 300 &&
                  r.statusCode < 400 &&
                  r.headers.location
                ) {
                  // follow one redirect
                  const nextUrl = r.headers.location.startsWith("http")
                    ? r.headers.location
                    : new URL(r.headers.location, url).toString();
                  return (nextUrl.startsWith("https:") ? https : http)
                    .get(nextUrl, (r2) => {
                      const chunks = [];
                      r2.on("data", (d) => chunks.push(d));
                      r2.on("end", () => {
                        const buf = Buffer.concat(chunks);
                        const b64 = buf.toString("base64");
                        const lines = b64.match(/.{1,64}/g) || [];
                        const pem = `-----BEGIN CERTIFICATE-----\n${lines.join(
                          "\n"
                        )}\n-----END CERTIFICATE-----\n`;
                        resolve(pem);
                      });
                    })
                    .on("error", reject);
                }
                const chunks = [];
                r.on("data", (d) => chunks.push(d));
                r.on("end", () => {
                  const buf = Buffer.concat(chunks);
                  const b64 = buf.toString("base64");
                  const lines = b64.match(/.{1,64}/g) || [];
                  const pem = `-----BEGIN CERTIFICATE-----\n${lines.join(
                    "\n"
                  )}\n-----END CERTIFICATE-----\n`;
                  resolve(pem);
                });
              })
              .on("error", reject);
          } catch (e) {
            reject(e);
          }
        });

      const getAIAIssuerUrls = (infoAccess) => {
        const urls = [];
        if (!infoAccess) return urls;
        const push = (val) => {
          if (!val) return;
          if (Array.isArray(val)) urls.push(...val);
          else urls.push(val);
        };
        push(infoAccess["CA Issuers - URI"]);
        push(infoAccess["1.3.6.1.5.5.7.48.2"]); // OID for CA Issuers
        return urls.filter((u) => typeof u === "string");
      };

      const checkTrust = () =>
        new Promise((resolve) => {
          const request = https.request(
            {
              host: domain,
              method: "HEAD",
              port: 443,
              servername: domain,
              rejectUnauthorized: true,
              timeout: 8000,
            },
            (r) => {
              r.destroy();
              resolve({ isTrusted: true, error: null });
            }
          );
          request.on("error", (err) => {
            resolve({
              isTrusted: false,
              error: err && (err.code || err.message),
            });
          });
          request.on("timeout", () => {
            request.destroy();
            resolve({ isTrusted: null, error: "TIMEOUT" });
          });
          request.end();
        });

      (async () => {
        try {
          let issuerPEM = null;
          if (cert.issuerCertificate && cert.issuerCertificate.raw) {
            issuerPEM = toPEM(cert.issuerCertificate.raw);
          }
          if (!issuerPEM && cert.infoAccess) {
            const candidates = getAIAIssuerUrls(cert.infoAccess);
            if (candidates.length) {
              console.log("AIA issuer candidates:", candidates);
            }
            for (const url of candidates) {
              try {
                issuerPEM = await fetchIssuerAsPEM(url);
                if (issuerPEM) break;
              } catch (_) {}
            }
          }

          const trustPromise = checkTrust();
          if (leafPEM && issuerPEM) {
            ocsp.check(
              { cert: leafPEM, issuer: issuerPEM },
              async (err, ocspData) => {
                const { isTrusted, error } = await trustPromise;
                if (err) {
                  console.log("OCSP error:", err && err.message);
                  return respond(null, isTrusted, error);
                }
                const statusType = ocspData && ocspData.type; // 'good' | 'revoked' | 'unknown'
                console.log("OCSP status:", statusType);
                const isRevoked = statusType === "revoked";
                return respond(isRevoked, isTrusted, error);
              }
            );
          } else {
            const { isTrusted, error } = await trustPromise;
            respond(null, isTrusted, error);
          }
        } catch (e) {
          respond(null, null, e && e.message);
        }
      })();
    }
  );

  socket.setTimeout(10000, () => {
    socket.destroy();
    res.status(504).json({ error: "TLS connection timeout" });
  });

  socket.on("error", (err) => {
    res.status(502).json({ error: err.message });
  });
});

// Start server
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`CRLite server running on port ${port}`);
});
