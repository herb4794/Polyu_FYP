const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const { loadPem, importPrivateKey, rsaDecrypt, aesDecryptGcm } = require('./utils');

const app = express();
app.use(cors());
app.use(bodyParser.json({ limit: '20mb' }));

// Config
const PORT = 5000;

// Keys
const AN_PRIV = importPrivateKey(loadPem(__dirname + '/keys/analyzer_private.pem'));
const AN_PUB_PEM = loadPem(__dirname + '/keys/analyzer_public.pem');


// Simple storage & metrics
const receivedBatches = [];
const aggregates = []; // per batch aggregate covariance (mean of cov)


app.get('/pubkey', (req, res) => {
  res.type('text/plain').send(AN_PUB_PEM);
});


app.post('/ingest', async (req, res) => {
  try {
    const { crowdId, batch } = req.body;
    if (!Array.isArray(batch) || !crowdId) return res.status(400).json({ ok: false, error: 'bad payload' });


    const decoded = [];
    for (const innerBytes of batch) {
      // innerBytes: JSON(innerPackage) encrypted to Analyzer pubkey by Shuffler? No—it's encrypted by client.
      // Here: decrypt RSA → get innerPackage (wrapped AES + iv + ct)
      const innerJson = rsaDecrypt(AN_PRIV, Buffer.from(innerBytes));
      const pkg = JSON.parse(innerJson.toString('utf8'));


      const jwk = JSON.parse(Buffer.from(pkg.wrappedAes ? [] : []).toString()); // placeholder if needed
      // Actually wrappedAes was RSA-encrypted JWK by Analyzer pubkey on client. We already RSA-decrypted.
      const aesJwk = JSON.parse(innerJson.toString('utf8')).wrappedAes ? JSON.parse(new TextDecoder().decode()) : null;
      // Adjust: client packaged as { alg, wrappedAes, iv, ct }
      const { alg, wrappedAes, iv, ct } = pkg;


      /*NOTE : wrappedAes is already decrypted? Not yet — above rsaDecrypt output IS the innerPackage, not AES key.
        Correct process: innerPackage.wrappedAes is RSA-encrypted AES JWK with Analyzer pubkey. But we just
        RSA-decrypted the WHOLE innerPackage. That’s inconsistent with client step. Let's fix:
        In client: we RSA-encrypted only the AES JWK, not the innerPackage. Right.
        So innerPackage transport to Analyzer is NOT RSA-encrypted as a whole; it was AES-GCM ciphertext + RSA-wrapped key, then outer RSA to shuffler. After shuffler stripped outer, Analyzer receives innerPackage JSON (not encrypted), BUT in our shuffler implementation we forwarded raw bytes, so here we must parse from bytes directly (already plaintext JSON). Therefore, remove extra RSA here for the package; we should treat innerBytes as UTF-8 JSON of innerPackage. */
    }


    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// Corrected ingest (replace the above handler with this one)
app._router.stack = app._router.stack.filter(l => !(l.route && l.route.path === '/ingest'));
app.post('/ingest', async (req, res) => {
  try {
    const { crowdId, batch } = req.body;
    const decoded = [];


    for (const jsonBytes of batch) {
      const pkgText = Buffer.from(Uint8Array.from(jsonBytes)).toString('utf8').trim();
      const pkg = JSON.parse(pkgText);

      const { wrappedAes, iv, ct } = pkg; // wrappedAes is RSA-encrypted JWK with Analyzer pubkey


      // Decrypt wrapped AES key with Analyzer private key
      const jwkJson = rsaDecrypt(AN_PRIV, Buffer.from(wrappedAes, 'base64')).toString('utf8');
      const jwk = JSON.parse(jwkJson);

      // Decrypt AES-GCM payload
      // AES-GCM 解 inner
      const plainBuf = await aesDecryptGcm(
        jwk,
        Buffer.from(iv, 'base64'),
        Buffer.from(ct, 'base64')
      );
      const obj = JSON.parse(plainBuf.toString('utf8'));
      decoded.push(obj);
    }


    // Aggregate covariance (mean across items)
    const dims = decoded[0]?.encoded?.dim || 0;
    const covSum = new Array(dims * dims).fill(0);
    for (const d of decoded) {
      const arr = d.encoded.cov;
      for (let i = 0; i < covSum.length; i++) covSum[i] += arr[i] || 0;
    }
    const covMean = covSum.map(x => x / decoded.length);


    aggregates.push({ crowdId, n: decoded.length, covMean, ts: Date.now() });
    receivedBatches.push({ crowdId, size: decoded.length, ts: Date.now() });


    res.json({ ok: true, decoded: decoded.length });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.get('/stats', (req, res) => {
  res.json({ batches: receivedBatches, aggregatesCount: aggregates.length });
});

app.listen(PORT, () => console.log(`Analyzer listening on http://localhost:${PORT}`));

setInterval(async () => {
  try {
    const res = await fetch(`http://localhost:${PORT}/stats`);
    const stats = await res.json();
    console.log('[analyzer] periodic stats:', JSON.stringify(stats));
  } catch (e) {
    console.error('[analyzer] periodic stats error', e.message);
  }
}, 5000);
