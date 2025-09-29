const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const { loadPem, importPrivateKey, rsaDecrypt, aesDecryptGcm } = require("./utils");
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));

const app = express();
app.use(cors());
app.use(bodyParser.json({ limit: '20mb' }));

// Config
const PORT = 4000;
const ANALYZER_INGEST = 'http://localhost:5000/ingest';
const K_BY_CROWD = { location: 5, health: 5, finance: 5, general: 5 }; // demo values

// Keys
const SH_PRIV = importPrivateKey(loadPem(__dirname + '/keys/shuffler_private.pem'));
const SH_PUB_PEM = loadPem(__dirname + '/keys/shuffler_public.pem');

// In-memory batches
const buckets = new Map(); // crowdId -> [{ innerBytes, meta }]

app.get('/pubkey', (req, res) => {
  res.type('text/plain').send(SH_PUB_PEM);
});

// FIX:: PayloadTooLargeError: request entity too large. 4,463,809 bytes beyond limit of 2,097,152 bytes
//
// app.post("/submit", async (req, res) => {
//   try {
//     const { crowdId, blob } = req.body; // blob: {wrappedAes, iv, ct}
//     if (!crowdId || !blob?.wrappedAes || !blob?.iv || !blob?.ct) {
//       return res.status(400).json({ ok: false, error: "invalid blob" });
//     }

//     // 解外層 AES 金鑰
//     const jwkJson = rsaDecrypt(SH_PRIV, Buffer.from(blob.wrappedAes)).toString("utf8");
//     const jwk = JSON.parse(jwkJson);

//     // AES-GCM 解出 innerPackage（JSON 字串）
//     const ab = await aesDecryptGcm(jwk, blob.iv, blob.ct);
//     const innerJsonBytes = new Uint8Array(ab); // 直接存 bytes，避免元資料

//     const arr = buckets.get(crowdId) || [];
//     arr.push(innerJsonBytes);
//     buckets.set(crowdId, arr);

//     const need = (K_BY_CROWD[crowdId] || 10) - arr.length;
//     res.json({ ok: true, received: arr.length, needForDispatch: Math.max(need, 0) });

//     if (need <= 0) {
//       // 洗牌 + 送往 Analyzer
//       const batch = buckets.get(crowdId); buckets.set(crowdId, []);
//       for (let i = batch.length - 1; i > 0; i--) {
//         const j = Math.floor(Math.random() * (i + 1));
//         [batch[i], batch[j]] = [batch[j], batch[i]];
//       }
//       await fetch(ANALYZER_INGEST, {
//         method: "POST",
//         headers: { "Content-Type": "application/json" },
//         body: JSON.stringify({ crowdId, batch: batch.map(b => Array.from(b)), ts: Date.now() })
//       });
//     }
//   } catch (e) {
//     console.error(e);
//     res.status(500).json({ ok: false, error: e.message });
//   }
// }) */;

app.post('/submit', async (req, res) => {
  try {
    const { crowdId, blob } = req.body;
    if (!crowdId || !blob?.wrappedAes || !blob?.iv || !blob?.ct) {
      return res.status(400).json({ ok: false, error: 'invalid blob' });

    }
    const { wrappedAes, iv, ct } = blob;    // 解 outer AES JWK
    // RSA unwrap outer AES key
    const jwkJson = rsaDecrypt(SH_PRIV, Buffer.from(wrappedAes, 'base64')).toString('utf8');
    const jwk = JSON.parse(jwkJson);    // AES-GCM 解 outer ciphertext → 得到 innerPackage(JSON)

    const pt = await aesDecryptGcm(
      jwk,
      Buffer.from(iv, 'base64'),
      Buffer.from(ct, 'base64')
    );
    // innerPackage is JSON string → storage bytes（or storage string）
    const innerJsonBytes = Array.from(new Uint8Array(pt));

    const arr = buckets.get(crowdId) || [];
    arr.push(innerJsonBytes);
    buckets.set(crowdId, arr);

    const need = (K_BY_CROWD[crowdId] || 10) - arr.length;
    res.json({ ok: true, received: arr.length, needForDispatch: Math.max(need, 0) });

    if (need <= 0) {
      // 洗牌 + dispatch
      const batch = buckets.get(crowdId); buckets.set(crowdId, []);
      for (let i = batch.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [batch[i], batch[j]] = [batch[j], batch[i]];
      }
      await fetch(ANALYZER_INGEST, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ crowdId, batch, ts: Date.now() })
      });
    }
  } catch (e) {
    console.error('[shuffler] submit error', e);
    res.status(500).json({ ok: false, error: e.message, stage: 'shuffler.submit' });
  }
});
app.use((req, res) => res.status(404).json({ ok: false, error: 'not found', path: req.path }));

app.use((err, req, res, next) => {
  console.error('[shuffler] unhandled', err);
  res.status(500).json({ ok: false, error: 'internal error' });
});

// Global Error handling(insurance)
app.use((err, req, res, next) => {
  console.error('[shuffler] unhandled', err);
  res.status(500).json({ ok: false, error: 'internal error' });
});

app.listen(PORT, () => console.log(`Shuffler listening on http://localhost:${PORT}`));
