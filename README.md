# MyGPTShield – Non‑AI ESA Prototype


A minimal, working prototype of the Encode→Shuffle→Analyze pipeline **without any LLMs**. The goal is to validate privacy behaviors (scrub, coarsen, noise, fragmentation), batching thresholds, permutation-based shuffling, and analyzer aggregation/latency.


## What it does
- **Encoder (Chrome Extension)**: scrubs & coarsens a raw prompt, vectorizes & shards, adds noise, builds a covariance matrix; nested encryption (inner AES-GCM with RSA-wrapped key for Analyzer; outer RSA for Shuffler).
- **Shuffler (Node)**: holds per-crowd batches until threshold k, strips outer layer (RSA decrypt), shuffles, forwards inner packages to Analyzer.
- **Analyzer (Node)**: unwraps AES key (RSA), decrypts payload, aggregates covariance means, exposes simple `/stats`.


## Quick start
1. **Generate RSA keys** (use OpenSSL):
```bash
# Shuffler
openssl genrsa -out src/keys/shuffler_private.pem 2048
openssl rsa -in src/keys/shuffler_private.pem -pubout -out server/keys/shuffler_public.pem
# Analyzer
openssl genrsa -out src/keys/analyzer_private.pem 2048
openssl rsa -in src/keys/analyzer_private.pem -pubout -out server/keys/analyzer_public.pem
```


2. **Install & run servers**
```bash
npm install
npm run analyzer # http://localhost:5000
npm run shuffler # http://localhost:4000
```


3. **Load the extension** (Chrome → Extensions → Developer mode → Load unpacked → select `extension/`).


4. **Test**
- Open the popup, enter a prompt, choose Crowd ID, click **Encode → Encrypt → Send**.
- Send ≥k submissions for the same crowd (default k=5 in shuffler) to trigger a batch dispatch.
- Check `http://localhost:5000/stats` for Analyzer stats.


## Notes
- This prototype focuses on **privacy mechanism** only (no AI). It validates latency & batching behavior.
- Noise slider acts as an **ε surrogate** for intuition; formal ε calculation can be added later.
- All in-memory storage. For production, persist and audit logs with rotation.


## Next steps
- Add formal DP accounting and ε estimation per crowd.
- Add integrity proofs (e.g., audit tokens) across shuffler → analyzer path.
- Implement timer-based flushing (max wait) in shuffler.
- Export aggregates for offline evaluation (semantic utility metrics).
