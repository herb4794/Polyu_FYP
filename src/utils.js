const crypto = require('crypto');
const fs = require('fs');


function loadPem(path) {
  return fs.readFileSync(path, 'utf8');
}


function importPrivateKey(pem) {
  return crypto.createPrivateKey(pem);
}


function importPublicKey(pem) {
  return crypto.createPublicKey(pem);
}


function rsaDecrypt(privKey, bytes) {
  return crypto.privateDecrypt(
    { key: privKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    Buffer.from(bytes)
  );
}


async function aesDecryptGcm(jwk, ivArr, ctArr) {
  // Node: use WebCrypto for AES-GCM via globalThis.crypto (Node 20+)
  const key = await crypto.webcrypto.subtle.importKey('jwk', jwk, { name: 'AES-GCM' }, false, ['decrypt']);
  const pt = await crypto.webcrypto.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(ivArr) },
    key,
    new Uint8Array(ctArr)
  );
  return Buffer.from(pt);
}


module.exports = { loadPem, importPrivateKey, importPublicKey, rsaDecrypt, aesDecryptGcm };
