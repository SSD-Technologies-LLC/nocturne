// Nocturne Client-Side Encryption — crypto.js
// AES-256-GCM via Web Crypto API + Argon2id via argon2-browser WASM.
// Parameters match Go's internal/crypto: time=3, mem=64MB, threads=4, keyLen=32.

(function () {
  'use strict';

  // Derive a 256-bit key from password + salt using Argon2id.
  // Parameters must match Go's internal/crypto/kdf.go exactly.
  async function deriveKey(password, salt) {
    var result = await argon2.hash({
      pass: password,
      salt: salt,
      time: 3,
      mem: 65536,       // 64 MB in KiB
      parallelism: 4,
      hashLen: 32,
      type: argon2.ArgonType.Argon2id
    });
    return result.hash;  // Uint8Array(32)
  }

  // Encrypt plaintext (Uint8Array) with password (string).
  // Returns { ciphertext: Uint8Array, salt: Uint8Array(32), nonce: Uint8Array(12) }.
  // The ciphertext includes the 16-byte GCM auth tag (same as Go's gcm.Seal).
  async function encryptAES(plaintext, password) {
    var salt = crypto.getRandomValues(new Uint8Array(32));
    var nonce = crypto.getRandomValues(new Uint8Array(12));
    var keyBytes = await deriveKey(password, salt);

    var cryptoKey = await crypto.subtle.importKey(
      'raw', keyBytes, 'AES-GCM', false, ['encrypt']
    );

    var ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce }, cryptoKey, plaintext
    );

    return {
      ciphertext: new Uint8Array(ciphertext),
      salt: salt,
      nonce: nonce
    };
  }

  // Decrypt ciphertext (Uint8Array, with appended auth tag) using password, salt, nonce.
  // Returns Uint8Array of plaintext.
  async function decryptAES(ciphertext, password, salt, nonce) {
    var keyBytes = await deriveKey(password, salt);

    var cryptoKey = await crypto.subtle.importKey(
      'raw', keyBytes, 'AES-GCM', false, ['decrypt']
    );

    var plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce }, cryptoKey, ciphertext
    );

    return new Uint8Array(plaintext);
  }

  // Convert Uint8Array to base64 string.
  function toBase64(uint8Array) {
    var binary = '';
    for (var i = 0; i < uint8Array.length; i++) {
      binary += String.fromCharCode(uint8Array[i]);
    }
    return btoa(binary);
  }

  // Convert base64 string to Uint8Array.
  function fromBase64(base64) {
    var binary = atob(base64);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  // Expose on window for use by app.js and download.js.
  window.nocturneEncrypt = encryptAES;
  window.nocturneDecrypt = decryptAES;
  window.nocturneToBase64 = toBase64;
  window.nocturneFromBase64 = fromBase64;

})();
