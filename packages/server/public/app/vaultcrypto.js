// Browser-side zero-knowledge crypto for the VaultKeep web vault.
//
// Uses the SAME Argon2id (via hash-wasm, loaded from argon2.umd.min.js) and the
// SAME auth-verifier derivation as the desktop app — so a vault created on one
// works on the other. Everything runs in the browser; the server only ever sees
// ciphertext and the one-way auth verifier.
//   - Argon2id  → 256-bit key from the master password (identical to desktop)
//   - AES-256-GCM (WebCrypto) → authenticated vault encryption
//   - HMAC-SHA256 (WebCrypto) → the one-way auth verifier

const enc = new TextEncoder();
const dec = new TextDecoder();

function b64(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}
function unb64(str) {
  return Uint8Array.from(atob(str), (c) => c.charCodeAt(0));
}

// Derive the 256-bit master key with Argon2id, matching the desktop params.
// Returns { aesKey: CryptoKey, keyBits: Uint8Array }.
async function deriveKey(masterPassword, saltB64, params) {
  const p = params || { memoryKiB: 65536, iterations: 3, parallelism: 4 };
  const raw = await hashwasm.argon2id({
    password: masterPassword,
    salt: unb64(saltB64),
    parallelism: p.parallelism,
    iterations: Math.max(1, p.iterations),
    memorySize: p.memoryKiB,
    hashLength: 32,
    outputType: "binary",
  });
  const keyBits = new Uint8Array(raw);
  const aesKey = await crypto.subtle.importKey(
    "raw", keyBits, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]
  );
  return { aesKey, keyBits };
}

// The auth verifier: HMAC-SHA256(keyBits, "vaultkeep-auth-verifier:" + password).
// MUST match the desktop's deriveAuthVerifier so logins interoperate.
async function deriveAuthVerifier(keyBits, masterPassword) {
  const hmacKey = await crypto.subtle.importKey(
    "raw", keyBits, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign(
    "HMAC", hmacKey, enc.encode("vaultkeep-auth-verifier:" + masterPassword)
  );
  return b64(sig);
}

// AES-256-GCM encrypt → base64(nonce(12) ‖ ciphertext ‖ tag(16)).
async function encryptJSON(aesKey, obj) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce }, aesKey, enc.encode(JSON.stringify(obj))
  );
  const out = new Uint8Array(nonce.length + ct.byteLength);
  out.set(nonce, 0);
  out.set(new Uint8Array(ct), nonce.length);
  return b64(out);
}

async function decryptJSON(aesKey, blobB64) {
  const blob = unb64(blobB64);
  const nonce = blob.slice(0, 12);
  const ct = blob.slice(12);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, aesKey, ct);
  return JSON.parse(dec.decode(pt));
}

function randomSaltB64() {
  return b64(crypto.getRandomValues(new Uint8Array(16)));
}

// Strong random password generator (CSPRNG).
function generatePassword(length = 20) {
  const sets = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%^&*-_=+?";
  const arr = crypto.getRandomValues(new Uint32Array(length));
  let out = "";
  for (let i = 0; i < length; i++) out += sets[arr[i] % sets.length];
  return out;
}

// Shared default Argon2id params (must equal the server/desktop defaults).
const DEFAULT_KDF = { memoryKiB: 65536, iterations: 3, parallelism: 4 };

window.VaultCrypto = {
  deriveKey, deriveAuthVerifier, encryptJSON, decryptJSON,
  randomSaltB64, generatePassword, DEFAULT_KDF,
};
