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

// ---- Recovery kit (must stay byte-compatible with @vaultkeep/crypto) ----

// Crockford base32 (no I/L/O/U): VK-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX.
const RK_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
function generateRecoveryKey() {
  const groups = [];
  for (let g = 0; g < 5; g++) {
    let s = "";
    while (s.length < 5) {
      const b = crypto.getRandomValues(new Uint8Array(1))[0];
      if (b < 224) s += RK_ALPHABET[b % 32]; // unbiased rejection sampling
    }
    groups.push(s);
  }
  return "VK-" + groups.join("-");
}

function normalizeRecoveryKey(input) {
  return input.toUpperCase().replace(/[^0-9A-Z]/g, "").replace(/^VK/, "")
    .replace(/[IL]/g, "1").replace(/O/g, "0");
}

// HKDF-SHA256 split of the recovery key into the auth half (sent to the
// server, which stores a hash) and the wrap half (never leaves the browser).
async function recoveryParts(recoveryKey, saltB64) {
  const ikm = await crypto.subtle.importKey(
    "raw", enc.encode(normalizeRecoveryKey(recoveryKey)), "HKDF", false, ["deriveBits"]
  );
  const bits = (info) => crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: unb64(saltB64), info: enc.encode(info) }, ikm, 256
  );
  return {
    authVerifier: b64(await bits("vaultkeep-recovery-auth")),
    wrapKeyBits: await bits("vaultkeep-recovery-wrap"),
  };
}

// GCM-wrap the raw master key bits (plaintext = their base64 string, exactly
// like the node implementation, so desktop and web recovery kits interoperate).
async function wrapMasterKey(wrapKeyBits, masterKeyBits) {
  const key = await crypto.subtle.importKey("raw", wrapKeyBits, { name: "AES-GCM" }, false, ["encrypt"]);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, enc.encode(b64(masterKeyBits)));
  const out = new Uint8Array(12 + ct.byteLength);
  out.set(nonce, 0);
  out.set(new Uint8Array(ct), 12);
  return b64(out);
}

async function unwrapMasterKey(wrapKeyBits, blobB64) {
  const key = await crypto.subtle.importKey("raw", wrapKeyBits, { name: "AES-GCM" }, false, ["decrypt"]);
  const blob = unb64(blobB64);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: blob.slice(0, 12) }, key, blob.slice(12));
  return unb64(dec.decode(pt)); // raw master key bytes
}

// Rebuild the vault CryptoKey from recovered raw key bits.
async function importAesKey(keyBits) {
  return crypto.subtle.importKey("raw", keyBits, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

// Shared default Argon2id params (must equal the server/desktop defaults).
const DEFAULT_KDF = { memoryKiB: 65536, iterations: 3, parallelism: 4 };

window.VaultCrypto = {
  deriveKey, deriveAuthVerifier, encryptJSON, decryptJSON,
  randomSaltB64, generatePassword, DEFAULT_KDF,
  generateRecoveryKey, normalizeRecoveryKey, recoveryParts,
  wrapMasterKey, unwrapMasterKey, importAesKey,
};
