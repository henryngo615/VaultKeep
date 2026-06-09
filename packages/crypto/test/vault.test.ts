import { describe, it, expect } from "vitest";
import {
  deriveMasterKey,
  generateSalt,
  encrypt,
  decrypt,
  unlockVault,
  generatePassword,
  generatePassphrase,
  generateExchangeKeys,
  deriveSharedSecret,
  generateSigningKeys,
  signMessage,
  verifyMessage,
} from "../src/index.js";

// Use cheap KDF params so tests run fast. Production uses 256 MiB / 4 iters.
const FAST_KDF = { memoryKiB: 8192, iterations: 2, parallelism: 1 };

describe("KDF", () => {
  it("derives a deterministic 32-byte key for the same password+salt", async () => {
    const salt = generateSalt();
    const k1 = await deriveMasterKey("correct horse battery", salt, FAST_KDF);
    const k2 = await deriveMasterKey("correct horse battery", salt, FAST_KDF);
    expect(k1.length).toBe(32);
    expect(k1.equals(k2)).toBe(true);
  });

  it("produces different keys for different salts", async () => {
    const k1 = await deriveMasterKey("pw", generateSalt(), FAST_KDF);
    const k2 = await deriveMasterKey("pw", generateSalt(), FAST_KDF);
    expect(k1.equals(k2)).toBe(false);
  });
});

describe("AES-256-GCM vault encryption", () => {
  it("round-trips plaintext", async () => {
    const key = await deriveMasterKey("pw", generateSalt(), FAST_KDF);
    const secret = JSON.stringify({ password: "hunter2", url: "amazon.com" });
    expect(decrypt(key, encrypt(key, secret))).toBe(secret);
  });

  it("produces different ciphertext each time (random nonce)", async () => {
    const key = await deriveMasterKey("pw", generateSalt(), FAST_KDF);
    expect(encrypt(key, "same")).not.toBe(encrypt(key, "same"));
  });

  it("rejects tampered ciphertext (GCM auth tag)", async () => {
    const key = await deriveMasterKey("pw", generateSalt(), FAST_KDF);
    const blob = Buffer.from(encrypt(key, "secret"), "base64");
    blob[blob.length - 1] ^= 0xff; // flip a bit in the auth tag
    expect(() => decrypt(key, blob.toString("base64"))).toThrow();
  });

  it("fails to decrypt with the wrong key", async () => {
    const k1 = await deriveMasterKey("pw1", generateSalt(), FAST_KDF);
    const k2 = await deriveMasterKey("pw2", generateSalt(), FAST_KDF);
    expect(() => decrypt(k2, encrypt(k1, "secret"))).toThrow();
  });
});

describe("unlockVault helper", () => {
  it("encrypts and decrypts, then locks", async () => {
    const salt = generateSalt();
    const v = await unlockVault("master", salt, FAST_KDF);
    expect(v.decrypt(v.encrypt("data"))).toBe("data");
    v.lock();
  });
});

describe("password generator", () => {
  it("respects length bounds", () => {
    const pw = generatePassword({
      length: 20,
      uppercase: true,
      lowercase: true,
      numbers: true,
      symbols: true,
    });
    expect(pw.length).toBe(20);
  });

  it("only uses enabled sets", () => {
    const pw = generatePassword({
      length: 50,
      uppercase: false,
      lowercase: true,
      numbers: false,
      symbols: false,
    });
    expect(/^[a-z]+$/.test(pw)).toBe(true);
  });

  it("generates multi-word passphrases", () => {
    expect(generatePassphrase(4).split("-")).toHaveLength(4);
  });
});

describe("device key exchange + signing", () => {
  it("two devices derive the same shared secret (X25519 ECDH)", () => {
    const a = generateExchangeKeys();
    const b = generateExchangeKeys();
    const secretA = deriveSharedSecret(a.privateKey, b.publicKey);
    const secretB = deriveSharedSecret(b.privateKey, a.publicKey);
    expect(secretA.equals(secretB)).toBe(true);
  });

  it("verifies a valid Ed25519 signature and rejects a forged one", () => {
    const keys = generateSigningKeys();
    const sig = signMessage(keys.privateKey, "approve-device:xyz");
    expect(verifyMessage(keys.publicKey, "approve-device:xyz", sig)).toBe(true);
    expect(verifyMessage(keys.publicKey, "approve-device:EVIL", sig)).toBe(
      false
    );
  });
});
