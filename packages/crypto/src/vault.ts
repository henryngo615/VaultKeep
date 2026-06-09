import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";

/**
 * AES-256-GCM authenticated encryption.
 *
 * Wire format of the returned blob (all concatenated, then base64):
 *
 *   ┌──────────────┬───────────────────────┬──────────────┐
 *   │ nonce (12 B) │ ciphertext (variable) │ authTag (16) │
 *   └──────────────┴───────────────────────┴──────────────┘
 *
 * GCM gives us confidentiality AND integrity: if the server (or anyone)
 * tampers with a single byte, decryption throws instead of returning garbage.
 */

const NONCE_BYTES = 12;
const TAG_BYTES = 16;

export function encrypt(key: Buffer, plaintext: string): string {
  if (key.length !== 32) throw new Error("AES-256 requires a 32-byte key");
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  const ct = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([nonce, ct, tag]).toString("base64");
}

export function decrypt(key: Buffer, blobB64: string): string {
  if (key.length !== 32) throw new Error("AES-256 requires a 32-byte key");
  const blob = Buffer.from(blobB64, "base64");
  if (blob.length < NONCE_BYTES + TAG_BYTES) {
    throw new Error("ciphertext too short / malformed");
  }
  const nonce = blob.subarray(0, NONCE_BYTES);
  const tag = blob.subarray(blob.length - TAG_BYTES);
  const ct = blob.subarray(NONCE_BYTES, blob.length - TAG_BYTES);

  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAuthTag(tag);
  // .final() throws if the auth tag doesn't verify — this is our tamper check.
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString("utf8");
}

/** Constant-time comparison helper (e.g. for verifying recovery keys). */
export function safeEqual(a: string, b: string): boolean {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ba.length !== bb.length) return false;
  return timingSafeEqual(ba, bb);
}
