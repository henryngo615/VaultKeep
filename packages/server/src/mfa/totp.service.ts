import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

/**
 * RFC 6238 TOTP (Time-based One-Time Password) — the daily-driver MFA method.
 * The shared secret is generated server-side at enrollment, shown to the user
 * as a QR/otpauth URI, then stored ENCRYPTED (to the user's vault key).
 *
 * This implementation is real and self-contained — no external dependency.
 */

const STEP_SECONDS = 30;
const DIGITS = 6;

/** Base32 (RFC 4648) without padding — the format authenticator apps expect. */
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function generateSecret(bytes = 20): string {
  const buf = randomBytes(bytes);
  let bits = "";
  for (const b of buf) bits += b.toString(2).padStart(8, "0");
  let out = "";
  for (let i = 0; i + 5 <= bits.length; i += 5) {
    out += B32[parseInt(bits.slice(i, i + 5), 2)];
  }
  return out;
}

export function otpauthURI(secret: string, label: string, issuer = "VaultKeep") {
  const l = encodeURIComponent(`${issuer}:${label}`);
  return `otpauth://totp/${l}?secret=${secret}&issuer=${encodeURIComponent(
    issuer
  )}&algorithm=SHA1&digits=${DIGITS}&period=${STEP_SECONDS}`;
}

function b32decode(s: string): Buffer {
  let bits = "";
  for (const c of s.toUpperCase().replace(/=+$/, "")) {
    const v = B32.indexOf(c);
    if (v < 0) continue;
    bits += v.toString(2).padStart(5, "0");
  }
  const bytes: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return Buffer.from(bytes);
}

function codeAt(secret: string, counter: number): string {
  const key = b32decode(secret);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const hmac = createHmac("sha1", key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const bin =
    ((hmac[offset] & 0x7f) << 24) |
    (hmac[offset + 1] << 16) |
    (hmac[offset + 2] << 8) |
    hmac[offset + 3];
  return (bin % 10 ** DIGITS).toString().padStart(DIGITS, "0");
}

/** The code valid right now — used by tests and for display in setup flows. */
export function currentCode(secret: string): string {
  return codeAt(secret, Math.floor(Date.now() / 1000 / STEP_SECONDS));
}

/** Verify a user-supplied code, allowing ±1 step for clock skew. */
export function verifyTOTP(secret: string, token: string): boolean {
  const counter = Math.floor(Date.now() / 1000 / STEP_SECONDS);
  for (const drift of [-1, 0, 1]) {
    const expected = Buffer.from(codeAt(secret, counter + drift));
    const got = Buffer.from(token);
    if (expected.length === got.length && timingSafeEqual(expected, got)) {
      return true;
    }
  }
  return false;
}
